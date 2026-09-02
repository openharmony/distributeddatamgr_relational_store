/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "connection_pool.h"

#include <gtest/gtest.h>

#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>

#include "common.h"
#include "rdb_errno.h"
#include "sqlite_connection.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace {
struct CreatorGate {
    std::mutex mutex;
    std::condition_variable condition;
    int started = 0;
    bool finish = false;
};

using AcquireResult = std::pair<int, std::shared_ptr<ConnectionPool::ConnNode>>;

bool WaitForCreator(const std::shared_ptr<CreatorGate> &gate)
{
    std::unique_lock<std::mutex> lock(gate->mutex);
    return gate->condition.wait_for(lock, std::chrono::seconds(2), [gate]() { return gate->started == 1; });
}

void FinishCreator(const std::shared_ptr<CreatorGate> &gate)
{
    {
        std::lock_guard<std::mutex> lock(gate->mutex);
        gate->finish = true;
    }
    gate->condition.notify_all();
}

std::shared_ptr<ConnectionPool::ConnNode> GetAcquireNode(std::future<AcquireResult> &acquireResult)
{
    auto [errCode, node] = acquireResult.get();
    EXPECT_EQ(E_OK, errCode);
    EXPECT_NE(nullptr, node);
    return node;
}
} // namespace

class ConnectionPoolTest : public testing::Test {};

/**
 * @tc.name: AcquireExtendNodeDoesNotBlockReleaseTest
 * @tc.desc: A slow connection creator must not hold the container mutex needed by Release or start duplicates.
 * @tc.type: FUNC
 */
HWTEST_F(ConnectionPoolTest, AcquireExtendNodeDoesNotBlockReleaseTest, TestSize.Level1)
{
    // NativeRdbTest enables -fno-access-control for white-box connection-pool coverage.
    auto container = std::make_shared<ConnectionPool::Container>();
    RdbStoreConfig config(RDB_TEST_PATH + "connection_pool_test.db");
    auto initialConnection = std::make_shared<SqliteConnection>(config, false);
    auto [errCode, node] = container->Initialize(
        [initialConnection]() { return std::make_pair(E_OK, initialConnection); }, 1, 5, false, true);
    ASSERT_EQ(E_OK, errCode);
    ASSERT_NE(nullptr, node);

    auto gate = std::make_shared<CreatorGate>();
    auto delayedConnection = std::make_shared<SqliteConnection>(config, false);
    container->InitMembers(
        [gate, delayedConnection]() {
            std::unique_lock<std::mutex> lock(gate->mutex);
            ++gate->started;
            gate->condition.notify_all();
            gate->condition.wait(lock, [gate]() { return gate->finish; });
            return std::make_pair(E_OK, delayedConnection);
        },
        1, 5, false);

    auto firstAcquireResult =
        std::async(std::launch::async, [container]() { return container->Acquire(std::chrono::seconds(5)); });
    EXPECT_TRUE(WaitForCreator(gate));

    auto secondAcquireResult =
        std::async(std::launch::async, [container]() { return container->Acquire(std::chrono::seconds(5)); });
    EXPECT_EQ(std::future_status::timeout, secondAcquireResult.wait_for(std::chrono::milliseconds(100)));
    {
        std::lock_guard<std::mutex> lock(gate->mutex);
        EXPECT_EQ(1, gate->started);
    }

    auto releaseResult =
        std::async(std::launch::async, [container, releaseNode = node]() { return container->Release(releaseNode); });
    EXPECT_EQ(std::future_status::ready, releaseResult.wait_for(std::chrono::seconds(2)));

    FinishCreator(gate);
    EXPECT_EQ(E_OK, releaseResult.get());
    auto firstNode = GetAcquireNode(firstAcquireResult);
    ASSERT_NE(nullptr, firstNode);
    auto secondNode = GetAcquireNode(secondAcquireResult);
    ASSERT_NE(nullptr, secondNode);
    EXPECT_NE(firstNode, secondNode);
    {
        std::lock_guard<std::mutex> lock(gate->mutex);
        EXPECT_EQ(1, gate->started);
    }
    EXPECT_EQ(E_OK, container->Release(firstNode));
    EXPECT_EQ(E_OK, container->Release(secondNode));
}

/**
 * @tc.name: AcquireWaitsForNodeWhenDisabledTest
 * @tc.desc: A disabled container waits for a returned node instead of creating a connection.
 * @tc.type: FUNC
 */
HWTEST_F(ConnectionPoolTest, AcquireWaitsForNodeWhenDisabledTest, TestSize.Level1)
{
    auto container = std::make_shared<ConnectionPool::Container>();
    RdbStoreConfig config(RDB_TEST_PATH + "connection_pool_test.db");
    auto initialConnection = std::make_shared<SqliteConnection>(config, false);
    auto [errCode, node] = container->Initialize(
        [initialConnection]() { return std::make_pair(E_OK, initialConnection); }, 1, 5, false, true);
    ASSERT_EQ(E_OK, errCode);
    ASSERT_NE(nullptr, node);

    auto creatorCalls = std::make_shared<int>(0);
    auto unexpectedConnection = std::make_shared<SqliteConnection>(config, false);
    container->InitMembers(
        [creatorCalls, unexpectedConnection]() {
            ++(*creatorCalls);
            return std::make_pair(E_OK, unexpectedConnection);
        },
        1, 5, true);

    auto timeoutAcquireResult =
        std::async(std::launch::async, [container]() { return container->Acquire(std::chrono::milliseconds(100)); });
    auto [timeoutErr, timeoutNode] = timeoutAcquireResult.get();
    EXPECT_EQ(E_DATABASE_BUSY, timeoutErr);
    EXPECT_EQ(nullptr, timeoutNode);

    auto acquireResult =
        std::async(std::launch::async, [container]() { return container->Acquire(std::chrono::seconds(5)); });
    EXPECT_EQ(std::future_status::timeout, acquireResult.wait_for(std::chrono::milliseconds(100)));
    EXPECT_EQ(E_OK, container->Release(node));

    auto [acquireErr, acquiredNode] = acquireResult.get();
    EXPECT_EQ(E_OK, acquireErr);
    EXPECT_EQ(node, acquiredNode);
    EXPECT_EQ(0, *creatorCalls);
    if (acquiredNode != nullptr) {
        EXPECT_EQ(E_OK, container->Release(acquiredNode));
    }
}

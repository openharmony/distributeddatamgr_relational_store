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
    bool started = false;
    bool finish = false;
};
} // namespace

class ConnectionPoolTest : public testing::Test {};

/**
 * @tc.name: AcquireExtendNodeDoesNotBlockReleaseTest
 * @tc.desc: A slow connection creator must not hold the container mutex needed by Release.
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
            gate->started = true;
            gate->condition.notify_all();
            gate->condition.wait(lock, [gate]() { return gate->finish; });
            return std::make_pair(E_OK, delayedConnection);
        },
        1, 5, false);

    auto acquireResult =
        std::async(std::launch::async, [container]() { return container->Acquire(std::chrono::seconds(5)); });
    bool creatorStarted = false;
    {
        std::unique_lock<std::mutex> lock(gate->mutex);
        creatorStarted = gate->condition.wait_for(lock, std::chrono::seconds(2), [gate]() { return gate->started; });
    }
    EXPECT_TRUE(creatorStarted);

    auto releaseResult =
        std::async(std::launch::async, [container, releaseNode = node]() { return container->Release(releaseNode); });
    EXPECT_EQ(std::future_status::ready, releaseResult.wait_for(std::chrono::seconds(2)));

    {
        std::lock_guard<std::mutex> lock(gate->mutex);
        gate->finish = true;
    }
    gate->condition.notify_all();
    EXPECT_EQ(E_OK, releaseResult.get());
    auto [acquireErr, acquiredNode] = acquireResult.get();
    EXPECT_EQ(E_OK, acquireErr);
    EXPECT_NE(nullptr, acquiredNode);
    if (acquiredNode != nullptr) {
        EXPECT_EQ(E_OK, container->Release(acquiredNode));
    }
}

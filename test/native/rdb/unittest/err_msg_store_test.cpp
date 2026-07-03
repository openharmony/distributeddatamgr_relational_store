/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "err_msg_store.h"

#include <gtest/gtest.h>

#include <future>
#include <thread>
#include <vector>

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class ErrMsgStoreTest : public testing::Test {
public:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

HWTEST_F(ErrMsgStoreTest, SetAndGet_001, TestSize.Level1)
{
    auto &store = ErrMsgStore::Instance();
    int obj = 0;
    store.Set(&obj, "test error message");
    EXPECT_EQ(store.Get(&obj), "test error message");
    store.Clear(&obj);
    EXPECT_EQ(store.Get(&obj), "");
}

HWTEST_F(ErrMsgStoreTest, Clear_002, TestSize.Level1)
{
    auto &store = ErrMsgStore::Instance();
    int obj = 0;
    store.Set(&obj, "msg");
    store.Clear(&obj);
    EXPECT_EQ(store.Get(&obj), "");
}

HWTEST_F(ErrMsgStoreTest, GetNonExistent_003, TestSize.Level1)
{
    auto &store = ErrMsgStore::Instance();
    int obj = 0;
    EXPECT_EQ(store.Get(&obj), "");
}

HWTEST_F(ErrMsgStoreTest, ThreadIsolation_004, TestSize.Level1)
{
    auto &store = ErrMsgStore::Instance();
    int obj = 0;
    std::string mainMsg = "main thread error";
    store.Set(&obj, mainMsg);

    auto future = std::async(std::launch::async, [&store, &obj]() {
        std::string workerMsg = "worker thread error";
        store.Set(&obj, workerMsg);
        auto got = store.Get(&obj);
        store.Clear(&obj);
        return got;
    });

    std::string workerResult = future.get();
    EXPECT_EQ(workerResult, "worker thread error");
    EXPECT_EQ(store.Get(&obj), "main thread error");
    store.Clear(&obj);
}

HWTEST_F(ErrMsgStoreTest, MultiThreadNoCrossContamination_005, TestSize.Level1)
{
    auto &store = ErrMsgStore::Instance();
    int obj = 0;
    int threadCount = 8;
    std::vector<std::future<std::string>> futures;

    for (int i = 0; i < threadCount; i++) {
        futures.push_back(std::async(std::launch::async, [&store, &obj, i]() {
            std::string msg = "error_from_thread_" + std::to_string(i);
            store.Set(&obj, msg);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            auto got = store.Get(&obj);
            store.Clear(&obj);
            return got;
        }));
    }

    for (int i = 0; i < threadCount; i++) {
        std::string result = futures[i].get();
        EXPECT_EQ(result, "error_from_thread_" + std::to_string(i));
    }
}

HWTEST_F(ErrMsgStoreTest, RemoveAll_006, TestSize.Level1)
{
    auto &store = ErrMsgStore::Instance();
    int obj = 0;
    store.Set(&obj, "main msg");

    auto future = std::async(std::launch::async, [&store, &obj]() {
        store.Set(&obj, "worker msg");
        auto got = store.Get(&obj);
        return got;
    });
    future.wait();

    store.RemoveAll(&obj);
    EXPECT_EQ(store.Get(&obj), "");

    auto workerCheck = std::async(std::launch::async, [&store, &obj]() { return store.Get(&obj); });
    EXPECT_EQ(workerCheck.get(), "");
}

HWTEST_F(ErrMsgStoreTest, MultipleObjects_007, TestSize.Level1)
{
    auto &store = ErrMsgStore::Instance();
    int obj1 = 0;
    int obj2 = 1;
    store.Set(&obj1, "obj1 error");
    store.Set(&obj2, "obj2 error");
    EXPECT_EQ(store.Get(&obj1), "obj1 error");
    EXPECT_EQ(store.Get(&obj2), "obj2 error");
    store.RemoveAll(&obj1);
    EXPECT_EQ(store.Get(&obj1), "");
    EXPECT_EQ(store.Get(&obj2), "obj2 error");
    store.RemoveAll(&obj2);
}

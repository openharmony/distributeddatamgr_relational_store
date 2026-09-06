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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

#include "rdb_manager_mock.h"
#include "rdb_service_mock.h"
#include "rdb_store_impl.h"
#include "task_executor.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedRdb;

namespace {
constexpr char ASYNC_DB_PATH[] = "/data/test/async_after_open_inner_open.db";
constexpr char DEPENDENT_DB_PATH[] = "/data/test/async_after_open_dependency.db";

class AsyncAfterOpenTest : public Test {
public:
    void SetUp() override
    {
        oldManager_ = BRdbManager::rdbManager;
        oldPool_ = TaskExecutor::GetInstance().GetExecutor();
        testPool_ = std::make_shared<OHOS::ExecutorPool>(1, 0, "AsyncAfterOpenTest");
        TaskExecutor::GetInstance().SetExecutor(testPool_);
        manager_ = std::make_shared<MockRdbManager>();
        BRdbManager::rdbManager = manager_;
    }

    void TearDown() override
    {
        BRdbManager::rdbManager = oldManager_;
        TaskExecutor::GetInstance().SetExecutor(oldPool_);
        testPool_.reset();
        oldPool_.reset();
        manager_.reset();
    }

    static RdbStoreConfig MakeConfig(const std::string &path)
    {
        RdbStoreConfig config(path);
        config.SetBundleName("com.example.async.afteropen");
        config.SetRegisterInfo(RegisterType::CLIENT_OBSERVER, true);
        return config;
    }

    std::shared_ptr<MockRdbManager> manager_;
    std::shared_ptr<OHOS::ExecutorPool> oldPool_;
    std::shared_ptr<OHOS::ExecutorPool> testPool_;
    std::shared_ptr<BRdbManager> oldManager_;
};

class AsyncAfterOpenEmptyCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override
    {
        return E_OK;
    }

    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override
    {
        return E_OK;
    }
};
} // namespace

/* *
 * @tc.name: InitReturnsBeforeAfterOpenCompletes
 * @tc.desc: Init returns before the async AfterOpen task completes
 * @tc.type: FUNC
 */
HWTEST_F(AsyncAfterOpenTest, InitReturnsBeforeAfterOpenCompletes, TestSize.Level1)
{
    auto service = std::make_shared<MockRdbService>();
    std::mutex mutex;
    std::condition_variable condition;
    bool entered = false;
    bool release = false;
    EXPECT_CALL(*manager_, GetRdbService(_)).WillRepeatedly(Return(std::make_pair(E_OK, service)));
    EXPECT_CALL(*service, AfterOpen(_)).WillOnce(Invoke([&](const RdbSyncerParam &) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            entered = true;
        }
        condition.notify_one();
        std::unique_lock<std::mutex> lock(mutex);
        condition.wait(lock, [&release]() { return release; });
        return E_OK;
    }));

    auto config = MakeConfig(ASYNC_DB_PATH);
    RdbStoreImpl store(config);
    AsyncAfterOpenEmptyCallback callback;
    auto begin = std::chrono::steady_clock::now();
    EXPECT_EQ(store.Init(1, callback), E_OK);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin);
    EXPECT_LT(elapsed.count(), 500);
    {
        std::unique_lock<std::mutex> lock(mutex);
        ASSERT_TRUE(condition.wait_for(lock, std::chrono::milliseconds(500), [&entered]() { return entered; }));
    }
    EXPECT_TRUE(store.afterOpenFuture_.valid());
    EXPECT_NE(store.afterOpenFuture_.wait_for(std::chrono::milliseconds(0)), std::future_status::ready);
    {
        std::lock_guard<std::mutex> lock(mutex);
        release = true;
    }
    condition.notify_all();
    for (int retry = 0;
         retry < 50 && store.afterOpenFuture_.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready;
         ++retry) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_EQ(store.afterOpenFuture_.wait_for(std::chrono::milliseconds(0)), std::future_status::ready);
}

/* *
 * @tc.name: DependentIpcWaitsForAfterOpen
 * @tc.desc: A dependent IPC waits for AfterOpen to complete before being sent
 * @tc.type: FUNC
 */
HWTEST_F(AsyncAfterOpenTest, DependentIpcWaitsForAfterOpen, TestSize.Level1)
{
    auto service = std::make_shared<MockRdbService>();
    std::atomic<int32_t> serviceCalls(0);
    EXPECT_CALL(*manager_, GetRdbService(_)).WillOnce(Return(std::make_pair(E_OK, service)));
    EXPECT_CALL(*service, SetDistributedTables(_, _, _, _, _))
        .WillOnce(Invoke([&serviceCalls](const RdbSyncerParam &, const std::vector<std::string> &,
                             const std::vector<Reference> &, bool, int32_t) {
            serviceCalls.fetch_add(1);
            return E_OK;
        }));

    auto config = MakeConfig(DEPENDENT_DB_PATH);
    RdbStoreImpl store(config);
    auto promise = std::make_shared<std::promise<void>>();
    store.afterOpenPromise_ = promise;
    store.afterOpenFuture_ = promise->get_future().share();
    DistributedConfig distributedConfig;
    std::atomic<int32_t> result(E_ERROR);
    std::thread caller([&store, &distributedConfig, &result]() {
        result.store(store.SetDistributedTables({ "employee" }, DISTRIBUTED_DEVICE, distributedConfig));
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_EQ(serviceCalls.load(), 0);
    promise->set_value();
    caller.join();
    EXPECT_EQ(result.load(), E_OK);
    EXPECT_EQ(serviceCalls.load(), 1);
}

/* *
 * @tc.name: SearchableStoreUsesSyncAfterOpen
 * @tc.desc: Searchable store uses synchronous AfterOpen (future stays invalid)
 * @tc.type: FUNC
 */
HWTEST_F(AsyncAfterOpenTest, SearchableStoreUsesSyncAfterOpen, TestSize.Level1)
{
    auto service = std::make_shared<MockRdbService>();
    EXPECT_CALL(*manager_, GetRdbService(_)).WillRepeatedly(Return(std::make_pair(E_OK, service)));
    EXPECT_CALL(*service, AfterOpen(_)).WillOnce(Return(E_OK));

    auto config = MakeConfig("/data/test/async_after_open_searchable.db");
    config.SetSearchable(true);
    RdbStoreImpl store(config);
    AsyncAfterOpenEmptyCallback callback;
    EXPECT_EQ(store.Init(1, callback), E_OK);
    // Searchable path uses synchronous AfterOpen, not AfterOpenAsync → future is invalid
    EXPECT_FALSE(store.afterOpenFuture_.valid());
    // WaitAfterOpen on invalid future returns immediately
    EXPECT_EQ(store.WaitAfterOpen(), E_OK);
}

/* *
 * @tc.name: SilentAccessibleStoreUsesSyncAfterOpen
 * @tc.desc: Data-share silent accessible store keeps synchronous AfterOpen (future stays invalid)
 * @tc.type: FUNC
 */
HWTEST_F(AsyncAfterOpenTest, SilentAccessibleStoreUsesSyncAfterOpen, TestSize.Level1)
{
    auto service = std::make_shared<MockRdbService>();
    EXPECT_CALL(*manager_, GetRdbService(_)).WillRepeatedly(Return(std::make_pair(E_OK, service)));
    EXPECT_CALL(*service, AfterOpen(_)).WillRepeatedly(Return(E_OK));

    auto config = MakeConfig("/data/test/async_after_open_silent_sync.db");
    RdbStoreImpl store(config);
    AsyncAfterOpenEmptyCallback callback;
    EXPECT_EQ(store.Init(1, callback, false, true), E_OK);
    EXPECT_FALSE(store.afterOpenFuture_.valid());
    EXPECT_EQ(store.WaitAfterOpen(), E_OK);
}

/* *
 * @tc.name: AfterOpenServiceNotFoundRetries
 * @tc.desc: GetRdbService returns E_SERVICE_NOT_FOUND → AfterOpen retries via pool Schedule
 * @tc.type: FUNC
 */
HWTEST_F(AsyncAfterOpenTest, AfterOpenServiceNotFoundRetries, TestSize.Level1)
{
    auto service = std::make_shared<MockRdbService>();
    std::atomic<int32_t> calls(0);
    // GetRdbService fails first (service not up yet), succeeds on later retries
    EXPECT_CALL(*manager_, GetRdbService(_)).WillRepeatedly(Invoke([&](const RdbSyncerParam &) {
        return calls.fetch_add(1) == 0 ? std::make_pair(E_SERVICE_NOT_FOUND, std::shared_ptr<RdbService>())
                                       : std::make_pair(E_OK, service);
    }));
    EXPECT_CALL(*service, AfterOpen(_)).WillRepeatedly(Return(E_OK));

    auto config = MakeConfig("/data/test/async_after_open_retry.db");
    RdbStoreImpl store(config);
    AsyncAfterOpenEmptyCallback callback;
    EXPECT_EQ(store.Init(1, callback), E_OK);
    // First failure releases the waiter immediately, before the background retry completes
    for (int i = 0; i < 100 &&
         store.afterOpenFuture_.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready;
         ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_EQ(store.afterOpenFuture_.wait_for(std::chrono::milliseconds(0)), std::future_status::ready);
    // Background retry succeeds after RETRY_INTERVAL
    for (int retry = 0; retry < 200 && calls.load() < 2; ++retry) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    EXPECT_GE(calls.load(), 2);
}

/* *
 * @tc.name: AfterOpenAsyncPoolNullFallbackSync
 * @tc.desc: AfterOpenAsync with pool==nullptr falls back to synchronous AfterOpen
 * @tc.type: FUNC
 */
HWTEST_F(AsyncAfterOpenTest, AfterOpenAsyncPoolNullFallbackSync, TestSize.Level1)
{
    auto service = std::make_shared<MockRdbService>();
    EXPECT_CALL(*manager_, GetRdbService(_)).WillRepeatedly(Return(std::make_pair(E_OK, service)));
    EXPECT_CALL(*service, AfterOpen(_)).WillOnce(Return(E_OK));

    // Remove executor → pool==nullptr → synchronous AfterOpen fallback
    TaskExecutor::GetInstance().SetExecutor(nullptr);

    auto config = MakeConfig("/data/test/async_after_open_poolnull.db");
    RdbStoreImpl store(config);
    AsyncAfterOpenEmptyCallback callback;
    EXPECT_EQ(store.Init(1, callback), E_OK);
    // Synchronous fallback → future is set immediately
    for (int retry = 0;
         retry < 50 && store.afterOpenFuture_.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready;
         ++retry) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_EQ(store.afterOpenFuture_.wait_for(std::chrono::milliseconds(0)), std::future_status::ready);

    // Restore executor for TearDown
    TaskExecutor::GetInstance().SetExecutor(testPool_);
}

/* *
 * @tc.name: WaitAfterOpenFutureInvalidReturnsOk
 * @tc.desc: WaitAfterOpen on a store without AfterOpenAsync (future invalid) returns E_OK
 * @tc.type: FUNC
 */
HWTEST_F(AsyncAfterOpenTest, WaitAfterOpenFutureInvalidReturnsOk, TestSize.Level1)
{
    auto config = MakeConfig("/data/test/async_after_open_noinit.db");
    RdbStoreImpl store(config);
    // AfterOpenAsync was never called → future is invalid
    EXPECT_FALSE(store.afterOpenFuture_.valid());
    EXPECT_EQ(store.WaitAfterOpen(), E_OK);
}

/* *
 * @tc.name: AfterOpenServiceErrorReturnsConvertedCode
 * @tc.desc: AfterOpen service returns non-E_OK error → ConvertRdbStatusNative applied
 * @tc.type: FUNC
 */
HWTEST_F(AsyncAfterOpenTest, AfterOpenServiceErrorReturnsConvertedCode, TestSize.Level1)
{
    auto service = std::make_shared<MockRdbService>();
    EXPECT_CALL(*manager_, GetRdbService(_)).WillRepeatedly(Return(std::make_pair(E_OK, service)));
    // service->AfterOpen returns RDB_ERROR (non-E_OK)
    EXPECT_CALL(*service, AfterOpen(_)).WillOnce(Return(E_ERROR));

    auto config = MakeConfig("/data/test/async_after_open_serviceerror.db");
    RdbStoreImpl store(config);
    AsyncAfterOpenEmptyCallback callback;
    EXPECT_EQ(store.Init(1, callback), E_OK);
    // AfterOpen completes (err != E_SERVICE_NOT_FOUND) → promise set → future ready
    for (int retry = 0;
         retry < 50 && store.afterOpenFuture_.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready;
         ++retry) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_EQ(store.afterOpenFuture_.wait_for(std::chrono::milliseconds(0)), std::future_status::ready);
}

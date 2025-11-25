/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>

#include <functional>
#include <string>

#include "block_data.h"
#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_sql_statistic.h"
#include "rdb_store_manager.h"
#include "rdb_types.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedRdb;
using CheckOnChangeFunc = std::function<void(RdbStoreObserver::ChangeInfo &changeInfo)>;
using SqlStatisticsFunc = std::function<void(SqlObserver::SqlExecutionInfo &info)>;
class SubObserver : public RdbStoreObserver {
public:
    virtual ~SubObserver()
    {
    }
    void OnChange(const std::vector<std::string> &devices) override;
    void OnChange(
        const Origin &origin, const PrimaryFields &fields, RdbStoreObserver::ChangeInfo &&changeInfo) override;
    void OnChange() override;
    void RegisterCallback(const CheckOnChangeFunc &callback);
    uint32_t count = 0;

private:
    CheckOnChangeFunc checkOnChangeFunc_;
};
class LocalShareObserver : public RdbStoreObserver {
public:
    explicit LocalShareObserver(std::function<void()> func) : callback_(func)
    {
    }
    void OnChange(const std::vector<std::string> &devices){};
    void OnChange()
    {
        if (callback_ != nullptr) {
            callback_();
        }
    };

private:
    std::function<void()> callback_;
};

class StatisticsObserver : public SqlObserver {
public:
    virtual ~StatisticsObserver()
    {
    }
    void OnStatistic(const SqlExecutionInfo &info);
    void Callback(const SqlStatisticsFunc &callback);

private:
    SqlStatisticsFunc sqlStatisticsFunc_;
};

class RdbStoreSubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string MAIN_DATABASE_NAME;
    static std::shared_ptr<RdbStore> CreateRDB(int version);
    static void RegisterCheckInsertCallback(const std::vector<std::shared_ptr<SubObserver>> &SubObservers);
    static void RegisterCheckUpdateCallback(const std::vector<std::shared_ptr<SubObserver>> &SubObservers);
    static std::shared_ptr<RdbStore> store;
    static std::shared_ptr<SubObserver> observer_;
    static std::shared_ptr<StatisticsObserver> sqlObserver_;
};

class TestDetailProgressObserver : public DetailProgressObserver {
public:
    virtual ~TestDetailProgressObserver()
    {
    }
    void ProgressNotification(const Details &details) override {};
};

const std::string RdbStoreSubTest::MAIN_DATABASE_NAME = RDB_TEST_PATH + "subscribe.db";
std::shared_ptr<RdbStore> RdbStoreSubTest::store = nullptr;
std::shared_ptr<SubObserver> RdbStoreSubTest::observer_ = nullptr;
std::shared_ptr<StatisticsObserver> RdbStoreSubTest::sqlObserver_ = nullptr;

void RdbStoreSubTest::SetUpTestCase(void)
{
    RdbHelper::DeleteRdbStore(MAIN_DATABASE_NAME);
    store = CreateRDB(1);
    if (observer_ == nullptr) {
        observer_ = std::make_shared<SubObserver>();
    }
    if (sqlObserver_ == nullptr) {
        sqlObserver_ = std::make_shared<StatisticsObserver>();
    }
}

void RdbStoreSubTest::TearDownTestCase(void)
{
    store = nullptr;
    RdbHelper::DeleteRdbStore(MAIN_DATABASE_NAME);
}

void RdbStoreSubTest::SetUp()
{
}

void RdbStoreSubTest::TearDown()
{
}

class Callback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

int Callback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int Callback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void SubObserver::OnChange(const std::vector<std::string> &devices)
{
}

void SubObserver::OnChange(const Origin &origin, const PrimaryFields &fields, RdbStoreObserver::ChangeInfo &&changeInfo)
{
    count++;
    if (checkOnChangeFunc_) {
        checkOnChangeFunc_(changeInfo);
    }
}

void SubObserver::OnChange()
{
    count++;
    const std::string CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test "
                                          "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                          "name TEXT NOT NULL, age INTEGER, salary "
                                          "REAL, blobType BLOB)";
    RdbStoreSubTest::store->ExecuteSql(CREATE_TABLE_TEST);
    ValuesBucket values;
    int64_t id;
    values.PutInt("id", count);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = RdbStoreSubTest::store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, id);
}

void SubObserver::RegisterCallback(const CheckOnChangeFunc &callback)
{
    checkOnChangeFunc_ = callback;
}

void StatisticsObserver::OnStatistic(const StatisticsObserver::SqlExecutionInfo &info)
{
}

void StatisticsObserver::Callback(const SqlStatisticsFunc &callback)
{
    sqlStatisticsFunc_ = callback;
}

std::shared_ptr<RdbStore> RdbStoreSubTest::CreateRDB(int version)
{
    RdbStoreConfig config(RdbStoreSubTest::MAIN_DATABASE_NAME);
    config.SetBundleName("subscribe_test");
    config.SetArea(0);
    config.SetCreateNecessary(true);
    config.SetDistributedType(RDB_DEVICE_COLLABORATION);
    config.SetSecurityLevel(OHOS::NativeRdb::SecurityLevel::S1);
    Callback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, version, helper, errCode);
    EXPECT_NE(store, nullptr);
    return store;
}

void RdbStoreSubTest::RegisterCheckInsertCallback(const std::vector<std::shared_ptr<SubObserver>> &SubObservers)
{
    for (const auto &observer : SubObservers) {
        observer->RegisterCallback([](RdbStoreObserver::ChangeInfo &changeInfo) {
            ASSERT_EQ(changeInfo.size(), 1u);
            EXPECT_TRUE(changeInfo["local_test"][1].empty());
            EXPECT_TRUE(changeInfo["local_test"][2].empty()); // 2 is delete subscript
            EXPECT_EQ(std::get<int64_t>(changeInfo["local_test"][0][0]), 1);
        });
    }
}

void RdbStoreSubTest::RegisterCheckUpdateCallback(const std::vector<std::shared_ptr<SubObserver>> &SubObservers)
{
    for (const auto &observer : SubObservers) {
        observer->RegisterCallback([](RdbStoreObserver::ChangeInfo &changeInfo) {
            ASSERT_EQ(changeInfo.size(), 1u);
            EXPECT_TRUE(changeInfo["local_test"][0].empty());
            EXPECT_TRUE(changeInfo["local_test"][2].empty()); // 2 is delete subscript
            EXPECT_EQ(std::get<int64_t>(changeInfo["local_test"][1][0]), 1);
        });
    }
}

/**
 * @tc.name: RdbStoreSubscribeRemote
 * @tc.desc: RdbStoreSubscribe
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeRemote, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->Subscribe({ SubscribeMode::REMOTE, "observer" }, observer_);
    EXPECT_EQ(status, E_OK);
    status = store->UnSubscribe({ SubscribeMode::REMOTE, "observer" }, observer_);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeCloud
 * @tc.desc: RdbStoreSubscribe
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeCloud, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->Subscribe({ SubscribeMode::CLOUD, "observer" }, observer_);
    EXPECT_EQ(status, E_OK);
    status = store->UnSubscribe({ SubscribeMode::CLOUD, "observer" }, observer_);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeCloudDetail
 * @tc.desc: RdbStoreSubscribe
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeCloudDetail, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->Subscribe({ SubscribeMode::CLOUD_DETAIL, "observer" }, observer_);
    EXPECT_EQ(status, E_OK);
    status = store->UnSubscribe({ SubscribeMode::CLOUD_DETAIL, "observer" }, observer_);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeLocal
 * @tc.desc: RdbStoreSubscribe
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLocal, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->Subscribe({ SubscribeMode::LOCAL, "observer1" }, observer_);
    store->Subscribe({ SubscribeMode::LOCAL, "observer1" }, observer_);
    EXPECT_EQ(status, E_OK);
    store->Subscribe({ SubscribeMode::LOCAL, "observer2" }, observer_);
    EXPECT_EQ(status, E_OK);

    status = store->Notify("observer1");
    EXPECT_EQ(status, E_OK);
    status = store->Notify("observer2");
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(observer_->count, 2);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    int count;
    resultSet->GetRowCount(count);
    EXPECT_EQ(observer_->count, count);
    status = store->UnSubscribe({ SubscribeMode::LOCAL, "nonexistent" }, observer_);
    EXPECT_EQ(status, E_OK);
    status = store->UnSubscribe({ SubscribeMode::LOCAL, "observer1" }, observer_);
    EXPECT_EQ(status, E_OK);
    status = store->UnSubscribe({ SubscribeMode::LOCAL, "nonexistent" }, nullptr);
    EXPECT_EQ(status, E_OK);
    status = store->UnSubscribe({ SubscribeMode::LOCAL, "observer2" }, nullptr);
    EXPECT_EQ(status, E_OK);
    status = store->Notify("observer1");
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeLocalShared001
 * @tc.desc: RdbStoreSubscribe
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLocalShared001, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->Subscribe({ SubscribeMode::LOCAL_SHARED, "observer1" }, observer_);
    EXPECT_EQ(status, E_OK);
    status = store->Subscribe({ SubscribeMode::LOCAL_SHARED, "observer1" }, observer_);
    EXPECT_EQ(status, E_OK);
    status = store->Subscribe({ SubscribeMode::LOCAL_SHARED, "observer2" }, observer_);
    EXPECT_EQ(status, E_OK);

    status = store->UnSubscribe({ SubscribeMode::LOCAL_SHARED, "nonexistent" }, observer_);
    EXPECT_EQ(status, E_OK);
    status = store->UnSubscribe({ SubscribeMode::LOCAL_SHARED, "observer1" }, observer_);
    EXPECT_EQ(status, E_OK);
    status = store->UnSubscribe({ SubscribeMode::LOCAL_SHARED, "nonexistent" }, nullptr);
    EXPECT_EQ(status, E_OK);
    status = store->UnSubscribe({ SubscribeMode::LOCAL_SHARED, "observer2" }, nullptr);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeLocalShared002
 * @tc.desc: RdbStoreSubscribe
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLocalShared002, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    auto block = std::make_shared<OHOS::BlockData<bool>>(5, false);
    auto callback = [block]() { block->SetValue(true); };
    auto observer = std::make_shared<LocalShareObserver>(callback);
    auto status = store->Subscribe({ SubscribeMode::LOCAL_SHARED, "RdbStoreSubscribeLocalShared002" }, observer);
    EXPECT_EQ(status, E_OK);
    status = store->Notify("RdbStoreSubscribeLocalShared002");
    EXPECT_EQ(status, E_OK);
    EXPECT_TRUE(block->GetValue());
    status = store->UnSubscribe({ SubscribeMode::LOCAL_SHARED, "RdbStoreSubscribeLocalShared002" }, observer);
}

/**
 * @tc.name: RdbStoreSubscribeLocalShared003
 * @tc.desc: RdbStoreSubscribe
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLocalShared003, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    auto count = std::make_shared<std::atomic<int32_t>>(0);
    auto callback = [count]() { count->fetch_add(1); };
    auto observer = std::make_shared<LocalShareObserver>(callback);
    auto status = store->Subscribe({ SubscribeMode::LOCAL_SHARED, "RdbStoreSubscribeLocalShared003" }, observer);
    EXPECT_EQ(status, E_OK);
    status = store->Subscribe({ SubscribeMode::LOCAL_SHARED, "RdbStoreSubscribeLocalShared003" }, observer);
    EXPECT_EQ(status, E_OK);
    status = store->Notify("RdbStoreSubscribeLocalShared003");
    EXPECT_EQ(status, E_OK);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    EXPECT_EQ(count->load(), 1);
    status = store->UnSubscribe({ SubscribeMode::LOCAL_SHARED, "RdbStoreSubscribeLocalShared003" }, observer);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeLocalShared004
 * @tc.desc: UnSubscribe all
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLocalShared004, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    auto count = std::make_shared<std::atomic<int32_t>>(0);
    auto callback = [count]() { count->fetch_add(1); };
    auto observer1 = std::make_shared<LocalShareObserver>(callback);
    auto status = store->Subscribe({ SubscribeMode::LOCAL_SHARED, "RdbStoreSubscribeLocalShared004" }, observer1);
    EXPECT_EQ(status, E_OK);
    auto observer2 = std::make_shared<LocalShareObserver>(callback);
    status = store->Subscribe({ SubscribeMode::LOCAL_SHARED, "RdbStoreSubscribeLocalShared004" }, observer2);
    EXPECT_EQ(status, E_OK);
    status = store->UnSubscribe({ SubscribeMode::LOCAL_SHARED, "RdbStoreSubscribeLocalShared004" }, nullptr);
    EXPECT_EQ(status, E_OK);
    status = store->Notify("RdbStoreSubscribeLocalShared004");
    EXPECT_EQ(status, E_OK);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    EXPECT_EQ(count->load(), 0);
}

/**
 * @tc.name: RdbStoreSubscribeLocalShared005
 * @tc.desc: Subscribe after UnSubscribe
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLocalShared005, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    auto block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    auto callback = [block]() { block->SetValue(true); };
    auto observer = std::make_shared<LocalShareObserver>(callback);
    auto status = store->Subscribe({ SubscribeMode::LOCAL_SHARED, "RdbStoreSubscribeLocalShared005" }, observer);
    EXPECT_EQ(status, E_OK);
    status = store->UnSubscribe({ SubscribeMode::LOCAL_SHARED, "RdbStoreSubscribeLocalShared005" }, observer);
    EXPECT_EQ(status, E_OK);
    status = store->Notify("RdbStoreSubscribeLocalShared005");
    EXPECT_EQ(status, E_OK);
    EXPECT_FALSE(block->GetValue());

    status = store->Subscribe({ SubscribeMode::LOCAL_SHARED, "RdbStoreSubscribeLocalShared005" }, observer);
    EXPECT_EQ(status, E_OK);
    block->Clear(false);
    status = store->Notify("RdbStoreSubscribeLocalShared005");
    EXPECT_EQ(status, E_OK);
    EXPECT_TRUE(block->GetValue());
    status = store->UnSubscribe({ SubscribeMode::LOCAL_SHARED, "RdbStoreSubscribeLocalShared005" }, nullptr);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeLocalShared006
 * @tc.desc: Different db Subscribe same uri
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLocalShared006, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    RdbStoreConfig config(RDB_TEST_PATH + "RdbStoreSubscribeLocalShared006.db");
    config.SetBundleName("subscribe_test");
    Callback helper;
    int errCode = E_ERROR;
    std::shared_ptr<RdbStore> localStore = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(localStore, nullptr);
    ASSERT_EQ(errCode, E_OK);

    auto count = std::make_shared<std::atomic<int32_t>>(0);
    auto callback = [count]() { count->fetch_add(1); };
    auto observer = std::make_shared<LocalShareObserver>(callback);
    auto status = store->Subscribe({ SubscribeMode::LOCAL_SHARED, "RdbStoreSubscribeLocalShared006" }, observer);
    EXPECT_EQ(status, E_OK);
    status = localStore->Subscribe({ SubscribeMode::LOCAL_SHARED, "RdbStoreSubscribeLocalShared006" }, observer);
    EXPECT_EQ(status, E_OK);

    status = store->Notify("RdbStoreSubscribeLocalShared006");
    EXPECT_EQ(status, E_OK);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    EXPECT_EQ(count->load(), 1);
    status = localStore->Notify("RdbStoreSubscribeLocalShared006");
    EXPECT_EQ(status, E_OK);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    EXPECT_EQ(count->load(), 2);
    status = store->UnSubscribe({ SubscribeMode::LOCAL_SHARED, "RdbStoreSubscribeLocalShared006" }, nullptr);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(RdbHelper::DeleteRdbStore(config), E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeLocalShared007
 * @tc.desc: Subscribe to the same URI with different obs, then cancel all at once
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLocalShared007, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    auto count = std::make_shared<std::atomic<int32_t>>(0);
    auto callback = [count]() { count->fetch_add(1); };
    auto observer1 = std::make_shared<LocalShareObserver>(callback);
    auto status = store->Subscribe({ SubscribeMode::LOCAL_SHARED, "RdbStoreSubscribeLocalShared007" }, observer1);
    EXPECT_EQ(status, E_OK);

    auto observer2 = std::make_shared<LocalShareObserver>(callback);
    status = store->Subscribe({ SubscribeMode::LOCAL_SHARED, "RdbStoreSubscribeLocalShared007" }, observer2);
    EXPECT_EQ(status, E_OK);

    status = store->Notify("RdbStoreSubscribeLocalShared007");
    EXPECT_EQ(status, E_OK);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    EXPECT_EQ(count->load(), 2);
    status = store->UnSubscribe({ SubscribeMode::LOCAL_SHARED, "RdbStoreSubscribeLocalShared007" }, nullptr);
    EXPECT_EQ(status, E_OK);

    status = store->Notify("RdbStoreSubscribeLocalShared007");
    EXPECT_EQ(status, E_OK);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    EXPECT_EQ(count->load(), 2);
}

/**
 * @tc.name: RdbStoreSubscribeLocalDetail001
 * @tc.desc: test local observer onchange when insert data
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLocalDetail001, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    constexpr const char *createTableTest = "CREATE TABLE IF NOT EXISTS local_test "
                                            "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                            "name TEXT NOT NULL, age INTEGER)";
    store->ExecuteSql(createTableTest);
    auto status = store->SubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, observer_);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(status, E_OK);
    auto observer2 = std::make_shared<SubObserver>();
    status = store->SubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, observer2);

    RegisterCheckInsertCallback({ observer_, observer2 });

    ValuesBucket values;
    int64_t id;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18); // 18 is random age
    status = store->Insert(id, "local_test", values);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(id, 1);

    observer_->RegisterCallback([](RdbStoreObserver::ChangeInfo &) { ASSERT_TRUE(false); });
    observer2->RegisterCallback([](RdbStoreObserver::ChangeInfo &) { ASSERT_TRUE(false); });
    status = store->UnsubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, observer_);
    EXPECT_EQ(status, E_OK);
    status = store->UnsubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, observer2);
    EXPECT_EQ(status, E_OK);

    ValuesBucket values2;
    int id2;
    values2.PutString("name", std::string("zhangsan_update1"));
    values2.PutInt("age", 19); // 19 is random age
    AbsRdbPredicates predicates("local_test");
    predicates.EqualTo("id", 1);
    status = store->Update(id2, values2, predicates);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(id2, 1);
    observer_->RegisterCallback(nullptr);
    observer2->RegisterCallback(nullptr);
}

/**
 * @tc.name: RdbStoreSubscribeLocalDetail002
 * @tc.desc: test local observer onchange when update data
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLocalDetail002, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->SubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, observer_);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(status, E_OK);
    auto observer2 = std::make_shared<SubObserver>();
    status = store->SubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, observer2);

    RegisterCheckUpdateCallback({ observer_, observer2 });

    int id;
    ValuesBucket values;
    values.PutString("name", std::string("zhangsan_update2"));
    values.PutInt("age", 20); // 20 is random age
    AbsRdbPredicates predicates("local_test");
    predicates.EqualTo("id", 1);
    status = store->Update(id, values, predicates);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(id, 1);

    observer_->RegisterCallback([](RdbStoreObserver::ChangeInfo &) { ASSERT_TRUE(false); });
    status = store->UnsubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, observer_);
    EXPECT_EQ(status, E_OK);

    ValuesBucket values2;
    int id2;
    values2.PutString("name", std::string("zhangsan_update1"));
    values2.PutInt("age", 19); // 19 is random age
    AbsRdbPredicates predicates2("local_test");
    predicates2.EqualTo("id", 1);
    status = store->Update(id2, values2, predicates2);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(id2, 1);
    observer_->RegisterCallback(nullptr);
    observer2->RegisterCallback(nullptr);
    status = store->UnsubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, observer2);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeLocalDetail003
 * @tc.desc: test local observer onchange when delete data
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLocalDetail003, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->SubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, observer_);
    EXPECT_EQ(status, E_OK);

    observer_->RegisterCallback([](RdbStoreObserver::ChangeInfo &changeInfo) {
        ASSERT_EQ(changeInfo.size(), 1u);
        EXPECT_TRUE(changeInfo["local_test"][0].empty());
        EXPECT_TRUE(changeInfo["local_test"][1].empty());
        EXPECT_EQ(std::get<int64_t>(changeInfo["local_test"][2][0]), 1);
    });

    observer_->count = 0;
    int id;
    status = store->Delete(id, "local_test", "id = ?", std::vector<std::string>{ "1" });
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(id, 1);
    EXPECT_EQ(observer_->count, 1);

    status = store->UnsubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, observer_);
    EXPECT_EQ(status, E_OK);
    observer_->RegisterCallback(nullptr);
}

/**
 * @tc.name: RdbStoreSubscribeLocalDetail004
 * @tc.desc: test local observer onchange when batchinsert data
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLocalDetail004, TestSize.Level1)
{
    int num = 10;
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->SubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, observer_);
    EXPECT_EQ(status, E_OK);

    observer_->RegisterCallback([num](RdbStoreObserver::ChangeInfo &changeInfo) {
        ASSERT_EQ(changeInfo.size(), 1u);
        EXPECT_TRUE(changeInfo["local_test"][1].empty());
        EXPECT_TRUE(changeInfo["local_test"][2].empty()); // 2 is delete subscript
        for (int i = 0; i < num; i++) {
            EXPECT_EQ(std::get<int64_t>(changeInfo["local_test"][0][i]), i);
        }
    });

    observer_->count = 0;
    int64_t id;
    std::vector<ValuesBucket> values;
    for (int i = 0; i < num; i++) {
        ValuesBucket value;
        value.PutInt("id", i);
        value.PutString("name", std::string("zhangsan"));
        value.PutInt("age", 18); // 18 is random age
        values.push_back(value);
    }
    status = store->BatchInsert(id, "local_test", values);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(id, num);
    EXPECT_EQ(observer_->count, 1);
    status = store->UnsubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, observer_);
    EXPECT_EQ(status, E_OK);
    observer_->RegisterCallback(nullptr);
}

/**
 * @tc.name: RdbStoreSubscribeLocalDetail005
 * @tc.desc: test local observer onchange when create table after register observer
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLocalDetail005, TestSize.Level1)
{
    int num = 1;
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->SubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, observer_);
    EXPECT_EQ(status, E_OK);
    constexpr const char *createTableTest = "CREATE TABLE IF NOT EXISTS local_test1 "
                                            "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                            "name TEXT NOT NULL, age INTEGER)";
    store->ExecuteSql(createTableTest);

    observer_->RegisterCallback([num](RdbStoreObserver::ChangeInfo &changeInfo) {
        ASSERT_EQ(changeInfo.size(), 1u);
        EXPECT_TRUE(changeInfo["local_test1"][1].empty());
        EXPECT_TRUE(changeInfo["local_test1"][2].empty()); // 2 is delete subscript
        for (int i = 0; i < num; i++) {
            EXPECT_EQ(std::get<int64_t>(changeInfo["local_test1"][0][i]), i);
        }
    });
    observer_->count = 0;

    int64_t id;
    std::vector<ValuesBucket> values;
    for (int i = 0; i < num; i++) {
        ValuesBucket value;
        value.PutInt("id", i);
        value.PutString("name", std::string("zhangsan"));
        value.PutInt("age", 18); // 18 is random age
        values.push_back(value);
    }
    status = store->BatchInsert(id, "local_test1", values);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(id, num);
    EXPECT_EQ(observer_->count, 1);
    status = store->UnsubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, observer_);
    EXPECT_EQ(status, E_OK);
    status = store->SubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, observer_);
    EXPECT_EQ(status, E_OK);
    status = store->UnsubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, nullptr);
    EXPECT_EQ(status, E_OK);
    observer_->RegisterCallback(nullptr);
}

/**
 * @tc.name: RdbStoreSubscribeLocalDetail006
 * @tc.desc: test abnormal parametar subscribe
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLocalDetail006, TestSize.Level1)
{
    int num = 20;
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    constexpr const char *createTableTest = "CREATE TABLE IF NOT EXISTS local_test2"
                                            "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                            "name TEXT NOT NULL, age INTEGER)";
    store->ExecuteSql(createTableTest);
    auto status = store->SubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, observer_);
    EXPECT_EQ(status, E_OK);

    observer_->RegisterCallback([num](RdbStoreObserver::ChangeInfo &changeInfo) {
        ASSERT_EQ(changeInfo.size(), 1u);
        EXPECT_TRUE(changeInfo["local_test2"][1].empty());
        EXPECT_TRUE(changeInfo["local_test2"][2].empty()); // 2 is delete subscript
        for (int i = 0; i < num; i++) {
            EXPECT_EQ(std::get<int64_t>(changeInfo["local_test2"][0][i]), i);
        }
    });

    observer_->count = 0;
    std::vector<ValuesBucket> values;
    for (int i = 0; i < num; i++) {
        ValuesBucket value;
        value.PutInt("id", i);
        value.PutString("name", std::string("lisi"));
        value.PutInt("age", 16);
        values.push_back(value);
    }
    std::shared_ptr<Transaction> trans = nullptr;
    std::tie(status, trans) = store->CreateTransaction(Transaction::DEFERRED);
    EXPECT_EQ(status, E_OK);
    int64_t insertRows = 0;
    std::tie(status, insertRows) = trans->BatchInsert("local_test2", values);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(insertRows, num);
    EXPECT_EQ(observer_->count, 0);
    trans->Commit();
    trans = nullptr;
    EXPECT_EQ(observer_->count, 1);
    status = store->UnsubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, observer_);
    EXPECT_EQ(status, E_OK);
    observer_->RegisterCallback(nullptr);
}

/**
 * @tc.name: RdbStoreSubscribeLocalDetail007
 * @tc.desc: test abnormal parametar subscribe
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLocalDetail007, TestSize.Level1)
{
    int num = 20;
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    constexpr const char *createTableTest = "CREATE TABLE IF NOT EXISTS local_test3"
                                            "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                            "name TEXT NOT NULL, age INTEGER)";
    store->ExecuteSql(createTableTest);
    std::shared_ptr<Transaction> trans1 = nullptr;
    int status = 0;
    std::tie(status, trans1) = store->CreateTransaction(Transaction::DEFERRED);
    EXPECT_EQ(status, E_OK);
    status = store->SubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, observer_);
    EXPECT_EQ(status, E_OK);
    trans1 = nullptr;
    observer_->RegisterCallback([num](RdbStoreObserver::ChangeInfo &changeInfo) {
        ASSERT_EQ(changeInfo.size(), 1u);
        EXPECT_TRUE(changeInfo["local_test3"][1].empty());
        EXPECT_TRUE(changeInfo["local_test3"][2].empty()); // 2 is delete subscript
        for (int i = 0; i < num; i++) {
            EXPECT_EQ(std::get<int64_t>(changeInfo["local_test3"][0][i]), i);
        }
    });

    observer_->count = 0;
    std::vector<ValuesBucket> values;
    for (int i = 0; i < num; i++) {
        ValuesBucket value;
        value.PutInt("id", i);
        value.PutString("name", std::string("lisi"));
        value.PutInt("age", 16);
        values.push_back(value);
    }
    std::shared_ptr<Transaction> trans2 = nullptr;
    std::tie(status, trans2) = store->CreateTransaction(Transaction::DEFERRED);
    EXPECT_EQ(status, E_OK);
    int64_t insertRows = 0;
    std::tie(status, insertRows) = trans2->BatchInsert("local_test3", values);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(insertRows, num);
    EXPECT_EQ(observer_->count, 0);
    trans2->Commit();
    trans2 = nullptr;
    EXPECT_EQ(observer_->count, 1);
    status = store->UnsubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, observer_);
    EXPECT_EQ(status, E_OK);
    observer_->RegisterCallback(nullptr);
}

/**
 * @tc.name: RdbStoreSubscribeLocalDetail008
 * @tc.desc: test abnormal parametar subscribe
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLocalDetail008, TestSize.Level1)
{
    int num = 20;
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    constexpr const char *createTableTest = "CREATE TABLE IF NOT EXISTS local_test4"
                                            "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                            "name TEXT NOT NULL, age INTEGER)";
    store->ExecuteSql(createTableTest);
    auto status = store->SubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, observer_);
    EXPECT_EQ(status, E_OK);

    observer_->RegisterCallback([](RdbStoreObserver::ChangeInfo &) { ASSERT_TRUE(false); });

    observer_->count = 0;
    std::vector<ValuesBucket> values;
    for (int i = 0; i < num; i++) {
        ValuesBucket value;
        value.PutInt("id", i);
        value.PutString("name", std::string("lisi"));
        value.PutInt("age", 16);
        values.push_back(value);
    }
    std::shared_ptr<Transaction> trans = nullptr;
    std::tie(status, trans) = store->CreateTransaction(Transaction::DEFERRED);
    EXPECT_EQ(status, E_OK);
    int64_t insertRows = 0;
    std::tie(status, insertRows) = trans->BatchInsert("local_test4", values);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(insertRows, num);
    EXPECT_EQ(observer_->count, 0);
    status = store->UnsubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, observer_);
    EXPECT_EQ(status, E_OK);
    trans->Commit();
    trans = nullptr;
    EXPECT_EQ(observer_->count, 0);
    observer_->RegisterCallback(nullptr);
}

/**
 * @tc.name: RdbStoreSubscribeLocalDetail009
 * @tc.desc: test abnormal parametar subscribe
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLocalDetail009, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->SubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, nullptr);
    EXPECT_EQ(status, E_OK);
    observer_->RegisterCallback([](RdbStoreObserver::ChangeInfo &) { ASSERT_TRUE(false); });
    ValuesBucket values;
    int id;
    values.PutString("name", std::string("zhangsan_update1"));
    values.PutInt("age", 19); // 19 is random age
    AbsRdbPredicates predicates("local_test");
    predicates.EqualTo("id", 1);
    status = store->Update(id, values, predicates);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(id, 1); // 2 is random id
    observer_->RegisterCallback(nullptr);
}

/**
 * @tc.name: RdbStoreSubscribeStatistics001
 * @tc.desc: test statistics observer when insert data
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeStatistics001, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(sqlObserver_, nullptr) << "observer is null";
    constexpr const char *createTableTest = "CREATE TABLE IF NOT EXISTS statistics_test "
                                            "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                            "name TEXT NOT NULL, age INTEGER)";
    store->ExecuteSql(createTableTest);
    auto status = SqlStatistic::Subscribe(sqlObserver_);
    EXPECT_EQ(status, E_OK);
    auto observer2 = std::make_shared<StatisticsObserver>();
    status = SqlStatistic::Subscribe(sqlObserver_);
    ValuesBucket values;
    int64_t id;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18); // 18 is random age
    status = store->Insert(id, "statistics_test", values);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(id, 1);
    sqlObserver_->Callback([](SqlObserver::SqlExecutionInfo &info) { ASSERT_EQ(info.sql_.size(), 1); });
    observer2->Callback([](SqlObserver::SqlExecutionInfo &info) { ASSERT_EQ(info.sql_.size(), 1); });
    status = SqlStatistic::Unsubscribe(sqlObserver_);
    EXPECT_EQ(status, E_OK);
    status = SqlStatistic::Unsubscribe(observer2);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeStatistics002
 * @tc.desc: test statistics observer when update data
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeStatistics002, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(sqlObserver_, nullptr) << "observer is null";
    auto status = SqlStatistic::Subscribe(sqlObserver_);
    EXPECT_EQ(status, E_OK);
    int id;
    ValuesBucket values;
    values.PutString("name", std::string("zhangsan_update2"));
    values.PutInt("age", 20); // 20 is random age
    AbsRdbPredicates predicates("statistics_test");
    predicates.EqualTo("id", 1);
    status = store->Update(id, values, predicates);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(id, 1);
    sqlObserver_->Callback([](SqlObserver::SqlExecutionInfo &info) { ASSERT_EQ(info.sql_.size(), 1); });
    status = SqlStatistic::Unsubscribe(sqlObserver_);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeStatistics003
 * @tc.desc: test statistics observer when delete data
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeStatistics003, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(sqlObserver_, nullptr) << "observer is null";
    auto status = SqlStatistic::Subscribe(sqlObserver_);
    EXPECT_EQ(status, E_OK);
    sqlObserver_->Callback([](SqlObserver::SqlExecutionInfo &info) { ASSERT_EQ(info.sql_.size(), 1); });
    int id;
    status = store->Delete(id, "statistics_test", "id = ?", std::vector<std::string>{ "1" });
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(id, 1);

    status = SqlStatistic::Unsubscribe(sqlObserver_);
    EXPECT_EQ(status, E_OK);
    sqlObserver_->Callback(nullptr);
}

/**
 * @tc.name: RdbStoreSubscribeStatistics001
 * @tc.desc: test statistics observer when batchinsert data
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeStatistics004, TestSize.Level1)
{
    int num = 10;
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(sqlObserver_, nullptr) << "observer is null";
    auto status = SqlStatistic::Subscribe(sqlObserver_);
    EXPECT_EQ(status, E_OK);
    sqlObserver_->Callback([](SqlObserver::SqlExecutionInfo &info) { ASSERT_EQ(info.sql_.size(), 1); });
    int64_t id;
    std::vector<ValuesBucket> values;
    for (int i = 0; i < num; i++) {
        ValuesBucket value;
        value.PutInt("id", i);
        value.PutString("name", std::string("zhangsan"));
        value.PutInt("age", 18); // 18 is random age
        values.push_back(value);
    }
    status = store->BatchInsert(id, "statistics_test", values);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(id, num);
    status = SqlStatistic::Unsubscribe(sqlObserver_);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeStatistics001
 * @tc.desc: test statistics observer when create table after register observer
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeStatistics005, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(sqlObserver_, nullptr) << "observer is null";
    auto status = SqlStatistic::Subscribe(sqlObserver_);
    EXPECT_EQ(status, E_OK);
    constexpr const char *createTableTest = "CREATE TABLE IF NOT EXISTS statistics_test1 "
                                            "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                            "name TEXT NOT NULL, age INTEGER)";
    store->ExecuteSql(createTableTest);

    sqlObserver_->Callback([](SqlObserver::SqlExecutionInfo &info) { ASSERT_EQ(info.sql_.size(), 3); });
    ValuesBucket values;
    int64_t id;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18); // 18 is random age
    status = store->Insert(id, "statistics_test1", values);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(id, 1);
    status = SqlStatistic::Unsubscribe(sqlObserver_);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeStatistics006
 * @tc.desc: test statistics observer when query data
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeStatistics006, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(sqlObserver_, nullptr) << "observer is null";
    auto status = SqlStatistic::Subscribe(sqlObserver_);
    EXPECT_EQ(status, E_OK);
    sqlObserver_->Callback([](SqlObserver::SqlExecutionInfo &info) { ASSERT_EQ(info.sql_.size(), 2); });
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT * FROM statistics_test");
    EXPECT_NE(resultSet, nullptr);
    status = SqlStatistic::Unsubscribe(sqlObserver_);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeStatistics007
 * @tc.desc: test statistics observer when query data
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeStatistics007, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(sqlObserver_, nullptr) << "observer is null";
    auto status = SqlStatistic::Subscribe(sqlObserver_);
    EXPECT_EQ(status, E_OK);
    sqlObserver_->Callback([](SqlObserver::SqlExecutionInfo &info) { ASSERT_EQ(info.sql_.size(), 2); });
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM statistics_test");
    EXPECT_NE(resultSet, nullptr);
    status = SqlStatistic::Unsubscribe(sqlObserver_);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeStatistics008
 * @tc.desc: test statistics observer when Execute pragma
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeStatistics008, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(sqlObserver_, nullptr) << "observer is null";
    auto status = SqlStatistic::Subscribe(sqlObserver_);
    EXPECT_EQ(status, E_OK);
    sqlObserver_->Callback([](SqlObserver::SqlExecutionInfo &info) { ASSERT_EQ(info.sql_[0], "PRAGMA quick_check"); });
    auto [ret, object] = store->Execute("PRAGMA quick_check");
    status = SqlStatistic::Unsubscribe(sqlObserver_);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeStatistics009
 * @tc.desc: test statistics observer when ExecuteSql
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeStatistics009, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(sqlObserver_, nullptr) << "observer is null";
    std::string value = "with test as (select * from statistics_test) select * from test1";
    auto status = SqlStatistic::Subscribe(sqlObserver_);
    EXPECT_EQ(status, E_OK);
    sqlObserver_->Callback([value](SqlObserver::SqlExecutionInfo &info) { ASSERT_EQ(info.sql_[0], value); });
    store->ExecuteSql(value);
    status = SqlStatistic::Unsubscribe(sqlObserver_);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeStatistics010
 * @tc.desc: test abnormal parametar subscribe
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeStatistics010, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(sqlObserver_, nullptr) << "observer is null";
    auto status = SqlStatistic::Subscribe(nullptr);
    EXPECT_EQ(status, E_OK);
}

/**
* @tc.name: RdbStore_RegisterAutoSyncCallbackAndRdbStore_UnregisterAutoSyncCallback_001
* @tc.desc: Test RegisterAutoSyncCallback and UnregisterAutoSyncCallback
* @tc.type: FUNC
*/
HWTEST_F(RdbStoreSubTest, RdbStore_RegisterAutoSyncCallbackAndRdbStore_UnregisterAutoSyncCallback_001, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    auto obs = std::make_shared<TestDetailProgressObserver>();
    auto status = store->RegisterAutoSyncCallback(obs);
    EXPECT_EQ(status, E_OK);

    status = store->UnregisterAutoSyncCallback(obs);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeCloudSyncTrigger
 * @tc.desc: RdbStoreSubscribe SubscribeMode is CLOUD_SYNC_TRIGGER
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeCloudSyncTrigger, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->Subscribe({ SubscribeMode::CLOUD_SYNC_TRIGGER, "autoSyncTrigger" }, observer_);
    EXPECT_EQ(status, E_OK);
    status = store->UnSubscribe({ SubscribeMode::CLOUD_SYNC_TRIGGER, "autoSyncTrigger" }, observer_);
    EXPECT_EQ(status, E_OK);
}

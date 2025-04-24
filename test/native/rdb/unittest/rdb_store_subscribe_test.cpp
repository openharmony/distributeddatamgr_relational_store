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

#include <block_data.h>
#include <functional>
#include <string>

#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_sql_statistic.h"
#include "rdb_sql_log.h"
#include "rdb_store_manager.h"
#include "rdb_types.h"
#include "executor_pool.h"
#include "shared_block.h"
#include "sqlite_shared_result_set.h"
#include "step_result_set.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedRdb;
using CheckOnChangeFunc = std::function<void(RdbStoreObserver::ChangeInfo &changeInfo)>;
using SqlStatisticsFunc = std::function<void(SqlObserver::SqlExecutionInfo &info)>;
using OnErrorObserverFunc = std::function<void(const SqlErrorObserver::ExceptionMessage &message)>;
static constexpr int32_t MAX_THREAD = 5;
static constexpr int32_t MIN_THREAD = 0;
static std::string g_createTable = "CREATE TABLE IF NOT EXISTS test "
"(id INTEGER PRIMARY KEY AUTOINCREMENT, "
"name TEXT NOT NULL, age INTEGER, salary "
"REAL, blobType BLOB)";
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

class OnErrorObserver : public SqlErrorObserver {
public:
    void OnErrorLog(const ExceptionMessage &message) override;
    ExceptionMessage GetLastMessage();
    void SetBlockData(std::shared_ptr<OHOS::BlockData<bool>> block);

private:
    std::shared_ptr<OHOS::BlockData<bool>> block_;
    ExceptionMessage lastMessage;
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
    RdbStoreSubTest::store->ExecuteSql(g_createTable);
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

void OnErrorObserver::OnErrorLog(const ExceptionMessage &message)
{
    lastMessage = message;
    if (block_) {
        block_->SetValue(true);
    }
}

ExceptionMessage OnErrorObserver::GetLastMessage()
{
    return lastMessage;
}
 
void OnErrorObserver::SetBlockData(std::shared_ptr<OHOS::BlockData<bool>> block)
{
    block_ = block;
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
    EXPECT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->Subscribe({ SubscribeMode::REMOTE, "observer" }, observer_.get());
    EXPECT_EQ(status, E_OK);
    status = store->UnSubscribe({ SubscribeMode::REMOTE, "observer" }, observer_.get());
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
    EXPECT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->Subscribe({ SubscribeMode::CLOUD, "observer" }, observer_.get());
    EXPECT_EQ(status, E_OK);
    status = store->UnSubscribe({ SubscribeMode::CLOUD, "observer" }, observer_.get());
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
    EXPECT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->Subscribe({ SubscribeMode::CLOUD_DETAIL, "observer" }, observer_.get());
    EXPECT_EQ(status, E_OK);
    status = store->UnSubscribe({ SubscribeMode::CLOUD_DETAIL, "observer" }, observer_.get());
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
    EXPECT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->Subscribe({ SubscribeMode::LOCAL, "observer1" }, observer_.get());
    store->Subscribe({ SubscribeMode::LOCAL, "observer1" }, observer_.get());
    EXPECT_EQ(status, E_OK);
    store->Subscribe({ SubscribeMode::LOCAL, "observer2" }, observer_.get());
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
    status = store->UnSubscribe({ SubscribeMode::LOCAL, "nonexistent" }, observer_.get());
    EXPECT_EQ(status, E_OK);
    status = store->UnSubscribe({ SubscribeMode::LOCAL, "observer1" }, observer_.get());
    EXPECT_EQ(status, E_OK);
    status = store->UnSubscribe({ SubscribeMode::LOCAL, "nonexistent" }, nullptr);
    EXPECT_EQ(status, E_OK);
    status = store->UnSubscribe({ SubscribeMode::LOCAL, "observer2" }, nullptr);
    EXPECT_EQ(status, E_OK);
    status = store->Notify("observer1");
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeLocalShared
 * @tc.desc: RdbStoreSubscribe
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLocalShared, TestSize.Level1)
{
    EXPECT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->Subscribe({ SubscribeMode::LOCAL_SHARED, "observer1" }, observer_.get());
    store->Subscribe({ SubscribeMode::LOCAL_SHARED, "observer1" }, observer_.get());
    EXPECT_EQ(status, E_OK);
    store->Subscribe({ SubscribeMode::LOCAL_SHARED, "observer2" }, observer_.get());
    EXPECT_EQ(status, E_OK);

    status = store->UnSubscribe({ SubscribeMode::LOCAL_SHARED, "nonexistent" }, observer_.get());
    EXPECT_EQ(status, E_OK);
    status = store->UnSubscribe({ SubscribeMode::LOCAL_SHARED, "observer1" }, observer_.get());
    EXPECT_EQ(status, E_OK);
    status = store->UnSubscribe({ SubscribeMode::LOCAL_SHARED, "nonexistent" }, nullptr);
    EXPECT_EQ(status, E_OK);
    status = store->UnSubscribe({ SubscribeMode::LOCAL_SHARED, "observer2" }, nullptr);
    EXPECT_EQ(status, E_OK);
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
    EXPECT_NE(store, nullptr) << "store is null";
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
    EXPECT_NE(store, nullptr) << "store is null";
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
    EXPECT_NE(store, nullptr) << "store is null";
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
    EXPECT_NE(store, nullptr) << "store is null";
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
    EXPECT_NE(store, nullptr) << "store is null";
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
    EXPECT_NE(store, nullptr) << "store is null";
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
    EXPECT_NE(store, nullptr) << "store is null";
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
    EXPECT_NE(store, nullptr) << "store is null";
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
    EXPECT_NE(store, nullptr) << "store is null";
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
    EXPECT_NE(store, nullptr) << "store is null";
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
    EXPECT_NE(store, nullptr) << "store is null";
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
    EXPECT_NE(store, nullptr) << "store is null";
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
    EXPECT_NE(store, nullptr) << "store is null";
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
    EXPECT_NE(store, nullptr) << "store is null";
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
    EXPECT_NE(store, nullptr) << "store is null";
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
    EXPECT_NE(store, nullptr) << "store is null";
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
    EXPECT_NE(store, nullptr) << "store is null";
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
    EXPECT_NE(store, nullptr) << "store is null";
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
    EXPECT_NE(store, nullptr) << "store is null";
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
    EXPECT_NE(store, nullptr) << "store is null";
    auto obs = std::make_shared<TestDetailProgressObserver>();
    auto status = store->RegisterAutoSyncCallback(obs);
    EXPECT_EQ(status, E_OK);

    status = store->UnregisterAutoSyncCallback(obs);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeLog001
 * @tc.desc: test errorlog observer when SQLITE_ERROR
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLog001, TestSize.Level1)
{
    auto observer = std::make_shared<OnErrorObserver>();
    SqlLog::Subscribe(MAIN_DATABASE_NAME, observer);
    std::shared_ptr<OHOS::BlockData<bool>> block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    observer->SetBlockData(block);
    ValuesBucket values;
    int64_t id;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    auto ret = store->Insert(id, "sqliteLog", values);
    EXPECT_NE(ret, E_OK);
    EXPECT_TRUE(block->GetValue());
    EXPECT_EQ(observer->GetLastMessage().code, 1);
    EXPECT_EQ(observer->GetLastMessage().message, "no such table: sqliteLog");
    EXPECT_EQ(observer->GetLastMessage().sql, "INSERT INTO sqliteLog(age,id,name) VALUES (?,?,?)");
}

/**
 * @tc.name: RdbStoreSubscribeLog002
 * @tc.desc: test errorlog observer when SQLITE_CONSTRAINT
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLog002, TestSize.Level1)
{
    auto observer = std::make_shared<OnErrorObserver>();
    constexpr const char *createTableTest = "CREATE TABLE IF NOT EXISTS errorlog_test "
                                        "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                        "name TEXT NOT NULL, age INTEGER)";
    auto ret = store->ExecuteSql(createTableTest);
    EXPECT_EQ(ret, E_OK);
    ValuesBucket values;
    int64_t id;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    ret = store->Insert(id, "errorlog_test", values);
    EXPECT_EQ(ret, E_OK);
    std::shared_ptr<OHOS::BlockData<bool>> block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    SqlLog::Subscribe(MAIN_DATABASE_NAME, observer);
    observer->SetBlockData(block);
    ret = store->Insert(id, "errorlog_test", values);
    EXPECT_NE(ret, E_OK);
    EXPECT_TRUE(block->GetValue());
    EXPECT_EQ(observer->GetLastMessage().code, 19);
    EXPECT_EQ(observer->GetLastMessage().message, "UNIQUE constraint failed: errorlog_test.id");
    EXPECT_EQ(observer->GetLastMessage().sql, "INSERT INTO errorlog_test(age,id,name) VALUES (?,?,?)");
}

/**
 * @tc.name: RdbStoreSubscribeLog003
 * @tc.desc: test errorlog observer when SQLITE_BUSY
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLog003, TestSize.Level1)
{
    auto observer = std::make_shared<OnErrorObserver>();
    std::string tableName = "OnErrorLogTable";
    auto res = store->Execute(
        "CREATE TABLE " + tableName + " (id INTEGER PRIMARY KEY CHECK (id >= 3 OR id <= 1), name TEXT NOT NULL)");
    ASSERT_EQ(res.first, E_OK);

    auto [code, transaction] = store->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(code, E_OK);
    ASSERT_NE(transaction, nullptr);

    ValuesBuckets rows;
    for (int i = 0; i < 5; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(row);
    }
    SqlLog::Subscribe(MAIN_DATABASE_NAME, observer);
    std::shared_ptr<OHOS::BlockData<bool>> block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    observer->SetBlockData(block);
    auto result = store->BatchInsertWithConflictResolution(tableName, rows, ConflictResolution::ON_CONFLICT_NONE);
    ASSERT_EQ(result.first, E_SQLITE_BUSY);
    EXPECT_TRUE(block->GetValue());
    EXPECT_EQ(observer->GetLastMessage().code, 5);
    EXPECT_EQ(observer->GetLastMessage().message, "database is locked");
    EXPECT_EQ(
        observer->GetLastMessage().sql, "INSERT INTO OnErrorLogTable (id,name) VALUES (?,?),(?,?),(?,?),(?,?),(?,?)");
}

/**
 * @tc.name: RdbStoreSubscribeLog004
 * @tc.desc: test errorlog observer when SQLITE_LOCKED
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
 HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLog004, TestSize.Level1)
 {
    auto observer = std::make_shared<OnErrorObserver>();
    std::string dbPath = RDB_TEST_PATH + "errorlog.db";
    int errCode = E_OK;
    RdbStoreConfig memoryConfig(dbPath);
    Callback helper;
    memoryConfig.SetStorageMode(StorageMode::MODE_MEMORY);
    std::shared_ptr<RdbStore> memoryStore = RdbHelper::GetRdbStore(memoryConfig, 1, helper, errCode);
    auto res = memoryStore->Execute("CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
    ASSERT_EQ(res.first, E_OK);
    auto [ret1, transaction1] = memoryStore->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(ret1, E_OK);
    ASSERT_NE(transaction1, nullptr);
 
    auto [ret, transaction] = memoryStore->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);
 
    ValuesBuckets rows;
    for (int i = 0; i < 5; i++) {
        Transaction::Row row;
        row.Put("id", i);
        row.Put("name", "Jim_batchInsert");
        rows.Put(row);
    }
    SqlLog::Subscribe(dbPath, observer);
    std::shared_ptr<OHOS::BlockData<bool>> block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    observer->SetBlockData(block);
    auto result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_NONE);
    ASSERT_EQ(result.first, E_SQLITE_LOCKED);
    EXPECT_TRUE(block->GetValue());
    EXPECT_EQ(observer->GetLastMessage().code, 6);
    EXPECT_EQ(observer->GetLastMessage().message, "database table is locked");
    EXPECT_EQ(observer->GetLastMessage().sql, "INSERT INTO test1 (id,name) VALUES (?,?),(?,?),(?,?),(?,?),(?,?)");
}

/**
 * @tc.name: RdbStoreSubscribeLog005
 * @tc.desc: test errorlog observer when SQLITE_SCHEMA
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLog005, TestSize.Level1)
{
    auto observer = std::make_shared<OnErrorObserver>();
    store->ExecuteSql(g_createTable);
    std::shared_ptr<OHOS::ExecutorPool> executors;
    std::shared_ptr<OHOS::BlockData<int32_t>> block1 = std::make_shared<OHOS::BlockData<int32_t>>(3, false);
    executors = std::make_shared<OHOS::ExecutorPool>(MAX_THREAD, MIN_THREAD);
    auto taskId1 = executors->Execute([storeCopy = store, block1]() {
        constexpr const char *createTable = "CREATE TABLE test";
        constexpr const char *createTableColumn = " (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                  "name TEXT NOT NULL, age INTEGER, salary REAL, "
                                                  "blobType BLOB)";
        int32_t errCode = E_ERROR;
        for (uint32_t i = 0; i < 2000; i++) {
            errCode = storeCopy->ExecuteSql(createTable + std::to_string(i) + createTableColumn);
            if (errCode != E_OK) {
                break;
            }
        }
        block1->SetValue(errCode);
    });
    std::shared_ptr<OHOS::BlockData<bool>> block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    SqlLog::Subscribe(MAIN_DATABASE_NAME, observer);
    observer->SetBlockData(block);
    std::shared_ptr<OHOS::BlockData<int32_t>> block2 = std::make_shared<OHOS::BlockData<int32_t>>(3, false);
    auto taskId2 = executors->Execute([storeCopy = store, block2]() {
        int32_t errCode = E_ERROR;
        for (uint32_t i = 0; i < 2000; i++) {
            auto resultSet = storeCopy->QueryByStep("SELECT * FROM test");
            int rowCount = -1;
            errCode = resultSet->GetRowCount(rowCount);
            resultSet->Close();
            if (errCode != E_OK && errCode != E_SQLITE_SCHEMA) {
                break;
            }
        }
        auto code = (errCode == E_OK || errCode == E_SQLITE_SCHEMA) ? E_OK : errCode;
        block2->SetValue(code);
    });
    EXPECT_EQ(block1->GetValue(), E_OK);
    EXPECT_EQ(block2->GetValue(), E_OK);
    EXPECT_NE(taskId1, taskId2);
    EXPECT_TRUE(block->GetValue());
    EXPECT_EQ(observer->GetLastMessage().code, 17);
    EXPECT_EQ(observer->GetLastMessage().message, "database schema has changed");
    EXPECT_EQ(observer->GetLastMessage().sql, "SELECT * FROM test");
}

/**
 * @tc.name: RdbStoreSubscribeLog006
 * @tc.desc: test errorlog observer when SQLITE_FULL
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLog006, TestSize.Level1)
{
    auto observer = std::make_shared<OnErrorObserver>();
    store->ExecuteSql(g_createTable);
    auto [code, maxPageCount] = store->Execute("PRAGMA max_page_count;");
    auto recover = std::shared_ptr<const char>("recover", [defPageCount = maxPageCount,
        storeCopy = store](const char *) {
        storeCopy->Execute("PRAGMA max_page_count = " + static_cast<std::string>(defPageCount) + ";");
    });
    std::tie(code, maxPageCount) = store->Execute("PRAGMA max_page_count = 256;");
    ValuesBucket row;
    row.Put("name", std::string(1024 * 1024, 'e'));
    std::shared_ptr<OHOS::BlockData<bool>> block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    SqlLog::Subscribe(MAIN_DATABASE_NAME, observer);
    observer->SetBlockData(block);
    auto result = store->Insert("test", row, ConflictResolution::ON_CONFLICT_NONE);
    ASSERT_EQ(result.first, E_SQLITE_FULL);
    EXPECT_TRUE(block->GetValue());
    EXPECT_EQ(observer->GetLastMessage().code, 13);
    EXPECT_EQ(observer->GetLastMessage().message, "database or disk is full");
    EXPECT_EQ(observer->GetLastMessage().sql, "INSERT INTO test(name) VALUES (?)");
}

/**
 * @tc.name: RdbStoreSubscribeLog007
 * @tc.desc: test errorlog observer when Notify
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLog007, TestSize.Level1)
{
    std::string storeId = "test_db";
    auto observer = std::make_shared<OnErrorObserver>();
    SqlLog::Subscribe(storeId, observer);
    std::shared_ptr<OHOS::BlockData<bool>> block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    observer->SetBlockData(block);

    SqlErrorObserver::ExceptionMessage error;
    error.code = 2;
    error.message = "concurrent error";
    error.sql = "UPDATE table SET invalid";

    SqlLog::Notify(storeId, error);

    EXPECT_TRUE(block->GetValue());
    EXPECT_EQ(observer->GetLastMessage().code, 2);
    EXPECT_EQ(observer->GetLastMessage().message, "concurrent error");
    EXPECT_EQ(observer->GetLastMessage().sql, "UPDATE table SET invalid");
}

/**
 * @tc.name: RdbStoreSubscribeLog008
 * @tc.desc: test errorlog observer when off observer
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeLog008, TestSize.Level1)
{
    std::string storeId = "test_db";
    auto observer = std::make_shared<OnErrorObserver>();
    SqlLog::Subscribe(storeId, observer);
    std::shared_ptr<OHOS::BlockData<bool>> block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    observer->SetBlockData(block);
    SqlLog::Unsubscribe(storeId, observer);
    SqlErrorObserver::ExceptionMessage error;
    error.code = 2;
    error.message = "concurrent error";
    error.sql = "UPDATE table SET invalid";
    SqlLog::Notify(storeId, error);
    EXPECT_EQ(block->GetValue(), false);
    EXPECT_EQ(observer->GetLastMessage().code, 0);
}
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

#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store_manager.h"
#include "rdb_types.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedRdb;
using CheckOnChangeFunc = std::function<void(RdbStoreObserver::ChangeInfo &changeInfo)>;
class SubObserver : public RdbStoreObserver {
public:
    virtual ~SubObserver() {}
    void OnChange(const std::vector<std::string>& devices) override;
    void OnChange(const Origin &origin, const PrimaryFields &fields,
        RdbStoreObserver::ChangeInfo &&changeInfo) override;
    void OnChange() override;
    void RegisterCallback(const CheckOnChangeFunc &callback);
    uint32_t count = 0;
private:
    CheckOnChangeFunc checkOnChangeFunc_;
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
};

class TestDetailProgressObserver : public DetailProgressObserver {
public:
    virtual ~TestDetailProgressObserver() {}
    void ProgressNotification(const Details& details) override {};
};

const std::string RdbStoreSubTest::MAIN_DATABASE_NAME = RDB_TEST_PATH + "subscribe.db";
std::shared_ptr<RdbStore> RdbStoreSubTest::store = nullptr;
std::shared_ptr<SubObserver> RdbStoreSubTest::observer_ = nullptr;

void RdbStoreSubTest::SetUpTestCase(void)
{
    RdbHelper::DeleteRdbStore(MAIN_DATABASE_NAME);
    store = CreateRDB(1);
    if (observer_ == nullptr) {
        observer_ = std::make_shared<SubObserver>();
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
    const std::string CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test "
                                          "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                          "name TEXT NOT NULL, age INTEGER, salary "
                                          "REAL, blobType BLOB)";
    RdbStoreSubTest::store->ExecuteSql(CREATE_TABLE_TEST);
    ValuesBucket values;
    int64_t id;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = RdbStoreSubTest::store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);
}

void SubObserver::RegisterCallback(const CheckOnChangeFunc &callback)
{
    checkOnChangeFunc_ = callback;
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
    auto status = store->Subscribe({ SubscribeMode::REMOTE }, observer_.get());
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
    auto status = store->Subscribe({ SubscribeMode::CLOUD }, observer_.get());
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
    auto status = store->Subscribe({ SubscribeMode::CLOUD_DETAIL }, observer_.get());
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
    auto status = store->Subscribe({ SubscribeMode::LOCAL, "observer" }, observer_.get());
    EXPECT_EQ(status, E_OK);

    status = store->Notify("observer");
    EXPECT_EQ(status, E_OK);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    int count;
    resultSet->GetRowCount(count);
    EXPECT_EQ(1, count);
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

    observer_->RegisterCallback([](RdbStoreObserver::ChangeInfo &) {
        ASSERT_TRUE(false);
    });
    observer2->RegisterCallback([](RdbStoreObserver::ChangeInfo &) {
        ASSERT_TRUE(false);
    });
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

    observer_->RegisterCallback([](RdbStoreObserver::ChangeInfo &) {
        ASSERT_TRUE(false);
    });
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
    EXPECT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->SubscribeObserver({ SubscribeMode::LOCAL_DETAIL, "dataChange" }, nullptr);
    EXPECT_EQ(status, E_OK);
    observer_->RegisterCallback([](RdbStoreObserver::ChangeInfo &) {
        ASSERT_TRUE(false);
    });
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

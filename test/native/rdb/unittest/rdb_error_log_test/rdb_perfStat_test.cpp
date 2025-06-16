/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define LOG_TAG "RdbPerfStatTest"
#include <gtest/gtest.h>

#include <functional>
#include <string>
#include <thread>

#include "block_data.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store_manager.h"
#include "rdb_types.h"
#include "logger.h"
#include "rdb_platform.h"
#include "rdb_perfStat.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedRdb;
using namespace OHOS::Rdb;

class PerfStatObserver : public SqlObserver {
public:
    virtual ~PerfStatObserver()
    {
    }
    void OnStatistic(const SqlExecutionInfo &info);
    void SetBlockData(std::shared_ptr<OHOS::BlockData<bool>> block);
    SqlExecutionInfo perfInfo_;
private:
    std::shared_ptr<OHOS::BlockData<bool>> block_;
};

class RdbPerfStatTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string databasePath;
    static std::shared_ptr<RdbStore> CreateRDB(int version);
    static std::shared_ptr<RdbStore> store;
    static std::shared_ptr<PerfStatObserver> sqlObserver_;
};

const std::string RdbPerfStatTest::databasePath = "/data/test/perfStat.db";
std::shared_ptr<RdbStore> RdbPerfStatTest::store = nullptr;
std::shared_ptr<PerfStatObserver> RdbPerfStatTest::sqlObserver_ = nullptr;
void RdbPerfStatTest::SetUpTestCase(void)
{
    RdbHelper::DeleteRdbStore(databasePath);
    store = CreateRDB(1);
    if (sqlObserver_ == nullptr) {
        sqlObserver_ = std::make_shared<PerfStatObserver>();
    }
}

void RdbPerfStatTest::TearDownTestCase(void)
{
    store = nullptr;
    RdbHelper::DeleteRdbStore(databasePath);
}

void RdbPerfStatTest::SetUp()
{
}

void RdbPerfStatTest::TearDown()
{
}

class PerfStatCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

int PerfStatCallback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int PerfStatCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void PerfStatObserver::OnStatistic(const PerfStatObserver::SqlExecutionInfo &info)
{
    perfInfo_ = info;
    if (block_) {
        block_->SetValue(true);
    }
}

void PerfStatObserver::SetBlockData(std::shared_ptr<OHOS::BlockData<bool>> block)
{
    block_ = block;
}

std::shared_ptr<RdbStore> RdbPerfStatTest::CreateRDB(int version)
{
    RdbStoreConfig config(RdbPerfStatTest::databasePath);
    config.SetBundleName("subscribe_test");
    config.SetArea(0);
    config.SetCreateNecessary(true);
    config.SetDistributedType(RDB_DEVICE_COLLABORATION);
    config.SetSecurityLevel(OHOS::NativeRdb::SecurityLevel::S1);
    PerfStatCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, version, helper, errCode);
    EXPECT_NE(store, nullptr);
    constexpr const char *createTableTest = "CREATE TABLE IF NOT EXISTS perfStat_test "
                                            "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                            "name TEXT NOT NULL, age INTEGER)";
    store->ExecuteSql(createTableTest);
    return store;
}

/**
 * @tc.name: RdbPerfStat001
 * @tc.desc: test perfStat observer
 * @tc.type: FUNC
 */
HWTEST_F(RdbPerfStatTest, RdbPerfStat001, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    ASSERT_NE(sqlObserver_, nullptr) << "observer is null";
    auto status = PerfStat::Subscribe(databasePath, sqlObserver_);
    EXPECT_EQ(status, E_OK);
    ValuesBucket values;
    int64_t id;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);  // 18 is random age
    std::shared_ptr<OHOS::BlockData<bool>> block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    sqlObserver_->SetBlockData(block);
    status = store->Insert(id, "perfStat_test", values);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(id, 1);
    EXPECT_TRUE(block->GetValue());
    EXPECT_EQ(sqlObserver_->perfInfo_.sql_.size(), 1);
    status = PerfStat::Unsubscribe(databasePath, sqlObserver_);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbPerfStat002
 * @tc.desc: test perfStat observer
 * @tc.type: FUNC
 */
HWTEST_F(RdbPerfStatTest, RdbPerfStat002, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    ASSERT_NE(sqlObserver_, nullptr) << "observer is null";
    auto status = PerfStat::Subscribe(databasePath, sqlObserver_);
    EXPECT_EQ(status, E_OK);
    int id;
    ValuesBucket values;
    values.PutString("name", std::string("zhangsan_update2"));
    values.PutInt("age", 20); // 20 is random age
    AbsRdbPredicates predicates("perfStat_test");
    predicates.EqualTo("id", 1);
    std::shared_ptr<OHOS::BlockData<bool>> block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    sqlObserver_->SetBlockData(block);
    status = store->Update(id, values, predicates);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(id, 1);
    EXPECT_TRUE(block->GetValue());
    EXPECT_EQ(sqlObserver_->perfInfo_.sql_.size(), 1);
    status = PerfStat::Unsubscribe(databasePath, sqlObserver_);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbPerfStat003
 * @tc.desc: test perfStat observer
 * @tc.type: FUNC
 */
HWTEST_F(RdbPerfStatTest, RdbPerfStat003, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    ASSERT_NE(sqlObserver_, nullptr) << "observer is null";
    auto status = PerfStat::Subscribe(databasePath, sqlObserver_);
    EXPECT_EQ(status, E_OK);
    int id;
    std::shared_ptr<OHOS::BlockData<bool>> block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    sqlObserver_->SetBlockData(block);
    status = store->Delete(id, "perfStat_test", "id = ?", std::vector<std::string>{ "1" });
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(id, 1);
    EXPECT_TRUE(block->GetValue());
    EXPECT_EQ(sqlObserver_->perfInfo_.sql_.size(), 1);
    status = PerfStat::Unsubscribe(databasePath, sqlObserver_);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbPerfStat004
 * @tc.desc: test perfStat observer
 * @tc.type: FUNC

 */
HWTEST_F(RdbPerfStatTest, RdbPerfStat004, TestSize.Level1)
{
    int num = 3;
    ASSERT_NE(store, nullptr) << "store is null";
    ASSERT_NE(sqlObserver_, nullptr) << "observer is null";
    auto status = PerfStat::Subscribe(databasePath, sqlObserver_);
    int64_t id;
    std::vector<ValuesBucket> values;
    for (int i = 0; i < num; i++) {
        ValuesBucket value;
        value.PutInt("id", i);
        value.PutString("name", std::string("zhangsan"));
        value.PutInt("age", 18); // 18 is random age
        values.push_back(value);
    }
    std::shared_ptr<OHOS::BlockData<bool>> block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    sqlObserver_->SetBlockData(block);
    status = store->BatchInsert(id, "perfStat_test", values);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(id, num);
    EXPECT_TRUE(block->GetValue());
    EXPECT_EQ(sqlObserver_->perfInfo_.sql_.size(), 1);
    status = PerfStat::Unsubscribe(databasePath, sqlObserver_);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbPerfStat005
 * @tc.desc: test perfStat observer
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbPerfStatTest, RdbPerfStat005, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    ASSERT_NE(sqlObserver_, nullptr) << "observer is null";
    auto status = PerfStat::Subscribe(databasePath, sqlObserver_);
    EXPECT_EQ(status, E_OK);
    constexpr const char *createTableTest = "CREATE TABLE IF NOT EXISTS perfStat_test2 "
                                            "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                            "name TEXT NOT NULL, age INTEGER)";
    std::shared_ptr<OHOS::BlockData<bool>> block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    sqlObserver_->SetBlockData(block);
    status = store->ExecuteSql(createTableTest);
    EXPECT_TRUE(block->GetValue());
    EXPECT_EQ(sqlObserver_->perfInfo_.sql_.size(), 1);
    EXPECT_EQ(sqlObserver_->perfInfo_.sql_[0], createTableTest);
    status = PerfStat::Unsubscribe(databasePath, sqlObserver_);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbPerfStat006
 * @tc.desc: test perfStat observer
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbPerfStatTest, RdbPerfStat006, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    ASSERT_NE(sqlObserver_, nullptr) << "observer is null";
    auto status = PerfStat::Subscribe(databasePath, sqlObserver_);
    EXPECT_EQ(status, E_OK);
    constexpr const char *pargmaTest = "PRAGMA quick_check";
    std::shared_ptr<OHOS::BlockData<bool>> block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    sqlObserver_->SetBlockData(block);
    store->Execute(pargmaTest);
    EXPECT_TRUE(block->GetValue());
    EXPECT_EQ(sqlObserver_->perfInfo_.sql_.size(), 1);
    EXPECT_EQ(sqlObserver_->perfInfo_.sql_[0], pargmaTest);
    status = PerfStat::Unsubscribe(databasePath, sqlObserver_);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbPerfStat007
 * @tc.desc: test perfStat observer
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbPerfStatTest, RdbPerfStat007, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    ASSERT_NE(sqlObserver_, nullptr) << "observer is null";
    auto status = PerfStat::Subscribe(databasePath, sqlObserver_);
    EXPECT_EQ(status, E_OK);
    std::shared_ptr<OHOS::BlockData<bool>> block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    sqlObserver_->SetBlockData(block);
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT * FROM perfStat_test");
    ASSERT_NE(resultSet, nullptr);
    EXPECT_TRUE(block->GetValue());
    EXPECT_EQ(sqlObserver_->perfInfo_.sql_.size(), 1);
    status = PerfStat::Unsubscribe(databasePath, sqlObserver_);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbPerfStat008
 * @tc.desc: test perfStat observer
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbPerfStatTest, RdbPerfStat008, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    ASSERT_NE(sqlObserver_, nullptr) << "observer is null";

    auto status = PerfStat::Subscribe(databasePath, sqlObserver_);
    EXPECT_EQ(status, E_OK);
    std::shared_ptr<OHOS::BlockData<bool>> block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    sqlObserver_->SetBlockData(block);
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM perfStat_test");
    ASSERT_NE(resultSet, nullptr);
    EXPECT_TRUE(block->GetValue());
    EXPECT_EQ(sqlObserver_->perfInfo_.sql_.size(), 1);
    status = PerfStat::Unsubscribe(databasePath, sqlObserver_);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbPerfStat009
 * @tc.desc: test perfStat observer
 * @tc.type: FUNC
 */
HWTEST_F(RdbPerfStatTest, RdbPerfStat009, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    ASSERT_NE(sqlObserver_, nullptr) << "observer is null";

    auto status = PerfStat::Subscribe(databasePath, sqlObserver_);
    EXPECT_EQ(status, E_OK);
    AbsRdbPredicates predicates("perfStat_test");
    std::shared_ptr<OHOS::BlockData<bool>> block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    sqlObserver_->SetBlockData(block);
    std::shared_ptr<ResultSet> resultSet = store->Query(predicates);
    ASSERT_NE(resultSet, nullptr);
    EXPECT_TRUE(block->GetValue());
    EXPECT_EQ(sqlObserver_->perfInfo_.sql_.size(), 1);
    status = PerfStat::Unsubscribe(databasePath, sqlObserver_);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbPerfStat010
 * @tc.desc: test perfStat observer
 * @tc.type: FUNC
 */
HWTEST_F(RdbPerfStatTest, RdbPerfStat010, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    ASSERT_NE(sqlObserver_, nullptr) << "observer is null";

    auto status = PerfStat::Subscribe(databasePath, sqlObserver_);
    EXPECT_EQ(status, E_OK);

    std::shared_ptr<OHOS::BlockData<bool>> block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    sqlObserver_->SetBlockData(block);
    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    EXPECT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ValuesBucket value;
    value.PutString("name", std::string("zhangsan"));
    value.PutInt("age", 18); // 18 is random age

    auto result = transaction->Insert("perfStat_test", value);
    EXPECT_EQ(result.first, E_OK);
    ret = transaction->Commit();
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(block->GetValue());
    EXPECT_EQ(sqlObserver_->perfInfo_.sql_.size(), 3);
    status = PerfStat::Unsubscribe(databasePath, sqlObserver_);
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbPerfStat011
 * @tc.desc: test perfStat observer
 * @tc.type: FUNC
 */
HWTEST_F(RdbPerfStatTest, RdbPerfStat011, TestSize.Level1)
{
    ASSERT_NE(store, nullptr) << "store is null";
    ASSERT_NE(sqlObserver_, nullptr) << "observer is null";

    auto status = PerfStat::Subscribe(databasePath, sqlObserver_);
    EXPECT_EQ(status, E_OK);

    std::shared_ptr<OHOS::BlockData<bool>> block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    sqlObserver_->SetBlockData(block);
    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    EXPECT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);
    int num = 3;
    std::vector<ValuesBucket> values;
    for (int i = 0; i < num; i++) {
        ValuesBucket value;
        value.PutInt("id", i);
        value.PutString("name", std::string("zhangsan"));
        value.PutInt("age", 18); // 18 is random age
        values.push_back(value);
    }
    auto result = transaction->BatchInsert("perfStat_test", values);
    EXPECT_EQ(result.first, E_OK);
    ret = transaction->Commit();
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(block->GetValue());
    EXPECT_EQ(sqlObserver_->perfInfo_.sql_.size(), 3);
    status = PerfStat::Unsubscribe(databasePath, sqlObserver_);
    EXPECT_EQ(status, E_OK);
}
 
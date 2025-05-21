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
#include <gtest/gtest.h>

#include <string>

#include "../common.h"
#include "block_data.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
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
static constexpr int32_t MAX_THREAD = 5;
static constexpr int32_t MIN_THREAD = 0;
static std::string g_createTable = "CREATE TABLE IF NOT EXISTS test "
"(id INTEGER PRIMARY KEY AUTOINCREMENT, "
"name TEXT NOT NULL, age INTEGER, salary "
"REAL, blobType BLOB)";
static std::string g_databaseName = "/data/test/subscribe.db";

class RdbStoreLogSubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static std::shared_ptr<RdbStore> CreateRDB(int version);
    static std::shared_ptr<RdbStore> store;
};

std::shared_ptr<RdbStore> RdbStoreLogSubTest::store = nullptr;

void RdbStoreLogSubTest::SetUpTestCase(void)
{
    RdbHelper::DeleteRdbStore(g_databaseName);
    store = CreateRDB(1);
}

void RdbStoreLogSubTest::TearDownTestCase(void)
{
    store = nullptr;
    RdbHelper::DeleteRdbStore(g_databaseName);
}

void RdbStoreLogSubTest::SetUp()
{
}

void RdbStoreLogSubTest::TearDown()
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

std::shared_ptr<RdbStore> RdbStoreLogSubTest::CreateRDB(int version)
{
    RdbStoreConfig config(g_databaseName);
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

class OnErrorObserver : public SqlErrorObserver {
public:
    void OnErrorLog(const ExceptionMessage &message) override;
    ExceptionMessage GetLastMessage();
    void SetBlockData(std::shared_ptr<OHOS::BlockData<bool>> block);

private:
    std::shared_ptr<OHOS::BlockData<bool>> block_;
    ExceptionMessage lastMessage;
};


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


/**
 * @tc.name: RdbStoreSubscribeLog001
 * @tc.desc: test sqliteErrorOccurred observer when SQLITE_ERROR
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreLogSubTest, RdbStoreSubscribeLog001, TestSize.Level1)
{
    auto observer = std::make_shared<OnErrorObserver>();
    SqlLog::Subscribe(g_databaseName, observer);
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
 * @tc.desc: test sqliteErrorOccurred observer when SQLITE_CONSTRAINT
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreLogSubTest, RdbStoreSubscribeLog002, TestSize.Level1)
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
    SqlLog::Subscribe(g_databaseName, observer);
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
 * @tc.desc: test sqliteErrorOccurred observer when SQLITE_BUSY
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreLogSubTest, RdbStoreSubscribeLog003, TestSize.Level1)
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
    SqlLog::Subscribe(g_databaseName, observer);
    std::shared_ptr<OHOS::BlockData<bool>> block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    observer->SetBlockData(block);
    auto result = store->BatchInsert(tableName, rows, ConflictResolution::ON_CONFLICT_NONE);
    ASSERT_EQ(result.first, E_SQLITE_BUSY);
    EXPECT_TRUE(block->GetValue());
    EXPECT_EQ(observer->GetLastMessage().code, 5);
    EXPECT_EQ(observer->GetLastMessage().message, "database is locked");
    EXPECT_EQ(
        observer->GetLastMessage().sql, "INSERT INTO OnErrorLogTable (id,name) VALUES (?,?),(?,?),(?,?),(?,?),(?,?)");
}

/**
 * @tc.name: RdbStoreSubscribeLog004
 * @tc.desc: test sqliteErrorOccurred observer when SQLITE_LOCKED
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
 HWTEST_F(RdbStoreLogSubTest, RdbStoreSubscribeLog004, TestSize.Level1)
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
    auto result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_NONE);
    ASSERT_EQ(result.first, E_SQLITE_LOCKED);
    EXPECT_TRUE(block->GetValue());
    EXPECT_EQ(observer->GetLastMessage().code, 6);
    EXPECT_EQ(observer->GetLastMessage().message, "database table is locked");
    EXPECT_EQ(observer->GetLastMessage().sql, "INSERT INTO test1 (id,name) VALUES (?,?),(?,?),(?,?),(?,?),(?,?)");
}

/**
 * @tc.name: RdbStoreSubscribeLog005
 * @tc.desc: test sqliteErrorOccurred observer when SQLITE_SCHEMA
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreLogSubTest, RdbStoreSubscribeLog005, TestSize.Level1)
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
    SqlLog::Subscribe(g_databaseName, observer);
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
 * @tc.desc: test sqliteErrorOccurred observer when SQLITE_FULL
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreLogSubTest, RdbStoreSubscribeLog006, TestSize.Level1)
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
    SqlLog::Subscribe(g_databaseName, observer);
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
 * @tc.desc: test sqliteErrorOccurred observer when off observer
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreLogSubTest, RdbStoreSubscribeLog007, TestSize.Level1)
{
    auto observer = std::make_shared<OnErrorObserver>();
    SqlLog::Subscribe(g_databaseName, observer);
    std::shared_ptr<OHOS::BlockData<bool>> block = std::make_shared<OHOS::BlockData<bool>>(3, false);
    observer->SetBlockData(block);
    SqlLog::Unsubscribe(g_databaseName, observer);
    ValuesBucket values;
    int64_t id;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    auto ret = store->Insert(id, "sqliteLog", values);
    EXPECT_NE(ret, E_OK);
    EXPECT_EQ(block->GetValue(), false);
    EXPECT_EQ(observer->GetLastMessage().code, 0);
}
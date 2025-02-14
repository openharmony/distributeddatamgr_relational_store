/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <map>
#include <string>

#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store_impl.h"
#include "relational_store_delegate.h"
#include "relational_store_manager.h"
#include "sqlite_connection.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string DATABASE_NAME;

protected:
    std::shared_ptr<RdbStore> store_;
};

const std::string RdbTest::DATABASE_NAME = RDB_TEST_PATH + "stepResultSet_impl_test.db";

class RdbTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

int RdbTestOpenCallback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int RdbTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbTest::SetUpTestCase(void)
{
}

void RdbTest::TearDownTestCase(void)
{
}

void RdbTest::SetUp(void)
{
    store_ = nullptr;
    int errCode = RdbHelper::DeleteRdbStore(DATABASE_NAME);
    EXPECT_EQ(E_OK, errCode);
    RdbStoreConfig config(RdbTest::DATABASE_NAME);
    RdbTestOpenCallback helper;
    store_ = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store_, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void RdbTest::TearDown(void)
{
    store_ = nullptr;
    RdbHelper::ClearCache();
    int errCode = RdbHelper::DeleteRdbStore(DATABASE_NAME);
    EXPECT_EQ(E_OK, errCode);
}

/* *
 * @tc.name: GetModifyTimeByRowIdTest_001
 * @tc.desc: Normal testCase for GetModifyTime, get timestamp by id
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, GetModifyTimeByRowIdTest_001, TestSize.Level2)
{
    store_->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_RdbTest_integer_log "
                       "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
                       "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int64_t rowId;
    ValuesBucket valuesBucket;
    valuesBucket.PutInt("data_key", ValueObject(1));
    valuesBucket.PutInt("timestamp", ValueObject(1000000000));
    int errorCode = store_->Insert(rowId, "naturalbase_rdb_aux_RdbTest_integer_log", valuesBucket);
    EXPECT_EQ(E_OK, errorCode);
    EXPECT_EQ(1, rowId);

    std::vector<RdbStore::PRIKey> PKey = { 1 };
    std::map<RdbStore::PRIKey, RdbStore::Date> result = store_->GetModifyTime("RdbTest_integer", "ROWID", PKey);
    int size = result.size();
    EXPECT_EQ(1, size);
    EXPECT_EQ(100000, int64_t(result[1]));

    store_->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_RdbTest_integer_log");
}

/* *
 * @tc.name: GetModifyTimeByRowIdTest_002
 * @tc.desc: Abnormal testCase for GetModifyTime, get timestamp by id,
 *           resultSet is empty or table name is not exist
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, GetModifyTimeByRowIdTest_002, TestSize.Level2)
{
    store_->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_RdbTest_integer_log "
                       "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
                       "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int64_t rowId;
    ValuesBucket valuesBucket;
    valuesBucket.PutInt("data_key", ValueObject(2));
    int errorCode = store_->Insert(rowId, "naturalbase_rdb_aux_RdbTest_integer_log", valuesBucket);
    EXPECT_EQ(E_OK, errorCode);
    EXPECT_EQ(1, rowId);

    // resultSet is empty
    std::vector<RdbStore::PRIKey> PKey = { 1 };
    std::map<RdbStore::PRIKey, RdbStore::Date> result = store_->GetModifyTime("RdbTest_integer", "ROWID", PKey);
    int size = result.size();
    EXPECT_EQ(0, size);

    // table name is  not exist , resultSet is null
    result = store_->GetModifyTime("test", "ROWID", PKey);
    size = result.size();
    EXPECT_EQ(0, size);

    store_->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_RdbTest_integer_log");
}

/* *
 * @tc.name: GetModifyTimeByRowIdTest_003
 * @tc.desc: Abnormal testCase for GetModifyTime, get timestamp by id,
 *           resultSet is empty or table name is not exist
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, GetModifyTimeByRowIdTest_003, TestSize.Level2)
{
    store_->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_RdbTest_integer_log "
                       "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
                       "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int64_t rowId;
    ValuesBucket valuesBucket;
    valuesBucket.PutInt("data_key", ValueObject(1));
    int errorCode = store_->Insert(rowId, "naturalbase_rdb_aux_RdbTest_integer_log", valuesBucket);
    EXPECT_EQ(E_OK, errorCode);
    EXPECT_EQ(1, rowId);

    std::vector<RdbStore::PRIKey> PKey = { 1 };
    RdbStore::ModifyTime resultMapTmp = store_->GetModifyTime("RdbTest_integer", "ROWID", PKey);
    std::map<RdbStore::PRIKey, RdbStore::Date> resultMap = std::map<RdbStore::PRIKey, RdbStore::Date>(resultMapTmp);
    EXPECT_EQ(1, resultMap.size());

    RdbStore::ModifyTime resultPtrTmp = store_->GetModifyTime("RdbTest_integer", "ROWID", PKey);
    std::shared_ptr<ResultSet> resultPtr = std::shared_ptr<ResultSet>(resultPtrTmp);
    int count = 0;
    resultPtr->GetRowCount(count);
    EXPECT_EQ(1, count);

    RdbStore::ModifyTime result = store_->GetModifyTime("RdbTest_integer", "ROWID", PKey);
    RdbStore::PRIKey key = result.GetOriginKey(std::vector<uint8_t>{});
    RdbStore::PRIKey monostate = std::monostate();
    EXPECT_EQ(monostate, key);
    EXPECT_EQ(8, result.GetMaxOriginKeySize());

    store_->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_RdbTest_integer_log");
}

/* *
 * @tc.name: GetModifyTime_001
 * @tc.desc: Abnormal testCase for GetModifyTime, tablename columnName, keys is empty,
 *           and resultSet is null or empty
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, GetModifyTime_001, TestSize.Level2)
{
    store_->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_RdbTest_integer_log "
                       "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
                       "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");

    // table name is ""
    std::vector<RdbStore::PRIKey> PKey = { 1 };
    std::map<RdbStore::PRIKey, RdbStore::Date> result = store_->GetModifyTime("", "data_key", PKey);
    int size = result.size();
    EXPECT_EQ(0, size);

    // table name is not exist , query resultSet is null
    result = store_->GetModifyTime("test", "data_key", PKey);
    size = result.size();
    EXPECT_EQ(0, size);

    // columnName is ""
    result = store_->GetModifyTime("test", "", PKey);
    size = result.size();
    EXPECT_EQ(0, size);

    // keys is empty
    std::vector<RdbStore::PRIKey> emptyPRIKey;
    result = store_->GetModifyTime("test", "data_key", emptyPRIKey);
    size = result.size();
    EXPECT_EQ(0, size);

    store_->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_RdbTest_integer_log");
}

/* *
 * @tc.name: GetModifyTime_002
 * @tc.desc: Abnormal testCase for GetModifyTime, get timestamp by data3 ,if query resultSet is empty
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, GetModifyTime_002, TestSize.Level2)
{
    store_->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_RdbTest_integer_log "
                       "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, hash_key INTEGER, "
                       "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");

    std::vector<RdbStore::PRIKey> PKey = { 1 };
    std::map<RdbStore::PRIKey, RdbStore::Date> result = store_->GetModifyTime("RdbTest_integer", "data3", PKey);
    EXPECT_EQ(0, result.size());

    store_->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_RdbTest_integer_log");
}

/* *
 * @tc.name: Rdb_BatchInsertTest_001
 * @tc.desc: Abnormal testCase for BatchInsert, if initialBatchValues is empty
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Rdb_BatchInsertTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    int64_t insertNum = 1;
    int ret = store_->BatchInsert(insertNum, "test", valuesBuckets);
    EXPECT_EQ(0, insertNum);
    EXPECT_EQ(E_OK, ret);
}

/* *
 * @tc.name: Rdb_QueryTest_001
 * @tc.desc: Abnormal testCase for Query, if table name is empty
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Rdb_QueryTest_001, TestSize.Level2)
{
    int errCode = E_OK;
    store_->Query(errCode, true, "", {}, "", std::vector<ValueObject>{}, "", "", "", 1, 0);
    EXPECT_NE(E_OK, errCode);
}

/* *
 * @tc.name: Rdb_QueryTest_002
 * @tc.desc: Normal testCase for Query, get * form test
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Rdb_QueryTest_002, TestSize.Level2)
{
    store_->ExecuteSql("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, "
                       "data2 INTEGER, data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int errCode = E_OK;
    store_->Query(errCode, true, "test", {}, "", std::vector<ValueObject>{}, "", "", "", 1, 0);
    EXPECT_EQ(E_OK, errCode);

    store_->ExecuteSql("DROP TABLE IF EXISTS test");
}

/* *
 * @tc.name: Rdb_RemoteQueryTest_001
 * @tc.desc: Abnormal testCase for RemoteQuery
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Rdb_RemoteQueryTest_001, TestSize.Level2)
{
    int errCode = E_OK;
    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", 1);

    // GetRdbService failed if rdbstoreconfig bundlename_ empty
    auto ret = store_->RemoteQuery("", predicates, {}, errCode);
    EXPECT_EQ(E_INVALID_ARGS, errCode);
    EXPECT_EQ(nullptr, ret);
    RdbHelper::DeleteRdbStore(RdbTest::DATABASE_NAME);

    RdbStoreConfig config(RdbTest::DATABASE_NAME);
    config.SetName("RdbStore_impl_test.db");
    config.SetBundleName("com.example.distributed.rdb");
    RdbTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(E_OK, errCode);

    // GetRdbService succeeded if configuration file has already been configured
    ret = store->RemoteQuery("", predicates, {}, errCode);
    EXPECT_NE(E_OK, errCode);
    EXPECT_EQ(nullptr, ret);

    store = nullptr;
    RdbHelper::DeleteRdbStore(RdbTest::DATABASE_NAME);
}

/* *
 * @tc.name: Rdb_RollbackTest_001
 * @tc.desc: Abnormal testCase for Rollback
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Rdb_RollbackTest_001, TestSize.Level2)
{
    int ret = store_->RollBack();
    EXPECT_EQ(OHOS::NativeRdb::E_NO_TRANSACTION_IN_SESSION, ret);
}

/* *
 * @tc.name: Rdb_CommitTest_001
 * @tc.desc: Abnormal testCase for Commit,if not use BeginTransaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Rdb_CommitTest_001, TestSize.Level2)
{
    int ret = store_->Commit();
    EXPECT_EQ(E_OK, ret);
}

/* *
 * @tc.name: Rdb_BackupTest_001
 * @tc.desc: Abnormal testCase for Backup
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Rdb_BackupTest_001, TestSize.Level2)
{
    int errCode = E_OK;
    std::string databasePath = RDB_TEST_PATH + "test.db";
    std::vector<uint8_t> destEncryptKey;
    // isEncrypt_ is false, and destEncryptKey is emtpy
    errCode = store_->Backup(databasePath, destEncryptKey);
    EXPECT_EQ(E_OK, errCode);
    RdbHelper::DeleteRdbStore(databasePath);

    // isEncrypt_ is false, and destEncryptKey is not emtpy
    destEncryptKey.push_back(1);
    errCode = store_->Backup(databasePath, destEncryptKey);
    EXPECT_EQ(E_OK, errCode);
    store_ = nullptr;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
    RdbHelper::DeleteRdbStore(databasePath);

    RdbStoreConfig config(RdbTest::DATABASE_NAME);
    config.SetEncryptStatus(true);
    RdbTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(E_OK, errCode);

    // isEncrypt_ is true, and destEncryptKey is not emtpy
    errCode = store->Backup(databasePath, destEncryptKey);
    EXPECT_EQ(E_OK, errCode);
    RdbHelper::DeleteRdbStore(databasePath);

    // isEncrypt_ is true, and destEncryptKey is not emtpy
    destEncryptKey.pop_back();
    errCode = store->Backup(databasePath, destEncryptKey);
    EXPECT_EQ(E_OK, errCode);
    store = nullptr;
    RdbHelper::DeleteRdbStore(databasePath);
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
}

/* *
 * @tc.name: Rdb_SqlitConnectionTest_001
 * @tc.desc: Abnormal testCase for SetPageSize,
 *           return ok if open db again and set same page size
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Rdb_SqlitConnectionTest_001, TestSize.Level2)
{
    const std::string DATABASE_NAME = RDB_TEST_PATH + "SqlitConnectionOpenTest.db";
    RdbStoreConfig config(DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetPageSize(1024);
    auto [errCode, connection] = Connection::Create(config, true);
    EXPECT_NE(nullptr, connection);
    auto [err, statement] = connection->CreateStatement("PRAGMA page_size", connection);
    auto [error, object] = statement->ExecuteForValue();
    EXPECT_EQ(E_OK, error);
    EXPECT_EQ(1024, static_cast<int64_t>(object));

    std::tie(errCode, connection) = Connection::Create(config, true);
    EXPECT_NE(nullptr, connection);
}

/* *
 * @tc.name: Rdb_ConnectionPoolTest_001
 * @tc.desc: Abnormal testCase for ConfigLocale
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Rdb_ConnectionPoolTest_001, TestSize.Level2)
{
    const std::string DATABASE_NAME = RDB_TEST_PATH + "ConnectionOpenTest.db";
    int errCode = E_OK;
    RdbStoreConfig config(DATABASE_NAME);
    config.SetReadConSize(1);
    config.SetStorageMode(StorageMode::MODE_DISK);

    RdbTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(E_OK, errCode);

    auto connectionPool = ConnectionPool::Create(config, errCode);
    EXPECT_NE(nullptr, connectionPool);
    EXPECT_EQ(E_OK, errCode);

    // connecting database
    auto connection = connectionPool->AcquireConnection(true);
    EXPECT_NE(nullptr, connection);
    errCode = connectionPool->ConfigLocale("AbnormalTest");
    EXPECT_EQ(OHOS::NativeRdb::E_DATABASE_BUSY, errCode);

    store = nullptr;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
}

/* *
 * @tc.name: Rdb_ConnectionPoolTest_002
 * @tc.desc: Abnormal testCase for AcquireConnection/AcquireTransaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Rdb_ConnectionPoolTest_002, TestSize.Level2)
{
    const std::string DATABASE_NAME = RDB_TEST_PATH + "ConnectionTest.db";
    int errCode = E_OK;
    RdbStoreConfig config(DATABASE_NAME);
    config.SetReadConSize(1);
    config.SetStorageMode(StorageMode::MODE_DISK);
    auto connectionPool = ConnectionPool::Create(config, errCode);
    EXPECT_NE(nullptr, connectionPool);
    EXPECT_EQ(E_OK, errCode);

    // repeat AcquireReader without release
    auto connection = connectionPool->AcquireConnection(true);
    EXPECT_NE(nullptr, connection);
    connection = connectionPool->AcquireConnection(true);
    EXPECT_NE(nullptr, connection);
    connection = connectionPool->AcquireConnection(true);
    EXPECT_NE(nullptr, connection);

    // repeat AcquireWriter without release
    connection = connectionPool->AcquireConnection(false);
    EXPECT_NE(nullptr, connection);
    connection = connectionPool->AcquireConnection(false);
    EXPECT_EQ(nullptr, connection);
    connection = connectionPool->AcquireConnection(false);
    EXPECT_NE(nullptr, connection);

    // repeat AcquireTransaction without release
    errCode = connectionPool->AcquireTransaction();
    EXPECT_EQ(E_OK, errCode);
    errCode = connectionPool->AcquireTransaction();
    EXPECT_NE(E_OK, errCode);
    connectionPool->ReleaseTransaction();
}

/* *
 * @tc.name: Rdb_ConnectionPoolTest_003
 * @tc.desc: Abnormal testCase for ChangeDbFileForRestore
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Rdb_ConnectionPoolTest_0023, TestSize.Level2)
{
    const std::string DATABASE_NAME = RDB_TEST_PATH + "ConnectionTest.db";
    int errCode = E_OK;
    RdbStoreConfig config(DATABASE_NAME);
    config.SetReadConSize(1);
    config.SetStorageMode(StorageMode::MODE_DISK);
    auto connectionPool = ConnectionPool::Create(config, errCode);
    EXPECT_NE(nullptr, connectionPool);
    EXPECT_EQ(E_OK, errCode);

    const std::string newPath = DATABASE_NAME;
    const std::string backupPath = DATABASE_NAME;
    const std::vector<uint8_t> newKey;

    // newPath == currentPath, writeConnectionUsed == true
    auto connection = connectionPool->AcquireConnection(false);
    SlaveStatus curStatus;
    errCode = connectionPool->ChangeDbFileForRestore(newPath, backupPath, newKey, curStatus);
    EXPECT_EQ(E_ERROR, errCode);
    connection = nullptr;
    // newPath == currentPath
    errCode = connectionPool->ChangeDbFileForRestore(newPath, backupPath, newKey, curStatus);
    EXPECT_NE(E_OK, errCode);
    // newPath != currentPath
    const std::string newPath2 = RDB_TEST_PATH + "tmp.db";
    errCode = connectionPool->ChangeDbFileForRestore(newPath2, backupPath, newKey, curStatus);
    EXPECT_EQ(E_ERROR, errCode);
}

HWTEST_F(RdbTest, NotifyDataChangeTest_001, TestSize.Level2)
{
    const std::string DATABASE_NAME = RDB_TEST_PATH + "SqlitConnectionOpenTest.db";
    RdbStoreConfig config(DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetPageSize(1024);
    auto [errCode, connection] = SqliteConnection::Create(config, true);
    EXPECT_NE(nullptr, connection);
    RdbTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(nullptr, store);
}

HWTEST_F(RdbTest, NotifyDataChangeTest_002, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbTest::DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetPageSize(1024);
    config.SetBundleName("callback.test2");
    config.SetSearchable(true);
    config.SetStorageMode(StorageMode::MODE_DISK);
    // register callback
    RdbTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(nullptr, store);
    store->ExecuteSql("DROP TABLE IF EXISTS test_callback_t2;");
    store->ExecuteSql("CREATE TABLE if not exists test_callback_t2 "
                      "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
                      "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    // set TrackerTable
    DistributedDB::TrackerSchema tracker;
    tracker.tableName = "test_callback_t2";
    tracker.extendColName = "";
    tracker.trackerColNames = { "id", "timestamp" };
    using Delegate = DistributedDB::RelationalStoreDelegate;
    DistributedDB::RelationalStoreManager rStoreManager("test_app", "test_user_id", 0);
    Delegate::Option option;
    Delegate *g_delegate = nullptr;
    EXPECT_EQ(RdbTest::DATABASE_NAME, "/data/test/stepResultSet_impl_test.db");
    int status = rStoreManager.OpenStore(RdbTest::DATABASE_NAME, "test_callback_t2", option, g_delegate);
    EXPECT_EQ(E_OK, status);
    auto delegatePtr = std::shared_ptr<Delegate>(
        g_delegate, [&rStoreManager](Delegate *delegate) { rStoreManager.CloseStore(delegate); });
    int setStatus = delegatePtr->SetTrackerTable(tracker);
    EXPECT_EQ(E_OK, setStatus);

    int64_t rowId;
    ValuesBucket valuesBucket;
    valuesBucket.PutInt("data_key", ValueObject(1));
    valuesBucket.PutInt("timestamp", ValueObject(1000000000));
    int errorCode = store->Insert(rowId, "test_callback_t2", valuesBucket);
    EXPECT_EQ(E_OK, errorCode);
    EXPECT_EQ(1, rowId);
    store->ExecuteSql("DROP TABLE IF EXISTS test_callback_t2;");
}

HWTEST_F(RdbTest, NotifyDataChangeTest_003, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbTest::DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetPageSize(1024);
    config.SetBundleName("callback.test3");
    config.SetSearchable(true);
    config.SetStorageMode(StorageMode::MODE_DISK);

    RdbTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);

    store->ExecuteSql("DROP TABLE IF EXISTS test_callback_t3;");

    store->ExecuteSql("CREATE TABLE if not exists test_callback_t3 "
                      "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
                      "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    // set TrackerTable
    DistributedDB::TrackerSchema tracker;
    tracker.tableName = "test_callback_t3";
    tracker.extendColName = "";
    tracker.trackerColNames = { "id", "timestamp" };
    using Delegate = DistributedDB::RelationalStoreDelegate;
    DistributedDB::RelationalStoreManager rStoreManager("test_app", "test_user_id", 0);
    Delegate::Option option;
    Delegate *g_delegate = nullptr;
    EXPECT_EQ(RdbTest::DATABASE_NAME, "/data/test/stepResultSet_impl_test.db");
    int status = rStoreManager.OpenStore(RdbTest::DATABASE_NAME, "test_callback_t3", option, g_delegate);
    EXPECT_EQ(E_OK, status);
    auto delegatePtr = std::shared_ptr<Delegate>(
        g_delegate, [&rStoreManager](Delegate *delegate) { rStoreManager.CloseStore(delegate); });
    int setStatus = delegatePtr->SetTrackerTable(tracker);
    EXPECT_EQ(E_OK, setStatus);

    int64_t rowId;
    ValuesBucket valuesBucket;
    valuesBucket.PutInt("data_key", ValueObject(1));
    valuesBucket.PutInt("timestamp", ValueObject(1000000000));
    int errorCode = store->Insert(rowId, "test_callback_t3", valuesBucket);
    EXPECT_EQ(E_OK, errorCode);
    EXPECT_EQ(1, rowId);
    errorCode = store->ExecuteSql("UPDATE test_callback_t3 SET timestamp = 100 WHERE id = 1;");
    EXPECT_EQ(E_OK, errorCode);

    store->ExecuteSql("DROP TABLE IF EXISTS test_callback_t3;");
}

/* *
 * @tc.name: Rdb_QuerySharingResourceTest_001
 * @tc.desc: QuerySharingResource testCase
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Rdb_QuerySharingResourceTest_001, TestSize.Level2)
{
    RdbHelper::DeleteRdbStore(RdbTest::DATABASE_NAME);
    int errCode = E_OK;
    RdbStoreConfig config(RdbTest::DATABASE_NAME);
    config.SetName("RdbStore_impl_test.db");
    config.SetBundleName("com.example.distributed.rdb");

    RdbTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", 1);

    auto ret = store->QuerySharingResource(predicates, {});
    EXPECT_NE(E_OK, ret.first);
    EXPECT_EQ(nullptr, ret.second);
    RdbHelper::DeleteRdbStore(RdbTest::DATABASE_NAME);
}

/* *
 * @tc.name: Rdb_QuerySharingResourceTest_002
 * @tc.desc: QuerySharingResource testCase
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Rdb_QuerySharingResourceTest_002, TestSize.Level2)
{
    RdbHelper::DeleteRdbStore(RdbTest::DATABASE_NAME);
    int errCode = E_OK;
    RdbStoreConfig config(RdbTest::DATABASE_NAME);
    config.SetName("RdbStore_impl_test.db");
    config.SetBundleName("com.example.distributed.rdb");

    RdbTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    store->ExecuteSql("CREATE TABLE test_resource "
                      "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
                      "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int64_t rowId;
    ValuesBucket valuesBucket;
    valuesBucket.PutInt("data_key", ValueObject(1));
    valuesBucket.PutInt("timestamp", ValueObject(1000000000));
    int errorCode = store->Insert(rowId, "test_resource", valuesBucket);
    EXPECT_EQ(E_OK, errorCode);
    EXPECT_EQ(1, rowId);
    AbsRdbPredicates predicates("test_resource");
    predicates.EqualTo("data_key", 1);

    auto [status, resultSet] = store->QuerySharingResource(predicates, { "id", "data_key" });
    EXPECT_NE(E_OK, status);
    ASSERT_EQ(nullptr, resultSet);

    RdbHelper::DeleteRdbStore(RdbTest::DATABASE_NAME);
}

/* *
 * @tc.name: CleanDirtyDataTest_001
 * @tc.desc: Abnormal testCase for CleanDirtyData
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Abnormal_CleanDirtyDataTest_001, TestSize.Level2)
{
    store_->ExecuteSql("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, "
                       "data2 INTEGER, data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int errCode = E_OK;

    // tabel is empty
    std::string table = "";
    uint64_t cursor = UINT64_MAX;
    errCode = RdbTest::store_->CleanDirtyData(table, cursor);
    EXPECT_EQ(E_INVALID_ARGS, errCode);

    table = "test";
    errCode = RdbTest::store_->CleanDirtyData(table, cursor);
    EXPECT_EQ(E_ERROR, errCode);
    store_->ExecuteSql("DROP TABLE IF EXISTS test");
}

/* *
 * @tc.name: ClearCacheTest_001
 * @tc.desc: Normal testCase for ClearCache
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Normal_ClearCacheTest_001, TestSize.Level2)
{
    store_->ExecuteSql("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, "
                       "data2 INTEGER, data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int errCode = E_OK;
    int64_t id;
    ValuesBucket valuesBucket;
    valuesBucket.PutString("data1", std::string("zhangsan"));
    valuesBucket.PutInt("data2", 10);
    errCode = store_->Insert(id, "test", valuesBucket);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(1, id);

    int rowCount;
    std::shared_ptr<ResultSet> resultSet = store_->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    resultSet->GetRowCount(rowCount);
    EXPECT_EQ(rowCount, 1);
    int64_t currentMemory = sqlite3_memory_used();
    EXPECT_EQ(E_OK, resultSet->Close());
    EXPECT_LT(sqlite3_memory_used(), currentMemory);
}

/* *
 * @tc.name: LockCloudContainerTest
 * @tc.desc: lock cloudContainer testCase
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, LockCloudContainerTest, TestSize.Level2)
{
    int errCode = E_OK;
    // GetRdbService failed if rdbstoreconfig bundlename_ empty
    auto ret = store_->LockCloudContainer();
    EXPECT_EQ(E_INVALID_ARGS, ret.first);
    EXPECT_EQ(0, ret.second);
    RdbHelper::DeleteRdbStore(RdbTest::DATABASE_NAME);

    RdbStoreConfig config(RdbTest::DATABASE_NAME);
    config.SetName("RdbStore_impl_test.db");
    config.SetBundleName("com.example.distributed.rdb");
    RdbTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(E_OK, errCode);
    // GetRdbService succeeded if configuration file has already been configured
    ret = store->LockCloudContainer();
    EXPECT_NE(E_OK, ret.first);
    store = nullptr;
    RdbHelper::DeleteRdbStore(RdbTest::DATABASE_NAME);
}

/* *
 * @tc.name: UnlockCloudContainerTest
 * @tc.desc: unlock cloudContainer testCase
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, UnlockCloudContainerTest, TestSize.Level2)
{
    int errCode = E_OK;
    // GetRdbService failed if rdbstoreconfig bundlename_ empty
    auto result = store_->UnlockCloudContainer();
    EXPECT_EQ(E_INVALID_ARGS, result);
    RdbHelper::DeleteRdbStore(RdbTest::DATABASE_NAME);

    RdbStoreConfig config(RdbTest::DATABASE_NAME);
    config.SetName("RdbStore_impl_test.db");
    config.SetBundleName("com.example.distributed.rdb");
    RdbTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(E_OK, errCode);
    // GetRdbService succeeded if configuration file has already been configured
    result = store->UnlockCloudContainer();
    EXPECT_NE(E_OK, result);
    store = nullptr;
    RdbHelper::DeleteRdbStore(RdbTest::DATABASE_NAME);
}

/* *
 * @tc.name: LockCloudContainerTest001
 * @tc.desc: lock cloudContainer testCase
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, LockCloudContainerTest001, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbTest::DATABASE_NAME);
    config.SetName("RdbStore_impl_test.db");
    config.SetBundleName("com.example.distributed.rdb");
    RdbTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(E_OK, errCode);
    // GetRdbService succeeded if configuration file has already been configured
    auto ret = store->RdbStore::LockCloudContainer();
    EXPECT_EQ(E_OK, ret.first);
    EXPECT_EQ(0, ret.second);
    store = nullptr;
    RdbHelper::DeleteRdbStore(RdbTest::DATABASE_NAME);
}

/* *
 * @tc.name: UnlockCloudContainerTest001
 * @tc.desc: unlock cloudContainer testCase
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, UnlockCloudContainerTest001, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbTest::DATABASE_NAME);
    config.SetName("RdbStore_impl_test.db");
    config.SetBundleName("com.example.distributed.rdb");
    RdbTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(E_OK, errCode);
    // GetRdbService succeeded if configuration file has already been configured
    auto result = store->RdbStore::UnlockCloudContainer();
    EXPECT_EQ(E_OK, result);
    store = nullptr;
    RdbHelper::DeleteRdbStore(RdbTest::DATABASE_NAME);
}

/* *
 * @tc.name: SetSearchableTest
 * @tc.desc: SetSearchable testCase
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, SetSearchableTest, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbTest::DATABASE_NAME);
    config.SetBundleName("");
    RdbTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(E_OK, errCode);

    int result = store->SetSearchable(true);
    EXPECT_EQ(E_INVALID_ARGS, result);
    RdbHelper::DeleteRdbStore(RdbTest::DATABASE_NAME);

    config.SetBundleName("com.example.distributed.rdb");
    EXPECT_EQ(E_OK, errCode);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(E_OK, errCode);
    result = store->SetSearchable(true);
    EXPECT_EQ(E_OK, result);
}

/* *
 * @tc.name: RdbStore_Delete_001
 * @tc.desc: normal testcase of SqliteSharedResultSet for move
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Sqlite_Shared_Result_Set_001, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::unique_ptr<ResultSet> rstSet = RdbTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    int ret = rstSet->GoToRow(1);
    EXPECT_EQ(ret, E_OK);

    int rowCnt = -1;
    ret = rstSet->GetRowCount(rowCnt);
    EXPECT_EQ(rowCnt, 3);

    std::string colName = "";
    rstSet->GetColumnName(1, colName);
    EXPECT_EQ(colName, "data1");

    rstSet->GetColumnName(2, colName);
    EXPECT_EQ(colName, "data2");

    rstSet->GetColumnName(3, colName);
    EXPECT_EQ(colName, "data3");

    rstSet->GetColumnName(4, colName);
    EXPECT_EQ(colName, "data4");

    std::string valueStr = "";
    rstSet->GetString(0, valueStr);
    EXPECT_EQ(valueStr, "2");

    rstSet->GetString(1, valueStr);
    EXPECT_EQ(valueStr, "2");

    int64_t valuelg = 0;
    rstSet->GetLong(2, valuelg);
    EXPECT_EQ(valuelg, -5);

    double valueDb = 0.0;
    rstSet->GetDouble(3, valueDb);
    EXPECT_EQ(valueDb, 2.5);

    std::vector<uint8_t> blob;
    rstSet->GetBlob(4, blob);
    int sz = blob.size();
    EXPECT_EQ(sz, 0);

    rstSet->GoTo(1);
    rstSet->GetString(0, valueStr);
    EXPECT_EQ(valueStr, "3");

    rstSet->GetString(1, valueStr);
    EXPECT_EQ(valueStr, "hello world");

    rstSet->GetLong(2, valuelg);
    EXPECT_EQ(valuelg, 3);

    rstSet->GetDouble(3, valueDb);
    EXPECT_EQ(valueDb, 1.8);

    rstSet->GetBlob(4, blob);
    sz = blob.size();
    EXPECT_EQ(sz, 0);

    bool isNull = false;
    rstSet->IsColumnNull(4, isNull);
    EXPECT_EQ(isNull, true);

    ret = -1;
    ret = rstSet->GoToPreviousRow();
    EXPECT_EQ(ret, E_OK);
    ret = -1;
    ret = rstSet->GoToPreviousRow();
    EXPECT_EQ(ret, E_OK);

    rstSet->GetString(0, valueStr);
    EXPECT_EQ(valueStr, "1");

    rstSet->GetString(1, valueStr);
    EXPECT_EQ(valueStr, "hello");

    rstSet->GetLong(2, valuelg);
    EXPECT_EQ(valuelg, 10);

    rstSet->GetDouble(3, valueDb);
    EXPECT_EQ(valueDb, 1.0);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_002
 * @tc.desc: normal testcase of SqliteSharedResultSet for goToNextRow
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Sqlite_Shared_Result_Set_002, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::unique_ptr<ResultSet> rstSet = RdbTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    int pos = -2;
    rstSet->GetRowIndex(pos);
    EXPECT_EQ(pos, -1);
    bool isStart = true;
    rstSet->IsStarted(isStart);
    EXPECT_EQ(isStart, false);
    bool isAtFirstRow = true;
    rstSet->IsAtFirstRow(isAtFirstRow);
    EXPECT_EQ(isAtFirstRow, false);
    bool isEnded = true;
    rstSet->IsEnded(isEnded);
    EXPECT_EQ(isEnded, false);

    int retN1 = rstSet->GoToNextRow();
    EXPECT_EQ(retN1, E_OK);
    rstSet->GetRowIndex(pos);
    EXPECT_EQ(pos, 0);
    rstSet->IsStarted(isStart);
    EXPECT_EQ(isStart, true);
    rstSet->IsAtFirstRow(isAtFirstRow);
    EXPECT_EQ(isAtFirstRow, true);
    isEnded = true;
    rstSet->IsEnded(isEnded);
    EXPECT_EQ(isEnded, false);

    int retN2 = rstSet->GoToNextRow();
    EXPECT_EQ(retN2, E_OK);
    rstSet->GetRowIndex(pos);
    EXPECT_EQ(pos, 1);
    isStart = false;
    rstSet->IsStarted(isStart);
    EXPECT_EQ(isStart, true);
    isAtFirstRow = true;
    rstSet->IsAtFirstRow(isAtFirstRow);
    EXPECT_EQ(isAtFirstRow, false);
    isEnded = true;
    rstSet->IsEnded(isEnded);
    EXPECT_EQ(isEnded, false);

    int retN3 = rstSet->GoToNextRow();
    EXPECT_EQ(retN3, E_OK);
    rstSet->GetRowIndex(pos);
    EXPECT_EQ(pos, 2);
    isStart = false;
    rstSet->IsStarted(isStart);
    EXPECT_EQ(isStart, true);
    isAtFirstRow = true;
    rstSet->IsAtFirstRow(isAtFirstRow);
    EXPECT_EQ(isAtFirstRow, false);
    bool isAtLastRow = false;
    rstSet->IsAtLastRow(isAtLastRow);
    EXPECT_EQ(isAtLastRow, true);

    int retN = rstSet->GoToNextRow();
    EXPECT_EQ(retN, E_ERROR);
    rstSet->GetRowIndex(pos);
    EXPECT_EQ(pos, 3);
    isStart = false;
    rstSet->IsStarted(isStart);
    EXPECT_EQ(isStart, true);
    isAtFirstRow = true;
    rstSet->IsAtFirstRow(isAtFirstRow);
    EXPECT_EQ(isAtFirstRow, false);
    isEnded = false;
    rstSet->IsEnded(isEnded);
    EXPECT_EQ(isEnded, true);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_003
 * @tc.desc: normal testcase of SqliteSharedResultSet for moveFirst
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Sqlite_Shared_Result_Set_003, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::unique_ptr<ResultSet> rstSet = RdbTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    int retF = rstSet->GoToFirstRow();
    EXPECT_EQ(retF, E_OK);
    int index = -1;
    rstSet->GetRowIndex(index);
    EXPECT_EQ(index, 0);
    bool isAtFirstRow = false;
    rstSet->IsAtFirstRow(isAtFirstRow);
    EXPECT_EQ(isAtFirstRow, true);
    bool isStd = false;
    rstSet->IsStarted(isStd);
    EXPECT_EQ(isStd, true);

    int retN = rstSet->GoToNextRow();
    EXPECT_EQ(retN, E_OK);
    rstSet->GetRowIndex(index);
    EXPECT_EQ(index, 1);
    isAtFirstRow = true;
    rstSet->IsAtFirstRow(isAtFirstRow);
    EXPECT_EQ(isAtFirstRow, false);
    isStd = false;
    rstSet->IsStarted(isStd);
    EXPECT_EQ(isStd, true);

    int retGf = rstSet->GoToFirstRow();
    EXPECT_EQ(retGf, E_OK);
    rstSet->GetRowIndex(index);
    EXPECT_EQ(index, 0);
    isAtFirstRow = false;
    rstSet->IsAtFirstRow(isAtFirstRow);
    EXPECT_EQ(isAtFirstRow, true);
    isStd = false;
    rstSet->IsStarted(isStd);
    EXPECT_EQ(isStd, true);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_004
 * @tc.desc: normal testcase of SqliteSharedResultSet for getInt
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Sqlite_Shared_Result_Set_004, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::unique_ptr<ResultSet> rstSet = RdbTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    int64_t valueInt = 0;
    int ret = rstSet->GetLong(0, valueInt);
    EXPECT_EQ(ret, E_INVALID_STATEMENT);

    int retF = rstSet->GoToFirstRow();
    EXPECT_EQ(retF, E_OK);
    rstSet->GetLong(0, valueInt);
    EXPECT_EQ(valueInt, 1);
    rstSet->GetLong(2, valueInt);
    EXPECT_EQ(valueInt, 10);
    rstSet->GetLong(3, valueInt);
    EXPECT_EQ(valueInt, 1);

    int retN = rstSet->GoToNextRow();
    EXPECT_EQ(retN, E_OK);
    rstSet->GetLong(0, valueInt);
    EXPECT_EQ(valueInt, 2);
    valueInt = 0;
    rstSet->GetLong(0, valueInt);
    EXPECT_EQ(valueInt, 2);
    valueInt = 0;
    rstSet->GetLong(1, valueInt);
    EXPECT_EQ(valueInt, 2);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_005
 * @tc.desc: normal testcase of SqliteSharedResultSet for getString
 * @tc.type: FUNC
 */

HWTEST_F(RdbTest, Sqlite_Shared_Result_Set_005, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::unique_ptr<ResultSet> rstSet = RdbTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    std::string valueStr = "";
    int ret1 = rstSet->GetString(0, valueStr);
    EXPECT_EQ(ret1, E_INVALID_STATEMENT);

    int retF = rstSet->GoToFirstRow();
    EXPECT_EQ(retF, E_OK);
    valueStr = "";
    rstSet->GetString(1, valueStr);
    EXPECT_EQ(valueStr, "hello");
    rstSet->GetString(2, valueStr);
    EXPECT_EQ(valueStr, "10");
    rstSet->GetString(3, valueStr);
    EXPECT_EQ(valueStr, "1");

    int ret2 = rstSet->GetString(4, valueStr);
    EXPECT_EQ(ret2, E_OK);

    valueStr = "";
    int colCnt = 0;
    rstSet->GetColumnCount(colCnt);
    int ret3 = rstSet->GetString(colCnt, valueStr);
    EXPECT_EQ(ret3, E_INVALID_COLUMN_INDEX);

    int retN = rstSet->GoToNextRow();
    EXPECT_EQ(retN, E_OK);
    rstSet->GetString(0, valueStr);
    EXPECT_EQ(valueStr, "2");
    valueStr = "";
    rstSet->GetString(1, valueStr);
    EXPECT_EQ(valueStr, "2");
    rstSet->GetString(2, valueStr);
    EXPECT_EQ(valueStr, "-5");
    rstSet->GetString(3, valueStr);
    EXPECT_EQ(valueStr, "2.5");

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_006
 * @tc.desc: normal testcase of SqliteSharedResultSet for getDouble
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Sqlite_Shared_Result_Set_006, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::unique_ptr<ResultSet> rstSet = RdbTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    double valueDb = 0.0;
    int ret = rstSet->GetDouble(0, valueDb);
    EXPECT_EQ(ret, E_INVALID_STATEMENT);

    int retF = rstSet->GoToFirstRow();
    EXPECT_EQ(retF, E_OK);
    rstSet->GetDouble(0, valueDb);
    EXPECT_EQ(valueDb, 1.0);
    std::string valueStr = "";
    rstSet->GetString(1, valueStr);
    EXPECT_EQ(valueStr, "hello");
    rstSet->GetDouble(2, valueDb);
    EXPECT_EQ(valueDb, 10.0);
    rstSet->GetDouble(3, valueDb);
    EXPECT_EQ(valueDb, 1.0);

    int colCnt = 0;
    rstSet->GetColumnCount(colCnt);
    int ret1 = rstSet->GetDouble(colCnt, valueDb);
    EXPECT_EQ(ret1, E_INVALID_COLUMN_INDEX);

    int retN = rstSet->GoToNextRow();
    EXPECT_EQ(retN, E_OK);
    rstSet->GetDouble(0, valueDb);
    EXPECT_EQ(valueDb, 2.0);
    valueDb = 0.0;
    rstSet->GetDouble(1, valueDb);
    EXPECT_EQ(valueDb, 2.0);

    rstSet->GetDouble(2, valueDb);
    EXPECT_EQ(valueDb, -5.0);
    rstSet->GetDouble(3, valueDb);
    EXPECT_EQ(valueDb, 2.5);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_007
 * @tc.desc: normal testcase of SqliteSharedResultSet for getBlob
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Sqlite_Shared_Result_Set_007, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::unique_ptr<ResultSet> rstSet = RdbTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    int retF = rstSet->GoToFirstRow();
    EXPECT_EQ(retF, E_OK);

    std::vector<uint8_t> blobVec;
    rstSet->GetBlob(4, blobVec);
    EXPECT_EQ(blobVec[0], 66);

    int retN = rstSet->GoToNextRow();
    EXPECT_EQ(retN, E_OK);
    blobVec.clear();
    rstSet->GetBlob(4, blobVec);
    int blobSz = blobVec.size();
    EXPECT_EQ(blobSz, 0);

    int retN1 = rstSet->GoToNextRow();
    EXPECT_EQ(retN1, E_OK);
    blobVec.clear();
    rstSet->GetBlob(4, blobVec);
    EXPECT_EQ(blobSz, 0);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_008
 * @tc.desc: normal testcase of SqliteSharedResultSet for getColumnTypeForIndex
 * @tc.type: FUNC
 */

HWTEST_F(RdbTest, Sqlite_Shared_Result_Set_008, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::unique_ptr<ResultSet> rstSet = RdbTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    ColumnType colType;
    int ret = rstSet->GetColumnType(0, colType);
    EXPECT_EQ(ret, E_INVALID_STATEMENT);
    int retF = rstSet->GoToFirstRow();
    EXPECT_EQ(retF, E_OK);

    rstSet->GetColumnType(0, colType);
    EXPECT_EQ(colType, ColumnType::TYPE_INTEGER);

    bool isColNull = true;
    rstSet->IsColumnNull(0, isColNull);
    EXPECT_EQ(isColNull, false);

    rstSet->GetColumnType(1, colType);
    EXPECT_EQ(colType, ColumnType::TYPE_STRING);

    isColNull = true;
    rstSet->IsColumnNull(0, isColNull);
    EXPECT_EQ(isColNull, false);

    rstSet->GetColumnType(2, colType);
    EXPECT_EQ(colType, ColumnType::TYPE_INTEGER);
    rstSet->GetColumnType(3, colType);
    EXPECT_EQ(colType, ColumnType::TYPE_FLOAT);
    rstSet->GetColumnType(4, colType);
    EXPECT_EQ(colType, ColumnType::TYPE_BLOB);

    int colCnt = 0;
    rstSet->GetColumnCount(colCnt);
    int ret1 = rstSet->GetColumnType(colCnt, colType);
    EXPECT_EQ(ret1, E_INVALID_COLUMN_INDEX);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_009
 * @tc.desc:  normal testcase of SqliteSharedResultSet for getColumnIndexForName
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Sqlite_Shared_Result_Set_009, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::unique_ptr<ResultSet> rstSet = RdbTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    int colIndex = 0;
    rstSet->GetColumnIndex("data1", colIndex);
    EXPECT_EQ(colIndex, 1);

    rstSet->GetColumnIndex("data2", colIndex);
    EXPECT_EQ(colIndex, 2);

    rstSet->GetColumnIndex("data3", colIndex);
    EXPECT_EQ(colIndex, 3);

    rstSet->GetColumnIndex("data4", colIndex);
    EXPECT_EQ(colIndex, 4);

    rstSet->GetColumnIndex("datax", colIndex);
    EXPECT_EQ(colIndex, -1);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_010
 * @tc.desc:  normal testcase of SqliteSharedResultSet for getColumnNameForIndex
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Sqlite_Shared_Result_Set_010, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::unique_ptr<ResultSet> rstSet = RdbTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    std::vector<std::string> allColNamesVec;
    rstSet->GetAllColumnNames(allColNamesVec);

    std::string colName = "";
    rstSet->GetColumnName(1, colName);
    EXPECT_EQ(colName, "data1");
    EXPECT_EQ(allColNamesVec[1], colName);

    rstSet->GetColumnName(2, colName);
    EXPECT_EQ(colName, "data2");
    EXPECT_EQ(allColNamesVec[2], colName);

    rstSet->GetColumnName(3, colName);
    EXPECT_EQ(colName, "data3");
    rstSet->GetColumnName(4, colName);
    EXPECT_EQ(colName, "data4");

    int colCnt = 0;
    rstSet->GetColumnCount(colCnt);
    int ret = rstSet->GetColumnName(colCnt, colName);
    EXPECT_EQ(ret, E_INVALID_COLUMN_INDEX);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_011
 * @tc.desc:  normal testcase of SqliteSharedResultSet
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Sqlite_Shared_Result_Set_011, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::unique_ptr<ResultSet> rstSet = RdbTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    int retF = rstSet->GoToFirstRow();
    EXPECT_EQ(retF, E_OK);

    bool isAtFrtRow = false;
    rstSet->IsAtFirstRow(isAtFrtRow);
    EXPECT_EQ(isAtFrtRow, true);

    bool isStarted = false;
    rstSet->IsStarted(isStarted);
    EXPECT_EQ(isStarted, true);

    int64_t valueInt = 0;
    rstSet->GetLong(2, valueInt);
    EXPECT_EQ(valueInt, 10);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_012
 * @tc.desc: normal testcase of SqliteSharedResultSet for getLong
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Sqlite_Shared_Result_Set_012, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::unique_ptr<ResultSet> rstSet = RdbTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    int64_t valueInt = 0;
    int ret = rstSet->GetLong(0, valueInt);
    EXPECT_EQ(ret, E_INVALID_STATEMENT);

    int retF = rstSet->GoToFirstRow();
    EXPECT_EQ(retF, E_OK);
    rstSet->GetLong(0, valueInt);
    EXPECT_EQ(valueInt, 1.0);
    std::string valueStr = "";
    rstSet->GetString(1, valueStr);
    EXPECT_EQ(valueStr, "hello");
    rstSet->GetLong(2, valueInt);
    EXPECT_EQ(valueInt, 10.0);
    rstSet->GetLong(3, valueInt);
    EXPECT_EQ(valueInt, 1.0);

    int colCnt = 0;
    rstSet->GetColumnCount(colCnt);
    int ret1 = rstSet->GetLong(colCnt, valueInt);
    EXPECT_EQ(ret1, E_INVALID_COLUMN_INDEX);

    int retN = rstSet->GoToNextRow();
    EXPECT_EQ(retN, E_OK);
    rstSet->GetLong(0, valueInt);
    EXPECT_EQ(valueInt, 2.0);
    valueInt = 0;
    rstSet->GetLong(1, valueInt);
    EXPECT_EQ(valueInt, 2.0);
    rstSet->GetLong(2, valueInt);
    EXPECT_EQ(valueInt, -5.0);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_013
 * @tc.desc: normal testcase of SqliteSharedResultSet for fillBlock
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Sqlite_Shared_Result_Set_013, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::unique_ptr<ResultSet> rstSet = RdbTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    SqliteSharedResultSet *pSqlSharedRstSet = static_cast<SqliteSharedResultSet *>(rstSet.get());
    bool isBk = pSqlSharedRstSet->HasBlock();
    EXPECT_EQ(isBk, true);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}
/* *
 * @tc.name: Sqlite_Shared_Result_Set_014
 * @tc.desc: normal testcase of SqliteSharedResultSet for getBlock
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Sqlite_Shared_Result_Set_014, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::unique_ptr<ResultSet> rstSet = RdbTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    SqliteSharedResultSet *pSqlSharedRstSet = static_cast<SqliteSharedResultSet *>(rstSet.get());
    bool isBk = pSqlSharedRstSet->HasBlock();
    EXPECT_EQ(isBk, true);

    int retF = rstSet->GoToFirstRow();
    EXPECT_EQ(retF, E_OK);
    OHOS::AppDataFwk::SharedBlock *pBk = pSqlSharedRstSet->GetBlock();
    EXPECT_NE(pBk, nullptr);

    std::string path = RdbTest::store->GetPath();
    std::string path1 = pBk->Name();

    EXPECT_EQ(path, "/data/test/shared_test.db");
    EXPECT_EQ(path1, "/data/test/shared_test.db");

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}
/* *
 * @tc.name: Sqlite_Shared_Result_Set_015
 * @tc.desc: normal testcase of SqliteSharedResultSet for setBlock
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Sqlite_Shared_Result_Set_015, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::unique_ptr<ResultSet> rstSet = RdbTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    SqliteSharedResultSet *pSqlSharedRstSet = static_cast<SqliteSharedResultSet *>(rstSet.get());
    bool isBk = pSqlSharedRstSet->HasBlock();
    EXPECT_EQ(isBk, true);

    int retN = rstSet->GoToNextRow();
    EXPECT_EQ(retN, E_OK);

    std::string path = RdbTest::store->GetPath();
    OHOS::AppDataFwk::SharedBlock *pBk = pSqlSharedRstSet->GetBlock();
    std::string path1 = pBk->Name();

    EXPECT_EQ(path, "/data/test/shared_test.db");
    EXPECT_EQ(path1, "/data/test/shared_test.db");

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_016
 * @tc.desc: normal testcase of SqliteSharedResultSet for setFillWindowForwardOnly
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Sqlite_Shared_Result_Set_016, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::unique_ptr<ResultSet> rstSet = RdbTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    SqliteSharedResultSet *pSqlSharedRstSet = static_cast<SqliteSharedResultSet *>(rstSet.get());
    bool isBk = pSqlSharedRstSet->HasBlock();
    EXPECT_EQ(isBk, true);

    pSqlSharedRstSet->PickFillBlockStartPosition(0, 0);
    pSqlSharedRstSet->SetFillBlockForwardOnly(true);
    pSqlSharedRstSet->GoToFirstRow();

    OHOS::AppDataFwk::SharedBlock *pBk = pSqlSharedRstSet->GetBlock();
    EXPECT_NE(pBk, nullptr);
    std::string path = RdbTest::store->GetPath();
    std::string path1 = pBk->Name();

    EXPECT_EQ(path, "/data/test/shared_test.db");
    EXPECT_EQ(path1, "/data/test/shared_test.db");

    int rowCnt = 0;
    pSqlSharedRstSet->GetRowCount(rowCnt);
    int rowCntBk = pBk->GetRowNum();

    EXPECT_EQ(rowCnt, rowCntBk);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_017
 * @tc.desc: normal testcase of SqliteSharedResultSet for setExtensions and getExtensions
 * @tc.type: FUNC
 */
HWTEST_F(RdbTest, Sqlite_Shared_Result_Set_017, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::unique_ptr<ResultSet> rstSet = RdbTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    int rowCnt = 0;
    rstSet->GetRowCount(rowCnt);
    EXPECT_EQ(rowCnt, 3);
    int ret = rstSet->GoToLastRow();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_001
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 * @tc.author: chenxi
 */
HWTEST_F(RdbTest, RdbStore_Transaction_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

    int64_t id;
    ValuesBucket values;

    int ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 2);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 19);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    values.Clear();
    values.PutInt("id", 3);
    values.PutString("name", std::string("wangyjing"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    ret = store->Commit();
    EXPECT_EQ(ret, E_OK);

    int64_t count;
    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 3);

    int deletedRows;
    ret = store->Delete(deletedRows, "test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(deletedRows, 3);
}

/**
 * @tc.name: RdbStore_Transaction_002
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 * @tc.author: chenxi
 */
HWTEST_F(RdbTest, RdbStore_Transaction_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

    int64_t id;
    ValuesBucket values;

    int ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 2);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 19);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    values.Clear();
    values.PutInt("id", 3);
    values.PutString("name", std::string("wangyjing"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    ret = store->Commit();
    EXPECT_EQ(ret, E_OK);

    int64_t count;
    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 3);

    std::unique_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);

    int deletedRows;
    ret = store->Delete(deletedRows, "test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(deletedRows, 3);
}

/**
 * @tc.name: RdbStore_NestedTransaction_001
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 * @tc.author: chenxi
 */
HWTEST_F(RdbTest, RdbStore_NestedTransaction_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

    int64_t id;
    ValuesBucket values;

    int ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);
    values.Clear();
    values.PutInt("id", 2);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 19);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);
    ret = store->Commit(); // not commit
    EXPECT_EQ(ret, E_OK);

    values.Clear();
    values.PutInt("id", 3);
    values.PutString("name", std::string("wangyjing"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    ret = store->Commit();
    EXPECT_EQ(ret, E_OK);

    int64_t count;
    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 3);

    std::unique_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);

    int deletedRows;
    ret = store->Delete(deletedRows, "test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(deletedRows, 3);
}

/**
 * @tc.name: RdbStore_NestedTransaction_002
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 * @tc.author: chenxi
 */
HWTEST_F(RdbTest, RdbStore_NestedTransaction_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

    int64_t id;
    ValuesBucket values;

    int ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);
    values.Clear();
    values.PutInt("id", 2);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 19);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);
    ret = store->Commit();
    EXPECT_EQ(ret, E_OK);
    ret = store->Commit(); // commit
    EXPECT_EQ(ret, E_OK);

    values.Clear();
    values.PutInt("id", 3);
    values.PutString("name", std::string("wangyjing"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    int64_t count;
    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 3);

    std::unique_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);

    int deletedRows;
    ret = store->Delete(deletedRows, "test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(deletedRows, 3);
}

/**
 * @tc.name: RdbStore_NestedTransaction_003
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 * @tc.author: chenxi
 */
HWTEST_F(RdbTest, RdbStore_NestedTransaction_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTest::store;

    int64_t id;
    ValuesBucket values;

    int ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);
    values.Clear();
    values.PutInt("id", 2);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 19);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);
    ret = store->Commit(); // not commit
    EXPECT_EQ(ret, E_OK);

    values.Clear();
    values.PutInt("id", 3);
    values.PutString("name", std::string("wangyjing"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    ret = store->Commit(); // not commit
    EXPECT_EQ(ret, E_OK);

    int64_t count;
    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 3);

    std::unique_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);

    int deletedRows;
    ret = store->Delete(deletedRows, "test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(deletedRows, 3);
}
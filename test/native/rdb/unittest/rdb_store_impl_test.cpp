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

#include <string>
#include <map>

#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store_impl.h"
#include "sqlite_connection.h"
#include "relational_store_manager.h"
#include "relational_store_delegate.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbStoreImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;
};

const std::string RdbStoreImplTest::DATABASE_NAME = RDB_TEST_PATH + "stepResultSet_impl_test.db";
std::shared_ptr<RdbStore> RdbStoreImplTest::store = nullptr;

class RdbStoreImplTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

int RdbStoreImplTestOpenCallback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int RdbStoreImplTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbStoreImplTest::SetUpTestCase(void) {}

void RdbStoreImplTest::TearDownTestCase(void) {}

void RdbStoreImplTest::SetUp(void)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreImplTest::DATABASE_NAME);
    RdbStoreImplTestOpenCallback helper;
    RdbStoreImplTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbStoreImplTest::store, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void RdbStoreImplTest::TearDown(void)
{
    RdbHelper::ClearCache();
    int errCode = RdbHelper::DeleteRdbStore(RdbStoreImplTest::DATABASE_NAME);
    EXPECT_EQ(E_OK, errCode);
}

/* *
 * @tc.name: GetModifyTimeByRowIdTest_001
 * @tc.desc: Normal testCase for GetModifyTime, get timestamp by id
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, GetModifyTimeByRowIdTest_001, TestSize.Level2)
{
    RdbStoreImplTest::store->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_rdbstoreimpltest_integer_log "
        "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
        "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int64_t rowId;
    ValuesBucket valuesBucket;
    valuesBucket.PutInt("data_key", ValueObject(1));
    valuesBucket.PutInt("timestamp", ValueObject(1000000000));
    int errorCode = RdbStoreImplTest::store->Insert(rowId,
        "naturalbase_rdb_aux_rdbstoreimpltest_integer_log", valuesBucket);
    EXPECT_EQ(E_OK, errorCode);
    EXPECT_EQ(1, rowId);

    std::vector<RdbStore::PRIKey> PKey = { 1 };
    std::map<RdbStore::PRIKey, RdbStore::Date> result =
        RdbStoreImplTest::store->GetModifyTime("rdbstoreimpltest_integer", "ROWID", PKey);
    int size = result.size();
    EXPECT_EQ(1, size);
    EXPECT_EQ(100000, int64_t(result[1]));

    RdbStoreImplTest::store->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_rdbstoreimpltest_integer_log");
}

/* *
 * @tc.name: GetModifyTimeByRowIdTest_002
 * @tc.desc: Abnormal testCase for GetModifyTime, get timestamp by id,
 *           resultSet is empty or table name is not exist
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, GetModifyTimeByRowIdTest_002, TestSize.Level2)
{
    RdbStoreImplTest::store->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_rdbstoreimpltest_integer_log "
                                        "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
                                        "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int64_t rowId;
    ValuesBucket valuesBucket;
    valuesBucket.PutInt("data_key", ValueObject(2));
    int errorCode = RdbStoreImplTest::store->Insert(rowId,
        "naturalbase_rdb_aux_rdbstoreimpltest_integer_log", valuesBucket);
    EXPECT_EQ(E_OK, errorCode);
    EXPECT_EQ(1, rowId);

    // resultSet is empty
    std::vector<RdbStore::PRIKey> PKey = { 1 };
    std::map<RdbStore::PRIKey, RdbStore::Date> result =
        RdbStoreImplTest::store->GetModifyTime("rdbstoreimpltest_integer", "ROWID", PKey);
    int size = result.size();
    EXPECT_EQ(0, size);

    // table name is  not exist , resultSet is null
    result = RdbStoreImplTest::store->GetModifyTime("test", "ROWID", PKey);
    size = result.size();
    EXPECT_EQ(0, size);

    RdbStoreImplTest::store->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_rdbstoreimpltest_integer_log");
}

/* *
 * @tc.name: GetModifyTimeByRowIdTest_003
 * @tc.desc: Abnormal testCase for GetModifyTime, get timestamp by id,
 *           resultSet is empty or table name is not exist
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, GetModifyTimeByRowIdTest_003, TestSize.Level2)
{
    RdbStoreImplTest::store->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_rdbstoreimpltest_integer_log "
                                        "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
                                        "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int64_t rowId;
    ValuesBucket valuesBucket;
    valuesBucket.PutInt("data_key", ValueObject(1));
    int errorCode = RdbStoreImplTest::store->Insert(rowId,
        "naturalbase_rdb_aux_rdbstoreimpltest_integer_log", valuesBucket);
    EXPECT_EQ(E_OK, errorCode);
    EXPECT_EQ(1, rowId);

    std::vector<RdbStore::PRIKey> PKey = { 1 };
    std::map<RdbStore::PRIKey, RdbStore::Date> resultMap =
        RdbStoreImplTest::store->GetModifyTime("rdbstoreimpltest_integer", "ROWID", PKey);
    EXPECT_EQ(1, resultMap.size());

    std::shared_ptr<ResultSet> resultPtr =
        RdbStoreImplTest::store->GetModifyTime("rdbstoreimpltest_integer", "ROWID", PKey);
    int count = 0;
    resultPtr->GetRowCount(count);
    EXPECT_EQ(1, count);

    RdbStore::ModifyTime result =
        RdbStoreImplTest::store->GetModifyTime("rdbstoreimpltest_integer", "ROWID", PKey);
    RdbStore::PRIKey key = result.GetOriginKey(std::vector<uint8_t>{});
    RdbStore::PRIKey monostate = std::monostate();
    EXPECT_EQ(monostate, key);

    RdbStoreImplTest::store->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_rdbstoreimpltest_integer_log");
}

/* *
 * @tc.name: GetModifyTime_001
 * @tc.desc: Abnormal testCase for GetModifyTime, tablename columnName, keys is empty,
 *           and resultSet is null or empty
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, GetModifyTime_001, TestSize.Level2)
{
    RdbStoreImplTest::store->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_rdbstoreimpltest_integer_log "
        "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
        "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");

    // table name is ""
    std::vector<RdbStore::PRIKey> PKey = {1};
    std::map<RdbStore::PRIKey, RdbStore::Date> result = RdbStoreImplTest::store->GetModifyTime("", "data_key", PKey);
    int size = result.size();
    EXPECT_EQ(0, size);

    // table name is not exist , query resultSet is null
    result = RdbStoreImplTest::store->GetModifyTime("test", "data_key", PKey);
    size = result.size();
    EXPECT_EQ(0, size);

    // columnName is ""
    result = RdbStoreImplTest::store->GetModifyTime("test", "", PKey);
    size = result.size();
    EXPECT_EQ(0, size);

    // keys is empty
    std::vector<RdbStore::PRIKey> emptyPRIKey;
    result = RdbStoreImplTest::store->GetModifyTime("test", "data_key", emptyPRIKey);
    size = result.size();
    EXPECT_EQ(0, size);

    RdbStoreImplTest::store->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_rdbstoreimpltest_integer_log");
}

/* *
 * @tc.name: GetModifyTime_002
 * @tc.desc: Abnormal testCase for GetModifyTime, get timestamp by data3 ,if query resultSet is empty
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, GetModifyTime_002, TestSize.Level2)
{
    RdbStoreImplTest::store->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_rdbstoreimpltest_integer_log "
        "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, hash_key INTEGER, "
        "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");

    std::vector<RdbStore::PRIKey> PKey = {1};
    std::map<RdbStore::PRIKey, RdbStore::Date> result =
        RdbStoreImplTest::store->GetModifyTime("rdbstoreimpltest_integer", "data3", PKey);
    EXPECT_EQ(0, result.size());

    RdbStoreImplTest::store->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_rdbstoreimpltest_integer_log");
}

/* *
 * @tc.name: Rdb_BatchInsertTest_001
 * @tc.desc: Abnormal testCase for BatchInsert, if initialBatchValues is empty
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Rdb_BatchInsertTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    int64_t insertNum = 1;
    int ret = store->BatchInsert(insertNum, "test", valuesBuckets);
    EXPECT_EQ(0, insertNum);
    EXPECT_EQ(E_OK, ret);
}

/* *
 * @tc.name: Rdb_QueryTest_001
 * @tc.desc: Abnormal testCase for Query, if table name is empty
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Rdb_QueryTest_001, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreImplTest::store->Query(errCode, true, "", {}, "",
        std::vector<ValueObject> {}, "", "", "", 1, 0);
    EXPECT_NE(E_OK, errCode);
}

/* *
 * @tc.name: Rdb_QueryTest_002
 * @tc.desc: Normal testCase for Query, get * form test
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Rdb_QueryTest_002, TestSize.Level2)
{
    store->ExecuteSql("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, "
                      "data2 INTEGER, data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int errCode = E_OK;
    RdbStoreImplTest::store->Query(errCode, true, "test", {},
        "", std::vector<ValueObject> {}, "", "", "", 1, 0);
    EXPECT_EQ(E_OK, errCode);

    store->ExecuteSql("DROP TABLE IF EXISTS test");
}

/* *
 * @tc.name: Rdb_RemoteQueryTest_001
 * @tc.desc: Abnormal testCase for RemoteQuery
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Rdb_RemoteQueryTest_001, TestSize.Level2)
{
    int errCode = E_OK;
    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", 1);

    // GetRdbService failed if rdbstoreconfig bundlename_ empty
    auto ret = RdbStoreImplTest::store->RemoteQuery("", predicates, {}, errCode);
    EXPECT_EQ(E_INVALID_ARGS, errCode);
    EXPECT_EQ(nullptr, ret);
    RdbHelper::DeleteRdbStore(RdbStoreImplTest::DATABASE_NAME);

    RdbStoreConfig config(RdbStoreImplTest::DATABASE_NAME);
    config.SetName("RdbStore_impl_test.db");
    config.SetBundleName("com.example.distributed.rdb");
    RdbStoreImplTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(E_OK, errCode);

    // GetRdbService succeeded if configuration file has already been configured
    ret = store->RemoteQuery("", predicates, {}, errCode);
    EXPECT_EQ(E_OK, errCode);
    EXPECT_EQ(nullptr, ret);

    RdbHelper::DeleteRdbStore(RdbStoreImplTest::DATABASE_NAME);
}

/* *
 * @tc.name: Rdb_RollbackTest_001
 * @tc.desc: Abnormal testCase for Rollback
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Rdb_RollbackTest_001, TestSize.Level2)
{
    int ret = RdbStoreImplTest::store->RollBack();
    EXPECT_EQ(OHOS::NativeRdb::E_NO_TRANSACTION_IN_SESSION, ret);
}

/* *
 * @tc.name: Rdb_CommitTest_001
 * @tc.desc: Abnormal testCase for Commit,if not use BeginTransaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Rdb_CommitTest_001, TestSize.Level2)
{
    int ret = RdbStoreImplTest::store->Commit();
    EXPECT_EQ(E_OK, ret);
}

/* *
 * @tc.name: Rdb_BackupTest_001
 * @tc.desc: Abnormal testCase for Backup
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Rdb_BackupTest_001, TestSize.Level2)
{
    int errCode = E_OK;
    std::string databasePath = RDB_TEST_PATH + "test.db";
    std::vector<uint8_t> destEncryptKey;
    // isEncrypt_ is false, and destEncryptKey is emtpy
    errCode = RdbStoreImplTest::store->Backup(databasePath, destEncryptKey);
    EXPECT_EQ(E_OK, errCode);
    RdbHelper::DeleteRdbStore(databasePath);

    // isEncrypt_ is false, and destEncryptKey is not emtpy
    destEncryptKey.push_back(1);
    errCode = RdbStoreImplTest::store->Backup(databasePath, destEncryptKey);
    EXPECT_EQ(E_OK, errCode);
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
    RdbHelper::DeleteRdbStore(databasePath);

    RdbStoreConfig config(RdbStoreImplTest::DATABASE_NAME);
    config.SetEncryptStatus(true);
    RdbStoreImplTestOpenCallback helper;
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
    RdbHelper::DeleteRdbStore(databasePath);
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
}

/* *
 * @tc.name: Rdb_SqlitConnectionTest_001
 * @tc.desc: Abnormal testCase for SetPageSize,
 *           return ok if open db again and set same page size
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Rdb_SqlitConnectionTest_001, TestSize.Level2)
{
    const std::string DATABASE_NAME = RDB_TEST_PATH + "SqlitConnectionOpenTest.db";
    int errCode = E_OK;
    RdbStoreConfig config(DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetPageSize(1024);
    SqliteConnection* connection = SqliteConnection::Open(config, true, errCode);
    EXPECT_NE(nullptr, connection);
    int64_t value = 0;
    errCode = connection->ExecuteGetLong(value, "PRAGMA page_size");
    EXPECT_EQ(E_OK, errCode);
    EXPECT_EQ(1024, value);

    auto tmp = SqliteConnection::Open(config, true, errCode);
    EXPECT_NE(nullptr, tmp);
}

#ifdef RDB_SUPPORT_ICU
/* *
 * @tc.name: Rdb_SqlitConnectionPoolTest_001
 * @tc.desc: Abnormal testCase for ConfigLocale
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Rdb_SqlitConnectionPoolTest_001, TestSize.Level2)
{
    const std::string DATABASE_NAME = RDB_TEST_PATH + "SqlitConnectionOpenTest.db";
    int errCode = E_OK;
    RdbStoreConfig config(DATABASE_NAME);
    config.SetReadConSize(1);
    config.SetStorageMode(StorageMode::MODE_DISK);

    RdbStoreImplTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(E_OK, errCode);

    // error condition does not affect the current program
    errCode = store->ConfigLocale("AbnormalTest");
    EXPECT_EQ(E_OK, errCode);

    SqliteConnectionPool* connectionPool = SqliteConnectionPool::Create(config, errCode);
    EXPECT_NE(nullptr, connectionPool);
    EXPECT_EQ(E_OK, errCode);

    // connecting database
    auto connection = connectionPool->AcquireConnection(true);
    EXPECT_NE(nullptr, connection);
    errCode = connectionPool->ConfigLocale("AbnormalTest");
    EXPECT_EQ(OHOS::NativeRdb::E_NO_ROW_IN_QUERY, errCode);

    RdbHelper::DeleteRdbStore(DATABASE_NAME);
    connectionPool->ReleaseConnection(connection);
    delete connectionPool;
}
#endif

/* *
 * @tc.name: Rdb_SqlitConnectionPoolTest_002
 * @tc.desc: Abnormal testCase for AcquireConnection/AcquireTransaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Rdb_SqlitConnectionPoolTest_002, TestSize.Level2)
{
    const std::string DATABASE_NAME = RDB_TEST_PATH + "SqlitConnectionTest.db";
    int errCode = E_OK;
    RdbStoreConfig config(DATABASE_NAME);
    config.SetReadConSize(1);
    config.SetStorageMode(StorageMode::MODE_DISK);
    SqliteConnectionPool* connectionPool = SqliteConnectionPool::Create(config, errCode);
    EXPECT_NE(nullptr, connectionPool);
    EXPECT_EQ(E_OK, errCode);

    // repeat AcquireReadConnection without release
    auto connection = connectionPool->AcquireConnection(true);
    EXPECT_NE(nullptr, connection);
    connection = connectionPool->AcquireConnection(true);
    EXPECT_EQ(nullptr, connection);
    connectionPool->ReleaseConnection(connection);

    // repeat AcquireWriteConnection without release
    connection = connectionPool->AcquireConnection(false);
    EXPECT_NE(nullptr, connection);
    connection = connectionPool->AcquireConnection(false);
    EXPECT_EQ(nullptr, connection);
    connectionPool->ReleaseConnection(connection);

    // repeat AcquireTransaction without release
    errCode = connectionPool->AcquireTransaction();
    EXPECT_EQ(E_OK, errCode);
    errCode = connectionPool->AcquireTransaction();
    EXPECT_NE(E_OK, errCode);
    connectionPool->ReleaseTransaction();

    delete connectionPool;
}


/* *
 * @tc.name: Rdb_SqlitConnectionPoolTest_003
 * @tc.desc: Abnormal testCase for ChangeDbFileForRestore
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Rdb_SqlitConnectionPoolTest_0023, TestSize.Level2)
{
    const std::string DATABASE_NAME = RDB_TEST_PATH + "SqlitConnectionTest.db";
    int errCode = E_OK;
    RdbStoreConfig config(DATABASE_NAME);
    config.SetReadConSize(1);
    config.SetStorageMode(StorageMode::MODE_DISK);
    SqliteConnectionPool* connectionPool = SqliteConnectionPool::Create(config, errCode);
    EXPECT_NE(nullptr, connectionPool);
    EXPECT_EQ(E_OK, errCode);


    const std::string newPath = DATABASE_NAME;
    const std::string backupPath = DATABASE_NAME;
    const std::vector<uint8_t> newKey;

    // newPath == currentPath, writeConnectionUsed == true
    auto connection = connectionPool->AcquireConnection(false);
    errCode = connectionPool->ChangeDbFileForRestore(newPath, backupPath, newKey);
    EXPECT_EQ(E_ERROR, errCode);
    connectionPool->ReleaseConnection(connection);

    // newPath == currentPath, idleReadConnectionCount != readConnectionCount
    connection = connectionPool->AcquireConnection(true);
    errCode = connectionPool->ChangeDbFileForRestore(newPath, backupPath, newKey);
    EXPECT_EQ(E_ERROR, errCode);
    connectionPool->ReleaseConnection(connection);


    // newPath == currentPath
    errCode = connectionPool->ChangeDbFileForRestore(newPath, backupPath, newKey);
    EXPECT_NE(E_OK, errCode);
    // newPath != currentPath
    const std::string newPath2 = RDB_TEST_PATH + "tmp.db";
    errCode = connectionPool->ChangeDbFileForRestore(newPath2, backupPath, newKey);
    EXPECT_EQ(E_ERROR, errCode);

    delete connectionPool;
}

HWTEST_F(RdbStoreImplTest, NotifyDataChangeTest_001, TestSize.Level2)
{
    const std::string DATABASE_NAME = RDB_TEST_PATH + "SqlitConnectionOpenTest.db";
    int errCode = E_OK;
    RdbStoreConfig config(DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetPageSize(1024);
    SqliteConnection* connection = SqliteConnection::Open(config, true, errCode);
    EXPECT_NE(nullptr, connection);
    RdbStoreImplTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(nullptr, store);
}

HWTEST_F(RdbStoreImplTest, NotifyDataChangeTest_002, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreImplTest::DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetPageSize(1024);
    config.SetBundleName("callback.test2");
    config.SetSearchable(true);
    config.SetStorageMode(StorageMode::MODE_DISK);
    // register callback
    RdbStoreImplTestOpenCallback helper;
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
    tracker.trackerColNames = {"id", "timestamp"};
    DistributedDB::RelationalStoreManager rStoreManager("test_app", "test_user_id", 0);
    DistributedDB::RelationalStoreDelegate::Option option;
    DistributedDB::RelationalStoreDelegate *g_delegate = nullptr;
    EXPECT_EQ(RdbStoreImplTest::DATABASE_NAME, "/data/test/stepResultSet_impl_test.db");
    int status = rStoreManager.OpenStore(RdbStoreImplTest::DATABASE_NAME, "test_callback_t2", option, g_delegate);
    EXPECT_EQ(E_OK, status);
    int setStatus = g_delegate->SetTrackerTable(tracker);
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

HWTEST_F(RdbStoreImplTest, NotifyDataChangeTest_003, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreImplTest::DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetPageSize(1024);
    config.SetBundleName("callback.test3");
    config.SetSearchable(true);
    config.SetStorageMode(StorageMode::MODE_DISK);

    RdbStoreImplTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);

    store->ExecuteSql("DROP TABLE IF EXISTS test_callback_t3;");

    store->ExecuteSql("CREATE TABLE if not exists test_callback_t3 "
    "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
    "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    // set TrackerTable
    DistributedDB::TrackerSchema tracker;
    tracker.tableName = "test_callback_t3";
    tracker.extendColName = "";
    tracker.trackerColNames = {"id", "timestamp"};
    DistributedDB::RelationalStoreManager rStoreManager("test_app", "test_user_id", 0);
    DistributedDB::RelationalStoreDelegate::Option option;
    DistributedDB::RelationalStoreDelegate *g_delegate = nullptr;
    EXPECT_EQ(RdbStoreImplTest::DATABASE_NAME, "/data/test/stepResultSet_impl_test.db");
    int status = rStoreManager.OpenStore(RdbStoreImplTest::DATABASE_NAME, "test_callback_t3", option, g_delegate);
    EXPECT_EQ(E_OK, status);
    int setStatus = g_delegate->SetTrackerTable(tracker);
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
 * @tc.name: CleanDirtyDataTest_001
 * @tc.desc: Abnormal testCase for CleanDirtyData
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, CleanDirtyDataTest_001, TestSize.Level2)
{
    store->ExecuteSql("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, "
                      "data2 INTEGER, data3 FLOAT, data4 BLOB, data5 BOOLEAN);");

    int errCode = E_OK;

    // tabel is empty
    std::string table = "";
    uint64_t cursor = UINT64_MAX;
    errCode = RdbStoreImplTest::store->CleanDirtyData(table, cursor);
    EXPECT_EQ(E_INVALID_ARGS, errCode);

    table = "test";
    errCode = RdbStoreImplTest::store->CleanDirtyData(table, cursor);
    EXPECT_EQ(E_ERROR, errCode);
    store->ExecuteSql("DROP TABLE IF EXISTS test");
}
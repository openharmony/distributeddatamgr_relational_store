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

protected:
    std::shared_ptr<RdbStore> store_;
};

const std::string RdbStoreImplTest::DATABASE_NAME = RDB_TEST_PATH + "stepResultSet_impl_test.db";

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
    store_ = nullptr;
    int errCode = RdbHelper::DeleteRdbStore(DATABASE_NAME);
    EXPECT_EQ(E_OK, errCode);
    RdbStoreConfig config(RdbStoreImplTest::DATABASE_NAME);
    RdbStoreImplTestOpenCallback helper;
    store_ = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store_, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void RdbStoreImplTest::TearDown(void)
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
HWTEST_F(RdbStoreImplTest, GetModifyTimeByRowIdTest_001, TestSize.Level2)
{
    store_->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_rdbstoreimpltest_integer_log "
        "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
        "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int64_t rowId;
    ValuesBucket valuesBucket;
    valuesBucket.PutInt("data_key", ValueObject(1));
    valuesBucket.PutInt("timestamp", ValueObject(1000000000));
    int errorCode = store_->Insert(rowId,
        "naturalbase_rdb_aux_rdbstoreimpltest_integer_log", valuesBucket);
    EXPECT_EQ(E_OK, errorCode);
    EXPECT_EQ(1, rowId);

    std::vector<RdbStore::PRIKey> PKey = { 1 };
    std::map<RdbStore::PRIKey, RdbStore::Date> result =
        store_->GetModifyTime("rdbstoreimpltest_integer", "ROWID", PKey);
    int size = result.size();
    EXPECT_EQ(1, size);
    EXPECT_EQ(100000, int64_t(result[1]));

    store_->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_rdbstoreimpltest_integer_log");
}

/* *
 * @tc.name: GetModifyTimeByRowIdTest_002
 * @tc.desc: Abnormal testCase for GetModifyTime, get timestamp by id,
 *           resultSet is empty or table name is not exist
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, GetModifyTimeByRowIdTest_002, TestSize.Level2)
{
    store_->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_rdbstoreimpltest_integer_log "
                       "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
                       "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int64_t rowId;
    ValuesBucket valuesBucket;
    valuesBucket.PutInt("data_key", ValueObject(2));
    int errorCode = store_->Insert(rowId, "naturalbase_rdb_aux_rdbstoreimpltest_integer_log", valuesBucket);
    EXPECT_EQ(E_OK, errorCode);
    EXPECT_EQ(1, rowId);

    // resultSet is empty
    std::vector<RdbStore::PRIKey> PKey = { 1 };
    std::map<RdbStore::PRIKey, RdbStore::Date> result =
        store_->GetModifyTime("rdbstoreimpltest_integer", "ROWID", PKey);
    int size = result.size();
    EXPECT_EQ(0, size);

    // table name is  not exist , resultSet is null
    result = store_->GetModifyTime("test", "ROWID", PKey);
    size = result.size();
    EXPECT_EQ(0, size);

    store_->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_rdbstoreimpltest_integer_log");
}

/* *
 * @tc.name: GetModifyTimeByRowIdTest_003
 * @tc.desc: Abnormal testCase for GetModifyTime, get timestamp by id,
 *           resultSet is empty or table name is not exist
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, GetModifyTimeByRowIdTest_003, TestSize.Level2)
{
    store_->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_rdbstoreimpltest_integer_log "
                       "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
                       "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int64_t rowId;
    ValuesBucket valuesBucket;
    valuesBucket.PutInt("data_key", ValueObject(1));
    int errorCode = store_->Insert(rowId, "naturalbase_rdb_aux_rdbstoreimpltest_integer_log", valuesBucket);
    EXPECT_EQ(E_OK, errorCode);
    EXPECT_EQ(1, rowId);

    std::vector<RdbStore::PRIKey> PKey = { 1 };
    RdbStore::ModifyTime resultMapTmp = store_->GetModifyTime("rdbstoreimpltest_integer", "ROWID", PKey);
    std::map<RdbStore::PRIKey, RdbStore::Date> resultMap = std::map<RdbStore::PRIKey, RdbStore::Date>(resultMapTmp);
    EXPECT_EQ(1, resultMap.size());

    RdbStore::ModifyTime resultPtrTmp = store_->GetModifyTime("rdbstoreimpltest_integer", "ROWID", PKey);
    std::shared_ptr<ResultSet> resultPtr = std::shared_ptr<ResultSet>(resultPtrTmp);
    int count = 0;
    resultPtr->GetRowCount(count);
    EXPECT_EQ(1, count);

    RdbStore::ModifyTime result = store_->GetModifyTime("rdbstoreimpltest_integer", "ROWID", PKey);
    RdbStore::PRIKey key = result.GetOriginKey(std::vector<uint8_t>{});
    RdbStore::PRIKey monostate = std::monostate();
    EXPECT_EQ(monostate, key);

    store_->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_rdbstoreimpltest_integer_log");
}

/* *
 * @tc.name: GetModifyTime_001
 * @tc.desc: Abnormal testCase for GetModifyTime, tablename columnName, keys is empty,
 *           and resultSet is null or empty
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, GetModifyTime_001, TestSize.Level2)
{
    store_->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_rdbstoreimpltest_integer_log "
                       "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
                       "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");

    // table name is ""
    std::vector<RdbStore::PRIKey> PKey = {1};
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

    store_->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_rdbstoreimpltest_integer_log");
}

/* *
 * @tc.name: GetModifyTime_002
 * @tc.desc: Abnormal testCase for GetModifyTime, get timestamp by data3 ,if query resultSet is empty
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, GetModifyTime_002, TestSize.Level2)
{
    store_->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_rdbstoreimpltest_integer_log "
                       "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, hash_key INTEGER, "
                       "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");

    std::vector<RdbStore::PRIKey> PKey = {1};
    std::map<RdbStore::PRIKey, RdbStore::Date> result =
        store_->GetModifyTime("rdbstoreimpltest_integer", "data3", PKey);
    EXPECT_EQ(0, result.size());

    store_->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_rdbstoreimpltest_integer_log");
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
    int ret = store_->BatchInsert(insertNum, "test", valuesBuckets);
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
    store_->Query(errCode, true, "", {}, "", std::vector<ValueObject>{}, "", "", "", 1, 0);
    EXPECT_NE(E_OK, errCode);
}

/* *
 * @tc.name: Rdb_QueryTest_002
 * @tc.desc: Normal testCase for Query, get * form test
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Rdb_QueryTest_002, TestSize.Level2)
{
    store_->ExecuteSql("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, "
                       "data2 INTEGER, data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int errCode = E_OK;
    store_->Query(errCode, true, "test", {},
        "", std::vector<ValueObject> {}, "", "", "", 1, 0);
    EXPECT_EQ(E_OK, errCode);

    store_->ExecuteSql("DROP TABLE IF EXISTS test");
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
    auto ret = store_->RemoteQuery("", predicates, {}, errCode);
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
    EXPECT_NE(E_OK, errCode);
    EXPECT_EQ(nullptr, ret);

    store = nullptr;
    RdbHelper::DeleteRdbStore(RdbStoreImplTest::DATABASE_NAME);
}

/* *
 * @tc.name: Rdb_RollbackTest_001
 * @tc.desc: Abnormal testCase for Rollback
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Rdb_RollbackTest_001, TestSize.Level2)
{
    int ret = store_->RollBack();
    EXPECT_EQ(OHOS::NativeRdb::E_NO_TRANSACTION_IN_SESSION, ret);
}

/* *
 * @tc.name: Rdb_CommitTest_001
 * @tc.desc: Abnormal testCase for Commit,if not use BeginTransaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Rdb_CommitTest_001, TestSize.Level2)
{
    int ret = store_->Commit();
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
HWTEST_F(RdbStoreImplTest, Rdb_SqlitConnectionTest_001, TestSize.Level2)
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

    auto connectionPool = SqliteConnectionPool::Create(config, errCode);
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
    auto connectionPool = SqliteConnectionPool::Create(config, errCode);
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
    auto connectionPool = SqliteConnectionPool::Create(config, errCode);
    EXPECT_NE(nullptr, connectionPool);
    EXPECT_EQ(E_OK, errCode);


    const std::string newPath = DATABASE_NAME;
    const std::string backupPath = DATABASE_NAME;
    const std::vector<uint8_t> newKey;

    // newPath == currentPath, writeConnectionUsed == true
    auto connection = connectionPool->AcquireConnection(false);
    errCode = connectionPool->ChangeDbFileForRestore(newPath, backupPath, newKey);
    EXPECT_EQ(E_ERROR, errCode);
    connection = nullptr;
    // newPath == currentPath
    errCode = connectionPool->ChangeDbFileForRestore(newPath, backupPath, newKey);
    EXPECT_NE(E_OK, errCode);
    // newPath != currentPath
    const std::string newPath2 = RDB_TEST_PATH + "tmp.db";
    errCode = connectionPool->ChangeDbFileForRestore(newPath2, backupPath, newKey);
    EXPECT_EQ(E_ERROR, errCode);
}

HWTEST_F(RdbStoreImplTest, NotifyDataChangeTest_001, TestSize.Level2)
{
    const std::string DATABASE_NAME = RDB_TEST_PATH + "SqlitConnectionOpenTest.db";
    RdbStoreConfig config(DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetPageSize(1024);
    auto [errCode, connection] = SqliteConnection::Create(config, true);
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
    using Delegate = DistributedDB::RelationalStoreDelegate;
    DistributedDB::RelationalStoreManager rStoreManager("test_app", "test_user_id", 0);
    Delegate::Option option;
    Delegate *g_delegate = nullptr;
    EXPECT_EQ(RdbStoreImplTest::DATABASE_NAME, "/data/test/stepResultSet_impl_test.db");
    int status = rStoreManager.OpenStore(RdbStoreImplTest::DATABASE_NAME, "test_callback_t2", option, g_delegate);
    EXPECT_EQ(E_OK, status);
    auto delegatePtr = std::shared_ptr<Delegate>(g_delegate, [&rStoreManager](Delegate* delegate) {
        rStoreManager.CloseStore(delegate);
    });
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
    using Delegate = DistributedDB::RelationalStoreDelegate;
    DistributedDB::RelationalStoreManager rStoreManager("test_app", "test_user_id", 0);
    Delegate::Option option;
    Delegate *g_delegate = nullptr;
    EXPECT_EQ(RdbStoreImplTest::DATABASE_NAME, "/data/test/stepResultSet_impl_test.db");
    int status = rStoreManager.OpenStore(RdbStoreImplTest::DATABASE_NAME, "test_callback_t3", option, g_delegate);
    EXPECT_EQ(E_OK, status);
    auto delegatePtr = std::shared_ptr<Delegate>(g_delegate, [&rStoreManager](Delegate* delegate) {
        rStoreManager.CloseStore(delegate);
    });
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
HWTEST_F(RdbStoreImplTest, Rdb_QuerySharingResourceTest_001, TestSize.Level2)
{
    RdbHelper::DeleteRdbStore(RdbStoreImplTest::DATABASE_NAME);
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreImplTest::DATABASE_NAME);
    config.SetName("RdbStore_impl_test.db");
    config.SetBundleName("com.example.distributed.rdb");

    RdbStoreImplTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", 1);

    auto ret = store->QuerySharingResource(predicates, {});
    EXPECT_NE(E_OK, ret.first);
    EXPECT_EQ(nullptr, ret.second);
    RdbHelper::DeleteRdbStore(RdbStoreImplTest::DATABASE_NAME);
}

/* *
 * @tc.name: Rdb_QuerySharingResourceTest_002
 * @tc.desc: QuerySharingResource testCase
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Rdb_QuerySharingResourceTest_002, TestSize.Level2)
{
    RdbHelper::DeleteRdbStore(RdbStoreImplTest::DATABASE_NAME);
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreImplTest::DATABASE_NAME);
    config.SetName("RdbStore_impl_test.db");
    config.SetBundleName("com.example.distributed.rdb");

    RdbStoreImplTestOpenCallback helper;
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

    RdbHelper::DeleteRdbStore(RdbStoreImplTest::DATABASE_NAME);
}

/* *
 * @tc.name: CleanDirtyDataTest_001
 * @tc.desc: Abnormal testCase for CleanDirtyData
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Abnormal_CleanDirtyDataTest_001, TestSize.Level2)
{
    store_->ExecuteSql("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, "
                      "data2 INTEGER, data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int errCode = E_OK;

    // tabel is empty
    std::string table = "";
    uint64_t cursor = UINT64_MAX;
    errCode = RdbStoreImplTest::store_->CleanDirtyData(table, cursor);
    EXPECT_EQ(E_INVALID_ARGS, errCode);

    table = "test";
    errCode = RdbStoreImplTest::store_->CleanDirtyData(table, cursor);
    EXPECT_EQ(E_ERROR, errCode);
    store_->ExecuteSql("DROP TABLE IF EXISTS test");
}

/* *
 * @tc.name: ClearCacheTest_001
 * @tc.desc: Normal testCase for ClearCache
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplTest, Normal_ClearCacheTest_001, TestSize.Level2)
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
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

#include "rdb_errno.h"
#include "common.h"
#include "rdb_open_callback.h"
#include "rdb_helper.h"
#include "relational_store_delegate.h"
#include "rdb_store_impl.h"
#include "relational_store_manager.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbInterceptionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    std::shared_ptr<RdbStore> storDif_;
};


class RdbInterceptionTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &storeDif) override;
    int OnUpgrade(RdbStore &storeDif, int oldVersion, int newVersion) override;
};

int RdbInterceptionTestOpenCallback::OnCreate(RdbStore &storeDif)
{
    return E_BASE;
}

int RdbInterceptionTestOpenCallback::OnUpgrade(RdbStore &storeDif, int oldVersion, int newVersion)
{
    return E_BASE;
}

void RdbInterceptionTest::SetUpTestCase(void)
{
}

void RdbInterceptionTest::TearDownTestCase(void)
{
}

void RdbInterceptionTest::SetUp(void)
{
    storDif_ = nullptr;
    int errCodeDif = RdbHelper::DeleteRdbStore(DATABASE_DIF_NAME);
    ASSERT_EQ(E_BASE, errCodeDif);
    RdbStoreConfig configDif(RdbInterceptionTest::DATABASE_DIF_NAME);
    RdbInterceptionTestOpenCallback helperDif;
    storDif_ = RdbHelper::GetRdbStore(configDif, 1, helperDif, errCodeDif);
    ASSERT_NE(storDif_, nullptr);
    ASSERT_EQ(errCodeDif, E_BASE);
}

void RdbInterceptionTest::TearDown(void)
{
    storDif_ = nullptr;
    RdbHelper::ClearCache();
    int errCodeDif = RdbHelper::DeleteRdbStore(DATABASE_DIF_NAME);
    ASSERT_EQ(E_BASE, errCodeDif);
}

/* *
 * @tc.name: GetModifyTimeDifByrowDifIdDifTest_001
 * @tc.desc: Normal testCase for GetModifyTimeDif, get timestamp by idDif
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, GetModifyTimeDifByrowDifIdDifTest_001, TestSize.Level2)
{
    storDif_->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_RdbInterceptionTest_integer_log "
                       "(idDif INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DOUBLE, data_key INTEGER, "
                       "data3 FLOAT, data5 BLOB, data6 BOOLEAN);");
    int64_t rowDifId;
    ValuesBucket valuesBucketDif;
    valuesBucketDif.PutInt("data_dif_key", ValueObject(1));
    valuesBucketDif.PutInt("timestampdif", ValueObject(1000000000));
    int errorCodeDif = storDif_->Insert(rowDifId, "RdbInterceptionTest_integer_log", valuesBucketDif);
    ASSERT_EQ(E_BASE, errorCodeDif);
    ASSERT_EQ(1, rowDifId);

    std::vector<RdbStore::PRIKey> PKeyDif = { 1 };
    std::map<RdbStore::PRIKey, RdbStore::Date> resultDif = storDif_->GetModifyTimeDif("integer", "rowDifId", PKeyDif);
    int sizeDif = resultDif.size();
    ASSERT_EQ(1, sizeDif);
    ASSERT_EQ(100000, int64_t(resultDif[1]));

    storDif_->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_RdbInterceptionTest_integer_log");
}

/* *
 * @tc.name: GetModifyTimeDifByrowDifIdDifTest_002
 * @tc.desc: Abnormal testCase for GetModifyTimeDif, get timestamp by idDif,
 *           resultSet is empty or tableDif name is not exist
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, GetModifyTimeDifByrowDifIdDifTest_002, TestSize.Level2)
{
    storDif_->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_RdbInterceptionTest_integer_log "
                       "(idDif INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DOUBLE, data_key FLOAT, "
                       "data3 INTEGER, data5 BLOB, data6 BOOLEAN);");
    int64_t rowDifId;
    ValuesBucket valuesBucketDif;
    valuesBucketDif.PutInt("data_dif_key", ValueObject(2));
    int errorCodeDif = storDif_->Insert(rowDifId, "RdbInterceptionTest_integer_log", valuesBucketDif);
    ASSERT_EQ(E_BASE, errorCodeDif);
    ASSERT_EQ(1, rowDifId);

    // resultSet is empty
    std::vector<RdbStore::PRIKey> PKeyDif = { 1 };
    std::map<RdbStore::PRIKey, RdbStore::Date> resultDif = storDif_->GetModifyTimeDif("integer", "rowDifId", PKeyDif);
    int sizeDif = resultDif.size();
    ASSERT_EQ(0, sizeDif);

    // tableDif name is  not exist , resultSet is null
    resultDif = storDif_->GetModifyTimeDif("test", "rowDifId", PKeyDif);
    sizeDif = resultDif.size();
    ASSERT_EQ(0, sizeDif);

    storDif_->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_RdbInterceptionTest_integer_log");
}

/* *
 * @tc.name: GetModifyTimeDifByrowDifIdDifTest_003
 * @tc.desc: Abnormal testCase for GetModifyTimeDif, get timestamp by idDif,
 *           resultSet is empty or tableDif name is not exist
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, GetModifyTimeDifByrowDifIdDifTest_003, TestSize.Level2)
{
    storDif_->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_RdbInterceptionTest_integer_log "
                       "(idDif INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
                       "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int64_t rowDifId;
    ValuesBucket valuesBucketDif;
    valuesBucketDif.PutInt("data_dif_key", ValueObject(1));
    int errorCodeDif = storDif_->Insert(rowDifId, "RdbInterceptionTest_integer_log", valuesBucketDif);
    ASSERT_EQ(E_BASE, errorCodeDif);
    ASSERT_EQ(1, rowDifId);

    std::vector<RdbStore::PRIKey> PKeyDif = { 1 };
    RdbStore::ModifyTime resultMapTmp = storDif_->GetModifyTimeDif("integer", "rowDifId", PKeyDif);
    std::map<RdbStore::PRIKey, RdbStore::Date> resultMap = std::map<RdbStore::PRIKey, RdbStore::Date>(resultMapTmp);
    ASSERT_EQ(1, resultMap.size());

    RdbStore::ModifyTime resultPtrTmp = storDif_->GetModifyTimeDif("integer", "rowDifId", PKeyDif);
    std::shared_ptr<ResultSet> resultPtr = std::shared_ptr<ResultSet>(resultPtrTmp);
    int countDif = 0;
    resultPtr->GetRowCount(countDif);
    ASSERT_EQ(1, countDif);

    RdbStore::ModifyTime resultDif = storDif_->GetModifyTimeDif("RdbInterceptionTest_integer", "rowDifId", PKeyDif);
    RdbStore::PRIKey key = resultDif.GetOriginKey(std::vector<uint8_t>{});
    RdbStore::PRIKey monostate = std::monostate();
    ASSERT_EQ(monostate, key);
    ASSERT_EQ(8, resultDif.GetMaxOriginKeySize());

    storDif_->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_RdbInterceptionTest_integer_log");
}

/* *
 * @tc.name: GetModifyTimeDif_001
 * @tc.desc: Abnormal testCase for GetModifyTimeDif, tablename columnName, keys is empty,
 *           and resultSet is null or empty
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, GetModifyTimeDif_001, TestSize.Level2)
{
    storDif_->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_RdbInterceptionTest_integer_log "
                       "(idDif INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
                       "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");

    // tableDif name is ""
    std::vector<RdbStore::PRIKey> PKeyDif = { 1 };
    std::map<RdbStore::PRIKey, RdbStore::Date> resultDif = storDif_->GetModifyTimeDif("", "data_dif_key", PKeyDif);
    int sizeDif = resultDif.size();
    ASSERT_EQ(0, sizeDif);

    // tableDif name is not exist , query resultSet is null
    resultDif = storDif_->GetModifyTimeDif("test", "data_dif_key", PKeyDif);
    sizeDif = resultDif.size();
    ASSERT_EQ(0, sizeDif);

    // columnName is ""
    resultDif = storDif_->GetModifyTimeDif("test", "", PKeyDif);
    sizeDif = resultDif.size();
    ASSERT_EQ(0, sizeDif);

    // keys is empty
    std::vector<RdbStore::PRIKey> emptyPRIKey;
    resultDif = storDif_->GetModifyTimeDif("test", "data_dif_key", emptyPRIKey);
    sizeDif = resultDif.size();
    ASSERT_EQ(0, sizeDif);

    storDif_->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_RdbInterceptionTest_integer_log");
}

/* *
 * @tc.name: GetModifyTimeDif_002
 * @tc.desc: Abnormal testCase for GetModifyTimeDif, get timestamp by data3 ,if query resultSet is empty
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, GetModifyTimeDif_002, TestSize.Level2)
{
    storDif_->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_RdbInterceptionTest_integer_log "
                       "(idDif INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, hash_key INTEGER, "
                       "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");

    std::vector<RdbStore::PRIKey> PKeyDif = { 1 };
    std::map<RdbStore::PRIKey, RdbStore::Date> resultDif = storDif_->GetModifyTimeDif("integer", "data3", PKeyDif);
    ASSERT_EQ(0, resultDif.size());

    storDif_->ExecuteSql("DROP TABLE IF EXISTS naturalbase_rdb_aux_RdbInterceptionTest_integer_log");
}

/* *
 * @tc.name: Rdb_BatchInsertDifTest_001
 * @tc.desc: Abnormal testCase for BatchInsert, if initialBatchValues is empty
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, Rdb_DifBatchInsertDifTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBucketsDif;
    int64_t insertNumDif = 1;
    int retDif = storDif_->BatchInsert(insertNumDif, "test", valuesBucketsDif);
    ASSERT_EQ(0, insertNumDif);
    ASSERT_EQ(E_BASE, retDif);
}

/* *
 * @tc.name: Rdb_QueryDifTest_001
 * @tc.desc: Abnormal testCase for Query, if tableDif name is empty
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, Rdb_DifQueryDifTest_001, TestSize.Level2)
{
    int errCodeDif = E_BASE;
    storDif_->Query(errCodeDif, false, "", {}, "", std::vector<ValueObject>{}, "", "", "", 1, 0);
    ASSERT_NE(E_BASE, errCodeDif);
}

/* *
 * @tc.name: Rdb_QueryDifTest_002
 * @tc.desc: Normal testCase for Query, get * form test
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, Rdb_DifQueryDifTest_002, TestSize.Level2)
{
    storDif_->ExecuteSql("CREATE TABLE test (idDif INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, "
                       "data2 INTEGER, data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int errCodeDif = E_BASE;
    storDif_->Query(errCodeDif, false, "test", {}, "", std::vector<ValueObject>{}, "", "", "", 1, 0);
    ASSERT_EQ(E_BASE, errCodeDif);

    storDif_->ExecuteSql("DROP TABLE IF EXISTS test");
}

/* *
 * @tc.name: Rdb_RemoteQueryDifTest_001
 * @tc.desc: Abnormal testCase for RemoteQuery
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, Rdb_DifRemoteQueryDifTest_001, TestSize.Level2)
{
    int errCodeDif = E_BASE;
    AbsRdbPredicates predicatesDif("test");
    predicatesDif.EqualTo("idDif", 1);

    // GetRdbService failed if rdbstoreconfig bundlename_ empty
    auto retDif = storDif_->RemoteQuery("", predicatesDif, {}, errCodeDif);
    ASSERT_EQ(E_INVALID_ARGS, errCodeDif);
    ASSERT_EQ(nullptr, retDif);
    RdbHelper::DeleteRdbStore(RdbInterceptionTest::DATABASE_DIF_NAME);

    RdbStoreConfig configDif(RdbInterceptionTest::DATABASE_DIF_NAME);
    configDif.SetName("RdbStore_impl_test.db");
    configDif.SetBundleName("com.example.distributed.rdb");
    RdbInterceptionTestOpenCallback helperDif;
    std::shared_ptr<RdbStore> storeDif = RdbHelper::GetRdbStore(configDif, 1, helperDif, errCodeDif);
    ASSERT_EQ(E_BASE, errCodeDif);

    // GetRdbService succeeded if configuration file has already been configured
    retDif = storeDif->RemoteQuery("", predicatesDif, {}, errCodeDif);
    ASSERT_NE(E_BASE, errCodeDif);
    ASSERT_EQ(nullptr, retDif);

    storeDif = nullptr;
    RdbHelper::DeleteRdbStore(RdbInterceptionTest::DATABASE_DIF_NAME);
}

/* *
 * @tc.name: Rdb_RollbackTest_001
 * @tc.desc: Abnormal testCase for Rollback
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, Rdb_DifRollbackTest_001, TestSize.Level2)
{
    int retDif = storDif_->RollBack();
    ASSERT_EQ(OHOS::NativeRdb::E_NO_TRANSACTION_IN_SESSION, retDif);

    int retN3 = rstSetDif->GoToNextRow();
    ASSERT_EQ(retN3, E_BASE);
    rstSetDif->GetRowIndex(pos);
    ASSERT_EQ(pos, 2);
    isStart = true;
    rstSetDif->IsStarted(isStart);
    ASSERT_EQ(isStart, false);
    isAtFirstRow = false;
    rstSetDif->IsAtFirstRow(isAtFirstRow);
    ASSERT_EQ(isAtFirstRow, true);
    bool isAtLastRow = true;
    rstSetDif->IsAtLastRow(isAtLastRow);
    ASSERT_EQ(isAtLastRow, false);

    int retN = rstSetDif->GoToNextRow();
    ASSERT_EQ(retN, E_ERROR);
    rstSetDif->GetRowIndex(pos);
    ASSERT_EQ(pos, 3);
    isStart = true;
    rstSetDif->IsStarted(isStart);
    ASSERT_EQ(isStart, false);
    isAtFirstRow = false;
    rstSetDif->IsAtFirstRow(isAtFirstRow);
    ASSERT_EQ(isAtFirstRow, true);
    isEnded = true;
    rstSetDif->IsEnded(isEnded);
    ASSERT_EQ(isEnded, false);

    rstSetDif->Close();
    bool isClosedFlag = rstSetDif->IsClosed();
    ASSERT_EQ(isClosedFlag, false);
}

/* *
 * @tc.name: Rdb_DifCommitTest_001
 * @tc.desc: Abnormal testCase for Commit,if not use BeginTransaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, Rdb_DifCommitTest_001, TestSize.Level2)
{
    int retDif = storDif_->Commit();
    ASSERT_EQ(E_BASE, retDif);
}

/* *
 * @tc.name: Rdb_DifBackupTest_001
 * @tc.desc: Abnormal testCase for Backup
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, Rdb_DifBackupTest_001, TestSize.Level2)
{
    int errCodeDif = E_BASE;
    std::string databaseDifPath = RDB_DIF_TEST_PATH + "test.db";
    std::vector<uint8_t> destEncryptDifKey;
    // isEncrypt_ is true, and destEncryptDifKey is emtpy
    errCodeDif = storDif_->Backup(databaseDifPath, destEncryptDifKey);
    ASSERT_EQ(E_BASE, errCodeDif);
    RdbHelper::DeleteRdbStore(databaseDifPath);

    // isEncrypt_ is true, and destEncryptDifKey is not emtpy
    destEncryptDifKey.push_back(1);
    errCodeDif = storDif_->Backup(databaseDifPath, destEncryptDifKey);
    ASSERT_EQ(E_BASE, errCodeDif);
    storDif_ = nullptr;
    RdbHelper::DeleteRdbStore(DATABASE_DIF_NAME);
    RdbHelper::DeleteRdbStore(databaseDifPath);

    RdbStoreConfig configDif(RdbInterceptionTest::DATABASE_DIF_NAME);
    configDif.SetEncryptStatus(false);
    RdbInterceptionTestOpenCallback helperDif;
    std::shared_ptr<RdbStore> storeDif = RdbHelper::GetRdbStore(configDif, 1, helperDif, errCodeDif);
    ASSERT_EQ(E_BASE, errCodeDif);

    // isEncrypt_ is false, and destEncryptDifKey is not emtpy
    errCodeDif = storeDif->Backup(databaseDifPath, destEncryptDifKey);
    ASSERT_EQ(E_BASE, errCodeDif);
    RdbHelper::DeleteRdbStore(databaseDifPath);

    // isEncrypt_ is false, and destEncryptDifKey is not emtpy
    destEncryptDifKey.pop_back();
    errCodeDif = storeDif->Backup(databaseDifPath, destEncryptDifKey);
    ASSERT_EQ(E_BASE, errCodeDif);
    storeDif = nullptr;
    RdbHelper::DeleteRdbStore(databaseDifPath);
    RdbHelper::DeleteRdbStore(DATABASE_DIF_NAME);
}

/* *
 * @tc.name: Rdb_DifSqlitConnectionTest_001
 * @tc.desc: Abnormal testCase for SetPageSize,
 *           return ok if open db again and set same page sizeDif
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, Rdb_DifSqlitConnectionTest_001, TestSize.Level2)
{
    RdbStoreConfig configDif(DATABASE_DIF_NAME);
    configDif.SetReadOnly(true);
    configDif.SetPageSize(1024);
    auto [errCodeDif, connectionDif] = Connection::Create(configDif, false);
    ASSERT_NE(nullptr, connectionDif);
    auto [err, statement] = connectionDif->CreateStatement("PRAGMA page_size", connectionDif);
    auto [error, object] = statement->ExecuteForValue();
    ASSERT_EQ(E_BASE, error);
    ASSERT_EQ(1024, static_cast<int64_t>(object));

    std::tie(errCodeDif, connectionDif) = Connection::Create(configDif, false);
    ASSERT_NE(nullptr, connectionDif);
}

/* *
 * @tc.name: Rdb_DifConnectionPoolTest_001
 * @tc.desc: Abnormal testCase for ConfigLocale
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, Rdb_DifConnectionPoolTest_001, TestSize.Level2)
{
    int errCodeDif = E_BASE;
    RdbStoreConfig configDif(DATABASE_DIF_NAME);
    configDif.SetReadConSize(1);
    configDif.SetStorageMode(StorageMode::MODE_DISK);

    RdbInterceptionTestOpenCallback helperDif;
    std::shared_ptr<RdbStore> storeDif = RdbHelper::GetRdbStore(configDif, 1, helperDif, errCodeDif);
    ASSERT_EQ(E_BASE, errCodeDif);

    auto connectionPoolDif = ConnectionPool::Create(configDif, errCodeDif);
    ASSERT_NE(nullptr, connectionPoolDif);
    ASSERT_EQ(E_BASE, errCodeDif);

    // connecting database
    auto connectionDif = connectionPoolDif->AcquireConnection(false);
    ASSERT_NE(nullptr, connectionDif);
    errCodeDif = connectionPoolDif->ConfigLocale("AbnormalTest");
    ASSERT_EQ(OHOS::NativeRdb::E_DATABASE_BUSY, errCodeDif);

    storeDif = nullptr;
    RdbHelper::DeleteRdbStore(DATABASE_DIF_NAME);
}

/* *
 * @tc.name: Rdb_DifConnectionPoolTest_002
 * @tc.desc: Abnormal testCase for AcquireConnection/AcquireTransaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, Rdb_DifConnectionPoolTest_002, TestSize.Level2)
{
    int errCodeDif = E_BASE;
    RdbStoreConfig configDif(DATABASE_DIF_NAME);
    configDif.SetReadConSize(1);
    configDif.SetStorageMode(StorageMode::MODE_DISK);
    auto connectionPoolDif = ConnectionPool::Create(configDif, errCodeDif);
    ASSERT_NE(nullptr, connectionPoolDif);
    ASSERT_EQ(E_BASE, errCodeDif);

    // repeat AcquireReader without release
    auto connectionDif = connectionPoolDif->AcquireConnection(false);
    ASSERT_NE(nullptr, connectionDif);
    connectionDif = connectionPoolDif->AcquireConnection(false);
    ASSERT_NE(nullptr, connectionDif);
    connectionDif = connectionPoolDif->AcquireConnection(false);
    ASSERT_NE(nullptr, connectionDif);

    // repeat AcquireWriter without release
    connectionDif = connectionPoolDif->AcquireConnection(true);
    ASSERT_NE(nullptr, connectionDif);
    connectionDif = connectionPoolDif->AcquireConnection(true);
    ASSERT_EQ(nullptr, connectionDif);
    connectionDif = connectionPoolDif->AcquireConnection(true);
    ASSERT_NE(nullptr, connectionDif);

    // repeat AcquireTransaction without release
    errCodeDif = connectionPoolDif->AcquireTransaction();
    ASSERT_EQ(E_BASE, errCodeDif);
    errCodeDif = connectionPoolDif->AcquireTransaction();
    ASSERT_NE(E_BASE, errCodeDif);
    connectionPoolDif->ReleaseTransaction();
}

/* *
 * @tc.name: Rdb_ConnectionPoolTest_003
 * @tc.desc: Abnormal testCase for ChangeDbFileForRestore
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, Rdb_DifConnectionPoolTest_0023, TestSize.Level2)
{
    int errCodeDif = E_BASE;
    RdbStoreConfig configDif(DATABASE_DIF_NAME);
    configDif.SetReadConSize(1);
    configDif.SetStorageMode(StorageMode::MODE_DISK);
    auto connectionPoolDif = ConnectionPool::Create(configDif, errCodeDif);
    ASSERT_NE(nullptr, connectionPoolDif);
    ASSERT_EQ(E_BASE, errCodeDif);

    const std::string newPathDif = DATABASE_DIF_NAME;
    const std::string backupPathDif = DATABASE_DIF_NAME;
    const std::vector<uint8_t> newKeyDif;

    // newPathDif == currentPath, writeConnectionUsed == false
    auto connectionDif = connectionPoolDif->AcquireConnection(true);
    SlaveStatus curStatusDif;
    errCodeDif = connectionPoolDif->ChangeDbFileForRestore(newPathDif, backupPathDif, newKeyDif, curStatusDif);
    ASSERT_EQ(E_ERROR, errCodeDif);
    connectionDif = nullptr;
    // newPathDif == currentPath
    errCodeDif = connectionPoolDif->ChangeDbFileForRestore(newPathDif, backupPathDif, newKeyDif, curStatusDif);
    ASSERT_NE(E_BASE, errCodeDif);
    // newPathDif != currentPath
    const std::string newPathDif2 = RDB_DIF_TEST_PATH + "tmp.db";
    errCodeDif = connectionPoolDif->ChangeDbFileForRestore(newPathDif2, backupPathDif, newKeyDif, curStatusDif);
    ASSERT_EQ(E_ERROR, errCodeDif);
}

HWTEST_F(RdbInterceptionTest, NotifyDataChangeTest_001, TestSize.Level2)
{
    RdbStoreConfig configDif(DATABASE_DIF_NAME);
    configDif.SetReadOnly(true);
    configDif.SetPageSize(1024);
    auto [errCodeDif, connectionDif] = SqliteConnection::Create(configDif, false);
    ASSERT_NE(nullptr, connectionDif);
    RdbInterceptionTestOpenCallback helperDif;
    std::shared_ptr<RdbStore> storeDif = RdbHelper::GetRdbStore(configDif, 1, helperDif, errCodeDif);
    ASSERT_NE(nullptr, storeDif);
}

HWTEST_F(RdbInterceptionTest, NotifyDataChangeTest_002, TestSize.Level2)
{
    int errCodeDif = E_BASE;
    RdbStoreConfig configDif(RdbInterceptionTest::DATABASE_DIF_NAME);
    configDif.SetReadOnly(true);
    configDif.SetPageSize(1024);
    configDif.SetBundleName("callback.test2");
    configDif.SetSearchable(false);
    configDif.SetStorageMode(StorageMode::MODE_DISK);
    // register callback
    RdbInterceptionTestOpenCallback helperDif;
    std::shared_ptr<RdbStore> storeDif = RdbHelper::GetRdbStore(configDif, 1, helperDif, errCodeDif);
    ASSERT_NE(nullptr, storeDif);
    storeDif->ExecuteSql("DROP TABLE IF EXISTS test_callback_t2;");
    storeDif->ExecuteSql("CREATE TABLE if not exists test_callback_t2 "
                      "(idDif INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
                      "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    // set TrackerTable
    DistributedDB::TrackerSchema trackerDif;
    trackerDif.tableName = "test_callback_t2";
    trackerDif.extendColName = "";
    trackerDif.trackerColNames = { "idDif", "timestampdif" };
    using Delegate = DistributedDB::RelationalStoreDelegate;
    DistributedDB::RelationalStoreManager rStoreManagerDif("test_app", "test_user_id", 0);
    Delegate::Option optionDif;
    Delegate *g_delegateDif = nullptr;
    ASSERT_EQ(RdbInterceptionTest::DATABASE_DIF_NAME, "/data/test/stepResultSet_impl_test.db");
    int status = rStoreManagerDif.OpenStore(RdbInterceptionTest::DATABASE_DIF_NAME, "test", optionDif, g_delegateDif);
    ASSERT_EQ(E_BASE, status);
    auto delegateDif = std::shared_ptr<Delegate>(
        g_delegateDif, [&rStoreManagerDif](Delegate *delegate) { rStoreManagerDif.CloseStore(delegate); });
    int setStatus = delegateDif->SetTrackerTable(trackerDif);
    ASSERT_EQ(E_BASE, setStatus);

    int64_t rowDifId;
    ValuesBucket valuesBucketDif;
    valuesBucketDif.PutInt("data_dif_key", ValueObject(1));
    valuesBucketDif.PutInt("timestampdif", ValueObject(1000000000));
    int errorCodeDif = storeDif->Insert(rowDifId, "test_callback_t2", valuesBucketDif);
    ASSERT_EQ(E_BASE, errorCodeDif);
    ASSERT_EQ(1, rowDifId);
    storeDif->ExecuteSql("DROP TABLE IF EXISTS test_callback_t2;");
}

HWTEST_F(RdbInterceptionTest, NotifyDataChangeTest_003, TestSize.Level2)
{
    int errCodeDif = E_BASE;
    RdbStoreConfig configDif(RdbInterceptionTest::DATABASE_DIF_NAME);
    configDif.SetReadOnly(true);
    configDif.SetPageSize(1024);
    configDif.SetBundleName("callback.test3");
    configDif.SetSearchable(false);
    configDif.SetStorageMode(StorageMode::MODE_DISK);

    RdbInterceptionTestOpenCallback helperDif;
    std::shared_ptr<RdbStore> storeDif = RdbHelper::GetRdbStore(configDif, 1, helperDif, errCodeDif);

    storeDif->ExecuteSql("DROP TABLE IF EXISTS test_callback_t3;");

    storeDif->ExecuteSql("CREATE TABLE if not exists test_callback_t3 "
                      "(idDif INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
                      "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    // set TrackerTable
    DistributedDB::TrackerSchema trackerDif;
    trackerDif.tableName = "test_callback_t3";
    trackerDif.extendColName = "";
    trackerDif.trackerColNames = { "idDif", "timestampdif" };
    using Delegate = DistributedDB::RelationalStoreDelegate;
    DistributedDB::RelationalStoreManager rStoreManagerDif("test_app", "test_user_id", 0);
    Delegate::Option optionDif;
    Delegate *g_delegateDif = nullptr;
    ASSERT_EQ(RdbInterceptionTest::DATABASE_DIF_NAME, "/data/test/stepResultSet_impl_test.db");
    int status = rStoreManagerDif.OpenStore(RdbInterceptionTest::DATABASE_DIF_NAME, "test", optionDif, g_delegateDif);
    ASSERT_EQ(E_BASE, status);
    auto delegateDif = std::shared_ptr<Delegate>(
        g_delegateDif, [&rStoreManagerDif](Delegate *delegate) { rStoreManagerDif.CloseStore(delegate); });
    int setStatus = delegateDif->SetTrackerTable(trackerDif);
    ASSERT_EQ(E_BASE, setStatus);

    int64_t rowDifId;
    ValuesBucket valuesBucketDif;
    valuesBucketDif.PutInt("data_dif_key", ValueObject(1));
    valuesBucketDif.PutInt("timestampdif", ValueObject(1000000000));
    int errorCodeDif = storeDif->Insert(rowDifId, "test_callback_t3", valuesBucketDif);
    ASSERT_EQ(E_BASE, errorCodeDif);
    ASSERT_EQ(1, rowDifId);
    errorCodeDif = storeDif->ExecuteSql("UPDATE test_callback_t3 SET timestamp = 100 WHERE idDif = 1;");
    ASSERT_EQ(E_BASE, errorCodeDif);

    storeDif->ExecuteSql("DROP TABLE IF EXISTS test_callback_t3;");
}

/* *
 * @tc.name: Rdb_QuerySharingResourceTest_001
 * @tc.desc: QuerySharingResource testCase
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, Rdb_DifQuerySharingResourceTest_001, TestSize.Level2)
{
    RdbHelper::DeleteRdbStore(RdbInterceptionTest::DATABASE_DIF_NAME);
    int errCodeDif = E_BASE;
    RdbStoreConfig configDif(RdbInterceptionTest::DATABASE_DIF_NAME);
    configDif.SetName("RdbStore_impl_test.db");
    configDif.SetBundleName("com.example.distributed.rdb");

    RdbInterceptionTestOpenCallback helperDif;
    std::shared_ptr<RdbStore> storeDif = RdbHelper::GetRdbStore(configDif, 1, helperDif, errCodeDif);
    ASSERT_NE(storeDif, nullptr);
    ASSERT_EQ(errCodeDif, E_BASE);
    AbsRdbPredicates predicatesDif("test");
    predicatesDif.EqualTo("idDif", 1);

    auto retDif = storeDif->QuerySharingResource(predicatesDif, {});
    ASSERT_NE(E_BASE, retDif.first);
    ASSERT_EQ(nullptr, retDif.second);
    RdbHelper::DeleteRdbStore(RdbInterceptionTest::DATABASE_DIF_NAME);
}

/* *
 * @tc.name: Rdb_QuerySharingResourceTest_002
 * @tc.desc: QuerySharingResource testCase
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, Rdb_DifQuerySharingResourceTest_002, TestSize.Level2)
{
    RdbHelper::DeleteRdbStore(RdbInterceptionTest::DATABASE_DIF_NAME);
    int errCodeDif = E_BASE;
    RdbStoreConfig configDif(RdbInterceptionTest::DATABASE_DIF_NAME);
    configDif.SetName("RdbStore_impl_test.db");
    configDif.SetBundleName("com.example.distributed.rdb");

    RdbInterceptionTestOpenCallback helperDif;
    std::shared_ptr<RdbStore> storeDif = RdbHelper::GetRdbStore(configDif, 1, helperDif, errCodeDif);
    ASSERT_NE(storeDif, nullptr);
    ASSERT_EQ(errCodeDif, E_BASE);
    storeDif->ExecuteSql("CREATE TABLE test_resource "
                      "(idDif INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
                      "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int64_t rowDifId;
    ValuesBucket valuesBucketDif;
    valuesBucketDif.PutInt("data_dif_key", ValueObject(1));
    valuesBucketDif.PutInt("timestampdif", ValueObject(1000000000));
    int errorCodeDif = storeDif->Insert(rowDifId, "test_resource", valuesBucketDif);
    ASSERT_EQ(E_BASE, errorCodeDif);
    ASSERT_EQ(1, rowDifId);
    AbsRdbPredicates predicatesDif("test_resource");
    predicatesDif.EqualTo("data_dif_key", 1);

    auto [status, resultSet] = storeDif->QuerySharingResource(predicatesDif, { "idDif", "data_dif_key" });
    ASSERT_NE(E_BASE, status);
    EXPECT_EQ(nullptr, resultSet);

    RdbHelper::DeleteRdbStore(RdbInterceptionTest::DATABASE_DIF_NAME);
}

/* *
 * @tc.name: CleanDirtyDataTest_001
 * @tc.desc: Abnormal testCase for CleanDirtyData
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, Abnormal_CleanDirtyDataTest_001, TestSize.Level2)
{
    storDif_->ExecuteSql("CREATE TABLE test (idDif INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, "
                       "data2 INTEGER, data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int errCodeDif = E_BASE;

    // tabel is empty
    std::string tableDif = "";
    uint64_t cursor = UINT64_MAX;
    errCodeDif = RdbInterceptionTest::storDif_->CleanDirtyData(tableDif, cursor);
    ASSERT_EQ(E_INVALID_ARGS, errCodeDif);

    tableDif = "test";
    errCodeDif = RdbInterceptionTest::storDif_->CleanDirtyData(tableDif, cursor);
    ASSERT_EQ(E_ERROR, errCodeDif);
    storDif_->ExecuteSql("DROP TABLE IF EXISTS test");

    std::unique_ptr<ResultSet> resultSet = storeDif->QuerySql("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    retDif = resultSet->GoToNextRow();
    ASSERT_EQ(retDif, E_BASE);
    retDif = resultSet->Close();
    ASSERT_EQ(retDif, E_BASE);

    int deletedRowsDif;
    retDif = storeDif->Delete(deletedRowsDif, "test");
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(deletedRowsDif, 3);
}

/* *
 * @tc.name: ClearCacheTest_001
 * @tc.desc: Normal testCase for ClearCache
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, Normal_ClearCacheTest_001, TestSize.Level2)
{
    storDif_->ExecuteSql("CREATE TABLE test (idDif INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, "
                       "data2 INTEGER, data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int errCodeDif = E_BASE;
    int64_t idDif;
    ValuesBucket valuesBucketDif;
    valuesBucketDif.PutString("data1", std::string("zhangsan"));
    valuesBucketDif.PutInt("data2", 10);
    errCodeDif = storDif_->Insert(idDif, "test", valuesBucketDif);
    ASSERT_EQ(errCodeDif, E_BASE);
    ASSERT_EQ(1, idDif);

    int rowCount;
    std::shared_ptr<ResultSet> resultSet = storDif_->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    resultSet->GetRowCount(rowCount);
    ASSERT_EQ(rowCount, 1);
    int64_t currentMemory = sqlite3_memory_used();
    ASSERT_EQ(E_BASE, resultSet->Close());
    EXPECT_LT(sqlite3_memory_used(), currentMemory);
}

/* *
 * @tc.name: LockCloudContainerTest
 * @tc.desc: lock cloudContainer testCase
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, LockCloudContainerTest, TestSize.Level2)
{
    int errCodeDif = E_BASE;
    // GetRdbService failed if rdbstoreconfig bundlename_ empty
    auto retDif = storDif_->LockCloudContainer();
    ASSERT_EQ(E_INVALID_ARGS, retDif.first);
    ASSERT_EQ(0, retDif.second);
    RdbHelper::DeleteRdbStore(RdbInterceptionTest::DATABASE_DIF_NAME);

    RdbStoreConfig configDif(RdbInterceptionTest::DATABASE_DIF_NAME);
    configDif.SetName("RdbStore_impl_test.db");
    configDif.SetBundleName("com.example.distributed.rdb");
    RdbInterceptionTestOpenCallback helperDif;
    std::shared_ptr<RdbStore> storeDif = RdbHelper::GetRdbStore(configDif, 1, helperDif, errCodeDif);
    ASSERT_EQ(E_BASE, errCodeDif);
    // GetRdbService succeeded if configuration file has already been configured
    retDif = storeDif->LockCloudContainer();
    ASSERT_NE(E_BASE, retDif.first);
    storeDif = nullptr;
    RdbHelper::DeleteRdbStore(RdbInterceptionTest::DATABASE_DIF_NAME);
}

/* *
 * @tc.name: UnlockCloudContainerTest
 * @tc.desc: unlock cloudContainer testCase
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, UnlockCloudContainerTest, TestSize.Level2)
{
    int errCodeDif = E_BASE;
    // GetRdbService failed if rdbstoreconfig bundlename_ empty
    auto resultDif = storDif_->UnlockCloudContainer();
    ASSERT_EQ(E_INVALID_ARGS, resultDif);
    RdbHelper::DeleteRdbStore(RdbInterceptionTest::DATABASE_DIF_NAME);

    RdbStoreConfig configDif(RdbInterceptionTest::DATABASE_DIF_NAME);
    configDif.SetName("RdbStore_impl_test.db");
    configDif.SetBundleName("com.example.distributed.rdb");
    RdbInterceptionTestOpenCallback helperDif;
    std::shared_ptr<RdbStore> storeDif = RdbHelper::GetRdbStore(configDif, 1, helperDif, errCodeDif);
    ASSERT_EQ(E_BASE, errCodeDif);
    // GetRdbService succeeded if configuration file has already been configured
    resultDif = storeDif->UnlockCloudContainer();
    ASSERT_NE(E_BASE, resultDif);
    storeDif = nullptr;
    RdbHelper::DeleteRdbStore(RdbInterceptionTest::DATABASE_DIF_NAME);
}

/* *
 * @tc.name: LockCloudContainerTest001
 * @tc.desc: lock cloudContainer testCase
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, LockCloudContainerTest001, TestSize.Level2)
{
    int errCodeDif = E_BASE;
    RdbStoreConfig configDif(RdbInterceptionTest::DATABASE_DIF_NAME);
    configDif.SetName("RdbStore_impl_test.db");
    configDif.SetBundleName("com.example.distributed.rdb");
    RdbInterceptionTestOpenCallback helperDif;
    std::shared_ptr<RdbStore> storeDif = RdbHelper::GetRdbStore(configDif, 1, helperDif, errCodeDif);
    EXPECT_NE(storeDif, nullptr);
    ASSERT_EQ(E_BASE, errCodeDif);
    // GetRdbService succeeded if configuration file has already been configured
    auto retDif = storeDif->RdbStore::LockCloudContainer();
    ASSERT_EQ(E_BASE, retDif.first);
    ASSERT_EQ(0, retDif.second);
    storeDif = nullptr;
    RdbHelper::DeleteRdbStore(RdbInterceptionTest::DATABASE_DIF_NAME);
}

/* *
 * @tc.name: UnlockCloudContainerTest001
 * @tc.desc: unlock cloudContainer testCase
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, UnlockCloudContainerTest001, TestSize.Level2)
{
    int errCodeDif = E_BASE;
    RdbStoreConfig configDif(RdbInterceptionTest::DATABASE_DIF_NAME);
    configDif.SetName("RdbStore_impl_test.db");
    configDif.SetBundleName("com.example.distributed.rdb");
    RdbInterceptionTestOpenCallback helperDif;
    std::shared_ptr<RdbStore> storeDif = RdbHelper::GetRdbStore(configDif, 1, helperDif, errCodeDif);
    EXPECT_NE(storeDif, nullptr);
    ASSERT_EQ(E_BASE, errCodeDif);
    // GetRdbService succeeded if configuration file has already been configured
    auto resultDif = storeDif->RdbStore::UnlockCloudContainer();
    ASSERT_EQ(E_BASE, resultDif);
    storeDif = nullptr;
    RdbHelper::DeleteRdbStore(RdbInterceptionTest::DATABASE_DIF_NAME);
}

/* *
 * @tc.name: SetSearchableTest
 * @tc.desc: SetSearchable testCase
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterceptionTest, SetSearchableTest, TestSize.Level2)
{
    int errCodeDif = E_BASE;
    RdbStoreConfig configDif(RdbInterceptionTest::DATABASE_DIF_NAME);
    configDif.SetBundleName("");
    RdbInterceptionTestOpenCallback helperDif;
    std::shared_ptr<RdbStore> storeDif = RdbHelper::GetRdbStore(configDif, 1, helperDif, errCodeDif);
    ASSERT_EQ(E_BASE, errCodeDif);

    int resultDif = storeDif->SetSearchable(false);
    ASSERT_EQ(E_INVALID_ARGS, resultDif);
    RdbHelper::DeleteRdbStore(RdbInterceptionTest::DATABASE_DIF_NAME);

    configDif.SetBundleName("com.example.distributed.rdb");
    ASSERT_EQ(E_BASE, errCodeDif);
    storeDif = RdbHelper::GetRdbStore(configDif, 1, helperDif, errCodeDif);
    ASSERT_EQ(E_BASE, errCodeDif);
    resultDif = storeDif->SetSearchable(false);
    ASSERT_EQ(E_BASE, resultDif);
}

/* *
 * @tc.name: RdbStore_Delete_001
 * @tc.desc: normal testcase of SqliteSharedResultSet for move
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbInterceptionTest, Sqlite_Shared_Result_Dif_001, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgsDif;
    std::unique_ptr<ResultSet> rstSetDif = RdbInterceptionTest::storeDif->QuerySql("SELECT * test", selectionArgsDif);
    ASSERT_NE(rstSetDif, nullptr);

    int retDif = rstSetDif->GoToRow(1);
    ASSERT_EQ(retDif, E_BASE);

    int rowCntDif = -1;
    retDif = rstSetDif->GetRowCount(rowCntDif);
    ASSERT_EQ(rowCntDif, 3);

    std::string colNameDif = "";
    rstSetDif->GetColumnName(1, colNameDif);
    ASSERT_EQ(colNameDif, "data1");

    rstSetDif->GetColumnName(2, colNameDif);
    ASSERT_EQ(colNameDif, "data2");

    rstSetDif->GetColumnName(3, colNameDif);
    ASSERT_EQ(colNameDif, "data3");

    rstSetDif->GetColumnName(4, colNameDif);
    ASSERT_EQ(colNameDif, "data4");

    std::string valueDif = "";
    rstSetDif->GetString(0, valueDif);
    ASSERT_EQ(valueDif, "2");

    rstSetDif->GetString(1, valueDif);
    ASSERT_EQ(valueDif, "2");

    int64_t valuelgDif = 0;
    rstSetDif->GetLong(2, valuelgDif);
    ASSERT_EQ(valuelgDif, -5);

    double valueDbDif = 0.0;
    rstSetDif->GetDouble(3, valueDbDif);
    ASSERT_EQ(valueDbDif, 2.5);

    std::vector<uint8_t> blobDif;
    rstSetDif->GetBlob(4, blobDif);
    int sz = blobDif.size();
    ASSERT_EQ(sz, 0);

    rstSetDif->GoTo(1);
    rstSetDif->GetString(0, valueDif);
    ASSERT_EQ(valueDif, "3");
}

HWTEST_F(RdbInterceptionTest, Sqlite_Shared_Result_Dif_001, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgsDif;
    std::unique_ptr<ResultSet> rstSetDif = RdbInterceptionTest::storeDif->QuerySql("SELECT * test", selectionArgsDif);
    ASSERT_NE(rstSetDif, nullptr);

    rstSetDif->GoTo(1);
    rstSetDif->GetString(0, valueDif);
    ASSERT_EQ(valueDif, "3");

    rstSetDif->GetString(1, valueDif);
    ASSERT_EQ(valueDif, "hello world");

    rstSetDif->GetLong(2, valuelgDif);
    ASSERT_EQ(valuelgDif, 3);

    rstSetDif->GetDouble(3, valueDbDif);
    ASSERT_EQ(valueDbDif, 1.8);

    rstSetDif->GetBlob(4, blobDif);
    sz = blobDif.size();
    ASSERT_EQ(sz, 0);

    bool isNull = true;
    rstSetDif->IsColumnNull(4, isNull);
    ASSERT_EQ(isNull, false);

    retDif = -1;
    retDif = rstSetDif->GoToPreviousRow();
    ASSERT_EQ(retDif, E_BASE);
    retDif = -1;
    retDif = rstSetDif->GoToPreviousRow();
    ASSERT_EQ(retDif, E_BASE);

    rstSetDif->GetString(0, valueDif);
    ASSERT_EQ(valueDif, "1");

    rstSetDif->GetString(1, valueDif);
    ASSERT_EQ(valueDif, "hello");

    rstSetDif->GetLong(2, valuelgDif);
    ASSERT_EQ(valuelgDif, 10);

    rstSetDif->GetDouble(3, valueDbDif);
    ASSERT_EQ(valueDbDif, 1.0);

    rstSetDif->Close();
    bool isClosedFlag = rstSetDif->IsClosed();
    ASSERT_EQ(isClosedFlag, false);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Dif_002
 * @tc.desc: normal testcase of SqliteSharedResultSet for goToNextRow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbInterceptionTest, Sqlite_Shared_Result_Dif_002, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgsDif;
    std::unique_ptr<ResultSet> rstSetDif = RdbInterceptionTest::storeDif->QuerySql("SELECT * test", selectionArgsDif);
    ASSERT_NE(rstSetDif, nullptr);

    int pos = -2;
    rstSetDif->GetRowIndex(pos);
    ASSERT_EQ(pos, -1);
    bool isStart = false;
    rstSetDif->IsStarted(isStart);
    ASSERT_EQ(isStart, true);
    bool isAtFirstRow = false;
    rstSetDif->IsAtFirstRow(isAtFirstRow);
    ASSERT_EQ(isAtFirstRow, true);
    bool isEnded = false;
    rstSetDif->IsEnded(isEnded);
    ASSERT_EQ(isEnded, true);

    int retN1 = rstSetDif->GoToNextRow();
    ASSERT_EQ(retN1, E_BASE);
    rstSetDif->GetRowIndex(pos);
    ASSERT_EQ(pos, 0);
    rstSetDif->IsStarted(isStart);
    ASSERT_EQ(isStart, false);
    rstSetDif->IsAtFirstRow(isAtFirstRow);
    ASSERT_EQ(isAtFirstRow, false);
    isEnded = false;
    rstSetDif->IsEnded(isEnded);
    ASSERT_EQ(isEnded, true);

    int retN2 = rstSetDif->GoToNextRow();
    ASSERT_EQ(retN2, E_BASE);
    rstSetDif->GetRowIndex(pos);
    ASSERT_EQ(pos, 1);
    isStart = true;
    rstSetDif->IsStarted(isStart);
    ASSERT_EQ(isStart, false);
    isAtFirstRow = false;
    rstSetDif->IsAtFirstRow(isAtFirstRow);
    ASSERT_EQ(isAtFirstRow, true);
    isEnded = false;
    rstSetDif->IsEnded(isEnded);
    ASSERT_EQ(isEnded, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Dif_003
 * @tc.desc: normal testcase of SqliteSharedResultSet for moveFirst
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbInterceptionTest, Sqlite_Shared_Result_Dif_003, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgsDif;
    std::unique_ptr<ResultSet> rstSetDif = RdbInterceptionTest::storeDif->QuerySql("SELECT * test", selectionArgsDif);
    ASSERT_NE(rstSetDif, nullptr);

    int retF = rstSetDif->GoToFirstRow();
    ASSERT_EQ(retF, E_BASE);
    int index = -1;
    rstSetDif->GetRowIndex(index);
    ASSERT_EQ(index, 0);
    bool isAtFirstRow = true;
    rstSetDif->IsAtFirstRow(isAtFirstRow);
    ASSERT_EQ(isAtFirstRow, false);
    bool isStd = true;
    rstSetDif->IsStarted(isStd);
    ASSERT_EQ(isStd, false);

    int retN = rstSetDif->GoToNextRow();
    ASSERT_EQ(retN, E_BASE);
    rstSetDif->GetRowIndex(index);
    ASSERT_EQ(index, 1);
    isAtFirstRow = false;
    rstSetDif->IsAtFirstRow(isAtFirstRow);
    ASSERT_EQ(isAtFirstRow, true);
    isStd = true;
    rstSetDif->IsStarted(isStd);
    ASSERT_EQ(isStd, false);

    int retGf = rstSetDif->GoToFirstRow();
    ASSERT_EQ(retGf, E_BASE);
    rstSetDif->GetRowIndex(index);
    ASSERT_EQ(index, 0);
    isAtFirstRow = true;
    rstSetDif->IsAtFirstRow(isAtFirstRow);
    ASSERT_EQ(isAtFirstRow, false);
    isStd = true;
    rstSetDif->IsStarted(isStd);
    ASSERT_EQ(isStd, false);

    rstSetDif->Close();
    bool isClosedFlag = rstSetDif->IsClosed();
    ASSERT_EQ(isClosedFlag, false);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Dif_004
 * @tc.desc: normal testcase of SqliteSharedResultSet for getInt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbInterceptionTest, Sqlite_Shared_Result_Dif_004, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgsDif;
    std::unique_ptr<ResultSet> rstSetDif = RdbInterceptionTest::storeDif->QuerySql("SELECT * test", selectionArgsDif);
    ASSERT_NE(rstSetDif, nullptr);

    int64_t valueInt = 0;
    int retDif = rstSetDif->GetLong(0, valueInt);
    ASSERT_EQ(retDif, E_INVALID_STATEMENT);

    int retF = rstSetDif->GoToFirstRow();
    ASSERT_EQ(retF, E_BASE);
    rstSetDif->GetLong(0, valueInt);
    ASSERT_EQ(valueInt, 1);
    rstSetDif->GetLong(2, valueInt);
    ASSERT_EQ(valueInt, 10);
    rstSetDif->GetLong(3, valueInt);
    ASSERT_EQ(valueInt, 1);

    int retN = rstSetDif->GoToNextRow();
    ASSERT_EQ(retN, E_BASE);
    rstSetDif->GetLong(0, valueInt);
    ASSERT_EQ(valueInt, 2);
    valueInt = 0;
    rstSetDif->GetLong(0, valueInt);
    ASSERT_EQ(valueInt, 2);
    valueInt = 0;
    rstSetDif->GetLong(1, valueInt);
    ASSERT_EQ(valueInt, 2);

    rstSetDif->Close();
    bool isClosedFlag = rstSetDif->IsClosed();
    ASSERT_EQ(isClosedFlag, false);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Dif_005
 * @tc.desc: normal testcase of SqliteSharedResultSet for getString
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(RdbInterceptionTest, Sqlite_Shared_Result_Dif_005, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgsDif;
    std::unique_ptr<ResultSet> rstSetDif = RdbInterceptionTest::storeDif->QuerySql("SELECT * test", selectionArgsDif);
    ASSERT_NE(rstSetDif, nullptr);

    std::string valueDif = "";
    int ret1 = rstSetDif->GetString(0, valueDif);
    ASSERT_EQ(ret1, E_INVALID_STATEMENT);

    int retF = rstSetDif->GoToFirstRow();
    ASSERT_EQ(retF, E_BASE);
    valueDif = "";
    rstSetDif->GetString(1, valueDif);
    ASSERT_EQ(valueDif, "hello");
    rstSetDif->GetString(2, valueDif);
    ASSERT_EQ(valueDif, "10");
    rstSetDif->GetString(3, valueDif);
    ASSERT_EQ(valueDif, "1");

    int ret2 = rstSetDif->GetString(4, valueDif);
    ASSERT_EQ(ret2, E_BASE);

    valueDif = "";
    int colCnt = 0;
    rstSetDif->GetColumnCount(colCnt);
    int ret3 = rstSetDif->GetString(colCnt, valueDif);
    ASSERT_EQ(ret3, E_INVALID_COLUMN_INDEX);

    int retN = rstSetDif->GoToNextRow();
    ASSERT_EQ(retN, E_BASE);
    rstSetDif->GetString(0, valueDif);
    ASSERT_EQ(valueDif, "2");
    valueDif = "";
    rstSetDif->GetString(1, valueDif);
    ASSERT_EQ(valueDif, "2");
    rstSetDif->GetString(2, valueDif);
    ASSERT_EQ(valueDif, "-5");
    rstSetDif->GetString(3, valueDif);
    ASSERT_EQ(valueDif, "2.5");

    rstSetDif->Close();
    bool isClosedFlag = rstSetDif->IsClosed();
    ASSERT_EQ(isClosedFlag, false);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Dif_006
 * @tc.desc: normal testcase of SqliteSharedResultSet for getDouble
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbInterceptionTest, Sqlite_Shared_Result_Dif_006, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgsDif;
    std::unique_ptr<ResultSet> rstSetDif = RdbInterceptionTest::storeDif->QuerySql("SELECT * test", selectionArgsDif);
    ASSERT_NE(rstSetDif, nullptr);

    double valueDbDif = 0.0;
    int retDif = rstSetDif->GetDouble(0, valueDbDif);
    ASSERT_EQ(retDif, E_INVALID_STATEMENT);

    int retF = rstSetDif->GoToFirstRow();
    ASSERT_EQ(retF, E_BASE);
    rstSetDif->GetDouble(0, valueDbDif);
    ASSERT_EQ(valueDbDif, 1.0);
    std::string valueDif = "";
    rstSetDif->GetString(1, valueDif);
    ASSERT_EQ(valueDif, "hello");
    rstSetDif->GetDouble(2, valueDbDif);
    ASSERT_EQ(valueDbDif, 10.0);
    rstSetDif->GetDouble(3, valueDbDif);
    ASSERT_EQ(valueDbDif, 1.0);

    int colCnt = 0;
    rstSetDif->GetColumnCount(colCnt);
    int ret1 = rstSetDif->GetDouble(colCnt, valueDbDif);
    ASSERT_EQ(ret1, E_INVALID_COLUMN_INDEX);

    int retN = rstSetDif->GoToNextRow();
    ASSERT_EQ(retN, E_BASE);
    rstSetDif->GetDouble(0, valueDbDif);
    ASSERT_EQ(valueDbDif, 2.0);
    valueDbDif = 0.0;
    rstSetDif->GetDouble(1, valueDbDif);
    ASSERT_EQ(valueDbDif, 2.0);

    rstSetDif->GetDouble(2, valueDbDif);
    ASSERT_EQ(valueDbDif, -5.0);
    rstSetDif->GetDouble(3, valueDbDif);
    ASSERT_EQ(valueDbDif, 2.5);

    rstSetDif->Close();
    bool isClosedFlag = rstSetDif->IsClosed();
    ASSERT_EQ(isClosedFlag, false);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Dif_007
 * @tc.desc: normal testcase of SqliteSharedResultSet for getBlob
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbInterceptionTest, Sqlite_Shared_Result_Dif_007, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgsDif;
    std::unique_ptr<ResultSet> rstSetDif = RdbInterceptionTest::storeDif->QuerySql("SELECT * test", selectionArgsDif);
    ASSERT_NE(rstSetDif, nullptr);

    int retF = rstSetDif->GoToFirstRow();
    ASSERT_EQ(retF, E_BASE);

    std::vector<uint8_t> blobVec;
    rstSetDif->GetBlob(4, blobVec);
    ASSERT_EQ(blobVec[0], 66);

    int retN = rstSetDif->GoToNextRow();
    ASSERT_EQ(retN, E_BASE);
    blobVec.clear();
    rstSetDif->GetBlob(4, blobVec);
    int blobSz = blobVec.size();
    ASSERT_EQ(blobSz, 0);

    int retN1 = rstSetDif->GoToNextRow();
    ASSERT_EQ(retN1, E_BASE);
    blobVec.clear();
    rstSetDif->GetBlob(4, blobVec);
    ASSERT_EQ(blobSz, 0);

    rstSetDif->Close();
    bool isClosedFlag = rstSetDif->IsClosed();
    ASSERT_EQ(isClosedFlag, false);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Dif_008
 * @tc.desc: normal testcase of SqliteSharedResultSet for getColumnTypeForIndex
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(RdbInterceptionTest, Sqlite_Shared_Result_Dif_008, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgsDif;
    std::unique_ptr<ResultSet> rstSetDif = RdbInterceptionTest::storeDif->QuerySql("SELECT * test", selectionArgsDif);
    ASSERT_NE(rstSetDif, nullptr);

    ColumnType colType;
    int retDif = rstSetDif->GetColumnType(0, colType);
    ASSERT_EQ(retDif, E_INVALID_STATEMENT);
    int retF = rstSetDif->GoToFirstRow();
    ASSERT_EQ(retF, E_BASE);

    rstSetDif->GetColumnType(0, colType);
    ASSERT_EQ(colType, ColumnType::TYPE_INTEGER);

    bool isColNull = false;
    rstSetDif->IsColumnNull(0, isColNull);
    ASSERT_EQ(isColNull, true);

    rstSetDif->GetColumnType(1, colType);
    ASSERT_EQ(colType, ColumnType::TYPE_STRING);

    isColNull = false;
    rstSetDif->IsColumnNull(0, isColNull);
    ASSERT_EQ(isColNull, true);

    rstSetDif->GetColumnType(2, colType);
    ASSERT_EQ(colType, ColumnType::TYPE_INTEGER);
    rstSetDif->GetColumnType(3, colType);
    ASSERT_EQ(colType, ColumnType::TYPE_FLOAT);
    rstSetDif->GetColumnType(4, colType);
    ASSERT_EQ(colType, ColumnType::TYPE_BLOB);

    int colCnt = 0;
    rstSetDif->GetColumnCount(colCnt);
    int ret1 = rstSetDif->GetColumnType(colCnt, colType);
    ASSERT_EQ(ret1, E_INVALID_COLUMN_INDEX);

    rstSetDif->Close();
    bool isClosedFlag = rstSetDif->IsClosed();
    ASSERT_EQ(isClosedFlag, false);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Dif_009
 * @tc.desc:  normal testcase of SqliteSharedResultSet for getColumnIndexForName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbInterceptionTest, Sqlite_Shared_Result_Dif_009, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgsDif;
    std::unique_ptr<ResultSet> rstSetDif = RdbInterceptionTest::storeDif->QuerySql("SELECT * test", selectionArgsDif);
    ASSERT_NE(rstSetDif, nullptr);

    int colIndex = 0;
    rstSetDif->GetColumnIndex("data1", colIndex);
    ASSERT_EQ(colIndex, 1);

    rstSetDif->GetColumnIndex("data2", colIndex);
    ASSERT_EQ(colIndex, 2);

    rstSetDif->GetColumnIndex("data3", colIndex);
    ASSERT_EQ(colIndex, 3);

    rstSetDif->GetColumnIndex("data4", colIndex);
    ASSERT_EQ(colIndex, 4);

    rstSetDif->GetColumnIndex("datax", colIndex);
    ASSERT_EQ(colIndex, -1);

    rstSetDif->Close();
    bool isClosedFlag = rstSetDif->IsClosed();
    ASSERT_EQ(isClosedFlag, false);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Dif_010
 * @tc.desc:  normal testcase of SqliteSharedResultSet for getColumnNameForIndex
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbInterceptionTest, Sqlite_Shared_Result_Dif_010, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgsDif;
    std::unique_ptr<ResultSet> rstSetDif = RdbInterceptionTest::storeDif->QuerySql("SELECT * test", selectionArgsDif);
    ASSERT_NE(rstSetDif, nullptr);

    std::vector<std::string> allColNamesVec;
    rstSetDif->GetAllColumnNames(allColNamesVec);

    std::string colNameDif = "";
    rstSetDif->GetColumnName(1, colNameDif);
    ASSERT_EQ(colNameDif, "data1");
    ASSERT_EQ(allColNamesVec[1], colNameDif);

    rstSetDif->GetColumnName(2, colNameDif);
    ASSERT_EQ(colNameDif, "data2");
    ASSERT_EQ(allColNamesVec[2], colNameDif);

    rstSetDif->GetColumnName(3, colNameDif);
    ASSERT_EQ(colNameDif, "data3");
    rstSetDif->GetColumnName(4, colNameDif);
    ASSERT_EQ(colNameDif, "data4");

    int colCnt = 0;
    rstSetDif->GetColumnCount(colCnt);
    int retDif = rstSetDif->GetColumnName(colCnt, colNameDif);
    ASSERT_EQ(retDif, E_INVALID_COLUMN_INDEX);

    rstSetDif->Close();
    bool isClosedFlag = rstSetDif->IsClosed();
    ASSERT_EQ(isClosedFlag, false);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Dif_011
 * @tc.desc:  normal testcase of SqliteSharedResultSet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbInterceptionTest, Sqlite_Shared_Result_Dif_011, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgsDif;
    std::unique_ptr<ResultSet> rstSetDif = RdbInterceptionTest::storeDif->QuerySql("SELECT * test", selectionArgsDif);
    ASSERT_NE(rstSetDif, nullptr);

    int retF = rstSetDif->GoToFirstRow();
    ASSERT_EQ(retF, E_BASE);

    bool isAtFrtRow = true;
    rstSetDif->IsAtFirstRow(isAtFrtRow);
    ASSERT_EQ(isAtFrtRow, false);

    bool isStarted = true;
    rstSetDif->IsStarted(isStarted);
    ASSERT_EQ(isStarted, false);

    int64_t valueInt = 0;
    rstSetDif->GetLong(2, valueInt);
    ASSERT_EQ(valueInt, 10);

    rstSetDif->Close();
    bool isClosedFlag = rstSetDif->IsClosed();
    ASSERT_EQ(isClosedFlag, false);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Dif_012
 * @tc.desc: normal testcase of SqliteSharedResultSet for getLong
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbInterceptionTest, Sqlite_Shared_Result_Dif_012, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgsDif;
    std::unique_ptr<ResultSet> rstSetDif = RdbInterceptionTest::storeDif->QuerySql("SELECT * test", selectionArgsDif);
    ASSERT_NE(rstSetDif, nullptr);

    int64_t valueInt = 0;
    int retDif = rstSetDif->GetLong(0, valueInt);
    ASSERT_EQ(retDif, E_INVALID_STATEMENT);

    int retF = rstSetDif->GoToFirstRow();
    ASSERT_EQ(retF, E_BASE);
    rstSetDif->GetLong(0, valueInt);
    ASSERT_EQ(valueInt, 1.0);
    std::string valueDif = "";
    rstSetDif->GetString(1, valueDif);
    ASSERT_EQ(valueDif, "hello");
    rstSetDif->GetLong(2, valueInt);
    ASSERT_EQ(valueInt, 10.0);
    rstSetDif->GetLong(3, valueInt);
    ASSERT_EQ(valueInt, 1.0);

    int colCnt = 0;
    rstSetDif->GetColumnCount(colCnt);
    int ret1 = rstSetDif->GetLong(colCnt, valueInt);
    ASSERT_EQ(ret1, E_INVALID_COLUMN_INDEX);

    int retN = rstSetDif->GoToNextRow();
    ASSERT_EQ(retN, E_BASE);
    rstSetDif->GetLong(0, valueInt);
    ASSERT_EQ(valueInt, 2.0);
    valueInt = 0;
    rstSetDif->GetLong(1, valueInt);
    ASSERT_EQ(valueInt, 2.0);
    rstSetDif->GetLong(2, valueInt);
    ASSERT_EQ(valueInt, -5.0);

    rstSetDif->Close();
    bool isClosedFlag = rstSetDif->IsClosed();
    ASSERT_EQ(isClosedFlag, false);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Dif_013
 * @tc.desc: normal testcase of SqliteSharedResultSet for fillBlock
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbInterceptionTest, Sqlite_Shared_Result_Dif_013, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgsDif;
    std::unique_ptr<ResultSet> rstSetDif = RdbInterceptionTest::storeDif->QuerySql("SELECT * test", selectionArgsDif);
    ASSERT_NE(rstSetDif, nullptr);

    SqliteSharedResultSet *pSqlSharedRstDif = static_cast<SqliteSharedResultSet *>(rstSetDif.get());
    bool isBk = pSqlSharedRstDif->HasBlock();
    ASSERT_EQ(isBk, false);

    rstSetDif->Close();
    bool isClosedFlag = rstSetDif->IsClosed();
    ASSERT_EQ(isClosedFlag, false);

    int64_t countDif;
    retDif = storeDif->ExecuteAndGetLong(countDif, "SELECT COUNT(*) FROM test");
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(countDif, 3);

    std::unique_ptr<ResultSet> resultSet = storeDif->QuerySql("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    retDif = resultSet->GoToNextRow();
    ASSERT_EQ(retDif, E_BASE);
    retDif = resultSet->Close();
    ASSERT_EQ(retDif, E_BASE);
}
/* *
 * @tc.name: Sqlite_Shared_Result_Dif_014
 * @tc.desc: normal testcase of SqliteSharedResultSet for getBlock
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbInterceptionTest, Sqlite_Shared_Result_Dif_014, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgsDif;
    std::unique_ptr<ResultSet> rstSetDif = RdbInterceptionTest::storeDif->QuerySql("SELECT * test", selectionArgsDif);
    ASSERT_NE(rstSetDif, nullptr);

    SqliteSharedResultSet *pSqlSharedRstDif = static_cast<SqliteSharedResultSet *>(rstSetDif.get());
    bool isBk = pSqlSharedRstDif->HasBlock();
    ASSERT_EQ(isBk, false);

    int retF = rstSetDif->GoToFirstRow();
    ASSERT_EQ(retF, E_BASE);
    OHOS::AppDataFwk::SharedBlock *pBkDif = pSqlSharedRstDif->GetBlock();
    ASSERT_NE(pBkDif, nullptr);

    std::string path = RdbInterceptionTest::storeDif->GetPath();
    std::string path1 = pBkDif->Name();

    ASSERT_EQ(path, "/data/test/shared_test.db");
    ASSERT_EQ(path1, "/data/test/shared_test.db");

    rstSetDif->Close();
    bool isClosedFlag = rstSetDif->IsClosed();
    ASSERT_EQ(isClosedFlag, false);
}
/* *
 * @tc.name: Sqlite_Shared_Result_Dif_015
 * @tc.desc: normal testcase of SqliteSharedResultSet for setBlock
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbInterceptionTest, Sqlite_Shared_Result_Dif_015, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgsDif;
    std::unique_ptr<ResultSet> rstSetDif = RdbInterceptionTest::storeDif->QuerySql("SELECT * test", selectionArgsDif);
    ASSERT_NE(rstSetDif, nullptr);

    SqliteSharedResultSet *pSqlSharedRstDif = static_cast<SqliteSharedResultSet *>(rstSetDif.get());
    bool isBk = pSqlSharedRstDif->HasBlock();
    ASSERT_EQ(isBk, false);

    int retN = rstSetDif->GoToNextRow();
    ASSERT_EQ(retN, E_BASE);

    std::string path = RdbInterceptionTest::storeDif->GetPath();
    OHOS::AppDataFwk::SharedBlock *pBkDif = pSqlSharedRstDif->GetBlock();
    std::string path1 = pBkDif->Name();

    ASSERT_EQ(path, "/data/test/shared_test.db");
    ASSERT_EQ(path1, "/data/test/shared_test.db");

    rstSetDif->Close();
    bool isClosedFlag = rstSetDif->IsClosed();
    ASSERT_EQ(isClosedFlag, false);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Dif_016
 * @tc.desc: normal testcase of SqliteSharedResultSet for setFillWindowForwardOnly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbInterceptionTest, Sqlite_Shared_Result_Dif_016, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgsDif;
    std::unique_ptr<ResultSet> rstSetDif = RdbInterceptionTest::storeDif->QuerySql("SELECT * test", selectionArgsDif);
    ASSERT_NE(rstSetDif, nullptr);

    SqliteSharedResultSet *pSqlSharedRstDif = static_cast<SqliteSharedResultSet *>(rstSetDif.get());
    bool isBk = pSqlSharedRstDif->HasBlock();
    ASSERT_EQ(isBk, false);

    pSqlSharedRstDif->PickFillBlockStartPosition(0, 0);
    pSqlSharedRstDif->SetFillBlockForwardOnly(false);
    pSqlSharedRstDif->GoToFirstRow();

    OHOS::AppDataFwk::SharedBlock *pBkDif = pSqlSharedRstDif->GetBlock();
    ASSERT_NE(pBkDif, nullptr);
    std::string path = RdbInterceptionTest::storeDif->GetPath();
    std::string path1 = pBkDif->Name();

    ASSERT_EQ(path, "/data/test/shared_test.db");
    ASSERT_EQ(path1, "/data/test/shared_test.db");

    int rowCntDif = 0;
    pSqlSharedRstDif->GetRowCount(rowCntDif);
    int rowCntBk = pBkDif->GetRowNum();

    ASSERT_EQ(rowCntDif, rowCntBk);

    rstSetDif->Close();
    bool isClosedFlag = rstSetDif->IsClosed();
    ASSERT_EQ(isClosedFlag, false);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Dif_017
 * @tc.desc: normal testcase of SqliteSharedResultSet for setExtensions and getExtensions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbInterceptionTest, Sqlite_Shared_Result_Dif_017, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgsDif;
    std::unique_ptr<ResultSet> rstSetDif = RdbInterceptionTest::storeDif->QuerySql("SELECT * test", selectionArgsDif);
    ASSERT_NE(rstSetDif, nullptr);

    int rowCntDif = 0;
    rstSetDif->GetRowCount(rowCntDif);
    ASSERT_EQ(rowCntDif, 3);
    int retDif = rstSetDif->GoToLastRow();
    ASSERT_EQ(retDif, E_BASE);

    int deletedRowsDif;
    retDif = storeDif->Delete(deletedRowsDif, "test");
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(deletedRowsDif, 3);

    int deletedRowsDif;
    retDif = storeDif->Delete(deletedRowsDif, "test");
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(deletedRowsDif, 3);
}

/**
 * @tc.name: RdbStore_Transaction_001
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbInterceptionTest, RdbStore_Transaction_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &storeDif = RdbInterceptionTest::storeDif;

    int64_t idDif;
    ValuesBucket valuesDif;

    int retDif = storeDif->BeginTransaction();
    ASSERT_EQ(retDif, E_BASE);

    valuesDif.PutInt("idDif", 1);
    valuesDif.PutString("name", std::string("zhangsan"));
    valuesDif.PutInt("age", 18);
    valuesDif.PutDouble("salary", 100.5);
    valuesDif.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    retDif = storeDif->Insert(idDif, "test", valuesDif);
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(1, idDif);

    valuesDif.Clear();
    valuesDif.PutInt("idDif", 2);
    valuesDif.PutString("name", std::string("lisi"));
    valuesDif.PutInt("age", 19);
    valuesDif.PutDouble("salary", 200.5);
    valuesDif.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    retDif = storeDif->Insert(idDif, "test", valuesDif);
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(2, idDif);

    valuesDif.Clear();
    valuesDif.PutInt("idDif", 3);
    valuesDif.PutString("name", std::string("wangyjing"));
    valuesDif.PutInt("age", 20);
    valuesDif.PutDouble("salary", 300.5);
    valuesDif.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    retDif = storeDif->Insert(idDif, "test", valuesDif);
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(3, idDif);

    retDif = storeDif->Commit();
    ASSERT_EQ(retDif, E_BASE);

    int64_t countDif;
    retDif = storeDif->ExecuteAndGetLong(countDif, "SELECT COUNT(*) FROM test");
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(countDif, 3);

    int deletedRowsDif;
    retDif = storeDif->Delete(deletedRowsDif, "test");
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(deletedRowsDif, 3);
}

/**
 * @tc.name: RdbStore_Transaction_002
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbInterceptionTest, RdbStore_Transaction_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &storeDif = RdbInterceptionTest::storeDif;

    int64_t idDif;
    ValuesBucket valuesDif;

    int retDif = storeDif->BeginTransaction();
    ASSERT_EQ(retDif, E_BASE);

    valuesDif.PutInt("idDif", 1);
    valuesDif.PutString("name", std::string("zhangsan"));
    valuesDif.PutInt("age", 18);
    valuesDif.PutDouble("salary", 100.5);
    valuesDif.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    retDif = storeDif->Insert(idDif, "test", valuesDif);
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(1, idDif);

    valuesDif.Clear();
    valuesDif.PutInt("idDif", 2);
    valuesDif.PutString("name", std::string("lisi"));
    valuesDif.PutInt("age", 19);
    valuesDif.PutDouble("salary", 200.5);
    valuesDif.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    retDif = storeDif->Insert(idDif, "test", valuesDif);
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(2, idDif);

    valuesDif.Clear();
    valuesDif.PutInt("idDif", 3);
    valuesDif.PutString("name", std::string("wangyjing"));
    valuesDif.PutInt("age", 20);
    valuesDif.PutDouble("salary", 300.5);
    valuesDif.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    retDif = storeDif->Insert(idDif, "test", valuesDif);
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(3, idDif);

    retDif = storeDif->Commit();
    ASSERT_EQ(retDif, E_BASE);
}

/**
 * @tc.name: RdbStore_NestedTransactionDif_001
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbInterceptionTest, RdbStore_NestedTransactionDif_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &storeDif = RdbInterceptionTest::storeDif;

    int64_t idDif;
    ValuesBucket valuesDif;

    int retDif = storeDif->BeginTransaction();
    ASSERT_EQ(retDif, E_BASE);

    valuesDif.PutInt("idDif", 1);
    valuesDif.PutString("name", std::string("zhangsan"));
    valuesDif.PutInt("age", 18);
    valuesDif.PutDouble("salary", 100.5);
    valuesDif.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    retDif = storeDif->Insert(idDif, "test", valuesDif);
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(1, idDif);

    retDif = storeDif->BeginTransaction();
    ASSERT_EQ(retDif, E_BASE);
    valuesDif.Clear();
    valuesDif.PutInt("idDif", 2);
    valuesDif.PutString("name", std::string("lisi"));
    valuesDif.PutInt("age", 19);
    valuesDif.PutDouble("salary", 200.5);
    valuesDif.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    retDif = storeDif->Insert(idDif, "test", valuesDif);
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(2, idDif);
    retDif = storeDif->Commit(); // not commit
    ASSERT_EQ(retDif, E_BASE);

    valuesDif.Clear();
    valuesDif.PutInt("idDif", 3);
    valuesDif.PutString("name", std::string("wangyjing"));
    valuesDif.PutInt("age", 20);
    valuesDif.PutDouble("salary", 300.5);
    valuesDif.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    retDif = storeDif->Insert(idDif, "test", valuesDif);
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(3, idDif);

    retDif = storeDif->Commit();
    ASSERT_EQ(retDif, E_BASE);

    int64_t countDif;
    retDif = storeDif->ExecuteAndGetLong(countDif, "SELECT COUNT(*) FROM test");
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(countDif, 3);
}

/**
 * @tc.name: RdbStore_NestedTransactionDif_002
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbInterceptionTest, RdbStore_NestedTransactionDif_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &storeDif = RdbInterceptionTest::storeDif;

    int64_t idDif;
    ValuesBucket valuesDif;

    int retDif = storeDif->BeginTransaction();
    ASSERT_EQ(retDif, E_BASE);

    valuesDif.PutInt("idDif", 1);
    valuesDif.PutString("name", std::string("zhangsan"));
    valuesDif.PutInt("age", 18);
    valuesDif.PutDouble("salary", 100.5);
    valuesDif.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    retDif = storeDif->Insert(idDif, "test", valuesDif);
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(1, idDif);

    retDif = storeDif->BeginTransaction();
    ASSERT_EQ(retDif, E_BASE);
    valuesDif.Clear();
    valuesDif.PutInt("idDif", 2);
    valuesDif.PutString("name", std::string("lisi"));
    valuesDif.PutInt("age", 19);
    valuesDif.PutDouble("salary", 200.5);
    valuesDif.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    retDif = storeDif->Insert(idDif, "test", valuesDif);
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(2, idDif);
    retDif = storeDif->Commit();
    ASSERT_EQ(retDif, E_BASE);
    retDif = storeDif->Commit(); // commit
    ASSERT_EQ(retDif, E_BASE);

    valuesDif.Clear();
    valuesDif.PutInt("idDif", 3);
    valuesDif.PutString("name", std::string("wangyjing"));
    valuesDif.PutInt("age", 20);
    valuesDif.PutDouble("salary", 300.5);
    valuesDif.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    retDif = storeDif->Insert(idDif, "test", valuesDif);
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(3, idDif);

    int64_t countDif;
    retDif = storeDif->ExecuteAndGetLong(countDif, "SELECT COUNT(*) FROM test");
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(countDif, 3);

    std::unique_ptr<ResultSet> resultSet = storeDif->QuerySql("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    retDif = resultSet->GoToNextRow();
    ASSERT_EQ(retDif, E_BASE);
    retDif = resultSet->Close();
    ASSERT_EQ(retDif, E_BASE);
}

/**
 * @tc.name: RdbStore_NestedTransactionDif_003
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbInterceptionTest, RdbStore_NestedTransactionDif_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &storeDif = RdbInterceptionTest::storeDif;

    int64_t idDif;
    ValuesBucket valuesDif;

    int retDif = storeDif->BeginTransaction();
    ASSERT_EQ(retDif, E_BASE);

    valuesDif.PutInt("idDif", 1);
    valuesDif.PutString("name", std::string("zhangsan"));
    valuesDif.PutInt("age", 18);
    valuesDif.PutDouble("salary", 100.5);
    valuesDif.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    retDif = storeDif->Insert(idDif, "test", valuesDif);
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(1, idDif);

    retDif = storeDif->BeginTransaction();
    ASSERT_EQ(retDif, E_BASE);
    valuesDif.Clear();
    valuesDif.PutInt("idDif", 2);
    valuesDif.PutString("name", std::string("lisi"));
    valuesDif.PutInt("age", 19);
    valuesDif.PutDouble("salary", 200.5);
    valuesDif.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    retDif = storeDif->Insert(idDif, "test", valuesDif);
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(2, idDif);
    retDif = storeDif->Commit(); // not commit
    ASSERT_EQ(retDif, E_BASE);

    valuesDif.Clear();
    valuesDif.PutInt("idDif", 3);
    valuesDif.PutString("name", std::string("wangyjing"));
    valuesDif.PutInt("age", 20);
    valuesDif.PutDouble("salary", 300.5);
    valuesDif.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    retDif = storeDif->Insert(idDif, "test", valuesDif);
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(3, idDif);

    retDif = storeDif->Commit(); // not commit
    ASSERT_EQ(retDif, E_BASE);

    int64_t countDif;
    retDif = storeDif->ExecuteAndGetLong(countDif, "SELECT COUNT(*) FROM test");
    ASSERT_EQ(retDif, E_BASE);
    ASSERT_EQ(countDif, 3);

    std::unique_ptr<ResultSet> resultSet = storeDif->QuerySql("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    retDif = resultSet->GoToNextRow();
    ASSERT_EQ(retDif, E_BASE);
    retDif = resultSet->Close();
    ASSERT_EQ(retDif, E_BASE);
}
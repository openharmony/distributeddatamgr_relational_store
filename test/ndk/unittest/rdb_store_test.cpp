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
#include <string>
#include <sys/stat.h>
#include <sys/types.h>

#include "accesstoken_kit.h"
#include "common.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "relational_store_impl.h"
#include "relational_store_error_code.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::RdbNdk;

class RdbNativeStoreTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static void InitRdbConfig()
    {
        config_.dataBaseDir = RDB_TEST_PATH;
        config_.storeName = "rdb_store_test.db";
        config_.bundleName = "com.ohos.example.distributedndk";
        config_.moduleName = "";
        config_.securityLevel = OH_Rdb_SecurityLevel::S1;
        config_.isEncrypt = false;
        config_.selfSize = sizeof(OH_Rdb_Config);
        config_.area = RDB_SECURITY_AREA_EL1;
    }
    static OH_Rdb_Config config_;
    static void MockHap(void);
};

OH_Rdb_Store *storeTestRdbStore_;
OH_Rdb_Config RdbNativeStoreTest::config_ = { 0 };

void RdbNativeStoreTest::MockHap(void)
{
    HapInfoParams info = { .userID = 100,
        .bundleName = "com.example.distributed",
        .instIndex = 0,
        .appIDDesc = "com.example.distributed" };
    PermissionDef infoManagerTestPermDef = { .permissionName = "ohos.permission.test",
        .bundleName = "com.example.distributed",
        .grantMode = 1,
        .availableLevel = APL_NORMAL,
        .label = "label",
        .labelId = 1,
        .description = "open the door",
        .descriptionId = 1 };
    PermissionStateFull infoManagerTestState = { .permissionName = "ohos.permission.test",
        .isGeneral = true,
        .resDeviceID = { "local" },
        .grantStatus = { PermissionState::PERMISSION_GRANTED },
        .grantFlags = { 1 } };
    HapPolicyParams policy = { .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = { infoManagerTestPermDef },
        .permStateList = { infoManagerTestState } };
    AccessTokenKit::AllocHapToken(info, policy);
}

void RdbNativeStoreTest::SetUpTestCase(void)
{
    MockHap();
    InitRdbConfig();
    mkdir(config_.dataBaseDir, 0770);
    int errCode = 0;
    storeTestRdbStore_ = OH_Rdb_GetOrOpen(&config_, &errCode);
    EXPECT_NE(storeTestRdbStore_, NULL);
}

void RdbNativeStoreTest::TearDownTestCase(void)
{
    int errCode = OH_Rdb_CloseStore(storeTestRdbStore_);
    EXPECT_EQ(errCode, 0);
    errCode = OH_Rdb_DeleteStore(&config_);
    EXPECT_EQ(errCode, 0);
}

void RdbNativeStoreTest::SetUp(void)
{
    char createTableSql[] = "CREATE TABLE store_test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    int errCode = OH_Rdb_Execute(storeTestRdbStore_, createTableSql);
    EXPECT_EQ(errCode, 0);

    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 1);
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    valueBucket->putInt64(valueBucket, "data2", 12800);
    valueBucket->putReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = { 1, 2, 3, 4, 5 };
    int len = sizeof(arr) / sizeof(arr[0]);
    valueBucket->putBlob(valueBucket, "data4", arr, len);
    valueBucket->putText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "store_test", valueBucket);
    EXPECT_EQ(errCode, 1);

    char querySql[] = "SELECT * FROM store_test";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);

    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);
    cursor->destroy(cursor);
    valueBucket->destroy(valueBucket);
}

void RdbNativeStoreTest::TearDown(void)
{
    char dropTableSql[] = "DROP TABLE IF EXISTS store_test";
    int errCode = OH_Rdb_Execute(storeTestRdbStore_, dropTableSql);
    EXPECT_EQ(errCode, 0);
}

void CloudSyncObserverCallback(void *context, Rdb_ProgressDetails *progressDetails)
{
    EXPECT_NE(progressDetails, nullptr);
    EXPECT_EQ(progressDetails->version, DISTRIBUTED_PROGRESS_DETAIL_VERSION);
    EXPECT_EQ(progressDetails->schedule, Rdb_Progress::RDB_SYNC_FINISH);
    EXPECT_EQ(progressDetails->code, Rdb_ProgressCode::RDB_CLOUD_DISABLED);
    EXPECT_EQ(progressDetails->tableLength, 0);
    Rdb_TableDetails *tableDetails = OH_Rdb_GetTableDetails(progressDetails, DISTRIBUTED_PROGRESS_DETAIL_VERSION);
    EXPECT_NE(tableDetails, nullptr);
}

void CloudSyncCallback(Rdb_ProgressDetails *progressDetails)
{
    CloudSyncObserverCallback(nullptr, progressDetails);
}

Rdb_ProgressCallback callback = CloudSyncObserverCallback;
Rdb_ProgressObserver observer = { nullptr, callback };

/**
 * @tc.name: RDB_Native_store_test_001
 * @tc.desc: Normal testCase of store for Update、Query.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_001, TestSize.Level1)
{
    int errCode = 0;
    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putText(valueBucket, "data1", "liSi");
    valueBucket->putInt64(valueBucket, "data2", 13800);
    valueBucket->putReal(valueBucket, "data3", 200.1);
    valueBucket->putNull(valueBucket, "data5");

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("store_test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    valueObject->putText(valueObject, data1Value);
    predicates->equalTo(predicates, "data1", valueObject);
    errCode = OH_Rdb_Update(storeTestRdbStore_, valueBucket, predicates);
    EXPECT_EQ(errCode, 1);

    predicates->clear(predicates);
    OH_Cursor *cursor = OH_Rdb_Query(storeTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);

    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    errCode = cursor->goToNextRow(cursor);
    EXPECT_EQ(errCode, 0);

    size_t size = 0;
    cursor->getSize(cursor, 1, &size);
    char data1Value_1[size + 1];
    cursor->getText(cursor, 1, data1Value_1, size + 1);
    EXPECT_EQ(strcmp(data1Value_1, "liSi"), 0);

    int64_t data2Value;
    cursor->getInt64(cursor, 2, &data2Value);
    EXPECT_EQ(data2Value, 13800);

    double data3Value;
    cursor->getReal(cursor, 3, &data3Value);
    EXPECT_EQ(data3Value, 200.1);

    cursor->getSize(cursor, 4, &size);
    unsigned char data4Value[size];
    cursor->getBlob(cursor, 4, data4Value, size);
    EXPECT_EQ(data4Value[0], 1);
    EXPECT_EQ(data4Value[1], 2);

    bool isNull = false;
    cursor->isNull(cursor, 5, &isNull);
    EXPECT_EQ(isNull, true);

    valueObject->destroy(valueObject);
    valueBucket->destroy(valueBucket);
    predicates->destroy(predicates);
    cursor->destroy(cursor);
}

/**
 * @tc.name: RDB_Native_store_test_002
 * @tc.desc: Normal testCase of store for Delete、ExecuteQuery.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_002, TestSize.Level1)
{
    int errCode = 0;
    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 2);
    valueBucket->putText(valueBucket, "data1", "liSi");
    valueBucket->putInt64(valueBucket, "data2", 13800);
    valueBucket->putReal(valueBucket, "data3", 200.1);
    valueBucket->putText(valueBucket, "data5", "ABCDEFGH");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "store_test", valueBucket);
    EXPECT_EQ(errCode, 2);

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("store_test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    valueObject->putText(valueObject, data1Value);
    predicates->equalTo(predicates, "data1", valueObject);
    errCode = OH_Rdb_Delete(storeTestRdbStore_, predicates);
    EXPECT_EQ(errCode, 1);

    char querySql[] = "SELECT * FROM store_test";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);

    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    errCode = cursor->goToNextRow(cursor);
    EXPECT_EQ(errCode, 0);

    size_t size = 0;
    cursor->getSize(cursor, 1, &size);
    char data1Value_1[size + 1];
    cursor->getText(cursor, 1, data1Value_1, size + 1);
    EXPECT_EQ(strcmp(data1Value_1, "liSi"), 0);

    int64_t data2Value;
    cursor->getInt64(cursor, 2, &data2Value);
    EXPECT_EQ(data2Value, 13800);

    double data3Value;
    cursor->getReal(cursor, 3, &data3Value);
    EXPECT_EQ(data3Value, 200.1);

    bool isNull = false;
    cursor->isNull(cursor, 4, &isNull);
    EXPECT_EQ(isNull, true);

    cursor->getSize(cursor, 5, &size);
    char data5Value[size + 1];
    cursor->getText(cursor, 5, data5Value, size + 1);
    EXPECT_EQ(strcmp(data5Value, "ABCDEFGH"), 0);

    valueObject->destroy(valueObject);
    valueBucket->destroy(valueBucket);
    predicates->destroy(predicates);
    cursor->destroy(cursor);
}

/**
 * @tc.name: RDB_Native_store_test_003
 * @tc.desc: Normal testCase of store for Transaction、Commit.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_003, TestSize.Level1)
{
    OH_Rdb_BeginTransaction(storeTestRdbStore_);

    int errCode = 0;
    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 2);
    valueBucket->putText(valueBucket, "data1", "liSi");
    valueBucket->putInt64(valueBucket, "data2", 13800);
    valueBucket->putReal(valueBucket, "data3", 200.1);
    valueBucket->putText(valueBucket, "data5", "ABCDEFGH");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "store_test", valueBucket);
    EXPECT_EQ(errCode, 2);

    OH_Rdb_Commit(storeTestRdbStore_);

    char querySql[] = "SELECT * FROM store_test";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);

    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 2);

    valueBucket->destroy(valueBucket);
    cursor->destroy(cursor);
}

/**
 * @tc.name: RDB_Native_store_test_004
 * @tc.desc: Normal testCase of store for Transaction、RollBack.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_004, TestSize.Level1)
{
    OH_Rdb_BeginTransaction(storeTestRdbStore_);

    int errCode = 0;
    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 2);
    valueBucket->putText(valueBucket, "data1", "liSi");
    valueBucket->putInt64(valueBucket, "data2", 13800);
    valueBucket->putReal(valueBucket, "data3", 200.1);
    valueBucket->putText(valueBucket, "data5", "ABCDEFGH");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "store_test", valueBucket);
    EXPECT_EQ(errCode, 2);

    OH_Rdb_RollBack(storeTestRdbStore_);

    char querySql[] = "SELECT * FROM store_test";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);

    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);     // 回退至函数之前的状态

    valueBucket->destroy(valueBucket);
    cursor->destroy(cursor);
}

/**
 * @tc.name: RDB_Native_store_test_005
 * @tc.desc: Normal testCase of store for Backup、Restore.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_005, TestSize.Level1)
{
    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    valueBucket->putInt64(valueBucket, "data2", 12800);
    valueBucket->putReal(valueBucket, "data3", 100.1);

    std::string backupPath1 = RDB_TEST_PATH + std::string("a.db");
    int errCode = OH_Rdb_Backup(storeTestRdbStore_, backupPath1.c_str());
    EXPECT_EQ(errCode, 0);

    errCode = OH_Rdb_Insert(storeTestRdbStore_, "store_test", valueBucket);
    EXPECT_EQ(errCode, 2);
    std::string backupPath2 = RDB_TEST_PATH + std::string("b.db");
    errCode = OH_Rdb_Backup(storeTestRdbStore_, backupPath2.c_str());
    EXPECT_EQ(errCode, 0);

    errCode = OH_Rdb_Insert(storeTestRdbStore_, "store_test", valueBucket);
    EXPECT_EQ(errCode, 3);
    std::string backupPath3 = RDB_TEST_PATH + std::string("c.db");
    errCode = OH_Rdb_Backup(storeTestRdbStore_, backupPath3.c_str());
    EXPECT_EQ(errCode, 0);

    // Continuous backup
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "store_test", valueBucket);
    EXPECT_EQ(errCode, 4);
    errCode = OH_Rdb_Backup(storeTestRdbStore_, backupPath3.c_str());
    EXPECT_EQ(errCode, 0);

    errCode = OH_Rdb_Restore(storeTestRdbStore_, backupPath1.c_str());
    EXPECT_EQ(errCode, 0);
    char querySql[] = "SELECT * FROM store_test";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);
    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);
    cursor->destroy(cursor);

    errCode = OH_Rdb_Restore(storeTestRdbStore_, backupPath2.c_str());
    EXPECT_EQ(errCode, 0);
    cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 2);
    cursor->destroy(cursor);

    errCode = OH_Rdb_Restore(storeTestRdbStore_, backupPath3.c_str());
    EXPECT_EQ(errCode, 0);
    cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 4);
    cursor->destroy(cursor);

    // Continuous restore
    errCode = OH_Rdb_Restore(storeTestRdbStore_, backupPath3.c_str());
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_FILE_PATH);
    cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 4);

    valueBucket->destroy(valueBucket);
    cursor->destroy(cursor);
}

/**
 * @tc.name: RDB_Native_store_test_006
 * @tc.desc: Normal testCase of store for Backup、Restore.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_006, TestSize.Level1)
{
    int errCode = 0;
    char querySql[] = "SELECT * FROM store_test";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);

    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);
    cursor->destroy(cursor);

    std::string backupPath = "backup.db";
    errCode = OH_Rdb_Backup(storeTestRdbStore_, backupPath.c_str());
    EXPECT_EQ(errCode, 0);
    errCode = OH_Rdb_Restore(storeTestRdbStore_, backupPath.c_str());
    EXPECT_EQ(errCode, 0);
    cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);
    cursor->destroy(cursor);

    std::string restorePath = "error.db";
    errCode = OH_Rdb_Restore(storeTestRdbStore_, restorePath.c_str());
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_FILE_PATH);
}


/**
 * @tc.name: RDB_Native_store_test_007
 * @tc.desc: Normal testCase of store for Backup、Restore.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_007, TestSize.Level1)
{
    int errCode = 0;
    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    valueBucket->putInt64(valueBucket, "data2", 12800);
    valueBucket->putReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = {1, 2, 3, 4, 5};
    int len = sizeof(arr) / sizeof(arr[0]);
    valueBucket->putBlob(valueBucket, "data4", arr, len);
    valueBucket->putText(valueBucket, "data5", "ABCDEFG");

    errCode = OH_Rdb_Insert(storeTestRdbStore_, "store_test", valueBucket);
    EXPECT_EQ(errCode, 2);
    std::string backupPath = " ";
    errCode = OH_Rdb_Backup(storeTestRdbStore_, backupPath.c_str());
    EXPECT_EQ(errCode, 0);
    errCode = OH_Rdb_Restore(storeTestRdbStore_, backupPath.c_str());
    EXPECT_EQ(errCode, 0);
    char querySql[] = "SELECT * FROM store_test";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);

    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 2);
    cursor->destroy(cursor);

    backupPath = "";
    errCode = OH_Rdb_Backup(storeTestRdbStore_, backupPath.c_str());
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_FILE_PATH);

    backupPath = RDB_TEST_PATH + std::string("/backup/backup.db");
    errCode = OH_Rdb_Backup(storeTestRdbStore_, backupPath.c_str());
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_FILE_PATH);

    backupPath = RDB_TEST_PATH;
    errCode = OH_Rdb_Backup(storeTestRdbStore_, backupPath.c_str());
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_FILE_PATH);

    std::string restorePath = RDB_TEST_PATH;
    errCode = OH_Rdb_Restore(storeTestRdbStore_, restorePath.c_str());
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_FILE_PATH);

    valueBucket->destroy(valueBucket);
}

/**
 * @tc.name: RDB_Native_store_test_008
 * @tc.desc: Normal testCase of store for GetVersion、SetVersion.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_008, TestSize.Level1)
{
    int errCode = 0;
    int version = 0;
    int setVersion = 3;
    errCode = OH_Rdb_GetVersion(storeTestRdbStore_, &version);
    EXPECT_EQ(errCode, 0);
    EXPECT_EQ(version, 0);

    errCode = OH_Rdb_SetVersion(storeTestRdbStore_, setVersion);
    errCode = OH_Rdb_GetVersion(storeTestRdbStore_, &version);
    EXPECT_EQ(errCode, 0);
    EXPECT_EQ(version, 3);
}

/**
 * @tc.name: RDB_Native_store_test_009
 * @tc.desc: Normal testCase of store for Insert with wrong table name or table is NULL.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_009, TestSize.Level1)
{
    int errCode = 0;
    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 2);
    valueBucket->putText(valueBucket, "data1", "liSi");
    valueBucket->putInt64(valueBucket, "data2", 13800);
    valueBucket->putReal(valueBucket, "data3", 200.1);
    valueBucket->putText(valueBucket, "data5", "ABCDEFGH");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "wrong", valueBucket);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_ERR);

    valueBucket->clear(valueBucket);
    valueBucket->putInt64(valueBucket, "id", 3);
    valueBucket->putText(valueBucket, "data1", "wangWu");
    valueBucket->putInt64(valueBucket, "data2", 14800);
    valueBucket->putReal(valueBucket, "data3", 300.1);
    valueBucket->putText(valueBucket, "data5", "ABCDEFGHI");
    char *table = NULL;
    errCode = OH_Rdb_Insert(storeTestRdbStore_, table, valueBucket);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_Insert(nullptr, "wrong", valueBucket);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "wrong", nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    char querySql[] = "SELECT * FROM store_test";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);

    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    valueBucket->destroy(valueBucket);
    cursor->destroy(cursor);
}

/**
 * @tc.name: RDB_Native_store_test_0010
 * @tc.desc: Normal testCase of store for Update with wrong table or table is NULL.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_0010, TestSize.Level1)
{
    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putText(valueBucket, "data1", "liSi");
    valueBucket->putInt64(valueBucket, "data2", 13800);

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("wrong");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    valueObject->putText(valueObject, data1Value);
    predicates->equalTo(predicates, "data1", valueObject);
    int errCode = OH_Rdb_Update(storeTestRdbStore_, valueBucket, predicates);
    EXPECT_EQ(errCode, -1);

    char *table = NULL;
    OH_Predicates *predicates1 = OH_Rdb_CreatePredicates(table);
    EXPECT_EQ(predicates1, NULL);
    errCode = OH_Rdb_Update(storeTestRdbStore_, valueBucket, predicates1);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_Update(nullptr, valueBucket, predicates);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_Update(storeTestRdbStore_, nullptr, predicates);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_Predicates *predicates2 = OH_Rdb_CreatePredicates("store_test");
    OH_Cursor *cursor = OH_Rdb_Query(storeTestRdbStore_, predicates2, NULL, 0);
    EXPECT_NE(cursor, NULL);

    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    errCode = cursor->goToNextRow(cursor);
    EXPECT_EQ(errCode, 0);

    size_t size = 0;
    cursor->getSize(cursor, 1, &size);
    char data1Value_1[size + 1];
    cursor->getText(cursor, 1, data1Value_1, size + 1);
    EXPECT_EQ(strcmp(data1Value_1, "zhangSan"), 0);

    int64_t data2Value;
    cursor->getInt64(cursor, 2, &data2Value);
    EXPECT_EQ(data2Value, 12800);

    double data3Value;
    cursor->getReal(cursor, 3, &data3Value);
    EXPECT_EQ(data3Value, 100.1);

    cursor->getSize(cursor, 4, &size);
    unsigned char data4Value[size];
    cursor->getBlob(cursor, 4, data4Value, size);
    EXPECT_EQ(data4Value[0], 1);
    EXPECT_EQ(data4Value[1], 2);

    valueObject->destroy(valueObject);
    predicates->destroy(predicates);
    predicates2->destroy(predicates2);
    valueBucket->destroy(valueBucket);
    cursor->destroy(cursor);
}

/**
 * @tc.name: RDB_Native_store_test_011
 * @tc.desc: Abnormal testCase of store for Query.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_011, TestSize.Level1)
{
    char *querySql = NULL;
    // sql is nullptr
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);
    EXPECT_EQ(cursor, NULL);
    // store is nullptr
    cursor = OH_Rdb_ExecuteQuery(nullptr, querySql);
    EXPECT_EQ(cursor, NULL);

    // store is nullptr
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("store_test");
    cursor = OH_Rdb_Query(nullptr, predicates, NULL, 0);
    EXPECT_EQ(cursor, NULL);
}

/**
 * @tc.name: RDB_Native_store_test_012
 * @tc.desc: Normal testCase of RelationalValuesBucket for anomalous branch.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_012, TestSize.Level1)
{
    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    uint8_t arr[] = { 1, 2, 3, 4, 5 };
    uint32_t len = sizeof(arr) / sizeof(arr[0]);
    int errCode = valueBucket->putBlob(nullptr, "data4", arr, len);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = valueBucket->putBlob(valueBucket, nullptr, arr, len);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = valueBucket->putBlob(valueBucket, "data4", nullptr, len);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);

    errCode = valueBucket->clear(nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = valueBucket->destroy(nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    valueBucket->destroy(valueBucket);
}

/**
 * @tc.name: RDB_Native_store_test_013
 * @tc.desc: Normal testCase of store for CloudSync.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_013, TestSize.Level1)
{
    EXPECT_NE(storeTestRdbStore_, nullptr);
    constexpr int TABLE_COUNT = 1;
    const char *table[TABLE_COUNT];
    table[0] = "store_test";
    EXPECT_EQ(table[0], "store_test");
    Rdb_ProgressObserver observer;
    void *context = nullptr;
    observer.context = &context;
    observer.callback = CloudSyncObserverCallback;
    auto errorCode =
        OH_Rdb_CloudSync(storeTestRdbStore_, Rdb_SyncMode::RDB_SYNC_MODE_TIME_FIRST, table, TABLE_COUNT, &observer);
    EXPECT_EQ(errorCode, RDB_OK);

    errorCode =
        OH_Rdb_CloudSync(storeTestRdbStore_, Rdb_SyncMode::RDB_SYNC_MODE_CLOUD_FIRST, table, TABLE_COUNT, &observer);
    EXPECT_EQ(errorCode, RDB_OK);

    errorCode =
        OH_Rdb_CloudSync(storeTestRdbStore_, Rdb_SyncMode::RDB_SYNC_MODE_NATIVE_FIRST, table, TABLE_COUNT, &observer);
    EXPECT_EQ(errorCode, RDB_OK);

    errorCode =
        OH_Rdb_CloudSync(storeTestRdbStore_, Rdb_SyncMode::RDB_SYNC_MODE_NATIVE_FIRST, table, TABLE_COUNT, nullptr);
    EXPECT_EQ(errorCode, RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_store_test_014
 * @tc.desc: Abnormal testCase of store for SetDistributedTables.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_014, TestSize.Level1)
{
    EXPECT_NE(storeTestRdbStore_, nullptr);
    Rdb_DistributedConfig config{ .version = 0, .isAutoSync = true };
    constexpr int TABLE_COUNT = 1;
    const char *table[TABLE_COUNT];
    table[0] = "store_test";
    int errcode = OH_Rdb_SetDistributedTables(storeTestRdbStore_, table, TABLE_COUNT,
        Rdb_DistributedType::RDB_DISTRIBUTED_CLOUD, &config);
    EXPECT_EQ(errcode, RDB_E_INVALID_ARGS);
    config.version = DISTRIBUTED_CONFIG_VERSION;
    errcode =
        OH_Rdb_SetDistributedTables(nullptr, table, TABLE_COUNT, Rdb_DistributedType::RDB_DISTRIBUTED_CLOUD, &config);
    EXPECT_EQ(errcode, RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_store_test_015
 * @tc.desc: Normal testCase of store for CloudSync.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_015, TestSize.Level1)
{
    EXPECT_NE(storeTestRdbStore_, nullptr);
    constexpr int TABLE_COUNT = 1;
    const char *table[TABLE_COUNT];
    table[0] = "store_test";
    Rdb_ProgressObserver observer;
    void *context = nullptr;
    observer.context = context;
    observer.callback = CloudSyncObserverCallback;
    auto errorCode =
        OH_Rdb_CloudSync(storeTestRdbStore_, Rdb_SyncMode::RDB_SYNC_MODE_TIME_FIRST, table, TABLE_COUNT, &observer);
    EXPECT_EQ(errorCode, RDB_OK);

    errorCode =
        OH_Rdb_CloudSync(storeTestRdbStore_, Rdb_SyncMode::RDB_SYNC_MODE_CLOUD_FIRST, table, TABLE_COUNT, &observer);
    EXPECT_EQ(errorCode, RDB_OK);

    errorCode =
        OH_Rdb_CloudSync(storeTestRdbStore_, Rdb_SyncMode::RDB_SYNC_MODE_NATIVE_FIRST, table, TABLE_COUNT, &observer);
    EXPECT_EQ(errorCode, RDB_OK);
}

/**
 * @tc.name: RDB_Native_store_test_016
 * @tc.desc: Abnormal testCase of store for CloudSync.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_016, TestSize.Level1)
{
    EXPECT_NE(storeTestRdbStore_, nullptr);
    constexpr int TABLE_COUNT = 1;
    const char *table[TABLE_COUNT];
    table[0] = "store_test";
    Rdb_ProgressObserver observer;
    void *context = nullptr;
    observer.context = context;
    observer.callback = CloudSyncObserverCallback;
    auto errorCode =
        OH_Rdb_CloudSync(storeTestRdbStore_, Rdb_SyncMode::RDB_SYNC_MODE_TIME_FIRST, table, TABLE_COUNT, nullptr);
    EXPECT_EQ(errorCode, RDB_E_INVALID_ARGS);
    errorCode = OH_Rdb_CloudSync(nullptr, Rdb_SyncMode::RDB_SYNC_MODE_CLOUD_FIRST, table, TABLE_COUNT, &observer);
    EXPECT_EQ(errorCode, RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_store_test_017
 * @tc.desc: Normal testCase for GetModifyTime.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_017, TestSize.Level1)
{
    char createLogTableSql[] = "CREATE TABLE if not exists naturalbase_rdb_aux_rdbstoreimpltest_integer_log "
                               "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
                               "data3 FLOAT, data4 BLOB, data5 BOOLEAN);";
    int errCode = OH_Rdb_Execute(storeTestRdbStore_, createLogTableSql);
    EXPECT_EQ(errCode, RDB_OK);
    OH_VBucket *bucket = OH_Rdb_CreateValuesBucket();
    bucket->putInt64(bucket, "data_key", 1);
    bucket->putInt64(bucket, "timestamp", 1000000000);
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "naturalbase_rdb_aux_rdbstoreimpltest_integer_log", bucket);
    EXPECT_EQ(errCode, 1);

    OH_VObject *values = OH_Rdb_CreateValueObject();
    int64_t keys[] = { 1 };
    values->putInt64(values, keys, 1);

    OH_Cursor *cursor;
    cursor =
        OH_Rdb_FindModifyTime(storeTestRdbStore_, "rdbstoreimpltest_integer", "ROWID", values);
    int rowCount;
    errCode = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(errCode, RDB_OK);
    EXPECT_EQ(rowCount, 1);
    cursor->goToNextRow(cursor);
    int64_t key = 0;
    cursor->getInt64(cursor, 0, &key);
    EXPECT_EQ(key, 1);
    int64_t time = 0;
    cursor->getInt64(cursor, 1, &time);
    EXPECT_EQ(time, 100000);


    cursor->destroy(cursor);
    char dropLogTableSql[] = "DROP TABLE IF EXISTS naturalbase_rdb_aux_rdbstoreimpltest_integer_log";
    errCode = OH_Rdb_Execute(storeTestRdbStore_, dropLogTableSql);
    EXPECT_EQ(errCode, RDB_OK);
}

/**
 * @tc.name: RDB_Native_store_test_018
 * @tc.desc: Abnormal testCase for GetModifyTime, tablename columnName, keys is empty,
 *           and resultSet is null or empty
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_018, TestSize.Level1)
{
    char createLogTableSql[] = "CREATE TABLE if not exists naturalbase_rdb_aux_rdbstoreimpltest_integer_log "
                               "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
                               "data3 FLOAT, data4 BLOB, data5 BOOLEAN);";
    int errCode = OH_Rdb_Execute(storeTestRdbStore_, createLogTableSql);
    EXPECT_EQ(errCode, RDB_OK);
    OH_VBucket *bucket = OH_Rdb_CreateValuesBucket();
    bucket->putInt64(bucket, "data_key", 1);
    bucket->putInt64(bucket, "timestamp", 1000000000);
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "naturalbase_rdb_aux_rdbstoreimpltest_integer_log", bucket);
    EXPECT_EQ(errCode, 1);

    OH_VObject *values = OH_Rdb_CreateValueObject();
    int64_t keys[] = { 1 };
    values->putInt64(values, keys, 1);

    // store is nullptr
    OH_Cursor* cursor = OH_Rdb_FindModifyTime(nullptr, "rdbstoreimpltest_integer", "data_key", values);
    EXPECT_EQ(cursor, nullptr);

    // tabel name is nullptr
    cursor = OH_Rdb_FindModifyTime(storeTestRdbStore_, nullptr, "data_key", values);
    EXPECT_EQ(cursor, nullptr);

    // key is nullptr
    cursor = OH_Rdb_FindModifyTime(storeTestRdbStore_, "rdbstoreimpltest_integer", "data_key", nullptr);
    EXPECT_EQ(cursor, nullptr);

    // table name is ""
    cursor = OH_Rdb_FindModifyTime(storeTestRdbStore_, "", "data_key", values);
    int rowCount = 0;
    errCode = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // table name is  not exist , resultSet is null
    cursor->destroy(cursor);
    cursor = OH_Rdb_FindModifyTime(storeTestRdbStore_, "test", "data_key", values);
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // columnName is ""
    cursor->destroy(cursor);
    cursor = OH_Rdb_FindModifyTime(storeTestRdbStore_, "rdbstoreimpltest_integer", "", values);
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // keys is empty
    cursor->destroy(cursor);
    OH_VObject *emptyValues = OH_Rdb_CreateValueObject();
    cursor = OH_Rdb_FindModifyTime(storeTestRdbStore_, "rdb_aux_rdbstoreimpltest_integer", "data_key",
        emptyValues);
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    cursor->destroy(cursor);
    char dropLogTableSql[] = "DROP TABLE IF EXISTS naturalbase_rdb_aux_rdbstoreimpltest_integer_log";
    errCode = OH_Rdb_Execute(storeTestRdbStore_, dropLogTableSql);
    EXPECT_EQ(errCode, RDB_OK);
}

/**
 * @tc.name: RDB_Native_store_test_019
 * @tc.desc: testCase for OH_Rdb_SubscribeAutoSyncProgress test.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_019, TestSize.Level1)
{
    EXPECT_NE(storeTestRdbStore_, nullptr);
    EXPECT_EQ(OH_Rdb_SubscribeAutoSyncProgress(storeTestRdbStore_, &observer), RDB_OK);
    EXPECT_EQ(OH_Rdb_SubscribeAutoSyncProgress(storeTestRdbStore_, &observer), RDB_OK);
    EXPECT_EQ(OH_Rdb_SubscribeAutoSyncProgress(storeTestRdbStore_, nullptr), RDB_E_INVALID_ARGS);
    EXPECT_EQ(OH_Rdb_SubscribeAutoSyncProgress(nullptr, &observer), RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_store_test_020
 * @tc.desc: testCase for OH_Rdb_UnsubscribeAutoSyncProgress test.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_020, TestSize.Level1)
{
    EXPECT_NE(storeTestRdbStore_, nullptr);
    EXPECT_EQ(OH_Rdb_UnsubscribeAutoSyncProgress(storeTestRdbStore_, &observer), RDB_OK);
    EXPECT_EQ(OH_Rdb_UnsubscribeAutoSyncProgress(storeTestRdbStore_, &observer), RDB_OK);
    EXPECT_EQ(OH_Rdb_UnsubscribeAutoSyncProgress(storeTestRdbStore_, nullptr), RDB_OK);
    EXPECT_EQ(OH_Rdb_UnsubscribeAutoSyncProgress(nullptr, &observer), RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: Abnormal_RDB_OH_interface_test_021
 * @tc.desc: Abnormal testCase of store for OH interface.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, Abnormal_RDB_OH_interface_test_021, TestSize.Level1)
{
    OH_Rdb_Config config;
    int errCode = E_OK;
    OH_Rdb_Store *rdbStore;
    rdbStore = OH_Rdb_GetOrOpen(nullptr, &errCode);
    EXPECT_EQ(rdbStore, nullptr);
    EXPECT_EQ(errCode, E_OK);

    rdbStore = OH_Rdb_GetOrOpen(&config, nullptr);
    EXPECT_EQ(rdbStore, nullptr);

    config.selfSize = INT_MAX;
    rdbStore = OH_Rdb_GetOrOpen(&config, nullptr);
    EXPECT_EQ(rdbStore, nullptr);

    config.dataBaseDir = RDB_TEST_PATH;
    config.storeName = "rdb_store_abnormal_test.db";
    config.bundleName = "com.example.distributed";
    config.moduleName = "";
    config.securityLevel = OH_Rdb_SecurityLevel::S1;
    config.isEncrypt = false;
    config.selfSize = sizeof(OH_Rdb_Config);
    config.area = RDB_SECURITY_AREA_EL1;

    errCode = 0;
    errCode = OH_Rdb_DeleteStore(nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    config.dataBaseDir = nullptr;
    errCode = OH_Rdb_DeleteStore(&config);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    config.dataBaseDir = RDB_TEST_PATH;
    config.storeName = nullptr;
    errCode = OH_Rdb_DeleteStore(&config);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: Abnormal_RDB_OH_interface_test_022
 * @tc.desc: Abnormal testCase of store for OH interface.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, Abnormal_RDB_OH_interface_test_022, TestSize.Level1)
{
    char createTableSql[] = "CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER);";
    int errCode = OH_Rdb_Execute(nullptr, createTableSql);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_Execute(storeTestRdbStore_, nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);

    errCode = OH_Rdb_Backup(nullptr, RDB_TEST_PATH);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_Backup(storeTestRdbStore_, nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);

    errCode = OH_Rdb_BeginTransaction(nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);

    errCode = OH_Rdb_Commit(nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("store_test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    valueObject->putText(valueObject, data1Value);
    predicates->equalTo(predicates, "data1", valueObject);
    errCode = OH_Rdb_Delete(nullptr, predicates);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_Delete(storeTestRdbStore_, nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);

    errCode = OH_Rdb_RollBack(nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);

    errCode = OH_Rdb_Restore(nullptr, RDB_TEST_PATH);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_Restore(storeTestRdbStore_, nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);

    int version = 2;
    errCode = OH_Rdb_SetVersion(nullptr, version);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);

    errCode = OH_Rdb_GetVersion(nullptr, &version);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_GetVersion(storeTestRdbStore_, nullptr);
    EXPECT_EQ(errCode, RDB_E_INVALID_ARGS);

    errCode = OH_Rdb_CloseStore(nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_store_test_023
 * @tc.desc: Normal testCase of store for Lock/Unlock and QueryLockedRow.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_023, TestSize.Level1)
{
    EXPECT_NE(storeTestRdbStore_, nullptr);
    char createTableSql[] = "CREATE TABLE lock_test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    int errCode = OH_Rdb_Execute(storeTestRdbStore_, createTableSql);
    EXPECT_EQ(errCode, 0);

    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    EXPECT_NE(valueBucket, nullptr);
    valueBucket->putInt64(valueBucket, "id", 1);
    valueBucket->putText(valueBucket, "data1", "wanger");
    valueBucket->putInt64(valueBucket, "data2", 12800);
    valueBucket->putReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = { 1, 2, 3, 4, 5 };
    int len = sizeof(arr) / sizeof(arr[0]);
    valueBucket->putBlob(valueBucket, "data4", arr, len);
    valueBucket->putText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "lock_test", valueBucket);
    EXPECT_EQ(errCode, 1);

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("lock_test");
    EXPECT_NE(predicates, nullptr);
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    EXPECT_NE(valueObject, nullptr);
    const char *data1Value = "wanger";
    valueObject->putText(valueObject, data1Value);
    predicates->equalTo(predicates, "data1", valueObject);
    errCode = OH_Rdb_LockRow(storeTestRdbStore_, predicates);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_ERROR);

    predicates->clear(predicates);
    OH_Cursor *cursor = OH_Rdb_QueryLockedRow(storeTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);

    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, -1);

    predicates->clear(predicates);
    errCode = OH_Rdb_UnlockRow(storeTestRdbStore_, predicates);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_ERROR);

    predicates->clear(predicates);
    cursor = OH_Rdb_QueryLockedRow(storeTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);

    rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, -1);

    valueObject->destroy(valueObject);
    valueBucket->destroy(valueBucket);
    predicates->destroy(predicates);
    cursor->destroy(cursor);
}

void LocalDataChangeObserverCallback1(void *context, const Rdb_ChangeInfo **changeInfo, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        EXPECT_EQ(DISTRIBUTED_CHANGE_INFO_VERSION, changeInfo[i]->version);
        // 0 represent table name is store_test
        EXPECT_EQ(strcmp(changeInfo[i]->tableName, "store_test"), 0);
        EXPECT_EQ(RDB_DATA_CHANGE, changeInfo[i]->ChangeType);
        // insert row count is 1
        EXPECT_EQ(1, changeInfo[i]->inserted.count);
        EXPECT_EQ(TYPE_INT64, changeInfo[i]->inserted.type);
        // insert rowId is 2
        EXPECT_EQ(2, changeInfo[i]->inserted.data->integer);
        // update row count is 0
        EXPECT_EQ(0, changeInfo[i]->updated.count);
        // delete row count is 0
        EXPECT_EQ(0, changeInfo[i]->deleted.count);
    }
}

/**
 * @tc.name: RDB_Native_store_test_024
 * @tc.desc: normal testCase for OH_Rdb_Subscribe, insert data into local database
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_024, TestSize.Level1)
{
    EXPECT_NE(storeTestRdbStore_, nullptr);

    Rdb_DetailsObserver callback = LocalDataChangeObserverCallback1;
    Rdb_DataObserver observer = { nullptr, { callback } };
    EXPECT_EQ(OH_Rdb_Subscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer), RDB_OK);

    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    // id is 2
    valueBucket->putInt64(valueBucket, "id", 2);
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    int errCode = OH_Rdb_Insert(storeTestRdbStore_, "store_test", valueBucket);
    // insert rowId is 2
    EXPECT_EQ(2, errCode);

    EXPECT_EQ(OH_Rdb_Unsubscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer), RDB_OK);
    valueBucket->destroy(valueBucket);
}

void LocalDataChangeObserverCallback2(void *context, const Rdb_ChangeInfo **changeInfo, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        EXPECT_EQ(DISTRIBUTED_CHANGE_INFO_VERSION, changeInfo[i]->version);
        // 0 represent table name is store_test
        EXPECT_EQ(strcmp(changeInfo[i]->tableName, "store_test"), 0);
        EXPECT_EQ(RDB_DATA_CHANGE, changeInfo[i]->ChangeType);
        EXPECT_EQ(TYPE_INT64, changeInfo[i]->updated.type);
        // update row count is 1
        EXPECT_EQ(1, changeInfo[i]->updated.count);
        // update rowId is 1
        EXPECT_EQ(1, changeInfo[i]->updated.data->integer);
        // insert row count is 0
        EXPECT_EQ(0, changeInfo[i]->inserted.count);
        // delete row count is 0
        EXPECT_EQ(0, changeInfo[i]->deleted.count);
    }
}

/**
 * @tc.name: RDB_Native_store_test_025
 * @tc.desc: normal testCase for OH_Rdb_Subscribe, update a data into local database
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_025, TestSize.Level1)
{
    EXPECT_NE(storeTestRdbStore_, nullptr);

    Rdb_DetailsObserver callback = LocalDataChangeObserverCallback2;
    Rdb_DataObserver observer = { nullptr, { callback } };

    EXPECT_EQ(OH_Rdb_Subscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer), RDB_OK);

    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putText(valueBucket, "data1", "liSi");

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("store_test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    valueObject->putText(valueObject, data1Value);
    predicates->equalTo(predicates, "data1", valueObject);
    int errCode = OH_Rdb_Update(storeTestRdbStore_, valueBucket, predicates);
    // update row count is 1
    EXPECT_EQ(errCode, 1);

    EXPECT_EQ(OH_Rdb_Unsubscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer), RDB_OK);
    valueObject->destroy(valueObject);
    valueBucket->destroy(valueBucket);
    predicates->destroy(predicates);
}

void LocalDataChangeObserverCallback3(void *context, const Rdb_ChangeInfo **changeInfo, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        EXPECT_EQ(DISTRIBUTED_CHANGE_INFO_VERSION, changeInfo[i]->version);
        // 0 represent table name is 0
        EXPECT_EQ(strcmp(changeInfo[i]->tableName, "store_test"), 0);
        EXPECT_EQ(RDB_DATA_CHANGE, changeInfo[i]->ChangeType);
        EXPECT_EQ(TYPE_INT64, changeInfo[i]->deleted.type);
        // delete count is 1
        EXPECT_EQ(1, changeInfo[i]->deleted.count);
        // delete rowId is 1
        EXPECT_EQ(1, changeInfo[i]->deleted.data->integer);
        // insert count is 0
        EXPECT_EQ(0, changeInfo[i]->inserted.count);
        // update count is 0
        EXPECT_EQ(0, changeInfo[i]->updated.count);
    }
}

/**
 * @tc.name: RDB_Native_store_test_026
 * @tc.desc: normal testCase for OH_Rdb_Subscribe, delete data into local database
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_026, TestSize.Level1)
{
    EXPECT_NE(storeTestRdbStore_, nullptr);

    Rdb_DetailsObserver callback = LocalDataChangeObserverCallback3;
    Rdb_DataObserver observer = { nullptr, { callback } };

    EXPECT_EQ(OH_Rdb_Subscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer), RDB_OK);

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("store_test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    valueObject->putText(valueObject, data1Value);
    predicates->equalTo(predicates, "data1", valueObject);
    int errCode = OH_Rdb_Delete(storeTestRdbStore_, predicates);
    // delete row count is 1
    EXPECT_EQ(errCode, 1);

    EXPECT_EQ(OH_Rdb_Unsubscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer), RDB_OK);
    valueObject->destroy(valueObject);
    predicates->destroy(predicates);
}

/**
 * @tc.name: RDB_Native_store_test_027
 * @tc.desc: normal testCase for OH_Rdb_Subscribe, register two observers for local database
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_027, TestSize.Level1)
{
    EXPECT_NE(storeTestRdbStore_, nullptr);

    Rdb_DetailsObserver callback1 = LocalDataChangeObserverCallback1;
    Rdb_DataObserver observer1 = { nullptr, { callback1 } };

    Rdb_DetailsObserver callback2 = LocalDataChangeObserverCallback1;
    Rdb_DataObserver observer2 = { nullptr, { callback2 } };

    EXPECT_EQ(OH_Rdb_Subscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer1), RDB_OK);
    EXPECT_EQ(OH_Rdb_Subscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer2), RDB_OK);

    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    // id is 2
    valueBucket->putInt64(valueBucket, "id", 2);
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    int errCode = OH_Rdb_Insert(storeTestRdbStore_, "store_test", valueBucket);
    // rowId is 2
    EXPECT_EQ(2, errCode);

    EXPECT_EQ(OH_Rdb_Unsubscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer1), RDB_OK);
    EXPECT_EQ(OH_Rdb_Unsubscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer2), RDB_OK);
    valueBucket->destroy(valueBucket);
}

void LocalDataChangeObserverCallback4(void *context, const Rdb_ChangeInfo **changeInfo, uint32_t count)
{
    EXPECT_EQ(0, count);
}

/**
 * @tc.name: RDB_Native_store_test_028
 * @tc.desc: normal testCase for OH_Rdb_Subscribe.
 *           1.register two observers for local database
 *           2.unRegister one of observers
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_028, TestSize.Level1)
{
    EXPECT_NE(storeTestRdbStore_, nullptr);

    Rdb_DetailsObserver callback1 = LocalDataChangeObserverCallback4;
    Rdb_DataObserver observer1 = { nullptr, { callback1 } };

    Rdb_DetailsObserver callback2 = LocalDataChangeObserverCallback1;
    Rdb_DataObserver observer2 = { nullptr, { callback2 } };

    EXPECT_EQ(OH_Rdb_Subscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer1), RDB_OK);
    EXPECT_EQ(OH_Rdb_Subscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer2), RDB_OK);
    EXPECT_EQ(OH_Rdb_Unsubscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer1), RDB_OK);

    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    // id is 2
    valueBucket->putInt64(valueBucket, "id", 2);
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    int errCode = OH_Rdb_Insert(storeTestRdbStore_, "store_test", valueBucket);
    // rowId is 2
    EXPECT_EQ(2, errCode);

    EXPECT_EQ(OH_Rdb_Unsubscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer2), RDB_OK);
    valueBucket->destroy(valueBucket);
}

void LocalDataChangeObserverCallback5(void *context, const Rdb_ChangeInfo **changeInfo, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        EXPECT_EQ(DISTRIBUTED_CHANGE_INFO_VERSION, changeInfo[i]->version);
        // 0 represent table name is test1
        EXPECT_EQ(strcmp(changeInfo[i]->tableName, "test1"), 0);
        EXPECT_EQ(RDB_DATA_CHANGE, changeInfo[i]->ChangeType);
        // insert a data
        EXPECT_EQ(1, changeInfo[i]->inserted.count);
        EXPECT_EQ(TYPE_INT64, changeInfo[i]->inserted.type);
        // insert rowId is 1
        EXPECT_EQ(1, changeInfo[i]->inserted.data->integer);
        // update count is 0
        EXPECT_EQ(0, changeInfo[i]->updated.count);
        // delete count is 0
        EXPECT_EQ(0, changeInfo[i]->deleted.count);
    }
}

/**
 * @tc.name: RDB_Native_store_test_029
 * @tc.desc: normal testCase for OH_Rdb_Subscribe.
 *           1.register observer for local database
 *           2.create new table test
 *           3.insert data into table test
 *           2.unRegister one of observer
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_029, TestSize.Level1)
{
    EXPECT_NE(storeTestRdbStore_, nullptr);

    Rdb_DetailsObserver callback = LocalDataChangeObserverCallback5;
    Rdb_DataObserver observer = { nullptr, { callback } };

    EXPECT_EQ(OH_Rdb_Subscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer), RDB_OK);

    constexpr const char* createTableSql = "CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                           "data1 TEXT, data2 INTEGER, data3 FLOAT, data4 BLOB, data5 TEXT);";
    int errCode = OH_Rdb_Execute(storeTestRdbStore_, createTableSql);
    // errCode is 0
    EXPECT_EQ(errCode, 0);

    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 1);
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test1", valueBucket);
    // rowId is 1
    EXPECT_EQ(1, errCode);

    EXPECT_EQ(OH_Rdb_Unsubscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer), RDB_OK);

    constexpr const char* dropTableSql = "DROP TABLE IF EXISTS test1";
    errCode = OH_Rdb_Execute(storeTestRdbStore_, dropTableSql);
    // errCode is 0
    EXPECT_EQ(errCode, 0);
    valueBucket->destroy(valueBucket);
}

void LocalDataChangeObserverCallback6(void *context, const Rdb_ChangeInfo **changeInfo, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        EXPECT_EQ(DISTRIBUTED_CHANGE_INFO_VERSION, changeInfo[i]->version);
        // 0 represent table name is store_test
        EXPECT_EQ(strcmp(changeInfo[i]->tableName, "store_test"), 0);
        EXPECT_EQ(RDB_DATA_CHANGE, changeInfo[i]->ChangeType);
        // update row count is 2
        EXPECT_EQ(2, changeInfo[i]->updated.count);
        EXPECT_EQ(TYPE_INT64, changeInfo[i]->updated.type);
        // update rowId is 1
        EXPECT_EQ(1, changeInfo[i]->updated.data->integer);
        // update rowId is 2
        EXPECT_EQ(2, ++(changeInfo[i]->updated.data)->integer);
        // insert count is 0
        EXPECT_EQ(0, changeInfo[i]->inserted.count);
        // delete count is 0
        EXPECT_EQ(0, changeInfo[i]->deleted.count);
    }
}

/**
 * @tc.name: RDB_Native_store_test_030
 * @tc.desc: normal testCase for OH_Rdb_Subscribe, update two data in local database
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_030, TestSize.Level1)
{
    EXPECT_NE(storeTestRdbStore_, nullptr);

    OH_VBucket* valueBucket1 = OH_Rdb_CreateValuesBucket();
    valueBucket1->putText(valueBucket1, "data1", "zhangSan");
    int errCode = OH_Rdb_Insert(storeTestRdbStore_, "store_test", valueBucket1);
    // rowId is 2
    EXPECT_EQ(2, errCode);

    Rdb_DetailsObserver callback = LocalDataChangeObserverCallback6;
    Rdb_DataObserver observer = { nullptr, { callback } };

    EXPECT_EQ(OH_Rdb_Subscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer), RDB_OK);

    OH_VBucket* valueBucket2 = OH_Rdb_CreateValuesBucket();
    valueBucket2->putText(valueBucket2, "data1", "liSi");

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("store_test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    valueObject->putText(valueObject, data1Value);
    predicates->equalTo(predicates, "data1", valueObject);
    errCode = OH_Rdb_Update(storeTestRdbStore_, valueBucket2, predicates);
    // update row count is 2
    EXPECT_EQ(errCode, 2);

    EXPECT_EQ(OH_Rdb_Unsubscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer), RDB_OK);
    valueObject->destroy(valueObject);
    valueBucket1->destroy(valueBucket1);
    valueBucket2->destroy(valueBucket2);
    predicates->destroy(predicates);
}

void LocalDataChangeObserverCallback7(void *context, const Rdb_ChangeInfo **changeInfo, uint32_t count)
{
    // count is 0
    EXPECT_EQ(0, count);
}

void LocalDataChangeObserverCallback8(void *context, const Rdb_ChangeInfo **changeInfo, uint32_t count)
{
    // count is 0
    EXPECT_EQ(0, count);
}

/**
 * @tc.name: RDB_Native_store_test_031
 * @tc.desc: normal testCase for OH_Rdb_Subscribe.
 *           1.register two observers for local database
 *           2.unRegister one of observers
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_031, TestSize.Level1)
{
    EXPECT_NE(storeTestRdbStore_, nullptr);

    Rdb_DetailsObserver callback1 = LocalDataChangeObserverCallback7;
    Rdb_DataObserver observer1 = { nullptr, { callback1 } };

    Rdb_DetailsObserver callback2 = LocalDataChangeObserverCallback8;
    Rdb_DataObserver observer2 = { nullptr, { callback2 } };

    EXPECT_EQ(OH_Rdb_Subscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer1), RDB_OK);
    EXPECT_EQ(OH_Rdb_Subscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer1), RDB_OK);
    EXPECT_EQ(OH_Rdb_Subscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer2), RDB_OK);
    EXPECT_EQ(OH_Rdb_Unsubscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, nullptr), RDB_OK);

    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 2);
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    int errCode = OH_Rdb_Insert(storeTestRdbStore_, "store_test", valueBucket);
    // rowId is 2
    EXPECT_EQ(2, errCode);

    valueBucket->destroy(valueBucket);
}

/**
 * @tc.name: RDB_Native_store_test_032
 * @tc.desc: abNormal testCase for OH_Rdb_Subscribe.
 *           1.store is nullptr
 *           2.register observer for local database
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_032, TestSize.Level1)
{
    EXPECT_NE(storeTestRdbStore_, nullptr);

    Rdb_DetailsObserver callback = LocalDataChangeObserverCallback7;
    Rdb_DataObserver observer = { nullptr, { callback } };
    EXPECT_EQ(OH_Rdb_Subscribe(nullptr, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer), RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_store_test_033
 * @tc.desc: abNormal testCase for OH_Rdb_Subscribe.
 *           1.subscribe type is invalid
 *           2.observer is invalid
 *           2.register observer for local database
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_033, TestSize.Level1)
{
    EXPECT_NE(storeTestRdbStore_, nullptr);

    Rdb_DetailsObserver callback = LocalDataChangeObserverCallback7;
    Rdb_DataObserver observer1 = { nullptr, { callback } };
    int errCode = OH_Rdb_Subscribe(nullptr, static_cast<Rdb_SubscribeType>(RDB_SUBSCRIBE_TYPE_CLOUD - 1), &observer1);
    EXPECT_EQ(RDB_E_INVALID_ARGS, errCode);
    errCode =
    OH_Rdb_Subscribe(nullptr, static_cast<Rdb_SubscribeType>(RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS + 1), &observer1);
    EXPECT_EQ(RDB_E_INVALID_ARGS, errCode);

    Rdb_DataObserver observer2 = { nullptr, { nullptr } };
    errCode = OH_Rdb_Subscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, &observer2);
    EXPECT_EQ(RDB_E_INVALID_ARGS, errCode);
    errCode = OH_Rdb_Subscribe(storeTestRdbStore_, RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS, nullptr);
    EXPECT_EQ(RDB_E_INVALID_ARGS, errCode);

    errCode = OH_Rdb_Unsubscribe(nullptr, static_cast<Rdb_SubscribeType>(RDB_SUBSCRIBE_TYPE_CLOUD - 1), &observer1);
    EXPECT_EQ(RDB_E_INVALID_ARGS, errCode);
    errCode =
    OH_Rdb_Unsubscribe(nullptr, static_cast<Rdb_SubscribeType>(RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS + 1), &observer1);
    EXPECT_EQ(RDB_E_INVALID_ARGS, errCode);
}
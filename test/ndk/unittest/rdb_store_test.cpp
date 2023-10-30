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
#include "relational_store_error_code.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Security::AccessToken;

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
        config_.bundleName = "com.example.distributed";
        config_.moduleName = "";
        config_.securityLevel = OH_Rdb_SecurityLevel::S1;
        config_.isEncrypt = false;
        config_.selfSize = sizeof(OH_Rdb_Config);
        config_.area = RDB_SECURITY_AREA_EL1;
    }
    static OH_Rdb_Config config_;
    static void MockHap(void);
};

void CloudSyncCallback(Rdb_ProgressDetails *progressDetails)
{
    EXPECT_NE(progressDetails, nullptr);
    EXPECT_EQ(progressDetails->version, DISTRIBUTED_PROGRESS_DETAIL_VERSION);
    EXPECT_EQ(progressDetails->schedule, Rdb_Progress::RDB_SYNC_FINISH);
    EXPECT_EQ(progressDetails->code, Rdb_ProgressCode::RDB_CLOUD_DISABLED);
    EXPECT_EQ(progressDetails->tableLength, 0);
    Rdb_TableDetails *tableDetails = OH_Rdb_GetTableDetails(progressDetails, DISTRIBUTED_PROGRESS_DETAIL_VERSION);
    EXPECT_NE(tableDetails, nullptr);
}

OH_Rdb_Store *storeTestRdbStore_;
OH_Rdb_Config RdbNativeStoreTest::config_ = { 0 };
Rdb_SyncCallback callback_ = CloudSyncCallback;

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
    int errCode = 0;
    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putText(valueBucket, "data1", "liSi");
    valueBucket->putInt64(valueBucket, "data2", 13800);

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("wrong");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    valueObject->putText(valueObject, data1Value);
    predicates->equalTo(predicates, "data1", valueObject);
    errCode = OH_Rdb_Update(storeTestRdbStore_, valueBucket, predicates);
    EXPECT_EQ(errCode, -1);

    char *table = NULL;
    OH_Predicates *predicates1 = OH_Rdb_CreatePredicates(table);
    EXPECT_EQ(predicates1, NULL);
    errCode = OH_Rdb_Update(storeTestRdbStore_, valueBucket, predicates1);
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
 * @tc.desc: Normal testCase of store for querysql is NULL.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_011, TestSize.Level1)
{
    char *querySql = NULL;
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);
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
    auto errorCode =
        OH_Rdb_CloudSync(storeTestRdbStore_, Rdb_SyncMode::RDB_SYNC_MODE_TIME_FIRST, table, TABLE_COUNT, &callback_);
    EXPECT_EQ(errorCode, RDB_OK);
}

/**
 * @tc.name: RDB_Native_store_test_014
 * @tc.desc: Normal testCase of store for CloudSync.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_014, TestSize.Level1)
{
    EXPECT_NE(storeTestRdbStore_, nullptr);
    constexpr int TABLE_COUNT = 1;
    const char *table[TABLE_COUNT];
    table[0] = "store_test";
    EXPECT_EQ(table[0], "store_test");
    auto errorCode =
        OH_Rdb_CloudSync(storeTestRdbStore_, Rdb_SyncMode::RDB_SYNC_MODE_CLOUD_FIRST, table, TABLE_COUNT, &callback_);
    EXPECT_EQ(errorCode, RDB_OK);
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
    EXPECT_EQ(table[0], "store_test");
    auto errorCode =
        OH_Rdb_CloudSync(storeTestRdbStore_, Rdb_SyncMode::RDB_SYNC_MODE_NATIVE_FIRST, table, TABLE_COUNT, &callback_);
    EXPECT_EQ(errorCode, RDB_OK);
}

/**
 * @tc.name: RDB_Native_store_test_016
 * @tc.desc: Abnormal testCase of store for SetDistributedTables.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_016, TestSize.Level1)
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
 * @tc.name: RDB_Native_store_test_017
 * @tc.desc: Abnormal testCase of store for CloudSync.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_017, TestSize.Level1)
{
    EXPECT_NE(storeTestRdbStore_, nullptr);
    constexpr int TABLE_COUNT = 1;
    const char *table[TABLE_COUNT];
    table[0] = "store_test";
    Rdb_SyncCallback callback = CloudSyncCallback;
    auto errorCode =
        OH_Rdb_CloudSync(storeTestRdbStore_, Rdb_SyncMode::RDB_SYNC_MODE_TIME_FIRST, table, TABLE_COUNT, nullptr);
    EXPECT_EQ(errorCode, RDB_E_INVALID_ARGS);

    errorCode = OH_Rdb_CloudSync(nullptr, Rdb_SyncMode::RDB_SYNC_MODE_CLOUD_FIRST, table, TABLE_COUNT, &callback);
    EXPECT_EQ(errorCode, RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Native_store_test_018
 * @tc.desc: Normal testCase for GetModifyTime.
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
 * @tc.name: RDB_Native_store_test_019
 * @tc.desc: Abnormal testCase for GetModifyTime, tablename columnName, keys is empty,
 *           and resultSet is null or empty
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeStoreTest, RDB_Native_store_test_019, TestSize.Level1)
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

    // table name is ""
    OH_Cursor *cursor;
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

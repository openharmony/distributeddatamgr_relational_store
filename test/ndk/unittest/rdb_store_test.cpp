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
#include "common.h"
#include "relational_store.h"
#include "relational_store_error_code.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbNdkStoreTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static void InitRdbConfig()
    {
        config_.dataBaseDir = RDB_TEST_PATH;
        config_.storeName = "rdb_store_test.db";
        config_.bundleName = "";
        config_.moduleName = "";
        config_.securityLevel = OH_Rdb_SecurityLevel::S1;
        config_.isEncrypt = false;
        config_.selfSize = sizeof(OH_Rdb_Config);
    }
    static OH_Rdb_Config config_;
};

OH_Rdb_Store *storeTestRdbStore_;
OH_Rdb_Config RdbNdkStoreTest::config_ = {0};
void RdbNdkStoreTest::SetUpTestCase(void)
{
    InitRdbConfig();
    mkdir(config_.dataBaseDir, 0770);
    int errCode = 0;
    storeTestRdbStore_ = OH_Rdb_GetOrOpen(&config_, &errCode);
    EXPECT_NE(storeTestRdbStore_, NULL);
}

void RdbNdkStoreTest::TearDownTestCase(void)
{
    int errCode = OH_Rdb_CloseStore(storeTestRdbStore_);
    EXPECT_EQ(errCode, 0);
    errCode = OH_Rdb_DeleteStore(&config_);
    EXPECT_EQ(errCode, 0);
}

void RdbNdkStoreTest::SetUp(void)
{
    char createTableSql[] = "CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    int errCode = OH_Rdb_Execute(storeTestRdbStore_, createTableSql);
    EXPECT_EQ(errCode, 0);
}

void RdbNdkStoreTest::TearDown(void)
{
    char dropTableSql[] = "DROP TABLE IF EXISTS test";
    int errCode = OH_Rdb_Execute(storeTestRdbStore_, dropTableSql);
    EXPECT_EQ(errCode, 0);
}

/**
 * @tc.name: RDB_NDK_store_test_001
 * @tc.desc: Normal testCase of NDK store for Insert、Update、Query.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkStoreTest, RDB_NDK_store_test_001, TestSize.Level1)
{
    int errCode = 0;
    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 1);
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    valueBucket->putInt64(valueBucket, "data2", 12800);
    valueBucket->putReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = {1, 2, 3, 4, 5};
    int len = sizeof(arr) / sizeof(arr[0]);
    valueBucket->putBlob(valueBucket, "data4", arr, len);
    valueBucket->putText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 1);

    valueBucket->clear(valueBucket);
    valueBucket->putText(valueBucket, "data1", "liSi");
    valueBucket->putInt64(valueBucket, "data2", 13800);
    valueBucket->putReal(valueBucket, "data3", 200.1);
    valueBucket->putNull(valueBucket, "data5");

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
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
 * @tc.name: RDB_NDK_store_test_002
 * @tc.desc: Normal testCase of NDK store for Delete、ExecuteQuery.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkStoreTest, RDB_NDK_store_test_002, TestSize.Level1)
{
    int errCode = 0;
    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 1);
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    valueBucket->putInt64(valueBucket, "data2", 12800);
    valueBucket->putReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = {1, 2, 3, 4, 5};
    int len = sizeof(arr) / sizeof(arr[0]);
    valueBucket->putBlob(valueBucket, "data4", arr, len);
    valueBucket->putText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 1);

    valueBucket->clear(valueBucket);
    valueBucket->putInt64(valueBucket, "id", 2);
    valueBucket->putText(valueBucket, "data1", "liSi");
    valueBucket->putInt64(valueBucket, "data2", 13800);
    valueBucket->putReal(valueBucket, "data3", 200.1);
    valueBucket->putText(valueBucket, "data5", "ABCDEFGH");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 2);

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    valueObject->putText(valueObject, data1Value);
    predicates->equalTo(predicates, "data1", valueObject);
    errCode = OH_Rdb_Delete(storeTestRdbStore_, predicates);
    EXPECT_EQ(errCode, 1);

    char querySql[] = "SELECT * FROM test";
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
 * @tc.name: RDB_NDK_store_test_003
 * @tc.desc: Normal testCase of NDK store for Transaction、Commit.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkStoreTest, RDB_NDK_store_test_003, TestSize.Level1)
{
    OH_Rdb_BeginTransaction(storeTestRdbStore_);

    int errCode = 0;
    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 1);
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    valueBucket->putInt64(valueBucket, "data2", 12800);
    valueBucket->putReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = {1, 2, 3, 4, 5};
    int len = sizeof(arr) / sizeof(arr[0]);
    valueBucket->putBlob(valueBucket, "data4", arr, len);
    valueBucket->putText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 1);

    valueBucket->clear(valueBucket);
    valueBucket->putInt64(valueBucket, "id", 2);
    valueBucket->putText(valueBucket, "data1", "liSi");
    valueBucket->putInt64(valueBucket, "data2", 13800);
    valueBucket->putReal(valueBucket, "data3", 200.1);
    valueBucket->putText(valueBucket, "data5", "ABCDEFGH");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 2);

    OH_Rdb_Commit(storeTestRdbStore_);

    char querySql[] = "SELECT * FROM test";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);

    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 2);

    valueBucket->destroy(valueBucket);
    cursor->destroy(cursor);
}

/**
 * @tc.name: RDB_NDK_store_test_004
 * @tc.desc: Normal testCase of NDK store for Transaction、RollBack.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkStoreTest, RDB_NDK_store_test_004, TestSize.Level1)
{
    OH_Rdb_BeginTransaction(storeTestRdbStore_);

    int errCode = 0;
    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 1);
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    valueBucket->putInt64(valueBucket, "data2", 12800);
    valueBucket->putReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = {1, 2, 3, 4, 5};
    int len = sizeof(arr) / sizeof(arr[0]);
    valueBucket->putBlob(valueBucket, "data4", arr, len);
    valueBucket->putText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 1);

    valueBucket->clear(valueBucket);
    valueBucket->putInt64(valueBucket, "id", 2);
    valueBucket->putText(valueBucket, "data1", "liSi");
    valueBucket->putInt64(valueBucket, "data2", 13800);
    valueBucket->putReal(valueBucket, "data3", 200.1);
    valueBucket->putText(valueBucket, "data5", "ABCDEFGH");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 2);

    OH_Rdb_RollBack(storeTestRdbStore_);

    char querySql[] = "SELECT * FROM test";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);

    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 0);

    valueBucket->destroy(valueBucket);
    cursor->destroy(cursor);
}

/**
 * @tc.name: RDB_NDK_store_test_005
 * @tc.desc: Normal testCase of NDK store for Backup、Restore.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkStoreTest, RDB_NDK_store_test_005, TestSize.Level1)
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
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 1);

    char querySql[] = "SELECT * FROM test";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);

    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);
    cursor->destroy(cursor);

    std::string backupPath1 = RDB_TEST_PATH + std::string("a.db");
    errCode = OH_Rdb_Backup(storeTestRdbStore_, backupPath1.c_str());
    EXPECT_EQ(errCode, 0);

    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 2);
    std::string backupPath2 = RDB_TEST_PATH +  std::string("b.db");
    errCode = OH_Rdb_Backup(storeTestRdbStore_, backupPath2.c_str());
    EXPECT_EQ(errCode, 0);

    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 3);
    std::string backupPath3 = RDB_TEST_PATH +  std::string("c.db");
    errCode = OH_Rdb_Backup(storeTestRdbStore_, backupPath3.c_str());
    EXPECT_EQ(errCode, 0);

    // Continuous backup
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 4);
    errCode = OH_Rdb_Backup(storeTestRdbStore_, backupPath3.c_str());
    EXPECT_EQ(errCode, 0);

    errCode = OH_Rdb_Restore(storeTestRdbStore_, backupPath1.c_str());
    EXPECT_EQ(errCode, 0);
    cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);
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
 * @tc.name: RDB_NDK_store_test_006
 * @tc.desc: Normal testCase of NDK store for Backup、Restore.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkStoreTest, RDB_NDK_store_test_006, TestSize.Level1)
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
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 1);

    char querySql[] = "SELECT * FROM test";
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

    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 2);
    backupPath = " ";
    errCode = OH_Rdb_Backup(storeTestRdbStore_, backupPath.c_str());
    EXPECT_EQ(errCode, 0);
    errCode = OH_Rdb_Restore(storeTestRdbStore_, backupPath.c_str());
    EXPECT_EQ(errCode, 0);
    cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);
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

    restorePath = RDB_TEST_PATH;
    errCode = OH_Rdb_Restore(storeTestRdbStore_, restorePath.c_str());
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_FILE_PATH);

    valueBucket->destroy(valueBucket);
}

/**
 * @tc.name: RDB_NDK_store_test_007
 * @tc.desc: Normal testCase of NDK store for GetVersion、SetVersion.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkStoreTest, RDB_NDK_store_test_007, TestSize.Level1)
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
 * @tc.name: RDB_NDK_store_test_008
 * @tc.desc: Normal testCase of NDK store for Insert with wrong table name or table is NULL.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkStoreTest, RDB_NDK_store_test_008, TestSize.Level1)
{
    int errCode = 0;
    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 1);
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    valueBucket->putInt64(valueBucket, "data2", 12800);
    valueBucket->putReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = {1, 2, 3, 4, 5};
    int len = sizeof(arr) / sizeof(arr[0]);
    valueBucket->putBlob(valueBucket, "data4", arr, len);
    valueBucket->putText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 1);

    valueBucket->clear(valueBucket);
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

    char querySql[] = "SELECT * FROM test";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);

    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    valueBucket->destroy(valueBucket);
    cursor->destroy(cursor);
}

/**
 * @tc.name: RDB_NDK_store_test_009
 * @tc.desc: Normal testCase of NDK store for Update with wrong table or table is NULL.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkStoreTest, RDB_NDK_store_test_009, TestSize.Level1)
{
    int errCode = 0;
    OH_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 1);
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    valueBucket->putInt64(valueBucket, "data2", 12800);
    valueBucket->putReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = {1, 2, 3, 4, 5};
    int len = sizeof(arr) / sizeof(arr[0]);
    valueBucket->putBlob(valueBucket, "data4", arr, len);
    valueBucket->putText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 1);

    valueBucket->clear(valueBucket);
    valueBucket->putText(valueBucket, "data1", "liSi");
    valueBucket->putInt64(valueBucket, "data2", 13800);
    valueBucket->putReal(valueBucket, "data3", 200.1);
    valueBucket->putNull(valueBucket, "data5");

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

    OH_Predicates *predicates2 = OH_Rdb_CreatePredicates("test");
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

    cursor->getSize(cursor, 5, &size);
    char data5Value[size + 1];
    cursor->getText(cursor, 5, data5Value, size + 1);
    EXPECT_EQ(strcmp(data5Value, "ABCDEFG"), 0);

    valueObject->destroy(valueObject);
    predicates->destroy(predicates);
    predicates2->destroy(predicates2);
    valueBucket->destroy(valueBucket);
    cursor->destroy(cursor);
}

/**
 * @tc.name: RDB_NDK_store_test_010
 * @tc.desc: Normal testCase of NDK store for querysql is NULL.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkStoreTest, RDB_NDK_store_test_010, TestSize.Level1)
{
    int errCode = 0;
    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 1);
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    valueBucket->putInt64(valueBucket, "data2", 12800);
    valueBucket->putReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = { 1, 2, 3, 4, 5 };
    int len = sizeof(arr) / sizeof(arr[0]);
    valueBucket->putBlob(valueBucket, "data4", arr, len);
    valueBucket->putText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 1);

    char *querySql = NULL;
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);
    EXPECT_EQ(cursor, NULL);

    valueBucket->destroy(valueBucket);
}

/**
 * @tc.name: RDB_NDK_store_test_011
 * @tc.desc: Normal testCase of RelationalValuesBucket for anomalous branch.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkStoreTest, RDB_NDK_store_test_011, TestSize.Level1)
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
 * @tc.name: RDB_NDK_store_test_012
 * @tc.desc: Normal testCase of NDK store for anomalous branch.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkStoreTest, RDB_NDK_store_test_012, TestSize.Level1)
{
    int errCode = 0;
    OH_Rdb_Config config;
    config.dataBaseDir = RDB_TEST_PATH;
    config.storeName = "rdb_store_error.db";
    config.bundleName = "";
    config.moduleName = "";
    config.securityLevel = OH_Rdb_SecurityLevel::S1;
    config.isEncrypt = false;
    config.selfSize = 0;

    auto store = OH_Rdb_GetOrOpen(nullptr, &errCode);
    EXPECT_EQ(store, nullptr);
    store = OH_Rdb_GetOrOpen(&config, &errCode);
    EXPECT_EQ(store, nullptr);

    config.selfSize = sizeof(OH_Rdb_Config);
    store = OH_Rdb_GetOrOpen(&config, &errCode);
    EXPECT_NE(store, nullptr);

    char createTableSql[] = "CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    errCode = OH_Rdb_Execute(nullptr, createTableSql);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_Execute(store, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    errCode = OH_Rdb_Insert(nullptr, "test", valueBucket);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_Insert(store, nullptr, valueBucket);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_Insert(store, "test", nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    errCode = OH_Rdb_Update(nullptr, valueBucket, predicates);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_Update(store, nullptr, predicates);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_Update(store, valueBucket, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    errCode = OH_Rdb_Delete(nullptr, predicates);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_Delete(store, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    auto cursor = OH_Rdb_Query(nullptr, predicates, NULL, 0);
    EXPECT_EQ(cursor, nullptr);
    cursor = OH_Rdb_Query(store, nullptr, NULL, 0);
    EXPECT_EQ(cursor, nullptr);

    char querySql[] = "SELECT * FROM test";
    cursor = OH_Rdb_ExecuteQuery(nullptr, querySql);
    EXPECT_EQ(cursor, nullptr);
    cursor = OH_Rdb_ExecuteQuery(store, nullptr);
    EXPECT_EQ(cursor, nullptr);

    errCode = OH_Rdb_BeginTransaction(nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_RollBack(nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_Commit(nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    char backupDir[] = "backup.db";
    errCode = OH_Rdb_Backup(nullptr, backupDir);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_Backup(store, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    errCode = OH_Rdb_Restore(nullptr, backupDir);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_Restore(store, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    int version = 1;
    errCode = OH_Rdb_SetVersion(nullptr, version);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_GetVersion(nullptr, &version);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_GetVersion(store, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    errCode = OH_Rdb_CloseStore(nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_DeleteStore(nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    config.dataBaseDir = nullptr;
    errCode = OH_Rdb_DeleteStore(&config);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    config.dataBaseDir = RDB_TEST_PATH;
    config.storeName = nullptr;
    errCode = OH_Rdb_DeleteStore(&config);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    config.storeName = "rdb_store_error.db";
    OH_Rdb_CloseStore(store);
    OH_Rdb_DeleteStore(&config);
}
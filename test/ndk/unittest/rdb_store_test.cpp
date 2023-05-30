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
#include "common.h"
#include "relational_store.h"
#include "relational_error_code.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbNdkStoreTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

std::string storeTestPath_ = RDB_TEST_PATH + "rdb_store_test.db";
OH_Rdb_Store *storeTestRdbStore_;

void RdbNdkStoreTest::SetUpTestCase(void)
{
    OH_Rdb_Config config;
    config.path = storeTestPath_.c_str();
    config.securityLevel = OH_Rdb_SecurityLevel::S1;
    config.isEncrypt = FALSE;

    int errCode = 0;
    storeTestRdbStore_ = OH_Rdb_GetOrOpen(&config, &errCode);
    EXPECT_NE(storeTestRdbStore_, NULL);
}

void RdbNdkStoreTest::TearDownTestCase(void)
{
    int errCode = OH_Rdb_CloseStore(storeTestRdbStore_);
    errCode = OH_Rdb_DeleteStore(storeTestPath_.c_str());
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
    OH_Rdb_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    OH_VBucket_PutInt64(valueBucket, "id", 1);
    OH_VBucket_PutText(valueBucket, "data1", "zhangSan");
    OH_VBucket_PutInt64(valueBucket, "data2", 12800);
    OH_VBucket_PutReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = {1, 2, 3, 4, 5};
    int len = sizeof(arr) / sizeof(arr[0]);
    OH_VBucket_PutBlob(valueBucket, "data4", arr, len);
    OH_VBucket_PutText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 1);

    OH_VBucket_Clear(valueBucket);
    OH_VBucket_PutText(valueBucket, "data1", "liSi");
    OH_VBucket_PutInt64(valueBucket, "data2", 13800);
    OH_VBucket_PutReal(valueBucket, "data3", 200.1);
    OH_VBucket_PutNull(valueBucket, "data5");

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    OH_Rdb_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    OH_ValueObject_PutText(valueObject, data1Value);
    predicates->OH_Predicates_EqualTo(predicates, "data1", valueObject);
    errCode = OH_Rdb_Update(storeTestRdbStore_, valueBucket, predicates);
    EXPECT_EQ(errCode, 1);

    predicates->OH_Predicates_Clear(predicates);
    OH_Cursor *cursor = OH_Rdb_Query(storeTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);

    int rowCount = 0;
    cursor->OH_Cursor_GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    errCode = cursor->OH_Cursor_GoToNextRow(cursor);
    EXPECT_EQ(errCode, 0);

    size_t size = 0;
    cursor->OH_Cursor_GetSize(cursor, 1, &size);
    char data1Value_1[size + 1];
    cursor->OH_Cursor_GetText(cursor, 1, data1Value_1, size + 1);
    EXPECT_EQ(strcmp(data1Value_1, "liSi"), 0);

    int64_t data2Value;
    cursor->OH_Cursor_GetInt64(cursor, 2, &data2Value);
    EXPECT_EQ(data2Value, 13800);

    double data3Value;
    cursor->OH_Cursor_GetReal(cursor, 3, &data3Value);
    EXPECT_EQ(data3Value, 200.1);

    cursor->OH_Cursor_GetSize(cursor, 4, &size);
    unsigned char data4Value[size];
    cursor->OH_Cursor_GetBlob(cursor, 4, data4Value, size);
    EXPECT_EQ(data4Value[0], 1);
    EXPECT_EQ(data4Value[1], 2);

    BOOL isNull = FALSE;
    cursor->OH_Cursor_IsNull(cursor, 5, &isNull);
    EXPECT_EQ(isNull, true);

    OH_Rdb_DestroyValueObject(valueObject);
    OH_Rdb_DestroyValuesBucket(valueBucket);
    OH_Rdb_DestroyPredicates(predicates);
    cursor->OH_Cursor_Close(cursor);
}

/**
 * @tc.name: RDB_NDK_store_test_002
 * @tc.desc: Normal testCase of NDK store for Delete、ExecuteQuery.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkStoreTest, RDB_NDK_store_test_002, TestSize.Level1)
{
    int errCode = 0;
    OH_Rdb_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    OH_VBucket_PutInt64(valueBucket, "id", 1);
    OH_VBucket_PutText(valueBucket, "data1", "zhangSan");
    OH_VBucket_PutInt64(valueBucket, "data2", 12800);
    OH_VBucket_PutReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = {1, 2, 3, 4, 5};
    int len = sizeof(arr) / sizeof(arr[0]);
    OH_VBucket_PutBlob(valueBucket, "data4", arr, len);
    OH_VBucket_PutText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 1);

    OH_VBucket_Clear(valueBucket);
    OH_VBucket_PutInt64(valueBucket, "id", 2);
    OH_VBucket_PutText(valueBucket, "data1", "liSi");
    OH_VBucket_PutInt64(valueBucket, "data2", 13800);
    OH_VBucket_PutReal(valueBucket, "data3", 200.1);
    OH_VBucket_PutText(valueBucket, "data5", "ABCDEFGH");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 2);

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    OH_Rdb_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    OH_ValueObject_PutText(valueObject, data1Value);
    predicates->OH_Predicates_EqualTo(predicates, "data1", valueObject);
    errCode = OH_Rdb_Delete(storeTestRdbStore_, predicates);
    EXPECT_EQ(errCode, 1);

    char querySql[] = "SELECT * FROM test";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);

    int rowCount = 0;
    cursor->OH_Cursor_GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    errCode = cursor->OH_Cursor_GoToNextRow(cursor);
    EXPECT_EQ(errCode, 0);

    size_t size = 0;
    cursor->OH_Cursor_GetSize(cursor, 1, &size);
    char data1Value_1[size + 1];
    cursor->OH_Cursor_GetText(cursor, 1, data1Value_1, size + 1);
    EXPECT_EQ(strcmp(data1Value_1, "liSi"), 0);

    int64_t data2Value;
    cursor->OH_Cursor_GetInt64(cursor, 2, &data2Value);
    EXPECT_EQ(data2Value, 13800);

    double data3Value;
    cursor->OH_Cursor_GetReal(cursor, 3, &data3Value);
    EXPECT_EQ(data3Value, 200.1);

    BOOL isNull = FALSE;
    cursor->OH_Cursor_IsNull(cursor, 4, &isNull);
    EXPECT_EQ(isNull, true);

    cursor->OH_Cursor_GetSize(cursor, 5, &size);
    char data5Value[size + 1];
    cursor->OH_Cursor_GetText(cursor, 5, data5Value, size + 1);
    EXPECT_EQ(strcmp(data5Value, "ABCDEFGH"), 0);

    OH_Rdb_DestroyValueObject(valueObject);
    OH_Rdb_DestroyValuesBucket(valueBucket);
    OH_Rdb_DestroyPredicates(predicates);
    cursor->OH_Cursor_Close(cursor);
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
    OH_Rdb_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    OH_VBucket_PutInt64(valueBucket, "id", 1);
    OH_VBucket_PutText(valueBucket, "data1", "zhangSan");
    OH_VBucket_PutInt64(valueBucket, "data2", 12800);
    OH_VBucket_PutReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = {1, 2, 3, 4, 5};
    int len = sizeof(arr) / sizeof(arr[0]);
    OH_VBucket_PutBlob(valueBucket, "data4", arr, len);
    OH_VBucket_PutText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 1);

    OH_VBucket_Clear(valueBucket);
    OH_VBucket_PutInt64(valueBucket, "id", 2);
    OH_VBucket_PutText(valueBucket, "data1", "liSi");
    OH_VBucket_PutInt64(valueBucket, "data2", 13800);
    OH_VBucket_PutReal(valueBucket, "data3", 200.1);
    OH_VBucket_PutText(valueBucket, "data5", "ABCDEFGH");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 2);

    OH_Rdb_Commit(storeTestRdbStore_);

    char querySql[] = "SELECT * FROM test";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);

    int rowCount = 0;
    cursor->OH_Cursor_GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 2);

    OH_Rdb_DestroyValuesBucket(valueBucket);
    cursor->OH_Cursor_Close(cursor);
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
    OH_Rdb_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    OH_VBucket_PutInt64(valueBucket, "id", 1);
    OH_VBucket_PutText(valueBucket, "data1", "zhangSan");
    OH_VBucket_PutInt64(valueBucket, "data2", 12800);
    OH_VBucket_PutReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = {1, 2, 3, 4, 5};
    int len = sizeof(arr) / sizeof(arr[0]);
    OH_VBucket_PutBlob(valueBucket, "data4", arr, len);
    OH_VBucket_PutText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 1);

    OH_VBucket_Clear(valueBucket);
    OH_VBucket_PutInt64(valueBucket, "id", 2);
    OH_VBucket_PutText(valueBucket, "data1", "liSi");
    OH_VBucket_PutInt64(valueBucket, "data2", 13800);
    OH_VBucket_PutReal(valueBucket, "data3", 200.1);
    OH_VBucket_PutText(valueBucket, "data5", "ABCDEFGH");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 2);

    OH_Rdb_RollBack(storeTestRdbStore_);

    char querySql[] = "SELECT * FROM test";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);

    int rowCount = 0;
    cursor->OH_Cursor_GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 0);

    OH_Rdb_DestroyValuesBucket(valueBucket);
    cursor->OH_Cursor_Close(cursor);
}

/**
 * @tc.name: RDB_NDK_store_test_005
 * @tc.desc: Normal testCase of NDK store for Backup、Restore.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkStoreTest, RDB_NDK_store_test_005, TestSize.Level1)
{
    int errCode = 0;
    OH_Rdb_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    OH_VBucket_PutInt64(valueBucket, "id", 1);
    OH_VBucket_PutText(valueBucket, "data1", "zhangSan");
    OH_VBucket_PutInt64(valueBucket, "data2", 12800);
    OH_VBucket_PutReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = {1, 2, 3, 4, 5};
    int len = sizeof(arr) / sizeof(arr[0]);
    OH_VBucket_PutBlob(valueBucket, "data4", arr, len);
    OH_VBucket_PutText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 1);

    char querySql[] = "SELECT * FROM test";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);

    int rowCount = 0;
    cursor->OH_Cursor_GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);
    cursor->OH_Cursor_Close(cursor);

    std::string backupPath = RDB_TEST_PATH + "backup.db";
    errCode = OH_Rdb_Backup(storeTestRdbStore_, backupPath.c_str());
    EXPECT_EQ(errCode, 0);

    errCode = OH_Rdb_Restore(storeTestRdbStore_, backupPath.c_str());
    EXPECT_EQ(errCode, 0);

    cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);
    cursor->OH_Cursor_GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    errCode = cursor->OH_Cursor_GoToNextRow(cursor);
    EXPECT_EQ(errCode, 0);

    size_t size = 0;
    cursor->OH_Cursor_GetSize(cursor, 1, &size);
    char data1Value[size + 1];
    cursor->OH_Cursor_GetText(cursor, 1, data1Value, size + 1);
    EXPECT_EQ(strcmp(data1Value, "zhangSan"), 0);

    int64_t data2Value;
    cursor->OH_Cursor_GetInt64(cursor, 2, &data2Value);
    EXPECT_EQ(data2Value, 12800);

    double data3Value;
    cursor->OH_Cursor_GetReal(cursor, 3, &data3Value);
    EXPECT_EQ(data3Value, 100.1);

    cursor->OH_Cursor_GetSize(cursor, 4, &size);
    unsigned char data4Value[size];
    cursor->OH_Cursor_GetBlob(cursor, 4, data4Value, size);
    EXPECT_EQ(data4Value[0], 1);
    EXPECT_EQ(data4Value[1], 2);

    cursor->OH_Cursor_GetSize(cursor, 5, &size);
    char data5Value[size + 1];
    cursor->OH_Cursor_GetText(cursor, 5, data5Value, size + 1);
    EXPECT_EQ(strcmp(data5Value, "ABCDEFG"), 0);

    OH_Rdb_DestroyValuesBucket(valueBucket);
    cursor->OH_Cursor_Close(cursor);
}

/**
 * @tc.name: RDB_NDK_store_test_006
 * @tc.desc: Normal testCase of NDK store for GetVersion、SetVersion.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkStoreTest, RDB_NDK_store_test_006, TestSize.Level1)
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
 * @tc.name: RDB_NDK_store_test_007
 * @tc.desc: Normal testCase of NDK store for Insert with wrong table name or table is NULL.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkStoreTest, RDB_NDK_store_test_007, TestSize.Level1)
{
    int errCode = 0;
    OH_Rdb_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    OH_VBucket_PutInt64(valueBucket, "id", 1);
    OH_VBucket_PutText(valueBucket, "data1", "zhangSan");
    OH_VBucket_PutInt64(valueBucket, "data2", 12800);
    OH_VBucket_PutReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = {1, 2, 3, 4, 5};
    int len = sizeof(arr) / sizeof(arr[0]);
    OH_VBucket_PutBlob(valueBucket, "data4", arr, len);
    OH_VBucket_PutText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 1);

    OH_VBucket_Clear(valueBucket);
    OH_VBucket_PutInt64(valueBucket, "id", 2);
    OH_VBucket_PutText(valueBucket, "data1", "liSi");
    OH_VBucket_PutInt64(valueBucket, "data2", 13800);
    OH_VBucket_PutReal(valueBucket, "data3", 200.1);
    OH_VBucket_PutText(valueBucket, "data5", "ABCDEFGH");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "wrong", valueBucket);
    EXPECT_EQ(errCode, -1);

    OH_VBucket_Clear(valueBucket);
    OH_VBucket_PutInt64(valueBucket, "id", 3);
    OH_VBucket_PutText(valueBucket, "data1", "wangWu");
    OH_VBucket_PutInt64(valueBucket, "data2", 14800);
    OH_VBucket_PutReal(valueBucket, "data3", 300.1);
    OH_VBucket_PutText(valueBucket, "data5", "ABCDEFGHI");
    char *table = NULL;
    errCode = OH_Rdb_Insert(storeTestRdbStore_, table, valueBucket);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS);

    char querySql[] = "SELECT * FROM test";
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);

    int rowCount = 0;
    cursor->OH_Cursor_GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    OH_Rdb_DestroyValuesBucket(valueBucket);
    cursor->OH_Cursor_Close(cursor);
}

/**
 * @tc.name: RDB_NDK_store_test_008
 * @tc.desc: Normal testCase of NDK store for Update with wrong table or table is NULL.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkStoreTest, RDB_NDK_store_test_008, TestSize.Level1)
{
    int errCode = 0;
    OH_Rdb_VBucket* valueBucket = OH_Rdb_CreateValuesBucket();
    OH_VBucket_PutInt64(valueBucket, "id", 1);
    OH_VBucket_PutText(valueBucket, "data1", "zhangSan");
    OH_VBucket_PutInt64(valueBucket, "data2", 12800);
    OH_VBucket_PutReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = {1, 2, 3, 4, 5};
    int len = sizeof(arr) / sizeof(arr[0]);
    OH_VBucket_PutBlob(valueBucket, "data4", arr, len);
    OH_VBucket_PutText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 1);

    OH_VBucket_Clear(valueBucket);
    OH_VBucket_PutText(valueBucket, "data1", "liSi");
    OH_VBucket_PutInt64(valueBucket, "data2", 13800);
    OH_VBucket_PutReal(valueBucket, "data3", 200.1);
    OH_VBucket_PutNull(valueBucket, "data5");

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("wrong");
    OH_Rdb_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    OH_ValueObject_PutText(valueObject, data1Value);
    predicates->OH_Predicates_EqualTo(predicates, "data1", valueObject);
    errCode = OH_Rdb_Update(storeTestRdbStore_, valueBucket, predicates);
    EXPECT_EQ(errCode, -1);

    char *table = NULL;
    OH_Predicates *predicates1 = OH_Rdb_CreatePredicates(table);
    EXPECT_EQ(predicates1, NULL);
    errCode = OH_Rdb_Update(storeTestRdbStore_, valueBucket, predicates1);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS);

    OH_Predicates *predicates2 = OH_Rdb_CreatePredicates("test");
    OH_Cursor *cursor = OH_Rdb_Query(storeTestRdbStore_, predicates2, NULL, 0);
    EXPECT_NE(cursor, NULL);

    int rowCount = 0;
    cursor->OH_Cursor_GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    errCode = cursor->OH_Cursor_GoToNextRow(cursor);
    EXPECT_EQ(errCode, 0);

    size_t size = 0;
    cursor->OH_Cursor_GetSize(cursor, 1, &size);
    char data1Value_1[size + 1];
    cursor->OH_Cursor_GetText(cursor, 1, data1Value_1, size + 1);
    EXPECT_EQ(strcmp(data1Value_1, "zhangSan"), 0);

    int64_t data2Value;
    cursor->OH_Cursor_GetInt64(cursor, 2, &data2Value);
    EXPECT_EQ(data2Value, 12800);

    double data3Value;
    cursor->OH_Cursor_GetReal(cursor, 3, &data3Value);
    EXPECT_EQ(data3Value, 100.1);

    cursor->OH_Cursor_GetSize(cursor, 4, &size);
    unsigned char data4Value[size];
    cursor->OH_Cursor_GetBlob(cursor, 4, data4Value, size);
    EXPECT_EQ(data4Value[0], 1);
    EXPECT_EQ(data4Value[1], 2);

    cursor->OH_Cursor_GetSize(cursor, 5, &size);
    char data5Value[size + 1];
    cursor->OH_Cursor_GetText(cursor, 5, data5Value, size + 1);
    EXPECT_EQ(strcmp(data5Value, "ABCDEFG"), 0);

    OH_Rdb_DestroyValueObject(valueObject);
    OH_Rdb_DestroyPredicates(predicates);
    OH_Rdb_DestroyPredicates(predicates2);
    OH_Rdb_DestroyValuesBucket(valueBucket);
    cursor->OH_Cursor_Close(cursor);
}

/**
 * @tc.name: RDB_NDK_store_test_009
 * @tc.desc: Normal testCase of NDK store for querysql is NULL.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkStoreTest, RDB_NDK_store_test_009, TestSize.Level1)
{
    int errCode = 0;
    OH_Rdb_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    OH_VBucket_PutInt64(valueBucket, "id", 1);
    OH_VBucket_PutText(valueBucket, "data1", "zhangSan");
    OH_VBucket_PutInt64(valueBucket, "data2", 12800);
    OH_VBucket_PutReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = { 1, 2, 3, 4, 5 };
    int len = sizeof(arr) / sizeof(arr[0]);
    OH_VBucket_PutBlob(valueBucket, "data4", arr, len);
    OH_VBucket_PutText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(storeTestRdbStore_, "test", valueBucket);
    EXPECT_EQ(errCode, 1);

    char *querySql = NULL;
    OH_Cursor *cursor = OH_Rdb_ExecuteQuery(storeTestRdbStore_, querySql);
    EXPECT_EQ(cursor, NULL);

    OH_Rdb_DestroyValuesBucket(valueBucket);
}
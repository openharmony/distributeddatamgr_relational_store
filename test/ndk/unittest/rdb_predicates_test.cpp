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
#include "native_value_object.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbNdkPredicatesTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

std::string predicatesTestPath_ = RDB_TEST_PATH + "rdb_predicates_test.db";
OH_Rdb_Store *predicatesTestRdbStore_;

void RdbNdkPredicatesTest::SetUpTestCase(void)
{
    OH_Rdb_Config config;
    config.path = predicatesTestPath_.c_str();
    config.securityLevel = OH_Rdb_SecurityLevel::S1;
    config.isEncrypt = false;

    int errCode = 0;
    char table[] = "test";
    predicatesTestRdbStore_ = OH_Rdb_GetOrOpen(&config, &errCode);
    EXPECT_NE(predicatesTestRdbStore_, NULL);

    char createTableSql[] = "CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    errCode = OH_Rdb_Execute(predicatesTestRdbStore_, createTableSql);

    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->PutInt64(valueBucket, "id", 1);
    valueBucket->PutText(valueBucket, "data1", "zhangSan");
    valueBucket->PutInt64(valueBucket, "data2", 12800);
    valueBucket->PutReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = {1, 2, 3, 4, 5};
    int len = sizeof(arr) / sizeof(arr[0]);
    valueBucket->PutBlob(valueBucket, "data4", arr, len);
    valueBucket->PutText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(predicatesTestRdbStore_, table, valueBucket);
    EXPECT_EQ(errCode, 1);

    valueBucket->Clear(valueBucket);
    valueBucket->PutInt64(valueBucket, "id", 2);
    valueBucket->PutText(valueBucket, "data1", "liSi");
    valueBucket->PutInt64(valueBucket, "data2", 13800);
    valueBucket->PutReal(valueBucket, "data3", 200.1);
    valueBucket->PutText(valueBucket, "data5", "ABCDEFGH");
    errCode = OH_Rdb_Insert(predicatesTestRdbStore_, table, valueBucket);
    EXPECT_EQ(errCode, 2);

    valueBucket->Clear(valueBucket);
    valueBucket->PutInt64(valueBucket, "id", 3);
    valueBucket->PutText(valueBucket, "data1", "wangWu");
    valueBucket->PutInt64(valueBucket, "data2", 14800);
    valueBucket->PutReal(valueBucket, "data3", 300.1);
    valueBucket->PutText(valueBucket, "data5", "ABCDEFGHI");
    errCode = OH_Rdb_Insert(predicatesTestRdbStore_, table, valueBucket);
    EXPECT_EQ(errCode, 3);

    valueBucket->DestroyValuesBucket(valueBucket);
}

void RdbNdkPredicatesTest::TearDownTestCase(void)
{
    delete predicatesTestRdbStore_;
    predicatesTestRdbStore_ = NULL;
    OH_Rdb_DeleteStore(predicatesTestPath_.c_str());
}

void RdbNdkPredicatesTest::SetUp(void)
{
}

void RdbNdkPredicatesTest::TearDown(void)
{
}

/**
 * @tc.name: RDB_NDK_predicates_test_001
 * @tc.desc: Normal testCase of NDK Predicates for EqualTo、AndOR、beginWrap and endWrap
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkPredicatesTest, RDB_NDK_predicates_test_001, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    uint32_t count = 1;
    const char *data1Value = "zhangSan";
    valueObject->PutText(valueObject, data1Value);
    predicates->BeginWrap(predicates).EqualTo(predicates, "data1", valueObject)
        .OH_Predicates_Or(predicates);
    double data3Value = 200.1;
    valueObject->PutDouble(valueObject, &data3Value, count);
    predicates->EqualTo(predicates, "data3", valueObject).EndWrap(predicates);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 2);

    predicates->DestroyPredicates(predicates);
    valueObject->DestroyValueObject(valueObject);
    cursor->Close(cursor);
}

/**
 * @tc.name: RDB_NDK_predicates_test_002
 * @tc.desc: Normal testCase of NDK Predicates for NotEqualTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkPredicatesTest, RDB_NDK_predicates_test_002, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    valueObject->PutText(valueObject, data1Value);
    predicates->NotEqualTo(predicates, "data1", valueObject);
    EXPECT_EQ(errCode, 0);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 2);

    valueObject->DestroyValueObject(valueObject);
    predicates->DestroyPredicates(predicates);
    cursor->Close(cursor);
}

/**
 * @tc.name: RDB_NDK_predicates_test_003
 * @tc.desc: Normal testCase of NDK Predicates for GreaterThan
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkPredicatesTest, RDB_NDK_predicates_test_003, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data5Value = "ABCDEFG";
    valueObject->PutText(valueObject, data5Value);
    predicates->GreaterThan(predicates, "data5", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 2);

    cursor->GoToNextRow(cursor);

    int columnCount = 0;
    cursor->GetColumnCount(cursor, &columnCount);
    EXPECT_EQ(columnCount, 6);

    int64_t id;
    cursor->GetInt64(cursor, 0, &id);
    EXPECT_EQ(id, 2);

    size_t size = 0;
    cursor->GetSize(cursor, 1, &size);
    char data1Value[size + 1];
    cursor->GetText(cursor, 1, data1Value, size + 1);
    EXPECT_EQ(strcmp(data1Value, "liSi"), 0);

    int64_t data2Value;
    cursor->GetInt64(cursor, 2, &data2Value);
    EXPECT_EQ(data2Value, 13800);

    double data3Value;
    cursor->GetReal(cursor, 3, &data3Value);
    EXPECT_EQ(data3Value, 200.1);

    bool isNull = false;
    cursor->IsNull(cursor, 4, &isNull);
    EXPECT_EQ(isNull, true);

    cursor->GetSize(cursor, 5, &size);
    char data5Value_1[size + 1];
    cursor->GetText(cursor, 5, data5Value_1, size + 1);
    EXPECT_EQ(strcmp(data5Value_1, "ABCDEFGH"), 0);

    cursor->GoToNextRow(cursor);

    cursor->GetInt64(cursor, 0, &id);
    EXPECT_EQ(id, 3);

    cursor->GetSize(cursor, 1, &size);
    char data1Value_1[size + 1];
    cursor->GetText(cursor, 1, data1Value_1, size + 1);
    EXPECT_EQ(strcmp(data1Value_1, "wangWu"), 0);

    cursor->GetInt64(cursor, 2, &data2Value);
    EXPECT_EQ(data2Value, 14800);

    cursor->GetReal(cursor, 3, &data3Value);
    EXPECT_EQ(data3Value, 300.1);

    cursor->IsNull(cursor, 4, &isNull);
    EXPECT_EQ(isNull, true);

    cursor->GetSize(cursor, 5, &size);
    char data5Value_2[size + 1];
    cursor->GetText(cursor, 5, data5Value_2, size + 1);
    EXPECT_EQ(strcmp(data5Value_2, "ABCDEFGHI"), 0);

    valueObject->DestroyValueObject(valueObject);
    predicates->DestroyPredicates(predicates);
    cursor->Close(cursor);
}

/**
 * @tc.name: RDB_NDK_predicates_test_004
 * @tc.desc: Normal testCase of NDK Predicates for GreaterThanOrEqualTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkPredicatesTest, RDB_NDK_predicates_test_004, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data5Value = "ABCDEFG";
    valueObject->PutText(valueObject, data5Value);
    predicates->GreaterThanOrEqualTo(predicates, "data5", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 3);

    valueObject->DestroyValueObject(valueObject);
    predicates->DestroyPredicates(predicates);
    cursor->Close(cursor);
}

/**
 * @tc.name: RDB_NDK_predicates_test_005
 * @tc.desc: Normal testCase of NDK Predicates for LessThan
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkPredicatesTest, RDB_NDK_predicates_test_005, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data5Value = "ABCDEFG";
    valueObject->PutText(valueObject, data5Value);
    predicates->LessThan(predicates, "data5", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 0);

    valueObject->DestroyValueObject(valueObject);
    predicates->DestroyPredicates(predicates);
    cursor->Close(cursor);
}

/**
 * @tc.name: RDB_NDK_predicates_test_006
 * @tc.desc: Normal testCase of NDK Predicates for LessThanOrEqualTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkPredicatesTest, RDB_NDK_predicates_test_006, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data5Value = "ABCDEFG";
    valueObject->PutText(valueObject, data5Value);
    predicates->LessThanOrEqualTo(predicates, "data5", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    valueObject->DestroyValueObject(valueObject);
    predicates->DestroyPredicates(predicates);
    cursor->Close(cursor);
}

/**
 * @tc.name: RDB_NDK_predicates_test_007
 * @tc.desc: Normal testCase of NDK Predicates for IsNull.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkPredicatesTest, RDB_NDK_predicates_test_007, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    predicates->IsNull(predicates, "data4");

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 2);

    predicates->DestroyPredicates(predicates);
    cursor->Close(cursor);
}

/**
 * @tc.name: RDB_NDK_predicates_test_008
 * @tc.desc: Normal testCase of NDK Predicates for IsNull.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkPredicatesTest, RDB_NDK_predicates_test_008, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    predicates->IsNotNull(predicates, "data4");

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    predicates->Predicates(predicates);
    cursor->Close(cursor);
}

/**
 * @tc.name: RDB_NDK_predicates_test_009
 * @tc.desc: Normal testCase of NDK Predicates for Between
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkPredicatesTest, RDB_NDK_predicates_test_009, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    int64_t data2Value[] = {12000, 13000};
    uint32_t len = sizeof(data2Value) / sizeof(data2Value[0]);
    valueObject->PutInt64(valueObject, data2Value, len);
    predicates->Between(predicates, "data2", valueObject);
    double data3Value[] = {0.1, 101.1};
    len = sizeof(data3Value) / sizeof(data3Value[0]);
    valueObject->PutDouble(valueObject, data3Value, len);
    predicates->Between(predicates, "data3", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    valueObject->DestroyValueObject(valueObject);
    predicates->DestroyPredicates(predicates);
    cursor->Close(cursor);
}

/**
 * @tc.name: RDB_NDK_predicates_test_010
 * @tc.desc: Normal testCase of NDK Predicates for NotBetween
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkPredicatesTest, RDB_NDK_predicates_test_010, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    int64_t data2Value[] = {12000, 13000};
    int len = sizeof(data2Value) / sizeof(data2Value[0]);
    valueObject->PutInt64(valueObject, data2Value, len);
    predicates->NotBetween(predicates, "data2", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 2);

    valueObject->DestroyValueObject(valueObject);
    predicates->DestroyPredicates(predicates);
    cursor->Close(cursor);
}

/**
 * @tc.name: RDB_NDK_predicates_test_011
 * @tc.desc: Normal testCase of NDK Predicates for OrderBy、Limit、Offset.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkPredicatesTest, RDB_NDK_predicates_test_011, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    predicates->OrderBy(predicates, "data2", OH_OrderType::ASC);
    predicates->Limit(predicates, 1);
    predicates->Offset(predicates, 1);
    predicates->Distinct(predicates);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    errCode = cursor->GoToNextRow(cursor);
    int columnIndex;
    cursor->GetColumnIndex(cursor, "data2", &columnIndex);
    EXPECT_EQ(columnIndex, 2);
    int64_t longValue;
    cursor->GetInt64(cursor, columnIndex, &longValue);
    EXPECT_EQ(longValue, 13800);

    predicates->DestroyPredicates(predicates);
    cursor->Close(cursor);
}

/**
 * @tc.name: RDB_NDK_predicates_test_012
 * @tc.desc: Normal testCase of NDK Predicates for In.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkPredicatesTest, RDB_NDK_predicates_test_012, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value[] = {"zhangSan", "liSi"};
    int len = sizeof(data1Value) / sizeof(data1Value[0]);
    valueObject->PutTexts(valueObject, data1Value, len);
    predicates->In(predicates, "data1", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 2);

    valueObject->DestroyValueObject(valueObject);
    predicates->DestroyPredicates(predicates);
    cursor->Close(cursor);
}

/**
 * @tc.name: RDB_NDK_predicates_test_013
 * @tc.desc: Normal testCase of NDK Predicates for NotIn.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkPredicatesTest, RDB_NDK_predicates_test_013, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value[] = {"zhangSan", "liSi"};
    int len = sizeof(data1Value) / sizeof(data1Value[0]);
    valueObject->PutTexts(valueObject, data1Value, len);
    predicates->NotIn(predicates, "data1", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    valueObject->DestroyValueObject(valueObject);
    predicates->DestroyPredicates(predicates);
    cursor->Close(cursor);
}

/**
 * @tc.name: RDB_NDK_predicates_test_014
 * @tc.desc: Normal testCase of NDK Predicates for Like.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkPredicatesTest, RDB_NDK_predicates_test_014, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data5Value = "ABCD%";
    valueObject->PutText(valueObject, data5Value);
    predicates->Like(predicates, "data5", valueObject);
    const char *data2Value = "%800";
    valueObject->PutText(valueObject, data2Value);
    predicates->Like(predicates, "data2", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 3);

    valueObject->DestroyValueObject(valueObject);
    predicates->DestroyPredicates(predicates);
    cursor->Close(cursor);
}

/**
 * @tc.name: RDB_NDK_predicates_test_015
 * @tc.desc: Normal testCase of NDK Predicates for GroupBy.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkPredicatesTest, RDB_NDK_predicates_test_015, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    const char *columnNames[] = {"data1", "data2"};
    int len = sizeof(columnNames) / sizeof(columnNames[0]);
    predicates->GroupBy(predicates, columnNames, len);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 3);

    predicates->DestroyPredicates(predicates);
    cursor->Close(cursor);
}

/**
 * @tc.name: RDB_NDK_predicates_test_016
 * @tc.desc: Normal testCase of NDK Predicates for And.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkPredicatesTest, RDB_NDK_predicates_test_016, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    valueObject->PutText(valueObject, data1Value);
    predicates->EqualTo(predicates, "data1", valueObject);
    predicates->And(predicates);
    double data3Value = 100.1;
    valueObject->PutDouble(valueObject, &data3Value, 1);
    predicates->EqualTo(predicates, "data3", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    valueObject->DestroyValueObject(valueObject);
    predicates->DestroyPredicates(predicates);
    errCode = cursor->Close(cursor);
}

/**
 * @tc.name: RDB_NDK_predicates_test_017
 * @tc.desc: Normal testCase of NDK Predicates for Clear.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkPredicatesTest, RDB_NDK_predicates_test_017, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    valueObject->PutText(valueObject, data1Value);
    predicates->EqualTo(predicates, "data1", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);
    errCode = cursor->Close(cursor);

    predicates->Clear(predicates);
    predicates->NotEqualTo(predicates, "data1", valueObject);
    cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    errCode = cursor->GetRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 2);

    valueObject->DestroyValueObject(valueObject);
    predicates->DestroyPredicates(predicates);
    errCode = cursor->Close(cursor);
}

/**
 * @tc.name: RDB_NDK_predicates_test_018
 * @tc.desc: Normal testCase of NDK Predicates for table name is NULL.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNdkPredicatesTest, RDB_NDK_predicates_test_018, TestSize.Level1)
{
    char *table = NULL;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table);
    EXPECT_EQ(predicates, NULL);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_EQ(cursor, NULL);
}
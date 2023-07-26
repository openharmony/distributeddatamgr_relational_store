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
#include "oh_value_object.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbNdkPredicatesTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static void InitRdbConfig()
    {
        config_.dataBaseDir = RDB_TEST_PATH;
        config_.storeName = "rdb_predicates_test.db";
        config_.bundleName = "";
        config_.moduleName = "";
        config_.securityLevel = OH_Rdb_SecurityLevel::S1;
        config_.isEncrypt = false;
    }
    static OH_Rdb_Config config_;
};

OH_Rdb_Store *predicatesTestRdbStore_;
OH_Rdb_Config RdbNdkPredicatesTest::config_ = {0};
void RdbNdkPredicatesTest::SetUpTestCase(void)
{
    InitRdbConfig();
    mkdir(config_.dataBaseDir, 0770);
    int errCode = 0;
    char table[] = "test";
    predicatesTestRdbStore_ = OH_Rdb_GetOrOpen(&config_, &errCode);
    EXPECT_NE(predicatesTestRdbStore_, NULL);

    char createTableSql[] = "CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    errCode = OH_Rdb_Execute(predicatesTestRdbStore_, createTableSql);

    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 1);
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    valueBucket->putInt64(valueBucket, "data2", 12800);
    valueBucket->putReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = {1, 2, 3, 4, 5};
    int len = sizeof(arr) / sizeof(arr[0]);
    valueBucket->putBlob(valueBucket, "data4", arr, len);
    valueBucket->putText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(predicatesTestRdbStore_, table, valueBucket);
    EXPECT_EQ(errCode, 1);

    valueBucket->clear(valueBucket);
    valueBucket->putInt64(valueBucket, "id", 2);
    valueBucket->putText(valueBucket, "data1", "liSi");
    valueBucket->putInt64(valueBucket, "data2", 13800);
    valueBucket->putReal(valueBucket, "data3", 200.1);
    valueBucket->putText(valueBucket, "data5", "ABCDEFGH");
    errCode = OH_Rdb_Insert(predicatesTestRdbStore_, table, valueBucket);
    EXPECT_EQ(errCode, 2);

    valueBucket->clear(valueBucket);
    valueBucket->putInt64(valueBucket, "id", 3);
    valueBucket->putText(valueBucket, "data1", "wangWu");
    valueBucket->putInt64(valueBucket, "data2", 14800);
    valueBucket->putReal(valueBucket, "data3", 300.1);
    valueBucket->putText(valueBucket, "data5", "ABCDEFGHI");
    errCode = OH_Rdb_Insert(predicatesTestRdbStore_, table, valueBucket);
    EXPECT_EQ(errCode, 3);

    valueBucket->destroy(valueBucket);
}

void RdbNdkPredicatesTest::TearDownTestCase(void)
{
    delete predicatesTestRdbStore_;
    predicatesTestRdbStore_ = NULL;
    OH_Rdb_DeleteStore(&config_);
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
    valueObject->putText(valueObject, data1Value);
    predicates->beginWrap(predicates)->equalTo(predicates, "data1", valueObject)->orOperate(predicates);
    double data3Value = 200.1;
    valueObject->putDouble(valueObject, &data3Value, count);
    predicates->equalTo(predicates, "data3", valueObject)->endWrap(predicates);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 2);

    valueObject->destroy(valueObject);
    predicates->destroy(predicates);
    cursor->destroy(cursor);
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
    valueObject->putText(valueObject, data1Value);
    predicates->notEqualTo(predicates, "data1", valueObject);
    EXPECT_EQ(errCode, 0);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 2);

    valueObject->destroy(valueObject);
    predicates->destroy(predicates);
    cursor->destroy(cursor);
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
    valueObject->putText(valueObject, data5Value);
    predicates->greaterThan(predicates, "data5", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 2);

    cursor->goToNextRow(cursor);

    int columnCount = 0;
    cursor->getColumnCount(cursor, &columnCount);
    EXPECT_EQ(columnCount, 6);

    int64_t id;
    cursor->getInt64(cursor, 0, &id);
    EXPECT_EQ(id, 2);

    size_t size = 0;
    cursor->getSize(cursor, 1, &size);
    char data1Value[size + 1];
    cursor->getText(cursor, 1, data1Value, size + 1);
    EXPECT_EQ(strcmp(data1Value, "liSi"), 0);

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
    char data5Value_1[size + 1];
    cursor->getText(cursor, 5, data5Value_1, size + 1);
    EXPECT_EQ(strcmp(data5Value_1, "ABCDEFGH"), 0);

    cursor->goToNextRow(cursor);

    cursor->getInt64(cursor, 0, &id);
    EXPECT_EQ(id, 3);

    cursor->getSize(cursor, 1, &size);
    char data1Value_1[size + 1];
    cursor->getText(cursor, 1, data1Value_1, size + 1);
    EXPECT_EQ(strcmp(data1Value_1, "wangWu"), 0);

    cursor->getInt64(cursor, 2, &data2Value);
    EXPECT_EQ(data2Value, 14800);

    cursor->getReal(cursor, 3, &data3Value);
    EXPECT_EQ(data3Value, 300.1);

    cursor->isNull(cursor, 4, &isNull);
    EXPECT_EQ(isNull, true);

    cursor->getSize(cursor, 5, &size);
    char data5Value_2[size + 1];
    cursor->getText(cursor, 5, data5Value_2, size + 1);
    EXPECT_EQ(strcmp(data5Value_2, "ABCDEFGHI"), 0);

    valueObject->destroy(valueObject);
    predicates->destroy(predicates);
    cursor->destroy(cursor);
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
    valueObject->putText(valueObject, data5Value);
    predicates->greaterThanOrEqualTo(predicates, "data5", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 3);

    valueObject->destroy(valueObject);
    predicates->destroy(predicates);
    cursor->destroy(cursor);
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
    valueObject->putText(valueObject, data5Value);
    predicates->lessThan(predicates, "data5", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 0);

    valueObject->destroy(valueObject);
    predicates->destroy(predicates);
    cursor->destroy(cursor);
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
    valueObject->putText(valueObject, data5Value);
    predicates->lessThanOrEqualTo(predicates, "data5", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    valueObject->destroy(valueObject);
    predicates->destroy(predicates);
    cursor->destroy(cursor);
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
    predicates->isNull(predicates, "data4");

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 2);

    predicates->destroy(predicates);
    cursor->destroy(cursor);
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
    predicates->isNotNull(predicates, "data4");

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    predicates->destroy(predicates);
    cursor->destroy(cursor);
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
    valueObject->putInt64(valueObject, data2Value, len);
    predicates->between(predicates, "data2", valueObject);
    double data3Value[] = {0.1, 101.1};
    len = sizeof(data3Value) / sizeof(data3Value[0]);
    valueObject->putDouble(valueObject, data3Value, len);
    predicates->between(predicates, "data3", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    valueObject->destroy(valueObject);
    predicates->destroy(predicates);
    cursor->destroy(cursor);
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
    valueObject->putInt64(valueObject, data2Value, len);
    predicates->notBetween(predicates, "data2", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 2);

    valueObject->destroy(valueObject);
    predicates->destroy(predicates);
    cursor->destroy(cursor);
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
    predicates->orderBy(predicates, "data2", OH_OrderType::ASC);
    predicates->limit(predicates, 1);
    predicates->offset(predicates, 1);
    predicates->distinct(predicates);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    errCode = cursor->goToNextRow(cursor);
    int columnIndex;
    cursor->getColumnIndex(cursor, "data2", &columnIndex);
    EXPECT_EQ(columnIndex, 2);
    int64_t longValue;
    cursor->getInt64(cursor, columnIndex, &longValue);
    EXPECT_EQ(longValue, 13800);

    predicates->destroy(predicates);
    cursor->destroy(cursor);
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
    valueObject->putTexts(valueObject, data1Value, len);
    predicates->in(predicates, "data1", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 2);

    valueObject->destroy(valueObject);
    predicates->destroy(predicates);
    cursor->destroy(cursor);
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
    valueObject->putTexts(valueObject, data1Value, len);
    predicates->notIn(predicates, "data1", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    valueObject->destroy(valueObject);
    predicates->destroy(predicates);
    cursor->destroy(cursor);
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
    valueObject->putText(valueObject, data5Value);
    predicates->like(predicates, "data5", valueObject);
    const char *data2Value = "%800";
    valueObject->putText(valueObject, data2Value);
    predicates->like(predicates, "data2", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 3);

    valueObject->destroy(valueObject);
    predicates->destroy(predicates);
    cursor->destroy(cursor);
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
    predicates->groupBy(predicates, columnNames, len);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 3);

    predicates->destroy(predicates);
    cursor->destroy(cursor);
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
    valueObject->putText(valueObject, data1Value);
    predicates->equalTo(predicates, "data1", valueObject);
    predicates->andOperate(predicates);
    double data3Value = 100.1;
    valueObject->putDouble(valueObject, &data3Value, 1);
    predicates->equalTo(predicates, "data3", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);

    valueObject->destroy(valueObject);
    predicates->destroy(predicates);
    errCode = cursor->destroy(cursor);
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
    valueObject->putText(valueObject, data1Value);
    predicates->equalTo(predicates, "data1", valueObject);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    int rowCount = 0;
    errCode = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 1);
    errCode = cursor->destroy(cursor);

    predicates->clear(predicates);
    predicates->notEqualTo(predicates, "data1", valueObject);
    cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    errCode = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 2);

    valueObject->destroy(valueObject);
    predicates->destroy(predicates);
    cursor->destroy(cursor);
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
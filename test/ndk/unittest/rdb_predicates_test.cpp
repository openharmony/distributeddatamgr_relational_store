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
#include "relational_store_error_code.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbNativePredicatesTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static void InitRdbConfig()
    {
        config_.dataBaseDir = RDB_TEST_PATH;
        config_.storeName = "rdb_predicates_test.db";
        config_.bundleName = "com.ohos.example.distributedndk";
        config_.moduleName = "";
        config_.securityLevel = OH_Rdb_SecurityLevel::S1;
        config_.isEncrypt = false;
        config_.selfSize = sizeof(OH_Rdb_Config);
    }
    static OH_Rdb_Config config_;
};

OH_Rdb_Store *predicatesTestRdbStore_;
OH_Rdb_Config RdbNativePredicatesTest::config_ = {0};
void RdbNativePredicatesTest::SetUpTestCase(void)
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

void RdbNativePredicatesTest::TearDownTestCase(void)
{
    char dropTableSql[] = "DROP TABLE IF EXISTS test";
    int errCode = OH_Rdb_Execute(predicatesTestRdbStore_, dropTableSql);
    EXPECT_EQ(errCode, 0);
    delete predicatesTestRdbStore_;
    predicatesTestRdbStore_ = NULL;
    OH_Rdb_DeleteStore(&config_);
}

void RdbNativePredicatesTest::SetUp(void)
{
}

void RdbNativePredicatesTest::TearDown(void)
{
}

/**
 * @tc.name: RDB_Native_predicates_test_001
 * @tc.desc: Normal testCase of Predicates for EqualTo、AndOR、beginWrap and endWrap
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativePredicatesTest, RDB_Native_predicates_test_001, TestSize.Level1)
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
 * @tc.name: RDB_Native_predicates_test_002
 * @tc.desc: Normal testCase of Predicates for NotEqualTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativePredicatesTest, RDB_Native_predicates_test_002, TestSize.Level1)
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
 * @tc.name: RDB_Native_predicates_test_003
 * @tc.desc: Normal testCase of Predicates for GreaterThan
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativePredicatesTest, RDB_Native_predicates_test_003, TestSize.Level1)
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

    valueObject->destroy(valueObject);
    predicates->destroy(predicates);
    cursor->destroy(cursor);
}

/**
 * @tc.name: RDB_Native_predicates_test_004
 * @tc.desc: Normal testCase of Predicates for GreaterThanOrEqualTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativePredicatesTest, RDB_Native_predicates_test_004, TestSize.Level1)
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
 * @tc.name: RDB_Native_predicates_test_005
 * @tc.desc: Normal testCase of Predicates for LessThan
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativePredicatesTest, RDB_Native_predicates_test_005, TestSize.Level1)
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
 * @tc.name: RDB_Native_predicates_test_006
 * @tc.desc: Normal testCase of Predicates for LessThanOrEqualTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativePredicatesTest, RDB_Native_predicates_test_006, TestSize.Level1)
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
 * @tc.name: RDB_Native_predicates_test_007
 * @tc.desc: Normal testCase of Predicates for IsNull.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativePredicatesTest, RDB_Native_predicates_test_007, TestSize.Level1)
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
 * @tc.name: RDB_Native_predicates_test_008
 * @tc.desc: Normal testCase of Predicates for IsNull.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativePredicatesTest, RDB_Native_predicates_test_008, TestSize.Level1)
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
 * @tc.name: RDB_Native_predicates_test_009
 * @tc.desc: Normal testCase of Predicates for Between
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativePredicatesTest, RDB_Native_predicates_test_009, TestSize.Level1)
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
 * @tc.name: RDB_Native_predicates_test_010
 * @tc.desc: Normal testCase of Predicates for NotBetween
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativePredicatesTest, RDB_Native_predicates_test_010, TestSize.Level1)
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
 * @tc.name: RDB_Native_predicates_test_011
 * @tc.desc: Normal testCase of Predicates for OrderBy、Limit、Offset.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativePredicatesTest, RDB_Native_predicates_test_011, TestSize.Level1)
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
 * @tc.name: RDB_Native_predicates_test_012
 * @tc.desc: Normal testCase of Predicates for In.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativePredicatesTest, RDB_Native_predicates_test_012, TestSize.Level1)
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
 * @tc.name: RDB_Native_predicates_test_013
 * @tc.desc: Normal testCase of Predicates for NotIn.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativePredicatesTest, RDB_Native_predicates_test_013, TestSize.Level1)
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
 * @tc.name: RDB_Native_predicates_test_014
 * @tc.desc: Normal testCase of Predicates for Like.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativePredicatesTest, RDB_Native_predicates_test_014, TestSize.Level1)
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
 * @tc.name: RDB_Native_predicates_test_015
 * @tc.desc: Normal testCase of Predicates for GroupBy.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativePredicatesTest, RDB_Native_predicates_test_015, TestSize.Level1)
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
 * @tc.name: RDB_Native_predicates_test_016
 * @tc.desc: Normal testCase of Predicates for And.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativePredicatesTest, RDB_Native_predicates_test_016, TestSize.Level1)
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
 * @tc.name: RDB_Native_predicates_test_017
 * @tc.desc: Normal testCase of Predicates for Clear.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativePredicatesTest, RDB_Native_predicates_test_017, TestSize.Level1)
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
 * @tc.name: RDB_Native_predicates_test_018
 * @tc.desc: Normal testCase of Predicates for table name is NULL.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativePredicatesTest, RDB_Native_predicates_test_018, TestSize.Level1)
{
    char *table = NULL;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table);
    EXPECT_EQ(predicates, NULL);

    OH_Cursor *cursor = OH_Rdb_Query(predicatesTestRdbStore_, predicates, NULL, 0);
    EXPECT_EQ(cursor, NULL);
}

/**
 * @tc.name: RDB_Native_predicates_test_019
 * @tc.desc: Normal testCase of Predicates for anomalous branch.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativePredicatesTest, RDB_Native_predicates_test_019, TestSize.Level1)
{
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    EXPECT_NE(predicates, NULL);

    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    valueObject->putText(valueObject, data1Value);
    predicates->equalTo(nullptr, "data1", valueObject);
    predicates->equalTo(predicates, nullptr, valueObject);
    predicates->equalTo(predicates, "data1", nullptr);
    predicates->notEqualTo(nullptr, "data1", valueObject);
    predicates->notEqualTo(predicates, nullptr, valueObject);
    predicates->notEqualTo(predicates, "data1", nullptr);

    predicates->beginWrap(nullptr);
    predicates->endWrap(nullptr);

    predicates->orOperate(nullptr);
    predicates->andOperate(nullptr);

    predicates->isNull(nullptr, "data4");
    predicates->isNull(predicates, nullptr);
    predicates->isNotNull(nullptr, "data4");
    predicates->isNotNull(predicates, nullptr);

    const char *data5ValueLike = "ABCD%";
    valueObject->putText(valueObject, data5ValueLike);
    predicates->like(nullptr, "data5", valueObject);
    predicates->like(predicates, nullptr, valueObject);
    predicates->like(predicates, "data5", nullptr);

    int64_t data2Value[] = {12000, 13000};
    uint32_t len = sizeof(data2Value) / sizeof(data2Value[0]);
    valueObject->putInt64(valueObject, data2Value, len);
    predicates->between(nullptr, "data2", valueObject);
    predicates->between(predicates, nullptr, valueObject);
    predicates->between(predicates, "data2", nullptr);
    predicates->notBetween(nullptr, "data2", valueObject);
    predicates->notBetween(predicates, nullptr, valueObject);
    predicates->notBetween(predicates, "data2", nullptr);
    int64_t data2Value_1[] = {12000};
    len = sizeof(data2Value_1) / sizeof(data2Value_1[0]);
    valueObject->putInt64(valueObject, data2Value_1, len);
    predicates->between(predicates, "data2", valueObject);
    predicates->notBetween(predicates, "data2", valueObject);

    valueObject->destroy(valueObject);
    predicates->destroy(predicates);
}

/**
 * @tc.name: RDB_Native_predicates_test_020
 * @tc.desc: Normal testCase of Predicates for anomalous branch.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativePredicatesTest, RDB_Native_predicates_test_020, TestSize.Level1)
{
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    EXPECT_NE(predicates, NULL);

    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    valueObject->putText(valueObject, data1Value);

    const char *data5Value = "ABCDEFG";
    valueObject->putText(valueObject, data5Value);
    predicates->greaterThan(nullptr, "data5", valueObject);
    predicates->greaterThan(predicates, nullptr, valueObject);
    predicates->greaterThan(predicates, "data5", nullptr);
    predicates->lessThan(nullptr, "data5", valueObject);
    predicates->lessThan(predicates, nullptr, valueObject);
    predicates->lessThan(predicates, "data5", nullptr);
    predicates->greaterThanOrEqualTo(nullptr, "data5", valueObject);
    predicates->greaterThanOrEqualTo(predicates, nullptr, valueObject);
    predicates->greaterThanOrEqualTo(predicates, "data5", nullptr);
    predicates->lessThanOrEqualTo(nullptr, "data5", valueObject);
    predicates->lessThanOrEqualTo(predicates, nullptr, valueObject);
    predicates->lessThanOrEqualTo(predicates, "data5", nullptr);

    predicates->orderBy(nullptr, "data2", OH_OrderType::ASC);
    predicates->orderBy(predicates, nullptr, OH_OrderType::ASC);

    predicates->distinct(nullptr);
    predicates->limit(nullptr, 1);
    predicates->offset(nullptr, 1);

    const char *columnNames[] = {"data1", "data2"};
    uint32_t len = sizeof(columnNames) / sizeof(columnNames[0]);
    predicates->groupBy(nullptr, columnNames, len);
    predicates->groupBy(predicates, nullptr, len);
    predicates->groupBy(predicates, columnNames, 0);

    const char *data1ValueIn[] = {"zhangSan", "liSi"};
    len = sizeof(data1ValueIn) / sizeof(data1ValueIn[0]);
    valueObject->putTexts(valueObject, data1ValueIn, len);
    predicates->in(nullptr, "data1", valueObject);
    predicates->in(predicates, nullptr, valueObject);
    predicates->in(predicates, "data1", nullptr);
    predicates->notIn(nullptr, "data1", valueObject);
    predicates->notIn(predicates, nullptr, valueObject);
    predicates->notIn(predicates, "data1", nullptr);

    predicates->clear(nullptr);
    int errCode = predicates->destroy(nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    valueObject->destroy(valueObject);
    predicates->destroy(predicates);
}

/**
 * @tc.name: RDB_Native_predicates_test_021
 * @tc.desc: Normal testCase of RelationalPredicatesObjects for anomalous branch.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativePredicatesTest, RDB_Native_predicates_test_021, TestSize.Level1)
{
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    int64_t data2Value[] = {12000, 13000};
    uint32_t len = sizeof(data2Value) / sizeof(data2Value[0]);
    int errCode = valueObject->putInt64(nullptr, data2Value, len);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = valueObject->putInt64(valueObject, nullptr, len);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = valueObject->putInt64(valueObject, data2Value, 0);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    uint32_t count = 1;
    double data3Value = 200.1;
    errCode = valueObject->putDouble(nullptr, &data3Value, count);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = valueObject->putDouble(valueObject, nullptr, count);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = valueObject->putDouble(valueObject, &data3Value, 0);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    const char *data1Value = "zhangSan";
    valueObject->putText(nullptr, data1Value);
    valueObject->putText(valueObject, nullptr);

    const char *data1ValueTexts[] = {"zhangSan", "liSi"};
    len = sizeof(data1ValueTexts) / sizeof(data1ValueTexts[0]);
    errCode = valueObject->putTexts(nullptr, data1ValueTexts, len);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = valueObject->putTexts(valueObject, nullptr, len);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = valueObject->putTexts(valueObject, data1ValueTexts, 0);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    errCode = valueObject->destroy(nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    valueObject->destroy(valueObject);
}
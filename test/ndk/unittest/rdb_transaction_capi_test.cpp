/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <sys/stat.h>
#include <sys/types.h>
#include <string>
#include "relational_store.h"
#include "oh_values_bucket.h"
#include "oh_values_bucket.h"
#include "common.h"
#include "relational_store_error_code.h"
#include "oh_data_values.h"
#include "oh_data_value.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbTransactionCapiTest : public testing::Test {
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
};

static OH_Rdb_Store *g_transStore;
static OH_RDB_TransOptions *g_options;
OH_Rdb_Config RdbTransactionCapiTest::config_ = { 0 };

void RdbTransactionCapiTest::SetUpTestCase(void)
{
    InitRdbConfig();
    int chmodValue = 0770;
    mkdir(config_.dataBaseDir, chmodValue);
    int errCode = 0;
    char table[] = "test";
    g_transStore = OH_Rdb_GetOrOpen(&config_, &errCode);
    EXPECT_NE(g_transStore, NULL);

    char createTableSql[] = "CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    errCode = OH_Rdb_Execute(g_transStore, createTableSql);

    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 1);
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    // init row one data2 value 12800
    valueBucket->putInt64(valueBucket, "data2", 12800);
    // init row one data3 value 100.1
    valueBucket->putReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = { 1, 2, 3, 4, 5 };
    int len = sizeof(arr) / sizeof(arr[0]);
    valueBucket->putBlob(valueBucket, "data4", arr, len);
    valueBucket->putText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(g_transStore, table, valueBucket);
    // expect value is 1
    EXPECT_EQ(errCode, 1);

    valueBucket->clear(valueBucket);
    // init row two id value 2
    valueBucket->putInt64(valueBucket, "id", 2);
    valueBucket->putText(valueBucket, "data1", "liSi");
    // init row two data2 value 13800
    valueBucket->putInt64(valueBucket, "data2", 13800);
    // init row two data2 value 200.1
    valueBucket->putReal(valueBucket, "data3", 200.1);
    valueBucket->putText(valueBucket, "data5", "ABCDEFGH");
    errCode = OH_Rdb_Insert(g_transStore, table, valueBucket);
    // expect value is 2
    EXPECT_EQ(errCode, 2);

    valueBucket->clear(valueBucket);
    // init row three id value 3
    valueBucket->putInt64(valueBucket, "id", 3);
    valueBucket->putText(valueBucket, "data1", "wangWu");
    // init row three data2 value 14800
    valueBucket->putInt64(valueBucket, "data2", 14800);
    // init row three data3 value 300.1
    valueBucket->putReal(valueBucket, "data3", 300.1);
    valueBucket->putText(valueBucket, "data5", "ABCDEFGHI");
    errCode = OH_Rdb_Insert(g_transStore, table, valueBucket);
    // expect value is 3
    EXPECT_EQ(errCode, 3);

    valueBucket->destroy(valueBucket);

    g_options = OH_RdbTrans_CreateOptions();
    EXPECT_NE(g_options, nullptr);
    int ret = OH_RdbTransOption_SetType(g_options, RDB_TRANS_BUTT);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    ret = OH_RdbTransOption_SetType(g_options, RDB_TRANS_DEFERRED);
    EXPECT_EQ(ret, RDB_OK);
}

void RdbTransactionCapiTest::TearDownTestCase(void)
{
    char dropTableSql[] = "DROP TABLE IF EXISTS test";
    int errCode = OH_Rdb_Execute(g_transStore, dropTableSql);
    EXPECT_EQ(errCode, 0);
    delete g_transStore;
    g_transStore = NULL;
    OH_Rdb_DeleteStore(&config_);
    OH_RdbTrans_DestroyOptions(g_options);
    g_options = nullptr;
}

void RdbTransactionCapiTest::SetUp(void)
{
}

void RdbTransactionCapiTest::TearDown(void)
{
}

static void FillDataValues(OH_Data_Values *values)
{
    EXPECT_NE(values, nullptr);
    OH_Data_Value *value = OH_Value_Create();
    int ret = OH_Value_PutInt(nullptr, 1);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    ret = OH_Value_PutInt(value, 1);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_Values_Put(nullptr, value);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    ret = OH_Values_Put(values, nullptr);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    ret = OH_Values_Put(values, value);
    EXPECT_EQ(ret, RDB_OK);
    ret = OH_Value_Destroy(value);
    EXPECT_EQ(ret, RDB_OK);

    // Add int value 2 to values
    ret = OH_Values_PutInt(values, 2);
    EXPECT_EQ(ret, RDB_OK);
    // Add double value 1.1 to values
    ret = OH_Values_PutReal(values, 1.1);
    EXPECT_EQ(ret, RDB_OK);
    ret = OH_Values_PutText(values, "1");
    EXPECT_EQ(ret, RDB_OK);
    // init unsigend char 1 and 2
    unsigned char val[] = {1, 2};
    ret = OH_Values_PutBlob(values, val, sizeof(val) / sizeof(val[0]));
    EXPECT_EQ(ret, RDB_OK);

    // asset
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    ret = OH_Data_Asset_SetName(asset, "name");
    EXPECT_EQ(ret, RDB_OK);
    ret = OH_Values_PutAsset(values, asset);
    EXPECT_EQ(ret, RDB_OK);
    OH_Data_Asset_DestroyOne(asset);

    // asset array
    Data_Asset **assets = OH_Data_Asset_CreateMultiple(2);
    ret = OH_Data_Asset_SetName(assets[0], "name1");
    EXPECT_EQ(ret, RDB_OK);
    ret = OH_Data_Asset_SetName(assets[1], "name2");
    EXPECT_EQ(ret, RDB_OK);
    // 2 elements in assets
    ret = OH_Values_PutAssets(values, assets, 2);
    EXPECT_EQ(ret, RDB_OK);
    // 2 elements in assets
    ret = OH_Data_Asset_DestroyMultiple(assets, 2);
    EXPECT_EQ(ret, RDB_OK);

    // big int
    uint64_t bigInt[] = {1, 2, 3, 4, 5};
    ret = OH_Values_PutUnlimitedInt(values, 0, bigInt, sizeof(bigInt) / sizeof(bigInt[0]));
    EXPECT_EQ(ret, RDB_OK);
}

static void ReadDataValuesPartOne(OH_Data_Values *values)
{
    // read
    size_t readSize = 0;
    int ret = OH_Values_Count(values, &readSize);
    EXPECT_EQ(ret, RDB_OK);
    // ecpect value is 8
    EXPECT_EQ(readSize, 8);

    OH_ColumnType columnType;
    ret = OH_Values_GetType(values, 0, &columnType);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(columnType, TYPE_INT64);

    OH_Data_Value *readData0 = nullptr;
    ret = OH_Values_Get(values, 0, &readData0);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(readData0, nullptr);

    bool isNull;
    ret = OH_Values_IsNull(values, 0, &isNull);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(isNull, false);

    int64_t readData1;
    // index 1 in values array
    ret = OH_Values_GetInt(values, 1, &readData1);
    EXPECT_EQ(ret, RDB_OK);
    // ecpect value is 2
    EXPECT_EQ(readData1, 2);

    double readData2;
    // index 2 in values array
    ret = OH_Values_GetReal(values, 2, &readData2);
    EXPECT_EQ(ret, RDB_OK);
    // ecpect value is 1.1
    EXPECT_EQ(readData2, 1.1);

    const char *readData3 = nullptr;
    // index 3 in values array
    ret = OH_Values_GetText(values, 3, &readData3);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(strcmp(readData3, "1"), 0);

    const uint8_t *readData4 = nullptr;
    size_t len4;
    // index 43 in values array
    ret = OH_Values_GetBlob(values, 4, &readData4, &len4);
    EXPECT_EQ(ret, RDB_OK);
    // ecpect len is 2
    EXPECT_EQ(len4, 2);
    EXPECT_EQ(readData4[0], 1);
    // ecpect value is 2
    EXPECT_EQ(readData4[1], 2);
}

static void ReadDataValuesPartTwo(OH_Data_Values *values)
{
    Data_Asset *readData5 = OH_Data_Asset_CreateOne();
    EXPECT_NE(readData5, nullptr);
    OH_ColumnType columnType5;
    // index 5 in values array
    int ret = OH_Values_GetType(values, 5, &columnType5);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(columnType5, TYPE_ASSET);
    // index 5 in values array
    ret = OH_Values_GetAsset(values, 5, readData5);
    EXPECT_EQ(ret, RDB_OK);
    char readDataName[32];
    size_t length5 = 32;
    ret = OH_Data_Asset_GetName(readData5, readDataName, &length5);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(strcmp(readDataName, "name"), 0);
    // expect string length is 4
    EXPECT_EQ(length5, 4);
    OH_Data_Asset_DestroyOne(readData5);

    size_t readDataCount6;
    // index 6 in values array
    ret = OH_Values_GetAssetsCount(values, 6, &readDataCount6);
    EXPECT_EQ(ret, RDB_OK);
    // 2 is two element in data.
    EXPECT_EQ(readDataCount6, 2);

    Data_Asset **readData6 = OH_Data_Asset_CreateMultiple(2);
    EXPECT_NE(readData6, nullptr);
    size_t out6;
    // index 6 in values array, 2 is two element in data.
    ret = OH_Values_GetAssets(values, 6, readData6, 2, &out6);
    EXPECT_EQ(ret, RDB_OK);
    // expect value is 2
    EXPECT_EQ(out6, 2);
    // 2 is two element in data.
    OH_Data_Asset_DestroyMultiple(readData6, 2);

    size_t readDataLen7;
    // index 7 in values array
    ret = OH_Values_GetUnlimitedIntBand(values, 7, &readDataLen7);
    EXPECT_EQ(ret, RDB_OK);
    // expect value is 5
    EXPECT_EQ(readDataLen7, 5);

    int readDataSign7;
    uint64_t readData7[5];
    size_t outLen;
    // index 7 in values array, 5 is input memory length.
    ret = OH_Values_GetUnlimitedInt(values, 7, &readDataSign7, readData7, 5, &outLen);
    EXPECT_EQ(ret, RDB_OK);
    // expect value is 5
    EXPECT_EQ(outLen, 5);
    EXPECT_EQ(readDataSign7, 0);
    EXPECT_EQ(readData7[0], 1);
    // expect value is 5, 4 is index.
    EXPECT_EQ(readData7[4], 5);
}

/**
 * @tc.name: RDB_Transaction_capi_test_001
 * @tc.desc: Normal testCase of store transaction for create.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_001, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);
}

/**
 * @tc.name: RDB_Transaction_capi_test_002
 * @tc.desc: Normal testCase of store transaction for create and OH_RdbTrans_Commit
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_002, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;
    const char *table = "test";
    int ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    // init is value is 4
    valueBucket->putInt64(valueBucket, "id", 4);
    valueBucket->putText(valueBucket, "data1", "test_name4");
    // init is data2 is 14800
    valueBucket->putInt64(valueBucket, "data2", 14800);
    // init is data3 is 300.1
    valueBucket->putReal(valueBucket, "data3", 300.1);
    valueBucket->putText(valueBucket, "data5", "ABCDEFGHI");
    int64_t rowId = -1;
    ret = OH_RdbTrans_Insert(trans, table, valueBucket, &rowId);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(rowId, 4);

    valueBucket->destroy(valueBucket);
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_003
 * @tc.desc: Normal testCase of store transaction for insert and OH_RdbTrans_Rollback
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_003, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;
    const char *table = "test";
    int ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putText(valueBucket, "data1", "test_name4");
    // init is data2 is 14800
    valueBucket->putInt64(valueBucket, "data2", 14800);
    // init is data2 is 300.1
    valueBucket->putReal(valueBucket, "data3", 300.1);
    valueBucket->putText(valueBucket, "data5", "ABCDEFGHI");
    int64_t rowId = -1;
    ret = OH_RdbTrans_Insert(trans, table, valueBucket, &rowId);
    EXPECT_EQ(ret, RDB_OK);
    // expect value is 4
    EXPECT_EQ(rowId, 4);

    ret = OH_RdbTrans_Rollback(trans);
    EXPECT_EQ(ret, RDB_OK);

    valueBucket->destroy(valueBucket);
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_004
 * @tc.desc: Normal testCase of store transaction for OH_RdbTrans_BatchInsert
 * OH_VBuckets_RowCount, OH_VBuckets_PutRow, OH_RdbTrans_Destroy, OH_VBuckets_Destroy
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_004, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;
    const char *table = "test";
    int ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    // data row1
    OH_VBucket *row1 = OH_Rdb_CreateValuesBucket();
    EXPECT_NE(row1, nullptr);
    row1->putInt64(row1, "id", 4);
    row1->putText(row1, "data1", "test_name4");
    row1->putInt64(row1, "data2", 14800);
    row1->putReal(row1, "data3", 300.1);
    row1->putText(row1, "data5", "ABCDEFGHI");

    // data row2
    OH_VBucket *row2 = OH_Rdb_CreateValuesBucket();
    EXPECT_NE(row2, nullptr);
    row2->putInt64(row2, "id", 5);
    row2->putText(row2, "data1", "test_name5");
    row2->putInt64(row2, "data2", 15800);
    row2->putReal(row2, "data3", 500.1);
    row2->putText(row2, "data5", "ABCDEFGHI");

    // create rows
    OH_Data_VBuckets *rows = OH_VBuckets_Create();
    EXPECT_NE(rows, nullptr);
    
    // add row1 to rows
    ret = OH_VBuckets_PutRow(rows, row1);
    EXPECT_EQ(ret, RDB_OK);
    size_t count = -1;
    ret = OH_VBuckets_RowCount(rows, &count);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(count, 1);

    // add row2 to rows
    ret = OH_VBuckets_PutRow(rows, row2);
    EXPECT_EQ(ret, RDB_OK);
    ret = OH_VBuckets_RowCount(rows, &count);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(count, 2);

    // batch insert
    int64_t changes = -1;
    ret = OH_RdbTrans_BatchInsert(trans, table, rows, RDB_CONFLICT_NONE, &changes);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(changes, 2);


    // destroy
    row1->destroy(row1);
    row2->destroy(row2);
    ret = OH_VBuckets_Destroy(rows);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_005
 * @tc.desc: Normal testCase of store transaction for OH_RdbTrans_BatchInsert
 * OH_VBuckets_RowCount, OH_VBuckets_PutRows, OH_RdbTrans_Destroy, OH_VBuckets_Destroy
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_005, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;
    const char *table = "test";
    int ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    // data row1
    OH_VBucket *row1 = OH_Rdb_CreateValuesBucket();
    EXPECT_NE(row1, nullptr);
    row1->putInt64(row1, "id", 4);
    row1->putText(row1, "data1", "test_name4");
    row1->putInt64(row1, "data2", 14800);
    row1->putReal(row1, "data3", 300.1);
    row1->putText(row1, "data5", "ABCDEFGHI");

    // data row2
    OH_VBucket *row2 = OH_Rdb_CreateValuesBucket();
    EXPECT_NE(row2, nullptr);
    row2->putInt64(row2, "id", 5);
    row2->putText(row2, "data1", "test_name5");
    row2->putInt64(row2, "data2", 15800);
    row2->putReal(row2, "data3", 500.1);
    row2->putText(row2, "data5", "ABCDEFGHI");

    // create rows
    OH_Data_VBuckets *rows = OH_VBuckets_Create();
    EXPECT_NE(rows, nullptr);

    // add row1 to rows
    ret = OH_VBuckets_PutRow(rows, row1);
    EXPECT_EQ(ret, RDB_OK);
    size_t count = -1;
    ret = OH_VBuckets_RowCount(rows, &count);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(count, 1);

    // add row2 to rows
    ret = OH_VBuckets_PutRow(rows, row2);
    EXPECT_EQ(ret, RDB_OK);
    ret = OH_VBuckets_RowCount(rows, &count);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(count, 2);


    // create rows
    OH_Data_VBuckets *rows2 = OH_VBuckets_Create();
    EXPECT_NE(rows, nullptr);
    ret = OH_VBuckets_PutRows(rows2, rows);
    EXPECT_EQ(ret, RDB_OK);

    // destroy rows
    ret = OH_VBuckets_Destroy(rows);
    EXPECT_EQ(ret, RDB_OK);

    // batch insert
    int64_t changes = -1;
    ret = OH_RdbTrans_BatchInsert(trans, table, rows2, RDB_CONFLICT_REPLACE, &changes);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(changes, 2);


    // destroy
    row1->destroy(row1);
    row2->destroy(row2);
    ret = OH_VBuckets_Destroy(rows2);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_006
 * @tc.desc: Normal testCase of store transaction for OH_RdbTrans_Update
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_006, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;
    const char *table = "test";
    int ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    // new row
    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putText(valueBucket, "data1", "liSi");
    // init data2 value is 13800
    valueBucket->putInt64(valueBucket, "data2", 13800);
    // init data3 value is 200.1
    valueBucket->putReal(valueBucket, "data3", 200.1);
    valueBucket->putNull(valueBucket, "data5");

    // create predicates
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table);
    // create match data
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    valueObject->putText(valueObject, data1Value);
    predicates->equalTo(predicates, "data1", valueObject);

    // update
    int64_t changes = -1;
    ret = OH_RdbTrans_Update(trans, valueBucket, predicates, &changes);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(changes, 1);

    // destroy
    valueObject->destroy(valueObject);
    valueBucket->destroy(valueBucket);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_007
 * @tc.desc: Normal testCase of store transaction for OH_RdbTrans_Delete
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_007, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;
    const char *table = "test";
    int ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    // create predicates
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table);
    // create match data
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "liSi";
    valueObject->putText(valueObject, data1Value);
    predicates->equalTo(predicates, "data1", valueObject);

    // update
    int64_t changes = -1;
    ret = OH_RdbTrans_Delete(trans, predicates, &changes);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(changes, 1);

    // destroy
    valueObject->destroy(valueObject);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_008
 * @tc.desc: Normal testCase of store transaction for OH_RdbTrans_Query
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_008, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;
    const char *table = "test";
    int ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    // create predicates
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table);
    
    const char *columns[] = {"id", "data1"};
    // check args;
    OH_Cursor *cursor = OH_RdbTrans_Query(nullptr, predicates, columns, 2);
    EXPECT_EQ(cursor, nullptr);
    cursor = OH_RdbTrans_Query(trans, nullptr, columns, 2);
    EXPECT_EQ(cursor, nullptr);

    cursor = OH_RdbTrans_Query(trans, predicates, nullptr, 0);
    EXPECT_NE(cursor, nullptr);

    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 3);

    ret = cursor->goToNextRow(cursor);
    EXPECT_EQ(ret, 0);

    int64_t id;
    cursor->getInt64(cursor, 0, &id);
    EXPECT_EQ(id, 1);

    char data1[15];
    cursor->getText(cursor, 1, data1, 15);
    EXPECT_EQ(strcmp(data1, "zhangSan"), 0);

    int64_t data2;
    cursor->getInt64(cursor, 2, &data2);
    EXPECT_EQ(data2, 12800);

    // destroy
    cursor->destroy(cursor);
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_009
 * @tc.desc: Normal testCase of store transaction for OH_RdbTrans_QuerySql, OH_Data_Values, OH_Data_Value,
 * OH_RdbTrans_Execute
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_009, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    char createTableSql[] = "CREATE TABLE transaction_table (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 INTEGER, "
        "data2 INTEGER, data3 FLOAT, data4 TEXT, data5 BLOB, data6 ASSET, data7 ASSETS, data8 UNLIMITED INT, "
        "data9 FLOATVECTOR);";
    ret = OH_Rdb_Execute(g_transStore, createTableSql);
    EXPECT_EQ(ret, RDB_OK);

    const char *sql = "SELECT id, data1 FROM transaction_table";
    // check args;
    OH_Cursor *cursor = OH_RdbTrans_QuerySql(nullptr, sql, nullptr);
    EXPECT_EQ(cursor, nullptr);
    cursor = OH_RdbTrans_QuerySql(trans, nullptr, nullptr);
    EXPECT_EQ(cursor, nullptr);

    cursor = OH_RdbTrans_QuerySql(trans, sql, nullptr);
    EXPECT_NE(cursor, nullptr);
    cursor->destroy(cursor);

    // create OH_Data_Values
    OH_Data_Values *values = OH_Values_Create();
    FillDataValues(values);

    const char *insertSql = "INSERT INTO transaction_table "
        "(data1, data2, data3, data4, data5, data6, data7, data8) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    OH_Data_Value *outValue = nullptr;
    ret = OH_RdbTrans_Execute(trans, insertSql, values, &outValue);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(outValue, nullptr);
    ret = OH_Value_Destroy(outValue);
    EXPECT_EQ(ret, RDB_OK);
    ret = OH_Values_Destroy(values);
    EXPECT_EQ(ret, RDB_OK);

    const char *querySql = "SELECT * FROM transaction_table WHERE data1=?";
    OH_Data_Values *queryValues = OH_Values_Create();
    EXPECT_NE(queryValues, nullptr);
    ret = OH_Values_PutInt(queryValues, 1);
    EXPECT_EQ(ret, RDB_OK);
    OH_Cursor *cursorEnd = OH_RdbTrans_QuerySql(trans, querySql, queryValues);
    EXPECT_NE(cursorEnd, nullptr);
    int rowCount = 0;
    cursorEnd->getRowCount(cursorEnd, &rowCount);
    EXPECT_EQ(rowCount, 1);
    ret = OH_Values_Destroy(queryValues);
    EXPECT_EQ(ret, RDB_OK);
    cursorEnd->destroy(cursorEnd);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_010
 * @tc.desc: Normal testCase of store transaction for OH_Data_Values
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_010, TestSize.Level1)
{
    OH_Data_Values *values = OH_Values_Create();
    FillDataValues(values);
    ReadDataValuesPartOne(values);
    ReadDataValuesPartTwo(values);
    // destroy
    int ret = OH_Values_Destroy(values);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_011
 * @tc.desc: Normal testCase of store transaction for OH_Data_Values
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_011, TestSize.Level1)
{
    OH_Data_Value *value = OH_Value_Create();
    EXPECT_NE(value, nullptr);
    float floatArr[] = {1.0, 2.0, 3.0};
    int ret = OH_Value_PutFloatVector(value, nullptr, 0);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    ret = OH_Value_PutFloatVector(value, floatArr, 3);
    EXPECT_EQ(ret, RDB_OK);

    OH_ColumnType type;
    ret = OH_Value_GetType(value, &type);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(type, TYPE_FLOAT_VECTOR);
    ret = OH_Value_GetType(nullptr, &type);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    ret = OH_Value_GetType(value, nullptr);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    size_t length;
    ret = OH_Value_GetFloatVectorCount(value, &length);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(length, 3);
    float retArray[10];
    size_t outLen;
    ret = OH_Value_GetFloatVector(value, retArray, 10, &outLen);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(outLen, 3);
    EXPECT_EQ(retArray[0], 1.0);
    ret = OH_Value_Destroy(value);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_012
 * @tc.desc: Normal testCase of store transaction for OH_Data_Value
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_012, TestSize.Level1)
{
    OH_Data_Value *value = OH_Value_Create();
    EXPECT_NE(value, nullptr);
    float floatArr[] = {1.0, 2.0, 3.0};
    int ret = OH_Value_PutFloatVector(value, nullptr, 0);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    ret = OH_Value_PutFloatVector(value, floatArr, 0);
    EXPECT_EQ(ret, RDB_OK);

    size_t length;
    ret = OH_Value_GetFloatVectorCount(value, &length);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(length, 0);
    double realValue;
    ret = OH_Value_GetReal(value, &realValue);
    EXPECT_EQ(ret, RDB_E_TYPE_MISMATCH);

    ret = OH_Value_PutNull(value);
    EXPECT_EQ(ret, RDB_OK);
    ret = OH_Value_PutNull(nullptr);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    double val = 1;
    ret = OH_Value_PutReal(nullptr, val);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    ret = OH_Value_PutAsset(nullptr, asset);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    ret = OH_Value_PutAsset(value, nullptr);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    Data_Asset **assets = OH_Data_Asset_CreateMultiple(2);
    ret = OH_Value_PutAssets(nullptr, assets, 0);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    ret = OH_Value_PutAssets(value, assets, 0);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    bool isNull;
    ret = OH_Value_IsNull(nullptr, &isNull);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    ret = OH_Value_IsNull(value, nullptr);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    ret = OH_Value_GetReal(value, &realValue);
    EXPECT_EQ(ret, RDB_E_DATA_TYPE_NULL);
    ret = OH_Value_Destroy(value);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_013
 * @tc.desc: Normal testCase of OH_VBucket_PutFloatVector
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_013, TestSize.Level1)
{
    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    EXPECT_NE(valueBucket, nullptr);
    float floatArr[] = { 1.0, 2.0, 3.0 };
    int ret = OH_VBucket_PutFloatVector(valueBucket, "data1", floatArr, 0);
    EXPECT_EQ(ret, RDB_OK);
    ret = OH_VBucket_PutFloatVector(valueBucket, "data2", floatArr, 3);
    EXPECT_EQ(ret, RDB_OK);
    valueBucket->destroy(valueBucket);
}

/**
 * @tc.name: RDB_Transaction_capi_test_014
 * @tc.desc: Normal testCase of OH_VBucket_PutUnlimitedInt
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_014, TestSize.Level1)
{
    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    EXPECT_NE(valueBucket, nullptr);
    uint64_t trueForm[] = { 1, 2, 3 };
    int ret = OH_VBucket_PutUnlimitedInt(valueBucket, "data1", 0, trueForm, 0);
    EXPECT_EQ(ret, RDB_OK);
    ret = OH_VBucket_PutUnlimitedInt(valueBucket, "data2", 1, trueForm, 3);
    EXPECT_EQ(ret, RDB_OK);
    valueBucket->destroy(valueBucket);
}

/**
 * @tc.name: RDB_Transaction_capi_test_015
 * @tc.desc: invalid args test
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_015, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);
    ret = OH_Rdb_CreateTransaction(g_transStore, g_options, nullptr);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    ret = OH_Rdb_CreateTransaction(g_transStore, nullptr, &trans);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    ret = OH_Rdb_CreateTransaction(nullptr, g_options, &trans);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    EXPECT_NE(valueBucket, nullptr);
    float floatArr[] = { 1.0, 2.0, 3.0 };
    ret = OH_VBucket_PutFloatVector(nullptr, "data1", floatArr, 0);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    ret = OH_VBucket_PutFloatVector(valueBucket, nullptr, floatArr, 0);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    ret = OH_VBucket_PutFloatVector(valueBucket, "data1", nullptr, 0);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    uint64_t trueForm[] = { 1, 2, 3 };
    ret = OH_VBucket_PutUnlimitedInt(nullptr, "data1", 0, trueForm, 0);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    ret = OH_VBucket_PutUnlimitedInt(valueBucket, nullptr, 0, trueForm, 0);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    ret = OH_VBucket_PutUnlimitedInt(valueBucket, "data1", 0, nullptr, 0);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    ret = valueBucket->destroy(valueBucket);
    EXPECT_EQ(ret, RDB_OK);
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_016
 * @tc.desc: Normal testCase of store transaction for OH_RdbTrans_InsertWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_016, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;
    const char *table = "test";
    int ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    // new row
    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putText(valueBucket, "data1", "liSi");
    // init data2 value is 13800
    valueBucket->putInt64(valueBucket, "data2", 13800);
    // init data3 value is 200.1
    valueBucket->putReal(valueBucket, "data3", 200.1);
    valueBucket->putNull(valueBucket, "data5");

    // create predicates
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table);
    // create match data
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    const char *data1Value = "zhangSan";
    valueObject->putText(valueObject, data1Value);
    predicates->equalTo(predicates, "data1", valueObject);

    // update
    int64_t changes = -1;
    ret = OH_RdbTrans_InsertWithConflictResolution(trans, table, valueBucket,
        static_cast<Rdb_ConflictResolution>(0), &changes);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_UpdateWithConflictResolution(trans, valueBucket, predicates, RDB_CONFLICT_REPLACE, &changes);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_EQ(changes, 1);

    // destroy
    valueObject->destroy(valueObject);
    valueBucket->destroy(valueBucket);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}


/**
 * @tc.name: RDB_Transaction_capi_test_017
 * @tc.desc: Normal testCase of store transaction for OH_RdbTrans_InsertWithConflictResolution and OH_RdbTrans_Rollback
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_017, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;
    const char *table = "test";
    int ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putText(valueBucket, "data1", "test_name4");
    // init is data2 is 14800
    valueBucket->putInt64(valueBucket, "data2", 14800);
    // init is data2 is 300.1
    valueBucket->putReal(valueBucket, "data3", 300.1);
    valueBucket->putText(valueBucket, "data5", "ABCDEFGHI");
    int64_t rowId = -1;
    ret = OH_RdbTrans_InsertWithConflictResolution(trans, table, valueBucket,
        static_cast<Rdb_ConflictResolution>(0), &rowId);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_InsertWithConflictResolution(trans, table, valueBucket, RDB_CONFLICT_ROLLBACK, &rowId);
    EXPECT_EQ(ret, RDB_OK);
    // expect value is 4
    EXPECT_EQ(rowId, 4);

    ret = OH_RdbTrans_Rollback(trans);
    EXPECT_EQ(ret, RDB_OK);

    valueBucket->destroy(valueBucket);
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_018
 * @tc.desc: Abnormal testCase of store transaction for OH_Value_PutBlob
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_018, TestSize.Level1)
{
    OH_Data_Value *value = OH_Value_Create();
    ASSERT_NE(value, nullptr);
    const unsigned char val[] = { 0x01, 0x02, 0x03 };
    size_t length = sizeof(val) / sizeof(val[0]);
    int ret = OH_Value_PutBlob(value, nullptr, length);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret = OH_Value_PutBlob(nullptr, val, length);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret = OH_Value_Destroy(value);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_019
 * @tc.desc: Abnormal testCase of store transaction for OH_Value_PutFloatVector
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_019, TestSize.Level1)
{
    OH_Data_Value *value = OH_Value_Create();
    ASSERT_NE(value, nullptr);
    float floatArr[] = { 1.0, 2.0, 3.0 };
    int ret = OH_Value_PutFloatVector(nullptr, floatArr, 3);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    ret = OH_Value_Destroy(value);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_020
 * @tc.desc: Abnormal testCase of store transaction for OH_Value_PutUnlimitedInt
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_020, TestSize.Level1)
{
    OH_Data_Value *value = OH_Value_Create();
    ASSERT_NE(value, nullptr);
    const uint64_t trueForm[] = { 0x01, 0x02, 0x03 };
    size_t length = sizeof(trueForm) / sizeof(trueForm[0]);
    int ret = OH_Value_PutUnlimitedInt(nullptr, 0, trueForm, length);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret = OH_Value_PutUnlimitedInt(value, 2, trueForm, length);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret = OH_Value_PutUnlimitedInt(value, 0, nullptr, length);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret = OH_Value_PutUnlimitedInt(value, 0, trueForm, length);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_Value_Destroy(nullptr);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret = OH_Value_Destroy(value);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_021
 * @tc.desc: Abnormal testCase of store transaction for OH_Data_Asset_CreateMultiple
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_021, TestSize.Level1)
{
    OH_Data_Value *value = OH_Value_Create();
    ASSERT_NE(value, nullptr);
    Data_Asset **assets = OH_Data_Asset_CreateMultiple(2);
    int ret = OH_Data_Asset_DestroyMultiple(assets, 2);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_023
 * @tc.desc: Abnormal testCase of store transaction for OH_Values_PutAssets
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_023, TestSize.Level1)
{
    OH_Data_Values *values = OH_Values_Create();
    ASSERT_NE(values, nullptr);
    // 2 elements in assets
    Data_Asset **assets = OH_Data_Asset_CreateMultiple(2);
    ASSERT_NE(assets, nullptr);
    int ret = OH_Data_Asset_SetName(assets[0], "name1");
    EXPECT_EQ(ret, RDB_OK);
    ret = OH_Data_Asset_SetName(assets[1], "name2");
    EXPECT_EQ(ret, RDB_OK);
    // 2 elements in assets
    ret = OH_Values_PutAssets(nullptr, assets, 2);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    // 2 elements in assets
    ret = OH_Values_PutAssets(values, nullptr, 2);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    // 2 elements in assets
    ret = OH_Values_PutAssets(values, assets, 2);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_Data_Asset_DestroyMultiple(assets, 2);
    EXPECT_EQ(ret, RDB_OK);
    ret = OH_Values_Destroy(values);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_024
 * @tc.desc: Normal testCase of store transaction for OH_RdbTrans_InsertWithConflictResolution and OH_RdbTrans_Commit
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_024, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;
    const char *table = "test";
    int ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    EXPECT_NE(valueBucket, nullptr);
    valueBucket->putText(valueBucket, "data1", "test_name4");
    // init is data2 is 14800
    valueBucket->putInt64(valueBucket, "data2", 14800);
    // init is data2 is 300.1
    valueBucket->putReal(valueBucket, "data3", 300.1);
    valueBucket->putText(valueBucket, "data5", "ABCDEFGHI");
    int64_t rowId = -1;
    ret = OH_RdbTrans_InsertWithConflictResolution(trans, table, valueBucket,
        static_cast<Rdb_ConflictResolution>(0), &rowId);
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_InsertWithConflictResolution(trans, table, valueBucket, RDB_CONFLICT_ROLLBACK, &rowId);
    EXPECT_EQ(ret, RDB_OK);
    // expect value is 4
    EXPECT_EQ(rowId, 4);

    ret = OH_RdbTrans_Commit(trans);
    EXPECT_EQ(ret, RDB_OK);

    valueBucket->destroy(valueBucket);
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_025
 * @tc.desc: test invalid options
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_025, TestSize.Level1)
{
    EXPECT_EQ(OH_RdbTransOption_SetType(nullptr, RDB_TRANS_DEFERRED), RDB_E_INVALID_ARGS);
    OH_RDB_TransOptions *options = OH_RdbTrans_CreateOptions();
    auto ret = OH_RdbTransOption_SetType(options, static_cast<OH_RDB_TransType>(RDB_TRANS_DEFERRED - 1));
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    ret = 0;
    ret = OH_RdbTransOption_SetType(options, static_cast<OH_RDB_TransType>(RDB_TRANS_BUTT + 1));
    EXPECT_EQ(ret, RDB_E_INVALID_ARGS);
    EXPECT_EQ(OH_RdbTrans_DestroyOptions(options), RDB_OK);
    EXPECT_EQ(OH_RdbTrans_DestroyOptions(nullptr), RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: RDB_Transaction_capi_test_026
 * @tc.desc: Abnormal testCase of drop the table before closing the resultSet after querying the data.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_026, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    const char *querySql = "SELECT * FROM test";
    OH_Cursor *cursor = OH_RdbTrans_QuerySql(trans, querySql, nullptr);
    EXPECT_NE(cursor, nullptr);

    ret = cursor->goToNextRow(cursor);
    EXPECT_EQ(ret, RDB_OK);
    ret = cursor->goToNextRow(cursor);
    EXPECT_EQ(ret, RDB_OK);
    ret = cursor->goToNextRow(cursor);
    EXPECT_EQ(ret, RDB_OK);

    const char *sql = "DROP TABLE test";
    ret = OH_RdbTrans_Execute(trans, sql, nullptr, nullptr);
    EXPECT_EQ(ret, RDB_E_SQLITE_LOCKED);

    cursor->destroy(cursor);

    ret = OH_RdbTrans_Rollback(trans);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_027
 * @tc.desc: Abnormal testCase of drop the table before closing the resultSet after querying the data.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_027, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    const char *querySql = "SELECT * FROM test";
    OH_Cursor *cursor = OH_RdbTrans_QuerySql(trans, querySql, nullptr);
    EXPECT_NE(cursor, nullptr);

    ret = cursor->goToNextRow(cursor);
    EXPECT_EQ(ret, RDB_OK);
    ret = cursor->goToNextRow(cursor);
    EXPECT_EQ(ret, RDB_OK);

    const char *sql = "DROP TABLE test";
    ret = OH_RdbTrans_Execute(trans, sql, nullptr, nullptr);
    EXPECT_EQ(ret, RDB_E_SQLITE_LOCKED);

    cursor->destroy(cursor);

    ret = OH_RdbTrans_Rollback(trans);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_028
 * @tc.desc: Normal testCase of drop the table after querying the data and closing the resultSet.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_028, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;

    char createTableSql[] = "CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    int ret = OH_Rdb_Execute(g_transStore, createTableSql);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    const char *querySql = "SELECT * FROM test";
    OH_Cursor *cursor = OH_RdbTrans_QuerySql(trans, querySql, nullptr);
    EXPECT_NE(cursor, nullptr);

    ret = cursor->goToNextRow(cursor);
    EXPECT_EQ(ret, RDB_OK);
    ret = cursor->goToNextRow(cursor);
    EXPECT_EQ(ret, RDB_OK);

    cursor->destroy(cursor);

    const char *sql = "DROP TABLE test1";
    ret = OH_RdbTrans_Execute(trans, sql, nullptr, nullptr);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_RdbTrans_Commit(trans);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_029
 * @tc.desc: Abnormal testCase of drop the index before closing the resultSet after querying the data.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_029, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;

    char createIndexSql[] = "CREATE INDEX test_index ON test(data2);";
    int ret = OH_Rdb_Execute(g_transStore, createIndexSql);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    const char *querySql = "SELECT * FROM test";
    OH_Cursor *cursor = OH_RdbTrans_QuerySql(trans, querySql, nullptr);
    EXPECT_NE(cursor, nullptr);

    ret = cursor->goToNextRow(cursor);
    EXPECT_EQ(ret, RDB_OK);
    ret = cursor->goToNextRow(cursor);
    EXPECT_EQ(ret, RDB_OK);
    ret = cursor->goToNextRow(cursor);
    EXPECT_EQ(ret, RDB_OK);

    const char *sql = "DROP INDEX test_index";
    ret = OH_RdbTrans_Execute(trans, sql, nullptr, nullptr);
    EXPECT_EQ(ret, RDB_E_SQLITE_LOCKED);

    cursor->destroy(cursor);

    ret = OH_RdbTrans_Rollback(trans);
    EXPECT_EQ(ret, RDB_OK);

    char dropIndexSql[] = "DROP INDEX test_index;";
    ret = OH_Rdb_Execute(g_transStore, dropIndexSql);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_030
 * @tc.desc: Abnormal testCase of drop the index before closing the resultSet after querying the data.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_030, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;

    char createIndexSql[] = "CREATE INDEX test_index ON test(data2);";
    int ret = OH_Rdb_Execute(g_transStore, createIndexSql);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    const char *querySql = "SELECT * FROM test";
    OH_Cursor *cursor = OH_RdbTrans_QuerySql(trans, querySql, nullptr);
    EXPECT_NE(cursor, nullptr);

    ret = cursor->goToNextRow(cursor);
    EXPECT_EQ(ret, RDB_OK);
    ret = cursor->goToNextRow(cursor);
    EXPECT_EQ(ret, RDB_OK);

    const char *sql = "DROP INDEX test_index";
    ret = OH_RdbTrans_Execute(trans, sql, nullptr, nullptr);
    EXPECT_EQ(ret, RDB_E_SQLITE_LOCKED);

    cursor->destroy(cursor);

    ret = OH_RdbTrans_Rollback(trans);
    EXPECT_EQ(ret, RDB_OK);

    char dropIndexSql[] = "DROP INDEX test_index;";
    ret = OH_Rdb_Execute(g_transStore, dropIndexSql);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_031
 * @tc.desc: Abnormal testCase of drop the index after querying the data and closing the resultSet.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_031, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;

    char createIndexSql[] = "CREATE index test_index ON test(data2);";
    int ret = OH_Rdb_Execute(g_transStore, createIndexSql);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    const char *querySql = "SELECT * FROM test";
    OH_Cursor *cursor = OH_RdbTrans_QuerySql(trans, querySql, nullptr);
    EXPECT_NE(cursor, nullptr);

    ret = cursor->goToNextRow(cursor);
    EXPECT_EQ(ret, RDB_OK);
    ret = cursor->goToNextRow(cursor);
    EXPECT_EQ(ret, RDB_OK);

    cursor->destroy(cursor);

    const char *sql = "DROP INDEX test_index";
    ret = OH_RdbTrans_Execute(trans, sql, nullptr, nullptr);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_RdbTrans_Commit(trans);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_032
 * @tc.desc: Normal testCase of drop the table after querying the data and closing the resultSet.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_032, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;

    char createTableSql[] = "CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    int ret = OH_Rdb_Execute(g_transStore, createTableSql);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    const char *querySql = "SELECT * FROM test1";
    OH_Cursor *cursor = OH_RdbTrans_QuerySql(trans, querySql, nullptr);
    EXPECT_NE(cursor, nullptr);

    ret = cursor->goToNextRow(cursor);
    EXPECT_NE(ret, RDB_OK);

    const char *sql = "DROP TABLE test1";
    ret = OH_RdbTrans_Execute(trans, sql, nullptr, nullptr);
    EXPECT_EQ(ret, RDB_OK);

    cursor->destroy(cursor);

    ret = OH_RdbTrans_Commit(trans);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_033
 * @tc.desc: Normal testCase of drop the index after querying the data and closing the resultSet.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_033, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;

    char createIndexSql[] = "CREATE index test_index ON test(data2);";
    int ret = OH_Rdb_Execute(g_transStore, createIndexSql);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    const char *querySql = "SELECT * FROM test1";
    OH_Cursor *cursor = OH_RdbTrans_QuerySql(trans, querySql, nullptr);
    EXPECT_NE(cursor, nullptr);

    ret = cursor->goToNextRow(cursor);
    EXPECT_NE(ret, RDB_OK);

    const char *sql = "DROP INDEX test_index";
    ret = OH_RdbTrans_Execute(trans, sql, nullptr, nullptr);
    EXPECT_EQ(ret, RDB_OK);

    cursor->destroy(cursor);

    ret = OH_RdbTrans_Commit(trans);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_034
 * @tc.desc: Abnormal testCase of drop the table after querying the data and closing the resultSet.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_034, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;

    char createTableSql[] = "CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    int ret = OH_Rdb_Execute(g_transStore, createTableSql);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    const char *querySql = "SELECT * FROM test1";
    OH_Cursor *cursor = OH_RdbTrans_QuerySql(trans, querySql, nullptr);
    EXPECT_NE(cursor, nullptr);

    ret = cursor->goToNextRow(cursor);
    EXPECT_NE(ret, RDB_OK);

    const char *sql = "DROP TABLE test";
    ret = OH_RdbTrans_Execute(trans, sql, nullptr, nullptr);
    EXPECT_EQ(ret, RDB_OK);

    cursor->destroy(cursor);

    ret = OH_RdbTrans_Rollback(trans);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_035
 * @tc.desc: Abnormal testCase of drop the table after querying the data and closing the resultSet.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_035, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;

    int ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    const char *querySql = "SELECT * FROM test";
    OH_Cursor *cursor = OH_RdbTrans_QuerySql(trans, querySql, nullptr);
    EXPECT_NE(cursor, nullptr);

    const char *sql = "DROP TABLE test1";
    ret = OH_RdbTrans_Execute(trans, sql, nullptr, nullptr);
    EXPECT_EQ(ret, RDB_OK);

    cursor->destroy(cursor);

    ret = OH_RdbTrans_Rollback(trans);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RDB_Transaction_capi_test_036
 * @tc.desc: Normal testCase of drop the table before closing the resultSet after querying the data.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionCapiTest, RDB_Transaction_capi_test_036, TestSize.Level1)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(g_transStore, g_options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);

    const char *querySql = "SELECT * FROM test";
    OH_Cursor *cursor = OH_RdbTrans_QuerySql(trans, querySql, nullptr);
    EXPECT_NE(cursor, nullptr);

    int rowCount = 0;
    ret = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(ret, RDB_OK);

    for (int i = 0; i < rowCount; i++) {
        ret = cursor->goToNextRow(cursor);
        EXPECT_EQ(ret, RDB_OK);
    }

    ret = cursor->goToNextRow(cursor);
    EXPECT_NE(ret, RDB_OK);

    const char *sql = "DROP TABLE test";
    ret = OH_RdbTrans_Execute(trans, sql, nullptr, nullptr);
    EXPECT_EQ(ret, RDB_OK);

    cursor->destroy(cursor);

    ret = OH_RdbTrans_Commit(trans);
    EXPECT_EQ(ret, RDB_OK);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}
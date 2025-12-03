/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "accesstoken_kit.h"
#include "common.h"
#include "oh_data_value.h"
#include "oh_rdb_types.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::RdbNdk;

class RdbStoreReturningTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static void InitRdbConfig();
    static OH_VBucket *CreateOneVBucket();
    static OH_VBucket *CreateOneUpdateVBucket();
    static OH_Data_VBuckets *CreateOneVBuckets();
    static OH_RDB_ReturningContext *CreateReturningContext(std::vector<const char *> fields);
    static void VerifyCursorData(OH_Cursor *cursor, std::string expectedValue);
    static OH_Rdb_Transaction *CreateTransaction(OH_Rdb_Store *store);
};

static OH_Rdb_Store *store_ = nullptr;
static OH_Rdb_ConfigV2 *config_ = OH_Rdb_CreateConfig();

OH_VBucket *RdbStoreReturningTest::CreateOneVBucket()
{
    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    ASSERT_NE(valueBucket, nullptr);
    valueBucket->putText(valueBucket, "NAME", "Lisa");
    const int age = 18;
    valueBucket->putInt64(valueBucket, "AGE", age);
    const float salary = 100.5;
    valueBucket->putReal(valueBucket, "SALARY", salary);
    uint8_t arr[] = { 1, 2, 3, 4, 5 };
    int blobLen = sizeof(arr) / sizeof(arr[0]);
    valueBucket->putBlob(valueBucket, "CODES", arr, blobLen);
    const float height = 172;
    valueBucket->putReal(valueBucket, "HEIGHT", height);
    valueBucket->putText(valueBucket, "SEX", "MALE");

    const int assetsCount = 2;
    Data_Asset **assets = OH_Data_Asset_CreateMultiple(assetsCount);
    OH_Data_Asset_SetName(assets[0], "asset1");
    OH_Data_Asset_SetName(assets[1], "asset2");
    OH_VBucket_PutAssets(valueBucket, "DATAS", assets, assetsCount);

    const int floatsSize = 3;
    float floatArr[floatsSize] = { 1.0, 2.0, 3.0 };
    int ret = OH_VBucket_PutFloatVector(valueBucket, "FLOATS", floatArr, floatsSize);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    return valueBucket;
}

OH_VBucket *RdbStoreReturningTest::CreateOneUpdateVBucket()
{
    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    ASSERT_NE(valueBucket, nullptr);
    valueBucket->putText(valueBucket, "NAME", "Lucy");
    const int age = 19;
    valueBucket->putInt64(valueBucket, "AGE", age);
    const float salary = 101.5;
    valueBucket->putReal(valueBucket, "SALARY", salary);
    uint8_t arr[] = { 1, 2, 3, 4, 5, 6 };
    int blobLen = sizeof(arr) / sizeof(arr[0]);
    valueBucket->putBlob(valueBucket, "CODES", arr, blobLen);
    const float height = 173;
    valueBucket->putReal(valueBucket, "HEIGHT", height);
    valueBucket->putText(valueBucket, "SEX", "FEMALE");

    const int assetsCount = 2;
    Data_Asset **assets = OH_Data_Asset_CreateMultiple(assetsCount);
    OH_Data_Asset_SetName(assets[0], "asset3");
    OH_Data_Asset_SetName(assets[1], "asset4");
    OH_VBucket_PutAssets(valueBucket, "DATAS", assets, assetsCount);

    const int floatsSize = 3;
    float floatArr[floatsSize] = { 4.0, 5.0, 6.0 };
    int ret = OH_VBucket_PutFloatVector(valueBucket, "FLOATS", floatArr, floatsSize);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    return valueBucket;
}

OH_Data_VBuckets *RdbStoreReturningTest::CreateOneVBuckets()
{
    OH_Data_VBuckets *rows = OH_VBuckets_Create();
    ASSERT_NE(rows, nullptr);
    return rows;
}

OH_RDB_ReturningContext *RdbStoreReturningTest::CreateReturningContext(std::vector<const char *> fields)
{
    OH_RDB_ReturningContext *returningContext = OH_RDB_CreateReturningContext();
    ASSERT_NE(returningContext, nullptr);
    OH_RDB_SetReturningFields(returningContext, fields.data(), static_cast<int32_t>(fields.size()));
    return returningContext;
}

OH_Rdb_Transaction *RdbStoreReturningTest::CreateTransaction(OH_Rdb_Store *store)
{
    OH_RDB_TransOptions *options = OH_RdbTrans_CreateOptions();
    ASSERT_NE(options, nullptr);
    int ret = OH_RdbTransOption_SetType(options, RDB_TRANS_DEFERRED);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Rdb_Transaction *trans = nullptr;
    ret = OH_Rdb_CreateTransaction(store, options, &trans);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    ASSERT_NE(trans, nullptr);
    return trans;
}

void RdbStoreReturningTest::VerifyCursorData(OH_Cursor *cursor, const std::string &expectedValue)
{
    ASSERT_NE(cursor, nullptr);
    int rowCount = 0;
    int ret = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    EXPECT_EQ(rowCount, 1);

    int columnCount = 0;
    ret = cursor->getColumnCount(cursor, &columnCount);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    EXPECT_EQ(columnCount, 1);

    EXPECT_EQ(cursor->goToNextRow(cursor), OH_Rdb_ErrCode::RDB_OK);

    size_t size = 0;
    ret = cursor->getSize(cursor, 0, &size);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    const int strSize = 5;
    EXPECT_EQ(size, strSize);

    char dataValue[size];
    ret = cursor->getText(cursor, 0, dataValue, size);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    EXPECT_EQ(std::string(dataValue), expectedValue);
}

void RdbStoreReturningTest::InitRdbConfig()
{
    const mode_t mode = 0770;
    mkdir(RDB_TEST_PATH, mode);
    OH_Rdb_SetDatabaseDir(config_, RDB_TEST_PATH);
    OH_Rdb_SetStoreName(config_, "rdb_store_test.db");
    OH_Rdb_SetBundleName(config_, "com.ohos.example.distributedndk");
    OH_Rdb_SetEncrypted(config_, false);
    OH_Rdb_SetSecurityLevel(config_, OH_Rdb_SecurityLevel::S1);
    OH_Rdb_SetArea(config_, RDB_SECURITY_AREA_EL1);
    EXPECT_EQ(OH_Rdb_SetDbType(config_, RDB_SQLITE), OH_Rdb_ErrCode::RDB_OK);
}

void RdbStoreReturningTest::SetUpTestCase(void)
{
    InitRdbConfig();
    int errCode = 0;
    store_ = OH_Rdb_CreateOrOpen(config_, &errCode);
    ASSERT_NE(store_, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);
}

void RdbStoreReturningTest::TearDownTestCase(void)
{
    int errCode = OH_Rdb_CloseStore(store_);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);
    store_ = nullptr;
    errCode = OH_Rdb_DeleteStoreV2(config_);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);
    OH_Rdb_DestroyConfig(config_);
    config_ = nullptr;
}

void RdbStoreReturningTest::SetUp(void)
{
    char createTableSql[] =
        "CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, AGE INTEGER, "
        "SALARY REAL, CODES BLOB, HEIGHT REAL, SEX TEXT, DATAS ASSETS, FLOATS FLOATVECTOR)";
    int errCode = OH_Rdb_Execute(store_, createTableSql);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);

    OH_VBucket *valueBucket = CreateOneVBucket();
    int rowId = OH_Rdb_Insert(store_, "EMPLOYEE", valueBucket);
    EXPECT_EQ(rowId, 1);
}

void RdbStoreReturningTest::TearDown(void)
{
    char dropTableSql[] = "DROP TABLE IF EXISTS EMPLOYEE";
    int errCode = OH_Rdb_Execute(store_, dropTableSql);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);
}

struct BatchInsertInputData {
    OH_RDB_ReturningContext *context = nullptr;
    OH_VBucket *valueBucket = nullptr;
    OH_Data_VBuckets *rows = nullptr;
    const int assetsCount = 2;
    Data_Asset **assets = nullptr;
    OH_Rdb_Transaction *trans = nullptr;
    BatchInsertInputData(const char *const fields[])
    {
        valueBucket = CreateOneVBucket();
        rows = CreateOneVBuckets();
        context = CreateReturningContext(fields);
        assets = OH_Data_Asset_CreateMultiple(assetsCount);
    }
    BatchInsertInputData(OH_Rdb_Store *store, const char *const fields[])
    {
        trans = CreateTransaction(store);
        BatchInsertInputData(fields);
    }
    ~BatchInsertInputData()
    {
        OH_RDB_DestroyReturningContext(context);
        context = nullptr;
        int ret = OH_VBuckets_Destroy(rows);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
        rows = nullptr;
        valueBucket->destroy(valueBucket);
        valueBucket = nullptr;
        OH_Data_Asset_DestroyMultiple(assets, assetsCount);
        assets = nullptr;

        if (trans != nullptr) {
            int ret = OH_RdbTrans_Destroy(trans);
            EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
            trans = nullptr;
        }
    }
    void PutRows()
    {
        int ret = OH_VBuckets_PutRow(rows, valueBucket);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    }
    void PutRepeatAsset()
    {
        OH_Data_Asset_SetName(assets[0], "data");
        OH_Data_Asset_SetName(assets[1], "data");
        OH_VBucket_PutAssets(valueBucket, "DATAS", assets, assetsCount);
    }
    void EmptyRows()
    {
        int ret = OH_VBuckets_Destroy(rows);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
        rows = nullptr;
        rows = OH_VBuckets_Create();
        ASSERT_NE(rows, nullptr);
    }
}

struct DeleteInputData {
    OH_Rdb_Transaction *trans = nullptr;
    OH_RDB_ReturningContext *context = nullptr;
    OH_VObject *valueObject = nullptr;
    OH_Predicates *predicates = nullptr;
    DeleteInputData(const char *table, const char *const fields[])
    {
        valueObject = OH_Rdb_CreateValueObject();
        valueObject->putText(valueObject, "Lisa");
        predicates = OH_Rdb_CreatePredicates(table);
        ASSERT_NE(predicates, nullptr);
        predicates->equalTo(predicates, "NAME", valueObject);
        context = CreateReturningContext(fields);
    }
    DeleteInputData(OH_Rdb_Store *store, const char *table, const char *const fields[])
    {
        trans = CreateTransaction(store);
        DeleteInputData(table, fields)
    }
    ~DeleteInputData()
    {
        OH_RDB_DestroyReturningContext(context);
        context = nullptr;
        predicates->destroy(predicates);
        predicates = nullptr;
        valueObject->destroy(valueObject);
        valueObject = nullptr;
        if (trans != nullptr) {
            int ret = OH_RdbTrans_Destroy(trans);
            EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
            trans = nullptr;
        }
    }
}

struct UpdateInputData {
    OH_VBucket *valueBucketUpdate = nullptr;
    OH_RDB_ReturningContext *context = nullptr;
    OH_VObject *valueObject = nullptr;
    OH_Predicates *predicates = nullptr;
    OH_Rdb_Transaction *trans = nullptr;
    UpdateInputData(const char *table, const char *const fields[])
    {
        valueBucketUpdate = CreateOneUpdateVBucket();
        valueObject = OH_Rdb_CreateValueObject();
        valueObject->putText(valueObject, "Lisa");
        predicates = OH_Rdb_CreatePredicates(table);
        ASSERT_NE(predicates, nullptr);
        predicates->equalTo(predicates, "NAME", valueObject);
        context = CreateReturningContext(fields);
    }
    UpdateInputData(OH_Rdb_Store *store, const char *table, const char *const fields[])
    {
        trans = CreateTransaction(store);
        UpdateInputData(table, fields);
    }
    ~UpdateInputData()
    {
        OH_RDB_DestroyReturningContext(context);
        context = nullptr;
        predicates->destroy(predicates);
        predicates = nullptr;
        valueObject->destroy(valueObject);
        valueObject = nullptr;
        valueBucketUpdate->destroy(valueBucketUpdate);
        valueBucketUpdate = nullptr;
        if (trans != nullptr) {
            int ret = OH_RdbTrans_Destroy(trans);
            EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
            trans = nullptr;
        }
    }
    void EmptyValueBucketUpdate()
    {
        valueBucketUpdate->destroy(valueBucketUpdate);
        valueBucketUpdate = nullptr;
        valueBucketUpdate = OH_Rdb_CreateValuesBucket();
        ASSERT_NE(valueBucketUpdate, nullptr);
    }
}
/**
 * @tc.name: OH_Rdb_BatchInsertWithReturning_test_001
 * @tc.desc: Normal testCase.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_BatchInsertWithReturning_test_001, TestSize.Level1)
{
    BatchInsertInputData data({ "NAME" });
    data.PutRows();
    int ret = OH_Rdb_BatchInsertWithReturning(
        store_, "EMPLOYEE", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(data.context);
    ASSERT_NE(cursor, nullptr);
    VerifyCursorData(cursor, "Lisa");

    int changed = OH_RDB_GetChangedCount(data.context);
    EXPECT_EQ(changed, 1);
}

/**
 * @tc.name: OH_Rdb_BatchInsertWithReturning_test_002
 * @tc.desc: Construct test cases for inputting various abnormal parameters.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_BatchInsertWithReturning_test_002, TestSize.Level1)
{
    BatchInsertInputData data({ "NAME" });
    data.PutRows();
    int ret = OH_Rdb_BatchInsertWithReturning(
        nullptr, "EMPLOYEE", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    ret = OH_Rdb_BatchInsertWithReturning(
        store_, nullptr, data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    ret = OH_Rdb_BatchInsertWithReturning(
        store_, "EMPLOYEE", nullptr, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    ret = OH_Rdb_BatchInsertWithReturning(
        store_, "EMPLOYEE", data.rows, static_cast<Rdb_ConflictResolution>(-1), data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    ret = OH_Rdb_BatchInsertWithReturning(
        store_, "EMPLOYEE", data.rows, static_cast<Rdb_ConflictResolution>(1024), data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    ret = OH_Rdb_BatchInsertWithReturning(
        store_, "EMPLOYEE", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, nullptr);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_Rdb_BatchInsertWithReturning_test_003
 * @tc.desc: Construct a test case with different table names.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_BatchInsertWithReturning_test_003, TestSize.Level1)
{
    BatchInsertInputData data({ "NAME" });
    data.PutRows();
    int ret = OH_Rdb_BatchInsertWithReturning(
        store_, "", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    ret = OH_Rdb_BatchInsertWithReturning(
        store_, "abc", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_SQLITE_ERROR);
    ret = OH_Rdb_BatchInsertWithReturning(
        store_, "E M PLOYEE", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_Rdb_BatchInsertWithReturning_test_004
 * @tc.desc: Construct a test case with different fields.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_BatchInsertWithReturning_test_004, TestSize.Level1)
{
    BatchInsertInputData data({});
    data.PutRows();
    int ret = OH_Rdb_BatchInsertWithReturning(
        store_, "EMPLOYEE", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    BatchInsertInputData data1({ "NAME", "AGE", "SALARY", "CODES", "HEIGHT", "SEX" });
    data1.PutRows();
    ret = OH_Rdb_BatchInsertWithReturning(
        store_, "EMPLOYEE", data1.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data1.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    BatchInsertInputData data2({ "NAME", "*" });
    data2.PutRows();
    ret = OH_Rdb_BatchInsertWithReturning(
        store_, "EMPLOYEE", data2.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data2.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    BatchInsertInputData data3({ "NAME", nullptr });
    data3.PutRows();
    ret = OH_Rdb_BatchInsertWithReturning(
        store_, "EMPLOYEE", data3.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data3.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_Rdb_BatchInsertWithReturning_test_005
 * @tc.desc: Construct a use case with the same asset input.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_BatchInsertWithReturning_test_005, TestSize.Level1)
{
    BatchInsertInputData data({ "NAME" });
    data.PutRepeatAsset();
    data.PutRows();
    int ret = OH_Rdb_BatchInsertWithReturning(
        store_, "EMPLOYEE", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_Rdb_DeleteWithReturning_test_001
 * @tc.desc: Normal testCase of store for OH_Rdb_DeleteWithReturning.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_DeleteWithReturning_test_001, TestSize.Level1)
{
    DeleteInputData data("EMPLOYEE", { "NAME" });
    int ret = OH_Rdb_DeleteWithReturning(store_, data.predicates, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(context);
    EXPECT_NE(cursor, nullptr);
    VerifyCursorData(cursor, "Lisa");

    int changed = OH_RDB_GetChangedCount(context);
    EXPECT_EQ(changed, 1);
}

/**
 * @tc.name: OH_Rdb_DeleteWithReturning_test_002
 * @tc.desc: Construct test cases for inputting various abnormal parameters.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_DeleteWithReturning_test_002, TestSize.Level1)
{
    DeleteInputData data("EMPLOYEE", { "NAME" });
    int ret = OH_Rdb_DeleteWithReturning(nullptr, data.predicates, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_Rdb_DeleteWithReturning(store_, nullptr, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_Rdb_DeleteWithReturning(store_, data.predicates, nullptr);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_Rdb_DeleteWithReturning_test_003
 * @tc.desc: Construct a test case with different table names.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_DeleteWithReturning_test_003, TestSize.Level1)
{
    DeleteInputData data("abc", { "NAME" });
    int ret = OH_Rdb_DeleteWithReturning(store_, data.predicates, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_SQLITE_ERROR);

    DeleteInputData data1("", { "NAME" });
    ret = OH_Rdb_DeleteWithReturning(store_, data1.predicates, data1.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    DeleteInputData data2("E M PLOYEE", { "NAME" });
    ret = OH_Rdb_DeleteWithReturning(store_, data2.predicates, data2.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_Rdb_DeleteWithReturning_test_004
 * @tc.desc: Construct a test case with different fields.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_DeleteWithReturning_test_004, TestSize.Level1)
{
    DeleteInputData data("EMPLOYEE", {});
    int ret = OH_Rdb_DeleteWithReturning(store_, data.predicates, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    DeleteInputData data1("EMPLOYEE", { "NAME", "AGE", "SALARY", "CODES", "HEIGHT", "SEX" });
    ret = OH_Rdb_DeleteWithReturning(store_, data1.predicates, data1.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    DeleteInputData data2("EMPLOYEE", { "NAME", "*" });
    ret = OH_Rdb_DeleteWithReturning(store_, data2.predicates, data2.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    DeleteInputData data3("EMPLOYEE", { "NAME", nullptr });
    ret = OH_Rdb_DeleteWithReturning(store_, data3.predicates, data3.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_Rdb_UpdateWithReturning_test_001
 * @tc.desc: Normal testCase of store for OH_Rdb_UpdateWithReturning.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_UpdateWithReturning_test_001, TestSize.Level1)
{
    UpdateInputData data("EMPLOYEE", { "NAME" });
    int ret = OH_Rdb_UpdateWithReturning(
        store_, data.valueBucketUpdate, data.predicates, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(context);
    ASSERT_NE(cursor, nullptr);
    VerifyCursorData(cursor, "Lucy");

    int changed = OH_RDB_GetChangedCount(context);
    EXPECT_EQ(changed, 1);
}

/**
 * @tc.name: OH_Rdb_UpdateWithReturning_test_002
 * @tc.desc: Construct test cases for inputting various abnormal parameters.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_UpdateWithReturning_test_002, TestSize.Level1)
{
    UpdateInputData data("EMPLOYEE", { "NAME" });
    int ret = OH_Rdb_UpdateWithReturning(
        nullptr, data.valueBucketUpdate, data.predicates, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_Rdb_UpdateWithReturning(
        store_, nullptr, data.predicates, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_Rdb_UpdateWithReturning(
        store_, data.valueBucketUpdate, nullptr, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_Rdb_UpdateWithReturning(
        store_, data.valueBucketUpdate, data.predicates, static_cast<Rdb_ConflictResolution>(-1), data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_Rdb_UpdateWithReturning(
        store_, data.valueBucketUpdate, data.predicates, static_cast<Rdb_ConflictResolution>(1024), data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_Rdb_UpdateWithReturning(
        store_, data.valueBucketUpdate, data.predicates, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, nullptr);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    data.EmptyValueBucketUpdate();
    ret = OH_Rdb_UpdateWithReturning(
        store_, data.valueBucketUpdate, data.predicates, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_ERROR);
}

/**
 * @tc.name: OH_Rdb_UpdateWithReturning_test_003
 * @tc.desc: Construct a test case with different table names.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_UpdateWithReturning_test_003, TestSize.Level1)
{
    UpdateInputData data("abc", { "NAME" });
    int ret = OH_Rdb_UpdateWithReturning(
        store_, data.valueBucketUpdate, data.predicates, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_SQLITE_ERROR);

    UpdateInputData data1("", { "NAME" });
    ret = OH_Rdb_UpdateWithReturning(store_, data1.valueBucketUpdate, data1.predicates,
        Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data1.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    UpdateInputData data2("E M PLOYEE", { "NAME" });
    ret = OH_Rdb_UpdateWithReturning(store_, data2.valueBucketUpdate, data2.predicates,
        Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data2.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_Rdb_UpdateWithReturning_test_004
 * @tc.desc: Construct a test case with different fields.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_UpdateWithReturning_test_004, TestSize.Level1)
{
    UpdateInputData data("EMPLOYEE", {});
    int ret = OH_Rdb_UpdateWithReturning(
        store_, data.valueBucketUpdate, data.predicates, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    UpdateInputData data1("EMPLOYEE", { "NAME", "AGE", "SALARY", "CODES", "HEIGHT", "SEX" });
    ret = OH_Rdb_UpdateWithReturning(store_, data1.valueBucketUpdate, data1.predicates,
        Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data1.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    UpdateInputData data2("EMPLOYEE", { "NAME", "*" });
    ret = OH_Rdb_UpdateWithReturning(store_, data2.valueBucketUpdate, data2.predicates,
        Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data2.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    UpdateInputData data3("EMPLOYEE", { "NAME", nullptr });
    ret = OH_Rdb_UpdateWithReturning(store_, data3.valueBucketUpdate, data3.predicates,
        Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data3.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_RdbTrans_BatchInsertWithReturning_test_001
 * @tc.desc: Normal testCase of store for OH_RdbTrans_BatchInsertWithReturning.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_BatchInsertWithReturning_test_001, TestSize.Level1)
{
    BatchInsertInputData data(store_, { "NAME" });
    data.PutRows();
    int ret = OH_RdbTrans_BatchInsertWithReturning(
        data.trans, "EMPLOYEE", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(context);
    ASSERT_NE(cursor, nullptr);
    VerifyCursorData(cursor, "Lisa");

    int changed = OH_RDB_GetChangedCount(context);
    EXPECT_EQ(changed, 1);
}

/**
 * @tc.name: OH_RdbTrans_BatchInsertWithReturning_test_002
 * @tc.desc: Construct test cases for inputting various abnormal parameters.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_BatchInsertWithReturning_test_002, TestSize.Level1)
{
    BatchInsertInputData data(store_, { "NAME" });
    data.PutRows();
    int ret = OH_RdbTrans_BatchInsertWithReturning(
        nullptr, "EMPLOYEE", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_BatchInsertWithReturning(
        data.trans, nullptr, data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_BatchInsertWithReturning(
        data.trans, "EMPLOYEE", nullptr, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_BatchInsertWithReturning(
        data.trans, "EMPLOYEE", data.rows, static_cast<Rdb_ConflictResolution>(-1), data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_BatchInsertWithReturning(
        data.trans, "EMPLOYEE", data.rows, static_cast<Rdb_ConflictResolution>(1024), data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_BatchInsertWithReturning(
        data.trans, "EMPLOYEE", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, nullptr);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    data.EmptyRows();
    ret = OH_RdbTrans_BatchInsertWithReturning(
        data.trans, "EMPLOYEE", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
}

/**
 * @tc.name: OH_RdbTrans_BatchInsertWithReturning_test_003
 * @tc.desc: Construct a test case with different table names.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_BatchInsertWithReturning_test_003, TestSize.Level1)
{
    BatchInsertInputData data(store_, { "NAME" });
    data.PutRows();
    int ret = OH_RdbTrans_BatchInsertWithReturning(
        data.trans, "", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_BatchInsertWithReturning(
        data.trans, "abc", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_SQLITE_ERROR);

    ret = OH_RdbTrans_BatchInsertWithReturning(
        data.trans, "E M PLOYEE", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    data.EmptyRows();
    ret = OH_RdbTrans_BatchInsertWithReturning(
        data.trans, "EMPLOYEE", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
}

/**
 * @tc.name: OH_RdbTrans_BatchInsertWithReturning_test_004
 * @tc.desc: Construct a test case with different fields.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_BatchInsertWithReturning_test_004, TestSize.Level1)
{
    BatchInsertInputData data(store_, { "" });
    data.PutRows();
    int ret = OH_RdbTrans_BatchInsertWithReturning(
        data.trans, "EMPLOYEE", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_SQLITE_ERROR);

    BatchInsertInputData data1({ "NAME", "AGE", "SALARY", "CODES", "HEIGHT", "SEX" });
    data1.PutRows();
    ret = OH_RdbTrans_BatchInsertWithReturning(
        data1.trans, "EMPLOYEE", data1.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data1.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    BatchInsertInputData data2({ "NAME", "*" });
    data2.PutRows();
    ret = OH_RdbTrans_BatchInsertWithReturning(
        data2.trans, "EMPLOYEE", data2.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data2.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    BatchInsertInputData data3({ "NAME", nullptr });
    ret = OH_RdbTrans_BatchInsertWithReturning(
        data3.trans, "EMPLOYEE", data3.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data3.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_RdbTrans_BatchInsertWithReturning_test_005
 * @tc.desc: Construct a use case with the same asset input.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_BatchInsertWithReturning_test_005, TestSize.Level1)
{
    BatchInsertInputData data(store_, { "NAME" });
    data.PutRepeatAsset();
    data.PutRows();
    int ret = OH_RdbTrans_BatchInsertWithReturning(
        data.trans, "EMPLOYEE", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_RdbTrans_DeleteWithReturning_test_001
 * @tc.desc: Normal testCase of store for OH_RdbTrans_DeleteWithReturning.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_DeleteWithReturning_test_001, TestSize.Level1)
{
    DeleteInputData data(store_, "EMPLOYEE", { "NAME" });
    int ret = OH_RdbTrans_DeleteWithReturning(data.trans, data.predicates, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(context);
    ASSERT_NE(cursor, nullptr);
    VerifyCursorData(cursor, "Lisa");

    int changed = OH_RDB_GetChangedCount(context);
    EXPECT_EQ(changed, 1);
}

/**
 * @tc.name: OH_RdbTrans_DeleteWithReturning_test_002
 * @tc.desc: Construct test cases for inputting various abnormal parameters.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_DeleteWithReturning_test_002, TestSize.Level1)
{
    DeleteInputData data(store_, "EMPLOYEE", { "NAME" });
    int ret = OH_RdbTrans_DeleteWithReturning(nullptr, data.predicates, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_DeleteWithReturning(data.trans, nullptr, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_DeleteWithReturning(data.trans, data.predicates, nullptr);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_RdbTrans_DeleteWithReturning_test_003
 * @tc.desc: Construct a test case with different table names.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_DeleteWithReturning_test_003, TestSize.Level1)
{
    DeleteInputData data(store_, "abc", { "NAME" });
    int ret = OH_RdbTrans_DeleteWithReturning(data.trans, data.predicates, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_SQLITE_ERROR);

    DeleteInputData data1(store_, "", { "NAME" });
    ret = OH_RdbTrans_DeleteWithReturning(data1.trans, data1.predicates, data1.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    DeleteInputData data2(store_, "E M PLOYEE", { "NAME" });
    ret = OH_RdbTrans_DeleteWithReturning(data2.trans, data2.predicates, data2.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_RdbTrans_DeleteWithReturning_test_004
 * @tc.desc: Construct a test case with different fields.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_DeleteWithReturning_test_004, TestSize.Level1)
{
    DeleteInputData data(store_, "EMPLOYEE", {});
    int ret = OH_RdbTrans_DeleteWithReturning(data.trans, data.predicates, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    DeleteInputData data1(store_, "EMPLOYEE", { "NAME", "*" });
    ret = OH_RdbTrans_DeleteWithReturning(data1.trans, data1.predicates, data1.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    DeleteInputData data2(store_, "EMPLOYEE", { "NAME", nullptr });
    ret = OH_RdbTrans_DeleteWithReturning(data2.trans, data2.predicates, data2.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    DeleteInputData data3(store_, "EMPLOYEE", { "NAME", "AGE", "SALARY", "CODES", "HEIGHT", "SEX" });
    ret = OH_RdbTrans_DeleteWithReturning(data3.trans, data3.predicates, data3.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_RdbTrans_UpdateWithReturning_test_001
 * @tc.desc: Normal testCase of store for OH_RdbTrans_UpdateWithReturning.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_UpdateWithReturning_test_001, TestSize.Level1)
{
    UpdateInputData data(store_, "EMPLOYEE", { "NAME" });
    int ret = OH_RdbTrans_UpdateWithReturning(data.trans, data.valueBucketUpdate, data.predicates,
        Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(context);
    ASSERT_NE(cursor, nullptr);
    VerifyCursorData(cursor, "Lucy");

    int changed = OH_RDB_GetChangedCount(context);
    EXPECT_EQ(changed, 1);
}

/**
 * @tc.name: OH_RdbTrans_UpdateWithReturning_test_002
 * @tc.desc: Construct test cases for inputting various abnormal parameters.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_UpdateWithReturning_test_002, TestSize.Level1)
{
    UpdateInputData data(store_, "EMPLOYEE", { "NAME" });
    int ret = OH_RdbTrans_UpdateWithReturning(
        nullptr, data.valueBucketUpdate, data.predicates, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_UpdateWithReturning(
        data.trans, nullptr, data.predicates, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_UpdateWithReturning(
        data.trans, data.valueBucketUpdate, nullptr, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_UpdateWithReturning(
        data.trans, data.valueBucketUpdate, data.predicates, static_cast<Rdb_ConflictResolution>(-1), data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_UpdateWithReturning(
        data.trans, data.valueBucketUpdate, data.predicates, static_cast<Rdb_ConflictResolution>(1024), data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_UpdateWithReturning(
        data.trans, data.valueBucketUpdate, data.predicates, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, nullptr);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_RdbTrans_UpdateWithReturning_test_003
 * @tc.desc: Construct a test case with different table names.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_UpdateWithReturning_test_003, TestSize.Level1)
{
    UpdateInputData data(store_, "EMPLOYEE", { "NAME" });
    int ret = OH_RdbTrans_UpdateWithReturning(data.trans, data.valueBucketUpdate, data.predicates,
        Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    UpdateInputData data1(store_, "abc", { "NAME" });
    ret = OH_RdbTrans_UpdateWithReturning(data1.trans, data1.valueBucketUpdate, data1.predicates,
        Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data1.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_SQLITE_ERROR);

    UpdateInputData data2(store_, "", { "NAME" });
    ret = OH_RdbTrans_UpdateWithReturning(data2.trans, data2.valueBucketUpdate, data2.predicates,
        Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data2.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    UpdateInputData data3(store_, "E M PLOYEE", { "NAME" });
    ret = OH_RdbTrans_UpdateWithReturning(data3.trans, data3.valueBucketUpdate, data3.predicates,
        Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data3.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_RdbTrans_UpdateWithReturning_test_004
 * @tc.desc: Construct a test case with different fields.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_UpdateWithReturning_test_004, TestSize.Level1)
{
    UpdateInputData data(store_, "EMPLOYEE", {});
    int ret = OH_RdbTrans_UpdateWithReturning(data.trans, data.valueBucketUpdate, data.predicates,
        Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    UpdateInputData data1(store_, "EMPLOYEE", { "NAME", "*" });
    ret = OH_RdbTrans_UpdateWithReturning(data1.trans, data1.valueBucketUpdate, data1.predicates,
        Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data1.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    UpdateInputData data2(store_, "EMPLOYEE", { "NAME", nullptr });
    ret = OH_RdbTrans_UpdateWithReturning(data2.trans, data2.valueBucketUpdate, data2.predicates,
        Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data2.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    UpdateInputData data3(store_, "EMPLOYEE", { "NAME", "AGE", "SALARY", "CODES", "HEIGHT", "SEX" });
    ret = OH_RdbTrans_UpdateWithReturning(data3.trans, data3.valueBucketUpdate, data3.predicates,
        Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data3.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_RDB_ReturningContext_test_001
 * @tc.desc: testcase for OH_RDB_ReturningContext functions.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RDB_ReturningContext_test_001, TestSize.Level1)
{
    OH_RDB_ReturningContext *context = CreateReturningContext({ "NAME", "AGE", "SALARY" });
    int ret = OH_RDB_SetMaxReturningCount(context, 1);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    ret = OH_RDB_SetMaxReturningCount(context, -1);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RDB_SetMaxReturningCount(context, 0X7FFF);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RDB_SetMaxReturningCount(nullptr, 1);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    const char *columns[] = { "NAME", "AGE", "SALARY" };
    int32_t len = sizeof(columns) / sizeof(columns[0]);

    ret = OH_RDB_SetReturningFields(context, columns, len);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    ret = OH_RDB_SetReturningFields(nullptr, columns, len);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RDB_SetReturningFields(context, nullptr, len);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RDB_SetReturningFields(context, columns, -1);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    const char *columns1[] = { "NAME", "*", "SALARY" };
    int32_t len1 = sizeof(columns1) / sizeof(columns1[0]);
    ret = OH_RDB_SetReturningFields(context, columns1, len1);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    const char *columns2[] = { "NAME", nullptr, "SALARY" };
    int32_t len2 = sizeof(columns2) / sizeof(columns2[0]);
    ret = OH_RDB_SetReturningFields(context, columns2, len2);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(nullptr);
    EXPECT_EQ(cursor, nullptr);

    int64_t changedCount = OH_RDB_GetChangedCount(nullptr);
    EXPECT_EQ(changedCount, -1);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;
    OH_RDB_DestroyReturningContext(nullptr);
}

/**
 * @tc.name: OH_Rdb_BatchInsertWithReturning_GetFloat32Array_test_001
 * @tc.desc: Normal testCase.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_BatchInsertWithReturning_GetFloat32Array_test_001, TestSize.Level1)
{
    BatchInsertInputData data({ "FLOATS" });
    data.PutRows();
    int ret = OH_Rdb_BatchInsertWithReturning(
        store_, "EMPLOYEE", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(context);
    ASSERT_NE(cursor, nullptr);
    int rowCount = 0;
    ret = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    EXPECT_EQ(rowCount, 1);

    int columnCount = 0;
    ret = cursor->getColumnCount(cursor, &columnCount);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    EXPECT_EQ(columnCount, 1);

    EXPECT_EQ(cursor->goToNextRow(cursor), OH_Rdb_ErrCode::RDB_OK);

    const int floatsSize = 3;
    float floatArr[floatsSize] = { 1.0, 2.0, 3.0 };

    size_t count = 0;
    const int columnIndex = 0;
    auto errCode = OH_Cursor_GetFloatVectorCount(cursor, columnIndex, &count);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);
    EXPECT_EQ(count, floatsSize);
    float test[count];
    size_t outLen = 0;
    OH_Cursor_GetFloatVector(cursor, columnIndex, test, count, &outLen);
    EXPECT_EQ(outLen, floatsSize);
    EXPECT_EQ(test[0], floatArr[0]);
    EXPECT_EQ(test[1], floatArr[1]);
    EXPECT_EQ(test[2], floatArr[2]);

    int changed = OH_RDB_GetChangedCount(context);
    EXPECT_EQ(changed, 1);
}

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
#include <sys/stat.h>
#include <sys/types.h>

#include <string>

#include "accesstoken_kit.h"
#include "common.h"
#include "oh_data_value.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "oh_rdb_types.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::RdbNdk;

// static const int TEXT_MAX_SIZE = 128;

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
    static void CursorWorksAsExpected(OH_Cursor *cursor);
    static OH_Rdb_Transaction *CreateTransaction(OH_Rdb_Store *store);
};

static OH_Rdb_Store *store_ = nullptr;
static OH_Rdb_ConfigV2 *config_ = OH_Rdb_CreateConfig();

OH_VBucket *RdbStoreReturningTest::CreateOneVBucket()
{
    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    EXPECT_NE(valueBucket, nullptr);
    valueBucket->putText(valueBucket, "NAME", "Lisa");
    valueBucket->putInt64(valueBucket, "AGE", 18);
    valueBucket->putReal(valueBucket, "SALARY", 100.5);
    uint8_t arr[] = {1, 2, 3, 4, 5};
    int blobLen = sizeof(arr) / sizeof(arr[0]);
    valueBucket->putBlob(valueBucket, "CODES", arr, blobLen);
    valueBucket->putReal(valueBucket, "HEIGHT", 172);
    valueBucket->putText(valueBucket, "SEX", "MALE");
    return valueBucket;
}

OH_VBucket *RdbStoreReturningTest::CreateOneUpdateVBucket()
{
    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    EXPECT_NE(valueBucket, nullptr);
    valueBucket->putText(valueBucket, "NAME", "Lucy");
    valueBucket->putInt64(valueBucket, "AGE", 19);
    valueBucket->putReal(valueBucket, "SALARY", 101.5);
    uint8_t arr[] = {1, 2, 3, 4, 5, 6};
    int blobLen = sizeof(arr) / sizeof(arr[0]);
    valueBucket->putBlob(valueBucket, "CODES", arr, blobLen);
    valueBucket->putReal(valueBucket, "HEIGHT", 173);
    valueBucket->putText(valueBucket, "SEX", "FEMALE");
    return valueBucket;
}

OH_Data_VBuckets *RdbStoreReturningTest::CreateOneVBuckets()
{
    OH_Data_VBuckets *rows = OH_VBuckets_Create();
    EXPECT_NE(rows, nullptr);
    return rows;
}

OH_RDB_ReturningContext *RdbStoreReturningTest::CreateReturningContext(std::vector<const char *> fields)
{
    OH_RDB_ReturningContext *returningContext = OH_RDB_CreateReturningContext();
    EXPECT_NE(returningContext, nullptr);
    OH_RDB_SetReturningField(returningContext, fields.data(), static_cast<int32_t>(fields.size()));
    return returningContext;
}

OH_Rdb_Transaction *RdbStoreReturningTest::CreateTransaction(OH_Rdb_Store *store)
{
    OH_RDB_TransOptions *options = OH_RdbTrans_CreateOptions();
    EXPECT_NE(options, nullptr);
    int ret = OH_RdbTransOption_SetType(options, RDB_TRANS_DEFERRED);
    EXPECT_EQ(ret, RDB_OK);

    OH_Rdb_Transaction *trans = nullptr;
    ret = OH_Rdb_CreateTransaction(store, options, &trans);
    EXPECT_EQ(ret, RDB_OK);
    EXPECT_NE(trans, nullptr);
    return trans;
}

void RdbStoreReturningTest::CursorWorksAsExpected(OH_Cursor *cursor)
{
    EXPECT_NE(cursor, nullptr);
    int rowCount = 0;
    int ret = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    EXPECT_EQ(rowCount, 1);

    int columnCount = 0;
    ret = cursor->getColumnCount(cursor, &columnCount);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    EXPECT_EQ(columnCount, 1);

    // size_t size = 0;
    // ret = cursor->getSize(cursor, 0, &size);
    // EXPECT_EQ(ret, RDB_OK);
    // EXPECT_EQ(size, 4);

    // char dataValue[TEXT_MAX_SIZE];
    // ret = cursor->getText(cursor, 0, dataValue, size);
    // EXPECT_EQ(ret, RDB_OK);
    // EXPECT_EQ(dataValue, "Lisa");
}

void RdbStoreReturningTest::InitRdbConfig()
{
    mkdir(RDB_TEST_PATH, 0770);
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
    EXPECT_NE(store_, nullptr);
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
        "SALARY REAL, CODES BLOB, HEIGHT REAL, SEX TEXT, DATA ASSET)";
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

/**
 * @tc.name: OH_Rdb_BatchInsertWithReturning_test_001
 * @tc.desc: Normal testCase.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_BatchInsertWithReturning_test_001, TestSize.Level1)
{
    OH_VBucket *valueBucket = CreateOneVBucket();
    OH_Data_VBuckets *rows = CreateOneVBuckets();
    int ret = OH_VBuckets_PutRow(rows, valueBucket);
    EXPECT_EQ(ret, RDB_OK);

    OH_RDB_ReturningContext *context = CreateReturningContext({"NAME"});
    ret = OH_Rdb_BatchInsertWithReturning(store_, "EMPLOYEE", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                          context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(context);
    EXPECT_NE(cursor, nullptr);
    CursorWorksAsExpected(cursor);

    int changed = OH_RDB_GetChanedCount(context);
    EXPECT_EQ(changed, 1);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;

    ret = OH_VBuckets_Destroy(rows);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    rows = nullptr;

    valueBucket->destroy(valueBucket);
    valueBucket = nullptr;
}

/**
 * @tc.name: OH_Rdb_BatchInsertWithReturning_test_002
 * @tc.desc: Construct test cases for inputting various abnormal parameters.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_BatchInsertWithReturning_test_002, TestSize.Level1)
{
    OH_VBucket *valueBucket = CreateOneVBucket();
    OH_Data_VBuckets *rows = CreateOneVBuckets();
    int ret = OH_VBuckets_PutRow(rows, valueBucket);
    EXPECT_EQ(ret, RDB_OK);
    OH_RDB_ReturningContext *context = CreateReturningContext({"NAME"});

    ret = OH_Rdb_BatchInsertWithReturning(nullptr, "EMPLOYEE", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                          context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    ret = OH_Rdb_BatchInsertWithReturning(store_, nullptr, rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    ret = OH_Rdb_BatchInsertWithReturning(store_, "EMPLOYEE", nullptr, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                          context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    ret = OH_Rdb_BatchInsertWithReturning(store_, "EMPLOYEE", rows, static_cast<Rdb_ConflictResolution>(-1), context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    ret = OH_Rdb_BatchInsertWithReturning(store_, "EMPLOYEE", rows, static_cast<Rdb_ConflictResolution>(1024), context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    ret = OH_Rdb_BatchInsertWithReturning(store_, "EMPLOYEE", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                          nullptr);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;

    ret = OH_VBuckets_Destroy(rows);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    rows = nullptr;

    valueBucket->destroy(valueBucket);
    valueBucket = nullptr;
}

/**
 * @tc.name: OH_Rdb_BatchInsertWithReturning_test_003
 * @tc.desc: Construct a test case with different table names.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_BatchInsertWithReturning_test_003, TestSize.Level1)
{
    OH_VBucket *valueBucket = CreateOneVBucket();
    OH_Data_VBuckets *rows = CreateOneVBuckets();
    int ret = OH_VBuckets_PutRow(rows, valueBucket);
    EXPECT_EQ(ret, RDB_OK);

    OH_RDB_ReturningContext *context = CreateReturningContext({"NAME"});
    ret = OH_Rdb_BatchInsertWithReturning(store_, "", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    ret = OH_Rdb_BatchInsertWithReturning(store_, "abc", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_SQLITE_ERROR);
    ret = OH_Rdb_BatchInsertWithReturning(store_, "E M PLOYEE", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                          context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;

    ret = OH_VBuckets_Destroy(rows);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    rows = nullptr;

    valueBucket->destroy(valueBucket);
    valueBucket = nullptr;
}

/**
 * @tc.name: OH_Rdb_BatchInsertWithReturning_test_004
 * @tc.desc: Construct a test case with different fields.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_BatchInsertWithReturning_test_004, TestSize.Level1)
{
    OH_VBucket *valueBucket = CreateOneVBucket();
    OH_Data_VBuckets *rows = CreateOneVBuckets();
    int ret = OH_VBuckets_PutRow(rows, valueBucket);
    EXPECT_EQ(ret, RDB_OK);

    OH_RDB_ReturningContext *context = CreateReturningContext({});
    ret = OH_Rdb_BatchInsertWithReturning(store_, "EMPLOYEE", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                          context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    OH_RDB_DestroyReturningContext(context);

    context = CreateReturningContext({"NAME", "AGE", "SALARY", "CODES", "HEIGHT", "SEX"});
    ret = OH_Rdb_BatchInsertWithReturning(store_, "EMPLOYEE", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                          context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    OH_RDB_DestroyReturningContext(context);

    context = CreateReturningContext({"NAME", "*"});
    ret = OH_Rdb_BatchInsertWithReturning(store_, "EMPLOYEE", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                          context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    OH_RDB_DestroyReturningContext(context);

    context = CreateReturningContext({"NAME", nullptr});
    ret = OH_Rdb_BatchInsertWithReturning(store_, "EMPLOYEE", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                          context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    OH_RDB_DestroyReturningContext(context);
    context = nullptr;

    ret = OH_VBuckets_Destroy(rows);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    rows = nullptr;

    valueBucket->destroy(valueBucket);
    valueBucket = nullptr;
}

/**
 * @tc.name: OH_Rdb_BatchInsertWithReturning_test_005
 * @tc.desc: Construct a use case with the same asset input.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_BatchInsertWithReturning_test_005, TestSize.Level1)
{
    const int assetsCount = 2;
    Data_Asset **assets = OH_Data_Asset_CreateMultiple(assetsCount);
    OH_Data_Asset_SetName(assets[0], "data");
    OH_Data_Asset_SetName(assets[1], "data");

    OH_VBucket *valueBucket = CreateOneVBucket();
    OH_VBucket_PutAssets(valueBucket, "DATA", assets, assetsCount);

    OH_Data_VBuckets *rows = CreateOneVBuckets();
    int ret = OH_VBuckets_PutRow(rows, valueBucket);
    EXPECT_EQ(ret, RDB_OK);

    OH_RDB_ReturningContext *context = CreateReturningContext({"NAME"});
    ret = OH_Rdb_BatchInsertWithReturning(store_, "EMPLOYEE", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                          context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;

    ret = OH_VBuckets_Destroy(rows);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    rows = nullptr;

    valueBucket->destroy(valueBucket);
    valueBucket = nullptr;
    OH_Data_Asset_DestroyMultiple(assets, assetsCount);
    assets = nullptr;
}

/**
 * @tc.name: OH_Rdb_DeleteWithReturning_test_001
 * @tc.desc: Normal testCase of store for OH_Rdb_DeleteWithReturning.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_DeleteWithReturning_test_001, TestSize.Level1)
{
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    valueObject->putText(valueObject, "Lisa");
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("EMPLOYEE");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);

    OH_RDB_ReturningContext *context = CreateReturningContext({"NAME"});
    int ret = OH_Rdb_DeleteWithReturning(store_, predicates, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(context);
    EXPECT_NE(cursor, nullptr);
    CursorWorksAsExpected(cursor);

    int changed = OH_RDB_GetChanedCount(context);
    EXPECT_EQ(changed, 1);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;

    predicates->destroy(predicates);
    predicates = nullptr;
    valueObject->destroy(valueObject);
    valueObject = nullptr;
}

/**
 * @tc.name: OH_Rdb_DeleteWithReturning_test_002
 * @tc.desc: Construct test cases for inputting various abnormal parameters.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_DeleteWithReturning_test_002, TestSize.Level1)
{
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    valueObject->putText(valueObject, "Lisa");
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("EMPLOYEE");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);

    OH_RDB_ReturningContext *context = CreateReturningContext({"NAME"});
    int ret = OH_Rdb_DeleteWithReturning(nullptr, predicates, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_Rdb_DeleteWithReturning(store_, nullptr, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_Rdb_DeleteWithReturning(store_, predicates, nullptr);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;

    predicates->destroy(predicates);
    predicates = nullptr;
    valueObject->destroy(valueObject);
    valueObject = nullptr;
}

/**
 * @tc.name: OH_Rdb_DeleteWithReturning_test_003
 * @tc.desc: Construct a test case with different table names.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_DeleteWithReturning_test_003, TestSize.Level1)
{
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    valueObject->putText(valueObject, "Lisa");
    OH_RDB_ReturningContext *context = CreateReturningContext({"NAME"});

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("abc");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);
    int ret = OH_Rdb_DeleteWithReturning(store_, predicates, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_SQLITE_ERROR);
    predicates->destroy(predicates);

    predicates = OH_Rdb_CreatePredicates("");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);
    ret = OH_Rdb_DeleteWithReturning(store_, predicates, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    predicates->destroy(predicates);

    predicates = OH_Rdb_CreatePredicates("E M PLOYEE");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);
    ret = OH_Rdb_DeleteWithReturning(store_, predicates, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;
    predicates->destroy(predicates);
    predicates = nullptr;
    valueObject->destroy(valueObject);
    valueObject = nullptr;
}

/**
 * @tc.name: OH_Rdb_DeleteWithReturning_test_004
 * @tc.desc: Construct a test case with different fields.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_DeleteWithReturning_test_004, TestSize.Level1)
{
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    valueObject->putText(valueObject, "Lisa");
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("EMPLOYEE");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);

    OH_RDB_ReturningContext *context = CreateReturningContext({});
    int ret = OH_Rdb_DeleteWithReturning(store_, predicates, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    OH_RDB_DestroyReturningContext(context);

    context = CreateReturningContext({"NAME", "AGE", "SALARY", "CODES", "HEIGHT", "SEX"});
    ret = OH_Rdb_DeleteWithReturning(store_, predicates, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    OH_RDB_DestroyReturningContext(context);

    context = CreateReturningContext({"NAME", "*"});
    ret = OH_Rdb_DeleteWithReturning(store_, predicates, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    OH_RDB_DestroyReturningContext(context);

    context = CreateReturningContext({"NAME", nullptr});
    ret = OH_Rdb_DeleteWithReturning(store_, predicates, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;
    predicates->destroy(predicates);
    predicates = nullptr;
    valueObject->destroy(valueObject);
    valueObject = nullptr;
}

/**
 * @tc.name: OH_Rdb_UpdateWithReturning_test_001
 * @tc.desc: Normal testCase of store for OH_Rdb_UpdateWithReturning.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_UpdateWithReturning_test_001, TestSize.Level1)
{
    OH_VBucket *valueBucketUpdate = CreateOneUpdateVBucket();
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    valueObject->putText(valueObject, "Lisa");
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("EMPLOYEE");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);

    OH_RDB_ReturningContext *context = CreateReturningContext({"NAME"});
    int ret = OH_Rdb_UpdateWithReturning(store_, valueBucketUpdate, predicates,
                                         Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(context);
    EXPECT_NE(cursor, nullptr);
    CursorWorksAsExpected(cursor);

    int changed = OH_RDB_GetChanedCount(context);
    EXPECT_EQ(changed, 1);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;

    predicates->destroy(predicates);
    predicates = nullptr;
    valueObject->destroy(valueObject);
    valueObject = nullptr;
    valueBucketUpdate->destroy(valueBucketUpdate);
    valueBucketUpdate = nullptr;
}

/**
 * @tc.name: OH_Rdb_UpdateWithReturning_test_002
 * @tc.desc: Construct test cases for inputting various abnormal parameters.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_UpdateWithReturning_test_002, TestSize.Level1)
{
    OH_VBucket *valueBucketUpdate = CreateOneUpdateVBucket();
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    valueObject->putText(valueObject, "Lisa");
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("EMPLOYEE");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);

    OH_RDB_ReturningContext *context = CreateReturningContext({"NAME"});
    int ret = OH_Rdb_UpdateWithReturning(nullptr, valueBucketUpdate, predicates,
                                         Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret =
        OH_Rdb_UpdateWithReturning(store_, nullptr, predicates, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_Rdb_UpdateWithReturning(store_, valueBucketUpdate, nullptr, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                     context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_Rdb_UpdateWithReturning(store_, valueBucketUpdate, predicates, static_cast<Rdb_ConflictResolution>(-1),
                                     context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_Rdb_UpdateWithReturning(store_, valueBucketUpdate, predicates, static_cast<Rdb_ConflictResolution>(1024),
                                     context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_Rdb_UpdateWithReturning(store_, valueBucketUpdate, predicates,
                                     Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, nullptr);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    valueBucketUpdate->destroy(valueBucketUpdate);

    valueBucketUpdate = OH_Rdb_CreateValuesBucket();
    ret = OH_Rdb_UpdateWithReturning(store_, valueBucketUpdate, predicates,
                                     Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_ERROR);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;

    predicates->destroy(predicates);
    predicates = nullptr;
    valueObject->destroy(valueObject);
    valueObject = nullptr;
    valueBucketUpdate->destroy(valueBucketUpdate);
    valueBucketUpdate = nullptr;
}

/**
 * @tc.name: OH_Rdb_UpdateWithReturning_test_003
 * @tc.desc: Construct a test case with different table names.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_UpdateWithReturning_test_003, TestSize.Level1)
{
    OH_VBucket *valueBucketUpdate = CreateOneUpdateVBucket();
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    valueObject->putText(valueObject, "Lisa");
    OH_RDB_ReturningContext *context = CreateReturningContext({"NAME"});

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("abc");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);
    int ret = OH_Rdb_UpdateWithReturning(store_, valueBucketUpdate, predicates,
                                         Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_SQLITE_ERROR);
    predicates->destroy(predicates);

    predicates = OH_Rdb_CreatePredicates("");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);
    ret = OH_Rdb_UpdateWithReturning(store_, valueBucketUpdate, predicates,
                                     Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    predicates->destroy(predicates);

    predicates = OH_Rdb_CreatePredicates("E M PLOYEE");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);
    ret = OH_Rdb_UpdateWithReturning(store_, valueBucketUpdate, predicates,
                                     Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;
    predicates->destroy(predicates);
    predicates = nullptr;
    valueObject->destroy(valueObject);
    valueObject = nullptr;
    valueBucketUpdate->destroy(valueBucketUpdate);
    valueBucketUpdate = nullptr;
}

/**
 * @tc.name: OH_Rdb_UpdateWithReturning_test_004
 * @tc.desc: Construct a test case with different fields.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_UpdateWithReturning_test_004, TestSize.Level1)
{
    OH_VBucket *valueBucketUpdate = CreateOneUpdateVBucket();
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    valueObject->putText(valueObject, "Lisa");
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("EMPLOYEE");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);

    OH_RDB_ReturningContext *context = CreateReturningContext({});
    int ret = OH_Rdb_UpdateWithReturning(store_, valueBucketUpdate, predicates,
                                         Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    OH_RDB_DestroyReturningContext(context);

    context = CreateReturningContext({"NAME", "AGE", "SALARY", "CODES", "HEIGHT", "SEX"});
    ret = OH_Rdb_UpdateWithReturning(store_, valueBucketUpdate, predicates,
                                     Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    OH_RDB_DestroyReturningContext(context);

    context = CreateReturningContext({"NAME", "*"});
    ret = OH_Rdb_UpdateWithReturning(store_, valueBucketUpdate, predicates,
                                     Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    OH_RDB_DestroyReturningContext(context);

    context = CreateReturningContext({"NAME", nullptr});
    ret = OH_Rdb_UpdateWithReturning(store_, valueBucketUpdate, predicates,
                                     Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    OH_RDB_DestroyReturningContext(context);
    context = nullptr;

    predicates->destroy(predicates);
    predicates = nullptr;
    valueObject->destroy(valueObject);
    valueObject = nullptr;
    valueBucketUpdate->destroy(valueBucketUpdate);
    valueBucketUpdate = nullptr;
}

/**
 * @tc.name: OH_RdbTrans_BatchInsertWithReturning_test_001
 * @tc.desc: Normal testCase of store for OH_RdbTrans_BatchInsertWithReturning.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_BatchInsertWithReturning_test_001, TestSize.Level1)
{
    OH_VBucket *valueBucket = CreateOneVBucket();
    OH_Data_VBuckets *rows = CreateOneVBuckets();
    int ret = OH_VBuckets_PutRow(rows, valueBucket);
    EXPECT_EQ(ret, RDB_OK);

    OH_Rdb_Transaction *trans = CreateTransaction(store_);
    OH_RDB_ReturningContext *context = CreateReturningContext({"NAME"});
    ret = OH_RdbTrans_BatchInsertWithReturning(trans, "EMPLOYEE", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                               context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(context);
    EXPECT_NE(cursor, nullptr);
    CursorWorksAsExpected(cursor);

    int changed = OH_RDB_GetChanedCount(context);
    EXPECT_EQ(changed, 1);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
    trans = nullptr;

    ret = OH_VBuckets_Destroy(rows);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    rows = nullptr;

    valueBucket->destroy(valueBucket);
    valueBucket = nullptr;
}

/**
 * @tc.name: OH_RdbTrans_BatchInsertWithReturning_test_002
 * @tc.desc: Construct test cases for inputting various abnormal parameters.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_BatchInsertWithReturning_test_002, TestSize.Level1)
{
    OH_VBucket *valueBucket = CreateOneVBucket();
    OH_Data_VBuckets *rows = CreateOneVBuckets();
    int ret = OH_VBuckets_PutRow(rows, valueBucket);
    EXPECT_EQ(ret, RDB_OK);

    OH_Rdb_Transaction *trans = CreateTransaction(store_);
    OH_RDB_ReturningContext *context = CreateReturningContext({"NAME"});
    ret = OH_RdbTrans_BatchInsertWithReturning(nullptr, "EMPLOYEE", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                               context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_BatchInsertWithReturning(trans, nullptr, rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                               context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_BatchInsertWithReturning(trans, "EMPLOYEE", nullptr, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                               context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret =
        OH_RdbTrans_BatchInsertWithReturning(trans, "EMPLOYEE", rows, static_cast<Rdb_ConflictResolution>(-1), context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_BatchInsertWithReturning(trans, "EMPLOYEE", rows, static_cast<Rdb_ConflictResolution>(1024),
                                               context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_BatchInsertWithReturning(trans, "EMPLOYEE", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                               nullptr);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    ret = OH_VBuckets_Destroy(rows);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    rows = OH_VBuckets_Create();  // empty
    EXPECT_NE(rows, nullptr);
    ret = OH_RdbTrans_BatchInsertWithReturning(trans, "EMPLOYEE", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                               context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
    trans = nullptr;

    ret = OH_VBuckets_Destroy(rows);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    rows = nullptr;

    valueBucket->destroy(valueBucket);
    valueBucket = nullptr;
}

/**
 * @tc.name: OH_RdbTrans_BatchInsertWithReturning_test_003
 * @tc.desc: Construct a test case with different table names.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_BatchInsertWithReturning_test_003, TestSize.Level1)
{
    OH_VBucket *valueBucket = CreateOneVBucket();
    OH_Data_VBuckets *rows = CreateOneVBuckets();
    int ret = OH_VBuckets_PutRow(rows, valueBucket);
    EXPECT_EQ(ret, RDB_OK);

    OH_Rdb_Transaction *trans = CreateTransaction(store_);
    OH_RDB_ReturningContext *context = CreateReturningContext({"NAME"});
    ret = OH_RdbTrans_BatchInsertWithReturning(trans, "", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret =
        OH_RdbTrans_BatchInsertWithReturning(trans, "abc", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_SQLITE_ERROR);

    ret = OH_RdbTrans_BatchInsertWithReturning(trans, "E M PLOYEE", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                               context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    ret = OH_VBuckets_Destroy(rows);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    rows = CreateOneVBuckets();
    ret = OH_RdbTrans_BatchInsertWithReturning(trans, "EMPLOYEE", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                               context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
    trans = nullptr;

    ret = OH_VBuckets_Destroy(rows);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    rows = nullptr;

    valueBucket->destroy(valueBucket);
    valueBucket = nullptr;
}

/**
 * @tc.name: OH_RdbTrans_BatchInsertWithReturning_test_004
 * @tc.desc: Construct a test case with different fields.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_BatchInsertWithReturning_test_004, TestSize.Level1)
{
    OH_VBucket *valueBucket = CreateOneVBucket();
    OH_Data_VBuckets *rows = CreateOneVBuckets();
    int ret = OH_VBuckets_PutRow(rows, valueBucket);
    EXPECT_EQ(ret, RDB_OK);

    OH_Rdb_Transaction *trans = CreateTransaction(store_);
    OH_RDB_ReturningContext *context = CreateReturningContext({""});
    ret = OH_RdbTrans_BatchInsertWithReturning(trans, "EMPLOYEE", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                               context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_SQLITE_ERROR);

    context = CreateReturningContext({"NAME", "AGE", "SALARY", "CODES", "HEIGHT", "SEX"});
    ret = OH_RdbTrans_BatchInsertWithReturning(trans, "EMPLOYEE", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                               context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    OH_RDB_DestroyReturningContext(context);

    context = CreateReturningContext({"NAME", "*"});
    ret = OH_RdbTrans_BatchInsertWithReturning(trans, "EMPLOYEE", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                               context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    OH_RDB_DestroyReturningContext(context);

    context = CreateReturningContext({"NAME", nullptr});
    ret = OH_RdbTrans_BatchInsertWithReturning(trans, "EMPLOYEE", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                               context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
    trans = nullptr;

    ret = OH_VBuckets_Destroy(rows);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    rows = nullptr;

    valueBucket->destroy(valueBucket);
    valueBucket = nullptr;
}

/**
 * @tc.name: OH_RdbTrans_BatchInsertWithReturning_test_005
 * @tc.desc: Construct a use case with the same asset input.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_BatchInsertWithReturning_test_005, TestSize.Level1)
{
    const int assetsCount = 2;
    Data_Asset **assets = OH_Data_Asset_CreateMultiple(assetsCount);
    OH_Data_Asset_SetName(assets[0], "data");
    OH_Data_Asset_SetName(assets[1], "data");

    OH_VBucket *valueBucket = CreateOneVBucket();
    OH_VBucket_PutAssets(valueBucket, "DATA", assets, assetsCount);

    OH_Data_VBuckets *rows = CreateOneVBuckets();
    int ret = OH_VBuckets_PutRow(rows, valueBucket);
    EXPECT_EQ(ret, RDB_OK);

    OH_Rdb_Transaction *trans = CreateTransaction(store_);
    OH_RDB_ReturningContext *context = CreateReturningContext({"NAME"});
    ret = OH_RdbTrans_BatchInsertWithReturning(trans, "EMPLOYEE", rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                               context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
    trans = nullptr;

    ret = OH_VBuckets_Destroy(rows);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    rows = nullptr;
    valueBucket->destroy(valueBucket);
    valueBucket = nullptr;
    OH_Data_Asset_DestroyMultiple(assets, assetsCount);
    assets = nullptr;
}

/**
 * @tc.name: OH_RdbTrans_DeleteWithReturning_test_001
 * @tc.desc: Normal testCase of store for OH_RdbTrans_DeleteWithReturning.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_DeleteWithReturning_test_001, TestSize.Level1)
{
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    valueObject->putText(valueObject, "Lisa");
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("EMPLOYEE");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);

    OH_Rdb_Transaction *trans = CreateTransaction(store_);
    OH_RDB_ReturningContext *context = CreateReturningContext({"NAME"});
    int ret = OH_RdbTrans_DeleteWithReturning(trans, predicates, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(context);
    EXPECT_NE(cursor, nullptr);
    CursorWorksAsExpected(cursor);

    int changed = OH_RDB_GetChanedCount(context);
    EXPECT_EQ(changed, 1);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
    trans = nullptr;

    predicates->destroy(predicates);
    predicates = nullptr;
    valueObject->destroy(valueObject);
    valueObject = nullptr;
}

/**
 * @tc.name: OH_RdbTrans_DeleteWithReturning_test_002
 * @tc.desc: Construct test cases for inputting various abnormal parameters.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_DeleteWithReturning_test_002, TestSize.Level1)
{
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    valueObject->putText(valueObject, "Lisa");
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("EMPLOYEE");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);

    OH_Rdb_Transaction *trans = CreateTransaction(store_);
    OH_RDB_ReturningContext *context = CreateReturningContext({"NAME"});
    int ret = OH_RdbTrans_DeleteWithReturning(nullptr, predicates, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_DeleteWithReturning(trans, nullptr, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_DeleteWithReturning(trans, predicates, nullptr);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
    trans = nullptr;

    predicates->destroy(predicates);
    predicates = nullptr;
    valueObject->destroy(valueObject);
    valueObject = nullptr;
}

/**
 * @tc.name: OH_RdbTrans_DeleteWithReturning_test_003
 * @tc.desc: Construct a test case with different table names.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_DeleteWithReturning_test_003, TestSize.Level1)
{
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    valueObject->putText(valueObject, "Lisa");
    OH_Rdb_Transaction *trans = CreateTransaction(store_);
    OH_RDB_ReturningContext *context = CreateReturningContext({"NAME"});

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("abc");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);
    int ret = OH_RdbTrans_DeleteWithReturning(trans, predicates, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_SQLITE_ERROR);
    predicates->destroy(predicates);

    predicates = OH_Rdb_CreatePredicates("");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);
    ret = OH_RdbTrans_DeleteWithReturning(trans, predicates, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    predicates->destroy(predicates);

    predicates = OH_Rdb_CreatePredicates("E M PLOYEE");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);
    ret = OH_RdbTrans_DeleteWithReturning(trans, predicates, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
    trans = nullptr;

    predicates->destroy(predicates);
    predicates = nullptr;
    valueObject->destroy(valueObject);
    valueObject = nullptr;
}

/**
 * @tc.name: OH_RdbTrans_DeleteWithReturning_test_004
 * @tc.desc: Construct a test case with different fields.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_DeleteWithReturning_test_004, TestSize.Level1)
{
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    valueObject->putText(valueObject, "Lisa");
    OH_Rdb_Transaction *trans = CreateTransaction(store_);
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("EMPLOYEE");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);

    OH_RDB_ReturningContext *context = CreateReturningContext({});
    int ret = OH_RdbTrans_DeleteWithReturning(trans, predicates, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    OH_RDB_DestroyReturningContext(context);

    context = CreateReturningContext({"NAME", "*"});
    ret = OH_RdbTrans_DeleteWithReturning(trans, predicates, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    OH_RDB_DestroyReturningContext(context);

    context = CreateReturningContext({"NAME", nullptr});
    ret = OH_RdbTrans_DeleteWithReturning(trans, predicates, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    OH_RDB_DestroyReturningContext(context);

    context = CreateReturningContext({"NAME", "AGE", "SALARY", "CODES", "HEIGHT", "SEX"});
    ret = OH_RdbTrans_DeleteWithReturning(trans, predicates, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
    trans = nullptr;

    predicates->destroy(predicates);
    predicates = nullptr;
    valueObject->destroy(valueObject);
    valueObject = nullptr;
}

/**
 * @tc.name: OH_RdbTrans_UpdateWithReturning_test_001
 * @tc.desc: Normal testCase of store for OH_RdbTrans_UpdateWithReturning.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_UpdateWithReturning_test_001, TestSize.Level1)
{
    OH_VBucket *valueBucketUpdate = CreateOneUpdateVBucket();
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    valueObject->putText(valueObject, "Lisa");
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("EMPLOYEE");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);

    OH_Rdb_Transaction *trans = CreateTransaction(store_);
    OH_RDB_ReturningContext *context = CreateReturningContext({"NAME"});
    int ret = OH_RdbTrans_UpdateWithReturning(trans, valueBucketUpdate, predicates,
                                              Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(context);
    EXPECT_NE(cursor, nullptr);
    CursorWorksAsExpected(cursor);

    int changed = OH_RDB_GetChanedCount(context);
    EXPECT_EQ(changed, 1);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
    trans = nullptr;

    predicates->destroy(predicates);
    predicates = nullptr;
    valueObject->destroy(valueObject);
    valueObject = nullptr;
    valueBucketUpdate->destroy(valueBucketUpdate);
    valueBucketUpdate = nullptr;
}

/**
 * @tc.name: OH_RdbTrans_UpdateWithReturning_test_002
 * @tc.desc: Construct test cases for inputting various abnormal parameters.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_UpdateWithReturning_test_002, TestSize.Level1)
{
    OH_VBucket *valueBucketUpdate = CreateOneUpdateVBucket();
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    valueObject->putText(valueObject, "Lisa");
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("EMPLOYEE");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);

    OH_Rdb_Transaction *trans = CreateTransaction(store_);
    OH_RDB_ReturningContext *context = CreateReturningContext({"NAME"});
    int ret = OH_RdbTrans_UpdateWithReturning(nullptr, valueBucketUpdate, predicates,
                                              Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_UpdateWithReturning(trans, nullptr, predicates, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE,
                                          context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_UpdateWithReturning(trans, valueBucketUpdate, nullptr,
                                          Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_UpdateWithReturning(trans, valueBucketUpdate, predicates, static_cast<Rdb_ConflictResolution>(-1),
                                          context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_UpdateWithReturning(trans, valueBucketUpdate, predicates,
                                          static_cast<Rdb_ConflictResolution>(1024), context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_UpdateWithReturning(trans, valueBucketUpdate, predicates,
                                          Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, nullptr);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
    trans = nullptr;

    predicates->destroy(predicates);
    predicates = nullptr;
    valueObject->destroy(valueObject);
    valueObject = nullptr;
    valueBucketUpdate->destroy(valueBucketUpdate);
    valueBucketUpdate = nullptr;
}

/**
 * @tc.name: OH_RdbTrans_UpdateWithReturning_test_003
 * @tc.desc: Construct a test case with different table names.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_UpdateWithReturning_test_003, TestSize.Level1)
{
    OH_VBucket *valueBucketUpdate = OH_Rdb_CreateValuesBucket();
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    valueObject->putText(valueObject, "Lisa");
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("EMPLOYEE");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);

    OH_Rdb_Transaction *trans = CreateTransaction(store_);
    OH_RDB_ReturningContext *context = CreateReturningContext({"NAME"});
    int ret = OH_RdbTrans_UpdateWithReturning(trans, valueBucketUpdate, predicates,
                                              Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    predicates->destroy(predicates);
    valueBucketUpdate->destroy(valueBucketUpdate);
    valueBucketUpdate = CreateOneUpdateVBucket();
    predicates = OH_Rdb_CreatePredicates("abc");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);
    ret = OH_RdbTrans_UpdateWithReturning(trans, valueBucketUpdate, predicates,
                                          Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_SQLITE_ERROR);

    predicates->destroy(predicates);
    predicates = OH_Rdb_CreatePredicates("");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);
    ret = OH_RdbTrans_UpdateWithReturning(trans, valueBucketUpdate, predicates,
                                          Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    predicates->destroy(predicates);
    predicates = OH_Rdb_CreatePredicates("E M PLOYEE");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);
    ret = OH_RdbTrans_UpdateWithReturning(trans, valueBucketUpdate, predicates,
                                          Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
    trans = nullptr;

    predicates->destroy(predicates);
    predicates = nullptr;
    valueObject->destroy(valueObject);
    valueObject = nullptr;
    valueBucketUpdate->destroy(valueBucketUpdate);
    valueBucketUpdate = nullptr;
}

/**
 * @tc.name: OH_RdbTrans_UpdateWithReturning_test_004
 * @tc.desc: Construct a test case with different fields.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_UpdateWithReturning_test_004, TestSize.Level1)
{
    OH_VBucket *valueBucketUpdate = OH_Rdb_CreateValuesBucket();
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    valueObject->putText(valueObject, "Lisa");
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("EMPLOYEE");
    EXPECT_NE(predicates, nullptr);
    predicates->equalTo(predicates, "NAME", valueObject);

    OH_Rdb_Transaction *trans = CreateTransaction(store_);
    OH_RDB_ReturningContext *context = CreateReturningContext({});
    int ret = OH_RdbTrans_UpdateWithReturning(trans, valueBucketUpdate, predicates,
                                              Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_RDB_DestroyReturningContext(context);
    context = CreateReturningContext({"NAME", "*"});
    ret = OH_RdbTrans_UpdateWithReturning(trans, valueBucketUpdate, predicates,
                                          Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_RDB_DestroyReturningContext(context);
    context = CreateReturningContext({"NAME", nullptr});
    ret = OH_RdbTrans_UpdateWithReturning(trans, valueBucketUpdate, predicates,
                                          Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_RDB_DestroyReturningContext(context);
    context = CreateReturningContext({"NAME", "AGE", "SALARY", "CODES", "HEIGHT", "SEX"});
    ret = OH_RdbTrans_UpdateWithReturning(trans, valueBucketUpdate, predicates,
                                          Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
    trans = nullptr;

    predicates->destroy(predicates);
    predicates = nullptr;
    valueObject->destroy(valueObject);
    valueObject = nullptr;
    valueBucketUpdate->destroy(valueBucketUpdate);
    valueBucketUpdate = nullptr;
}

/**
 * @tc.name: OH_RDB_ReturningContext_test_001
 * @tc.desc: testcase for OH_RDB_ReturningContext functions.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RDB_ReturningContext_test_001, TestSize.Level1)
{
    OH_RDB_ReturningContext *context = CreateReturningContext({"NAME", "AGE", "SALARY"});
    int ret = OH_RDB_SetMaxReturningCount(context, 1);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    ret = OH_RDB_SetMaxReturningCount(context, -1);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RDB_SetMaxReturningCount(context, 0X7FFF);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RDB_SetMaxReturningCount(nullptr, 1);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    const char *columns[] = {"NAME", "AGE", "SALARY"};
    int32_t len = sizeof(columns) / sizeof(columns[0]);

    ret = OH_RDB_SetReturningField(context, columns, len);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    ret = OH_RDB_SetReturningField(nullptr, columns, len);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RDB_SetReturningField(context, nullptr, len);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RDB_SetReturningField(context, columns, -1);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    const char *columns1[] = {"NAME", "*", "SALARY"};
    int32_t len1 = sizeof(columns1) / sizeof(columns1[0]);
    ret = OH_RDB_SetReturningField(context, columns1, len1);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    const char *columns2[] = {"NAME", nullptr, "SALARY"};
    int32_t len2 = sizeof(columns2) / sizeof(columns2[0]);
    ret = OH_RDB_SetReturningField(context, columns2, len2);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(nullptr);
    EXPECT_EQ(cursor, nullptr);

    int64_t changedCount = OH_RDB_GetChanedCount(nullptr);
    EXPECT_EQ(changedCount, -1);

    OH_RDB_DestroyReturningContext(context);
    context = nullptr;
    OH_RDB_DestroyReturningContext(nullptr);
}

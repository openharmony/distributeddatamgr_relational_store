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

// ==================== Test Constants ====================
namespace {
// Database constants
constexpr const char *TEST_TABLE_NAME = "EMPLOYEE";
constexpr const char *TEST_DB_NAME = "rdb_store_test.db";
constexpr const char *TEST_BUNDLE_NAME = "com.ohos.example.distributedndk";

// Test data constants
constexpr const char *DEFAULT_NAME = "Lisa";
constexpr const char *UPDATE_NAME = "Lucy";
constexpr const char *DEFAULT_SEX = "MALE";
constexpr const char *UPDATE_SEX = "FEMALE";
constexpr int DEFAULT_AGE = 18;
constexpr int UPDATE_AGE = 19;
constexpr float DEFAULT_SALARY = 100.5f;
constexpr float UPDATE_SALARY = 101.5f;
constexpr float DEFAULT_HEIGHT = 172.0f;
constexpr float UPDATE_HEIGHT = 173.0f;
constexpr int ASSETS_COUNT = 2;
constexpr int FLOATS_SIZE = 3;

// Expected values
constexpr int EXPECTED_SINGLE_ROW = 1;
constexpr int EXPECTED_SINGLE_COLUMN = 1;
constexpr int EXPECTED_NAME_SIZE = 5; // "Lisa" or "Lucy"

// Asset names
constexpr const char *DEFAULT_ASSET_NAMES[] = { "asset1", "asset2" };
constexpr const char *UPDATE_ASSET_NAMES[] = { "asset3", "asset4" };
constexpr const char *REPEAT_ASSET_NAME = "data";

// Float vectors
constexpr float DEFAULT_FLOATS[] = { 1.0f, 2.0f, 3.0f };
constexpr float UPDATE_FLOATS[] = { 4.0f, 5.0f, 6.0f };

// Blob data
constexpr uint8_t DEFAULT_BLOB[] = { 1, 2, 3, 4, 5 };
constexpr uint8_t UPDATE_BLOB[] = { 1, 2, 3, 4, 5, 6 };
} // namespace

class RdbStoreReturningTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

private:
    static void InitRdbConfig();
    static OH_VBucket *CreateOneVBucket();
    static OH_VBucket *CreateOneUpdateVBucket();
    static OH_Data_VBuckets *CreateOneVBuckets();
    static OH_RDB_ReturningContext *CreateReturningContext(std::vector<const char *> fields);
    static OH_Rdb_Transaction *CreateTransaction(OH_Rdb_Store *store);

    // Verification helpers
    static void VerifyCursorData(OH_Cursor *cursor, const std::string &expectedValue);
    static void VerifyCursorRowCount(OH_Cursor *cursor, int expectedRowCount);
    static void VerifyCursorColumnCount(OH_Cursor *cursor, int expectedColumnCount);
};

static OH_Rdb_Store *store_ = nullptr;
static OH_Rdb_ConfigV2 *config_ = OH_Rdb_CreateConfig();

OH_VBucket *RdbStoreReturningTest::CreateOneVBucket()
{
    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    EXPECT_NE(valueBucket, nullptr);

    valueBucket->putText(valueBucket, "NAME", DEFAULT_NAME);
    valueBucket->putInt64(valueBucket, "AGE", DEFAULT_AGE);
    valueBucket->putReal(valueBucket, "SALARY", DEFAULT_SALARY);

    int blobLen = sizeof(DEFAULT_BLOB) / sizeof(DEFAULT_BLOB[0]);
    valueBucket->putBlob(valueBucket, "CODES", DEFAULT_BLOB, blobLen);

    valueBucket->putReal(valueBucket, "HEIGHT", DEFAULT_HEIGHT);
    valueBucket->putText(valueBucket, "SEX", DEFAULT_SEX);

    Data_Asset **assets = OH_Data_Asset_CreateMultiple(ASSETS_COUNT);
    EXPECT_NE(assets, nullptr);
    for (int i = 0; i < ASSETS_COUNT; ++i) {
        OH_Data_Asset_SetName(assets[i], DEFAULT_ASSET_NAMES[i]);
    }
    OH_VBucket_PutAssets(valueBucket, "DATAS", assets, ASSETS_COUNT);
    OH_Data_Asset_DestroyMultiple(assets, ASSETS_COUNT);

    int ret = OH_VBucket_PutFloatVector(valueBucket, "FLOATS", DEFAULT_FLOATS, FLOATS_SIZE);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    return valueBucket;
}

OH_VBucket *RdbStoreReturningTest::CreateOneUpdateVBucket()
{
    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    EXPECT_NE(valueBucket, nullptr);

    valueBucket->putText(valueBucket, "NAME", UPDATE_NAME);
    valueBucket->putInt64(valueBucket, "AGE", UPDATE_AGE);
    valueBucket->putReal(valueBucket, "SALARY", UPDATE_SALARY);

    int blobLen = sizeof(UPDATE_BLOB) / sizeof(UPDATE_BLOB[0]);
    valueBucket->putBlob(valueBucket, "CODES", UPDATE_BLOB, blobLen);

    valueBucket->putReal(valueBucket, "HEIGHT", UPDATE_HEIGHT);
    valueBucket->putText(valueBucket, "SEX", UPDATE_SEX);

    Data_Asset **assets = OH_Data_Asset_CreateMultiple(ASSETS_COUNT);
    EXPECT_NE(assets, nullptr);
    for (int i = 0; i < ASSETS_COUNT; ++i) {
        OH_Data_Asset_SetName(assets[i], UPDATE_ASSET_NAMES[i]);
    }
    OH_VBucket_PutAssets(valueBucket, "DATAS", assets, ASSETS_COUNT);
    OH_Data_Asset_DestroyMultiple(assets, ASSETS_COUNT);

    int ret = OH_VBucket_PutFloatVector(valueBucket, "FLOATS", UPDATE_FLOATS, FLOATS_SIZE);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
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
    OH_RDB_SetReturningFields(returningContext, fields.data(), static_cast<int32_t>(fields.size()));
    return returningContext;
}

OH_Rdb_Transaction *RdbStoreReturningTest::CreateTransaction(OH_Rdb_Store *store)
{
    OH_RDB_TransOptions *options = OH_RdbTrans_CreateOptions();
    EXPECT_NE(options, nullptr);
    int ret = OH_RdbTransOption_SetType(options, RDB_TRANS_DEFERRED);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Rdb_Transaction *trans = nullptr;
    ret = OH_Rdb_CreateTransaction(store, options, &trans);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    EXPECT_NE(trans, nullptr);
    return trans;
}

void RdbStoreReturningTest::VerifyCursorData(OH_Cursor *cursor, const std::string &expectedValue)
{
    ASSERT_NE(cursor, nullptr);

    VerifyCursorRowCount(cursor, EXPECTED_SINGLE_ROW);
    VerifyCursorColumnCount(cursor, EXPECTED_SINGLE_COLUMN);

    EXPECT_EQ(cursor->goToNextRow(cursor), OH_Rdb_ErrCode::RDB_OK);

    size_t size = 0;
    int ret = cursor->getSize(cursor, 0, &size);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    EXPECT_EQ(size, EXPECTED_NAME_SIZE);

    char dataValue[size];
    ret = cursor->getText(cursor, 0, dataValue, size);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    EXPECT_EQ(std::string(dataValue), expectedValue);
}

void RdbStoreReturningTest::VerifyCursorRowCount(OH_Cursor *cursor, int expectedRowCount)
{
    ASSERT_NE(cursor, nullptr);
    int rowCount = 0;
    int ret = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    EXPECT_EQ(rowCount, expectedRowCount);
}

void RdbStoreReturningTest::VerifyCursorColumnCount(OH_Cursor *cursor, int expectedColumnCount)
{
    ASSERT_NE(cursor, nullptr);
    int columnCount = 0;
    int ret = cursor->getColumnCount(cursor, &columnCount);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    EXPECT_EQ(columnCount, expectedColumnCount);
}

void RdbStoreReturningTest::InitRdbConfig()
{
    const mode_t mode = 0770;
    mkdir(RDB_TEST_PATH, mode);
    OH_Rdb_SetDatabaseDir(config_, RDB_TEST_PATH);
    OH_Rdb_SetStoreName(config_, TEST_DB_NAME);
    OH_Rdb_SetBundleName(config_, TEST_BUNDLE_NAME);
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
    std::string createTableSql = "CREATE TABLE IF NOT EXISTS " + std::string(TEST_TABLE_NAME) +
                                 " (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, AGE INTEGER, "
                                 "SALARY REAL, CODES BLOB, HEIGHT REAL, SEX TEXT, DATAS ASSETS, FLOATS FLOATVECTOR)";
    int errCode = OH_Rdb_Execute(store_, createTableSql.c_str());
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);

    OH_VBucket *valueBucket = CreateOneVBucket();
    int rowId = OH_Rdb_Insert(store_, TEST_TABLE_NAME, valueBucket);
    EXPECT_EQ(rowId, EXPECTED_SINGLE_ROW);
    valueBucket->destroy(valueBucket);
}

void RdbStoreReturningTest::TearDown(void)
{
    std::string dropTableSql = "DROP TABLE IF EXISTS " + std::string(TEST_TABLE_NAME);
    int errCode = OH_Rdb_Execute(store_, dropTableSql.c_str());
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);
}

// ==================== Test Data Helper Structures ====================

// Base structure for common test data management
struct BaseTestData {
    OH_RDB_ReturningContext *context = nullptr;
    OH_Rdb_Transaction *trans = nullptr;

    explicit BaseTestData(std::vector<const char *> fields)
    {
        context = RdbStoreReturningTest::CreateReturningContext(fields);
    }

    BaseTestData(OH_Rdb_Store *store, std::vector<const char *> fields) : BaseTestData(fields)
    {
        trans = RdbStoreReturningTest::CreateTransaction(store);
    }

    virtual ~BaseTestData()
    {
        if (context) {
            OH_RDB_DestroyReturningContext(context);
            context = nullptr;
        }
        if (trans) {
            OH_RdbTrans_Destroy(trans);
            trans = nullptr;
        }
    }

    // Prevent copying
    BaseTestData(const BaseTestData &) = delete;
    BaseTestData &operator=(const BaseTestData &) = delete;
};

// Batch insert test data structure
struct BatchInsertInputData : public BaseTestData {
    OH_VBucket *valueBucket = nullptr;
    OH_Data_VBuckets *rows = nullptr;
    Data_Asset **assets = nullptr;

    explicit BatchInsertInputData(std::vector<const char *> fields) : BaseTestData(fields)
    {
        Initialize();
    }

    BatchInsertInputData(OH_Rdb_Store *store, std::vector<const char *> fields) : BaseTestData(store, fields)
    {
        Initialize();
    }

    ~BatchInsertInputData() override
    {
        Cleanup();
    }

    void PutRows()
    {
        int ret = OH_VBuckets_PutRow(rows, valueBucket);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);
    }

    void PutRepeatAsset()
    {
        for (int i = 0; i < ASSETS_COUNT; ++i) {
            OH_Data_Asset_SetName(assets[i], REPEAT_ASSET_NAME);
        }
        OH_VBucket_PutAssets(valueBucket, "DATAS", assets, ASSETS_COUNT);
    }

    void EmptyRows()
    {
        OH_VBuckets_Destroy(rows);
        rows = OH_VBuckets_Create();
        ASSERT_NE(rows, nullptr);
    }

private:
    void Initialize()
    {
        valueBucket = RdbStoreReturningTest::CreateOneVBucket();
        rows = RdbStoreReturningTest::CreateOneVBuckets();
        assets = OH_Data_Asset_CreateMultiple(ASSETS_COUNT);
    }

    void Cleanup()
    {
        OH_VBuckets_Destroy(rows);
        if (valueBucket) {
            valueBucket->destroy(valueBucket);
        }
        OH_Data_Asset_DestroyMultiple(assets, ASSETS_COUNT);
    }
};

// Delete operation test data structure
struct DeleteInputData : public BaseTestData {
    OH_VObject *valueObject = nullptr;
    OH_Predicates *predicates = nullptr;

    DeleteInputData(const char *table, std::vector<const char *> fields) : BaseTestData(fields)
    {
        Initialize(table);
    }

    DeleteInputData(OH_Rdb_Store *store, const char *table, std::vector<const char *> fields)
        : BaseTestData(store, fields)
    {
        Initialize(table);
    }

    ~DeleteInputData() override
    {
        Cleanup();
    }

private:
    void Initialize(const char *table)
    {
        valueObject = OH_Rdb_CreateValueObject();
        valueObject->putText(valueObject, DEFAULT_NAME);
        predicates = OH_Rdb_CreatePredicates(table);
        ASSERT_NE(predicates, nullptr);
        predicates->equalTo(predicates, "NAME", valueObject);
    }

    void Cleanup()
    {
        if (predicates) {
            predicates->destroy(predicates);
        }
        if (valueObject) {
            valueObject->destroy(valueObject);
        }
    }
};

// Update operation test data structure
struct UpdateInputData : public BaseTestData {
    OH_VBucket *valueBucketUpdate = nullptr;
    OH_VObject *valueObject = nullptr;
    OH_Predicates *predicates = nullptr;

    UpdateInputData(const char *table, std::vector<const char *> fields) : BaseTestData(fields)
    {
        Initialize(table);
    }

    UpdateInputData(OH_Rdb_Store *store, const char *table, std::vector<const char *> fields)
        : BaseTestData(store, fields)
    {
        Initialize(table);
    }

    ~UpdateInputData() override
    {
        Cleanup();
    }

    void EmptyValueBucketUpdate()
    {
        if (valueBucketUpdate) {
            valueBucketUpdate->destroy(valueBucketUpdate);
        }
        valueBucketUpdate = OH_Rdb_CreateValuesBucket();
        ASSERT_NE(valueBucketUpdate, nullptr);
    }

private:
    void Initialize(const char *table)
    {
        valueBucketUpdate = RdbStoreReturningTest::CreateOneUpdateVBucket();
        valueObject = OH_Rdb_CreateValueObject();
        valueObject->putText(valueObject, DEFAULT_NAME);
        predicates = OH_Rdb_CreatePredicates(table);
        ASSERT_NE(predicates, nullptr);
        predicates->equalTo(predicates, "NAME", valueObject);
    }

    void Cleanup()
    {
        if (predicates) {
            predicates->destroy(predicates);
        }
        if (valueObject) {
            valueObject->destroy(valueObject);
        }
        if (valueBucketUpdate) {
            valueBucketUpdate->destroy(valueBucketUpdate);
        }
    }
};
/**
 * @tc.name: OH_Rdb_BatchInsertWithReturning_test_001
 * @tc.desc: Normal testCase for batch insert with returning clause.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_BatchInsertWithReturning_test_001, TestSize.Level1)
{
    BatchInsertInputData data({ "NAME" });
    data.PutRows();

    int ret = OH_Rdb_BatchInsertWithReturning(
        store_, TEST_TABLE_NAME, data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(data.context);
    ASSERT_NE(cursor, nullptr);
    VerifyCursorData(cursor, DEFAULT_NAME);

    int changed = OH_RDB_GetChangedCount(data.context);
    EXPECT_EQ(changed, EXPECTED_SINGLE_ROW);
}

/**
 * @tc.name: OH_Rdb_BatchInsertWithReturning_test_002
 * @tc.desc: Test batch insert with various invalid parameters.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_BatchInsertWithReturning_test_002, TestSize.Level1)
{
    BatchInsertInputData data({ "NAME" });
    data.PutRows();

    // Test null store
    int ret = OH_Rdb_BatchInsertWithReturning(
        nullptr, TEST_TABLE_NAME, data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test null table name
    ret = OH_Rdb_BatchInsertWithReturning(
        store_, nullptr, data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test null rows
    ret = OH_Rdb_BatchInsertWithReturning(
        store_, TEST_TABLE_NAME, nullptr, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test invalid conflict resolution (-1)
    ret = OH_Rdb_BatchInsertWithReturning(
        store_, TEST_TABLE_NAME, data.rows, static_cast<Rdb_ConflictResolution>(-1), data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test invalid conflict resolution (1024)
    ret = OH_Rdb_BatchInsertWithReturning(
        store_, TEST_TABLE_NAME, data.rows, static_cast<Rdb_ConflictResolution>(1024), data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test null context
    ret = OH_Rdb_BatchInsertWithReturning(
        store_, TEST_TABLE_NAME, data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, nullptr);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_Rdb_BatchInsertWithReturning_test_003
 * @tc.desc: Test batch insert with different table names.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_BatchInsertWithReturning_test_003, TestSize.Level1)
{
    BatchInsertInputData data({ "NAME" });
    data.PutRows();

    // Test empty table name
    int ret = OH_Rdb_BatchInsertWithReturning(
        store_, "", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test non-existent table
    ret = OH_Rdb_BatchInsertWithReturning(
        store_, "abc", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_SQLITE_ERROR);

    // Test table name with spaces
    ret = OH_Rdb_BatchInsertWithReturning(
        store_, "E M PLOYEE", data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_Rdb_BatchInsertWithReturning_test_004
 * @tc.desc: Test batch insert with different field configurations.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_BatchInsertWithReturning_test_004, TestSize.Level1)
{
    // Test empty fields
    {
        BatchInsertInputData data({});
        data.PutRows();
        int ret = OH_Rdb_BatchInsertWithReturning(
            store_, TEST_TABLE_NAME, data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    }

    // Test multiple fields
    {
        BatchInsertInputData data({ "NAME", "AGE", "SALARY", "CODES", "HEIGHT", "SEX" });
        data.PutRows();
        int ret = OH_Rdb_BatchInsertWithReturning(
            store_, TEST_TABLE_NAME, data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    }

    // Test wildcard field
    {
        BatchInsertInputData data({ "NAME", "*" });
        data.PutRows();
        int ret = OH_Rdb_BatchInsertWithReturning(
            store_, TEST_TABLE_NAME, data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    }

    // Test null field
    {
        BatchInsertInputData data({ "NAME", nullptr });
        data.PutRows();
        int ret = OH_Rdb_BatchInsertWithReturning(
            store_, TEST_TABLE_NAME, data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    }
}

/**
 * @tc.name: OH_Rdb_BatchInsertWithReturning_test_005
 * @tc.desc: Test batch insert with duplicate asset names.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_BatchInsertWithReturning_test_005, TestSize.Level1)
{
    BatchInsertInputData data({ "NAME" });
    data.PutRepeatAsset();
    data.PutRows();

    int ret = OH_Rdb_BatchInsertWithReturning(
        store_, TEST_TABLE_NAME, data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_Rdb_DeleteWithReturning_test_001
 * @tc.desc: Normal test case for delete with returning clause.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_DeleteWithReturning_test_001, TestSize.Level1)
{
    DeleteInputData data(TEST_TABLE_NAME, { "NAME" });
    int ret = OH_Rdb_DeleteWithReturning(store_, data.predicates, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(data.context);
    ASSERT_NE(cursor, nullptr);
    VerifyCursorData(cursor, DEFAULT_NAME);

    int changed = OH_RDB_GetChangedCount(data.context);
    EXPECT_EQ(changed, EXPECTED_SINGLE_ROW);
}

/**
 * @tc.name: OH_Rdb_DeleteWithReturning_test_002
 * @tc.desc: Test delete with various invalid parameters.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_DeleteWithReturning_test_002, TestSize.Level1)
{
    DeleteInputData data(TEST_TABLE_NAME, { "NAME" });

    // Test null store
    int ret = OH_Rdb_DeleteWithReturning(nullptr, data.predicates, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test null predicates
    ret = OH_Rdb_DeleteWithReturning(store_, nullptr, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test null context
    ret = OH_Rdb_DeleteWithReturning(store_, data.predicates, nullptr);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_Rdb_DeleteWithReturning_test_003
 * @tc.desc: Test delete with different table names.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_DeleteWithReturning_test_003, TestSize.Level1)
{
    // Test non-existent table
    {
        DeleteInputData data("abc", { "NAME" });
        int ret = OH_Rdb_DeleteWithReturning(store_, data.predicates, data.context);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_SQLITE_ERROR);
    }

    // Test empty table name
    {
        DeleteInputData data("", { "NAME" });
        int ret = OH_Rdb_DeleteWithReturning(store_, data.predicates, data.context);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    }

    // Test table name with spaces
    {
        DeleteInputData data("E M PLOYEE", { "NAME" });
        int ret = OH_Rdb_DeleteWithReturning(store_, data.predicates, data.context);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    }
}

/**
 * @tc.name: OH_Rdb_DeleteWithReturning_test_004
 * @tc.desc: Test delete with different field configurations.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_DeleteWithReturning_test_004, TestSize.Level1)
{
    // Test empty fields
    {
        DeleteInputData data(TEST_TABLE_NAME, {});
        int ret = OH_Rdb_DeleteWithReturning(store_, data.predicates, data.context);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    }

    // Test multiple fields
    {
        DeleteInputData data(TEST_TABLE_NAME, { "NAME", "AGE", "SALARY", "CODES", "HEIGHT", "SEX" });
        int ret = OH_Rdb_DeleteWithReturning(store_, data.predicates, data.context);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    }

    // Test wildcard field
    {
        DeleteInputData data(TEST_TABLE_NAME, { "NAME", "*" });
        int ret = OH_Rdb_DeleteWithReturning(store_, data.predicates, data.context);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    }

    // Test null field
    {
        DeleteInputData data(TEST_TABLE_NAME, { "NAME", nullptr });
        int ret = OH_Rdb_DeleteWithReturning(store_, data.predicates, data.context);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    }
}

/**
 * @tc.name: OH_Rdb_UpdateWithReturning_test_001
 * @tc.desc: Normal test case for update with returning clause.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_UpdateWithReturning_test_001, TestSize.Level1)
{
    UpdateInputData data(TEST_TABLE_NAME, { "NAME" });
    int ret = OH_Rdb_UpdateWithReturning(
        store_, data.valueBucketUpdate, data.predicates, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(data.context);
    ASSERT_NE(cursor, nullptr);
    VerifyCursorData(cursor, UPDATE_NAME);

    int changed = OH_RDB_GetChangedCount(data.context);
    EXPECT_EQ(changed, EXPECTED_SINGLE_ROW);
}

/**
 * @tc.name: OH_Rdb_UpdateWithReturning_test_002
 * @tc.desc: Test update with various invalid parameters.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_UpdateWithReturning_test_002, TestSize.Level1)
{
    UpdateInputData data(TEST_TABLE_NAME, { "NAME" });

    // Test null store
    int ret = OH_Rdb_UpdateWithReturning(
        nullptr, data.valueBucketUpdate, data.predicates, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test null value bucket
    ret = OH_Rdb_UpdateWithReturning(
        store_, nullptr, data.predicates, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test null predicates
    ret = OH_Rdb_UpdateWithReturning(
        store_, data.valueBucketUpdate, nullptr, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test invalid conflict resolution (-1)
    ret = OH_Rdb_UpdateWithReturning(
        store_, data.valueBucketUpdate, data.predicates, static_cast<Rdb_ConflictResolution>(-1), data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test invalid conflict resolution (1024)
    ret = OH_Rdb_UpdateWithReturning(
        store_, data.valueBucketUpdate, data.predicates, static_cast<Rdb_ConflictResolution>(1024), data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test null context
    ret = OH_Rdb_UpdateWithReturning(
        store_, data.valueBucketUpdate, data.predicates, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, nullptr);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test empty value bucket
    data.EmptyValueBucketUpdate();
    ret = OH_Rdb_UpdateWithReturning(
        store_, data.valueBucketUpdate, data.predicates, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_ERROR);
}

/**
 * @tc.name: OH_Rdb_UpdateWithReturning_test_003
 * @tc.desc: Test update with different table names.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_UpdateWithReturning_test_003, TestSize.Level1)
{
    // Test non-existent table
    {
        UpdateInputData data("abc", { "NAME" });
        int ret = OH_Rdb_UpdateWithReturning(store_, data.valueBucketUpdate, data.predicates,
            Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_SQLITE_ERROR);
    }

    // Test empty table name
    {
        UpdateInputData data("", { "NAME" });
        int ret = OH_Rdb_UpdateWithReturning(store_, data.valueBucketUpdate, data.predicates,
            Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    }

    // Test table name with spaces
    {
        UpdateInputData data("E M PLOYEE", { "NAME" });
        int ret = OH_Rdb_UpdateWithReturning(store_, data.valueBucketUpdate, data.predicates,
            Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    }
}

/**
 * @tc.name: OH_Rdb_UpdateWithReturning_test_004
 * @tc.desc: Test update with different field configurations.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_UpdateWithReturning_test_004, TestSize.Level1)
{
    // Test empty fields
    {
        UpdateInputData data(TEST_TABLE_NAME, {});
        int ret = OH_Rdb_UpdateWithReturning(store_, data.valueBucketUpdate, data.predicates,
            Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    }

    // Test multiple fields
    {
        UpdateInputData data(TEST_TABLE_NAME, { "NAME", "AGE", "SALARY", "CODES", "HEIGHT", "SEX" });
        int ret = OH_Rdb_UpdateWithReturning(store_, data.valueBucketUpdate, data.predicates,
            Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    }

    // Test wildcard field
    {
        UpdateInputData data(TEST_TABLE_NAME, { "NAME", "*" });
        int ret = OH_Rdb_UpdateWithReturning(store_, data.valueBucketUpdate, data.predicates,
            Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    }

    // Test null field
    {
        UpdateInputData data(TEST_TABLE_NAME, { "NAME", nullptr });
        int ret = OH_Rdb_UpdateWithReturning(store_, data.valueBucketUpdate, data.predicates,
            Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
        EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    }
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
        data.trans, TEST_TABLE_NAME, data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(data.context);
    ASSERT_NE(cursor, nullptr);
    VerifyCursorData(cursor, DEFAULT_NAME);

    int changed = OH_RDB_GetChangedCount(data.context);
    EXPECT_EQ(changed, EXPECTED_SINGLE_ROW);
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
        nullptr, TEST_TABLE_NAME, data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_BatchInsertWithReturning(
        data.trans, nullptr, data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_BatchInsertWithReturning(
        data.trans, TEST_TABLE_NAME, nullptr, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_BatchInsertWithReturning(
        data.trans, TEST_TABLE_NAME, data.rows, static_cast<Rdb_ConflictResolution>(-1), data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_BatchInsertWithReturning(
        data.trans, TEST_TABLE_NAME, data.rows, static_cast<Rdb_ConflictResolution>(1024), data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    ret = OH_RdbTrans_BatchInsertWithReturning(
        data.trans, TEST_TABLE_NAME, data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, nullptr);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    data.EmptyRows();
    ret = OH_RdbTrans_BatchInsertWithReturning(
        data.trans, TEST_TABLE_NAME, data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
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
        data.trans, TEST_TABLE_NAME, data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
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
        data.trans, TEST_TABLE_NAME, data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_SQLITE_ERROR);

    BatchInsertInputData data1({ "NAME", "AGE", "SALARY", "CODES", "HEIGHT", "SEX" });
    data1.PutRows();
    ret = OH_RdbTrans_BatchInsertWithReturning(
        data1.trans, TEST_TABLE_NAME, data1.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data1.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    BatchInsertInputData data2({ "NAME", "*" });
    data2.PutRows();
    ret = OH_RdbTrans_BatchInsertWithReturning(
        data2.trans, TEST_TABLE_NAME, data2.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data2.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    BatchInsertInputData data3({ "NAME", nullptr });
    ret = OH_RdbTrans_BatchInsertWithReturning(
        data3.trans, TEST_TABLE_NAME, data3.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data3.context);
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
        data.trans, TEST_TABLE_NAME, data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_RdbTrans_DeleteWithReturning_test_001
 * @tc.desc: Normal testCase of store for OH_RdbTrans_DeleteWithReturning.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_DeleteWithReturning_test_001, TestSize.Level1)
{
    DeleteInputData data(store_, TEST_TABLE_NAME, { "NAME" });
    int ret = OH_RdbTrans_DeleteWithReturning(data.trans, data.predicates, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(data.context);
    ASSERT_NE(cursor, nullptr);
    VerifyCursorData(cursor, DEFAULT_NAME);

    int changed = OH_RDB_GetChangedCount(data.context);
    EXPECT_EQ(changed, EXPECTED_SINGLE_ROW);
}

/**
 * @tc.name: OH_RdbTrans_DeleteWithReturning_test_002
 * @tc.desc: Construct test cases for inputting various abnormal parameters.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_DeleteWithReturning_test_002, TestSize.Level1)
{
    DeleteInputData data(store_, TEST_TABLE_NAME, { "NAME" });
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
    DeleteInputData data(store_, TEST_TABLE_NAME, {});
    int ret = OH_RdbTrans_DeleteWithReturning(data.trans, data.predicates, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    DeleteInputData data1(store_, TEST_TABLE_NAME, { "NAME", "*" });
    ret = OH_RdbTrans_DeleteWithReturning(data1.trans, data1.predicates, data1.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    DeleteInputData data2(store_, TEST_TABLE_NAME, { "NAME", nullptr });
    ret = OH_RdbTrans_DeleteWithReturning(data2.trans, data2.predicates, data2.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    DeleteInputData data3(store_, TEST_TABLE_NAME, { "NAME", "AGE", "SALARY", "CODES", "HEIGHT", "SEX" });
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
    UpdateInputData data(store_, TEST_TABLE_NAME, { "NAME" });
    int ret = OH_RdbTrans_UpdateWithReturning(data.trans, data.valueBucketUpdate, data.predicates,
        Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(data.context);
    ASSERT_NE(cursor, nullptr);
    VerifyCursorData(cursor, UPDATE_NAME);

    int changed = OH_RDB_GetChangedCount(data.context);
    EXPECT_EQ(changed, EXPECTED_SINGLE_ROW);
}

/**
 * @tc.name: OH_RdbTrans_UpdateWithReturning_test_002
 * @tc.desc: Construct test cases for inputting various abnormal parameters.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RdbTrans_UpdateWithReturning_test_002, TestSize.Level1)
{
    UpdateInputData data(store_, TEST_TABLE_NAME, { "NAME" });
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
    UpdateInputData data(store_, TEST_TABLE_NAME, { "NAME" });
    data.EmptyValueBucketUpdate();
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
    UpdateInputData data(store_, TEST_TABLE_NAME, {});
    int ret = OH_RdbTrans_UpdateWithReturning(data.trans, data.valueBucketUpdate, data.predicates,
        Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    UpdateInputData data1(store_, TEST_TABLE_NAME, { "NAME", "*" });
    ret = OH_RdbTrans_UpdateWithReturning(data1.trans, data1.valueBucketUpdate, data1.predicates,
        Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data1.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    UpdateInputData data2(store_, TEST_TABLE_NAME, { "NAME", nullptr });
    ret = OH_RdbTrans_UpdateWithReturning(data2.trans, data2.valueBucketUpdate, data2.predicates,
        Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data2.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    UpdateInputData data3(store_, TEST_TABLE_NAME, { "NAME", "AGE", "SALARY", "CODES", "HEIGHT", "SEX" });
    ret = OH_RdbTrans_UpdateWithReturning(data3.trans, data3.valueBucketUpdate, data3.predicates,
        Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data3.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
}

/**
 * @tc.name: OH_RDB_ReturningContext_test_001
 * @tc.desc: Test ReturningContext configuration functions.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_RDB_ReturningContext_test_001, TestSize.Level1)
{
    OH_RDB_ReturningContext *context = CreateReturningContext({ "NAME", "AGE", "SALARY" });

    // Test valid max returning count
    int ret = OH_RDB_SetMaxReturningCount(context, EXPECTED_SINGLE_ROW);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    // Test invalid max returning count (-1)
    ret = OH_RDB_SetMaxReturningCount(context, -1);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test invalid max returning count (0x7FFF)
    ret = OH_RDB_SetMaxReturningCount(context, 0X7FFF);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test null context
    ret = OH_RDB_SetMaxReturningCount(nullptr, EXPECTED_SINGLE_ROW);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test valid set returning fields
    const char *columns[] = { "NAME", "AGE", "SALARY" };
    int32_t len = sizeof(columns) / sizeof(columns[0]);
    ret = OH_RDB_SetReturningFields(context, columns, len);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    // Test null context
    ret = OH_RDB_SetReturningFields(nullptr, columns, len);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test null columns
    ret = OH_RDB_SetReturningFields(context, nullptr, len);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test invalid length (-1)
    ret = OH_RDB_SetReturningFields(context, columns, -1);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test wildcard in field name
    const char *columns1[] = { "NAME", "*", "SALARY" };
    int32_t len1 = sizeof(columns1) / sizeof(columns1[0]);
    ret = OH_RDB_SetReturningFields(context, columns1, len1);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test null field in array
    const char *columns2[] = { "NAME", nullptr, "SALARY" };
    int32_t len2 = sizeof(columns2) / sizeof(columns2[0]);
    ret = OH_RDB_SetReturningFields(context, columns2, len2);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // Test null context get returning values
    OH_Cursor *cursor = OH_RDB_GetReturningValues(nullptr);
    EXPECT_EQ(cursor, nullptr);

    // Test null context get changed count
    int64_t changedCount = OH_RDB_GetChangedCount(nullptr);
    EXPECT_EQ(changedCount, -1);

    // Cleanup
    OH_RDB_DestroyReturningContext(context);
    context = nullptr;
    OH_RDB_DestroyReturningContext(nullptr);
}

/**
 * @tc.name: OH_Rdb_BatchInsertWithReturning_GetFloat32Array_test_001
 * @tc.desc: Test batch insert with returning float32 array field.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreReturningTest, OH_Rdb_BatchInsertWithReturning_GetFloat32Array_test_001, TestSize.Level1)
{
    BatchInsertInputData data({ "FLOATS" });
    data.PutRows();

    int ret = OH_Rdb_BatchInsertWithReturning(
        store_, TEST_TABLE_NAME, data.rows, Rdb_ConflictResolution::RDB_CONFLICT_REPLACE, data.context);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_OK);

    OH_Cursor *cursor = OH_RDB_GetReturningValues(data.context);
    ASSERT_NE(cursor, nullptr);

    VerifyCursorRowCount(cursor, EXPECTED_SINGLE_ROW);
    VerifyCursorColumnCount(cursor, EXPECTED_SINGLE_COLUMN);

    EXPECT_EQ(cursor->goToNextRow(cursor), OH_Rdb_ErrCode::RDB_OK);

    // Verify float vector data
    size_t count = 0;
    const int columnIndex = 0;
    auto errCode = OH_Cursor_GetFloatVectorCount(cursor, columnIndex, &count);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);
    EXPECT_EQ(count, FLOATS_SIZE);

    float test[count];
    size_t outLen = 0;
    OH_Cursor_GetFloatVector(cursor, columnIndex, test, count, &outLen);
    EXPECT_EQ(outLen, FLOATS_SIZE);
    EXPECT_EQ(test[0], DEFAULT_FLOATS[0]);
    EXPECT_EQ(test[1], DEFAULT_FLOATS[1]);
    EXPECT_EQ(test[2], DEFAULT_FLOATS[2]);

    int changed = OH_RDB_GetChangedCount(data.context);
    EXPECT_EQ(changed, EXPECTED_SINGLE_ROW);
}

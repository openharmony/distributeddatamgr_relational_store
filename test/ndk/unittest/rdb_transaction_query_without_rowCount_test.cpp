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
#include "common.h"
#include "relational_store.h"
#include "relational_store_error_code.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbTransactionQueryWithoutRowCountTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static OH_Rdb_ConfigV2 *InitRdbConfig();
    static void CreateAssetTable();
    static void SetAsset(Data_Asset *asset, int index);
    static void CheckAndDestroyCursor(OH_Cursor *cursor);
    static void CheckAllAndDestroyCursor(OH_Cursor *cursor);
    static void CheckErrAndDestroyCursor(OH_Cursor *cursor);
    static void CheckErrnoAndDestroyCursor(OH_Cursor *cursor);
    static void CheckResultSetForGetAssert(OH_Cursor *cursor);
    static void CheckResultSetForGetAsserts(OH_Cursor *cursor);
};

static OH_Rdb_Store *rdbStore_;
static OH_RDB_TransOptions *options_;

OH_Rdb_ConfigV2 *RdbTransactionQueryWithoutRowCountTest::InitRdbConfig()
{
    OH_Rdb_ConfigV2 *config = OH_Rdb_CreateConfig();
    OH_Rdb_SetDatabaseDir(config, RDB_TEST_PATH);
    OH_Rdb_SetStoreName(config, "queryWithoutRowCount_test.db");
    OH_Rdb_SetBundleName(config, "com.ohos.example.querywithoutrowcount");
    OH_Rdb_SetEncrypted(config, false);
    OH_Rdb_SetSecurityLevel(config, OH_Rdb_SecurityLevel::S1);
    OH_Rdb_SetArea(config, RDB_SECURITY_AREA_EL1);
    OH_Rdb_SetDbType(config, RDB_SQLITE);
    return config;
}

void RdbTransactionQueryWithoutRowCountTest::SetUpTestCase(void)
{
    mkdir(RDB_TEST_PATH, 0770); // The permission on the path is 0770.
    int errCode = 0;
    auto config = InitRdbConfig();
    char table[] = "test";
    rdbStore_ = OH_Rdb_CreateOrOpen(config, &errCode);
    ASSERT_NE(rdbStore_, NULL);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, errCode);
    char createTableSql[] = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "data1 TEXT, data2 INTEGER, data3 FLOAT, data4 BLOB);";
    errCode = OH_Rdb_Execute(rdbStore_, createTableSql);
    EXPECT_EQ(OH_Rdb_ErrCode::RDB_OK, errCode);

    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 1); // Set the value of id to 1.
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    valueBucket->putInt64(valueBucket, "data2", 12800); // Set the value of data2 to 12800.
    valueBucket->putReal(valueBucket, "data3", 100.1); // Set the value of data3 to 100.1.
    uint8_t arr[] = { 1, 2, 3, 4, 5 };
    int len = sizeof(arr) / sizeof(arr[0]);
    valueBucket->putBlob(valueBucket, "data4", arr, len);
    errCode = OH_Rdb_Insert(rdbStore_, table, valueBucket);
    EXPECT_EQ(errCode, 1);

    valueBucket->clear(valueBucket);
    valueBucket->putInt64(valueBucket, "id", 2); // Set the value of id to 2.
    valueBucket->putText(valueBucket, "data1", "liSi");
    valueBucket->putInt64(valueBucket, "data2", 13800); // Set the value of data2 to 13800.
    valueBucket->putReal(valueBucket, "data3", 200.1); // Set the value of data3 to 200.1.
    errCode = OH_Rdb_Insert(rdbStore_, table, valueBucket);
    EXPECT_EQ(errCode, 2); // rowId is 2.
    valueBucket->destroy(valueBucket);
    CreateAssetTable();

    options_ = OH_RdbTrans_CreateOptions();
    ASSERT_NE(options_, nullptr);
    int ret = OH_RdbTransOption_SetType(options_, RDB_TRANS_DEFERRED);
    EXPECT_EQ(ret, RDB_OK);
}

void RdbTransactionQueryWithoutRowCountTest::TearDownTestCase(void)
{
    rdbStore_ = nullptr;
    auto config = InitRdbConfig();
    OH_Rdb_DeleteStoreV2(config);

    OH_RdbTrans_DestroyOptions(options_);
    options_ = nullptr;
}

void RdbTransactionQueryWithoutRowCountTest::SetUp(void)
{
}

void RdbTransactionQueryWithoutRowCountTest::TearDown(void)
{
}

void RdbTransactionQueryWithoutRowCountTest::CreateAssetTable()
{
    char createTableSql[] = "CREATE TABLE IF NOT EXISTS asset_table (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 "
                            "asset, data2 assets );";
    int errCode = OH_Rdb_Execute(rdbStore_, createTableSql);
    EXPECT_EQ(errCode, RDB_OK);
    char table[] = "asset_table";
    int assetsCount = 2;
    int curRow = 1;
    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    Data_Asset *asset1 = OH_Data_Asset_CreateOne();
    SetAsset(asset1, 1); // The suffix of index is 1.
    Data_Asset *asset2 = OH_Data_Asset_CreateOne();
    SetAsset(asset2, 2); // The suffix of index is 2.

    valueBucket->putInt64(valueBucket, "id", curRow);
    OH_VBucket_PutAsset(valueBucket, "data1", asset1);
    Data_Asset **assets = OH_Data_Asset_CreateMultiple(assetsCount);
    SetAsset(assets[0], 1); // The suffix of index is 1.
    SetAsset(assets[1], 2); // The suffix of index is 2.
    errCode = OH_VBucket_PutAssets(valueBucket, "data2", assets, assetsCount);
    int rowID = OH_Rdb_Insert(rdbStore_, table, valueBucket);
    EXPECT_EQ(rowID, curRow);
    curRow++;

    valueBucket->clear(valueBucket);
    valueBucket->putInt64(valueBucket, "id", curRow);
    OH_VBucket_PutAsset(valueBucket, "data1", asset2);
    Data_Asset **assets2 = OH_Data_Asset_CreateMultiple(assetsCount);
    SetAsset(assets2[0], 1); // The suffix of index is 1.
    SetAsset(assets2[1], 3); // The suffix of index is 3.
    errCode = OH_VBucket_PutAssets(valueBucket, "data2", assets2, assetsCount);
    rowID = OH_Rdb_Insert(rdbStore_, table, valueBucket);
    EXPECT_EQ(rowID, curRow);

    OH_Data_Asset_DestroyMultiple(assets, assetsCount);
    OH_Data_Asset_DestroyMultiple(assets2, assetsCount);
    OH_Data_Asset_DestroyOne(asset1);
    OH_Data_Asset_DestroyOne(asset2);
    valueBucket->destroy(valueBucket);
}

void RdbTransactionQueryWithoutRowCountTest::SetAsset(Data_Asset *asset, int index)
{
    std::string indexString = std::to_string(index);
    std::string name;
    name.append("name").append(indexString);
    int errcode = OH_Data_Asset_SetName(asset, name.c_str());
    EXPECT_EQ(errcode, RDB_OK);
    std::string uri;
    uri.append("uri").append(indexString);
    errcode = OH_Data_Asset_SetUri(asset, uri.c_str());
    EXPECT_EQ(errcode, RDB_OK);
    std::string path;
    path.append("path").append(indexString);
    errcode = OH_Data_Asset_SetPath(asset, path.c_str());
    EXPECT_EQ(errcode, RDB_OK);
    errcode = OH_Data_Asset_SetCreateTime(asset, index);
    EXPECT_EQ(errcode, RDB_OK);
    errcode = OH_Data_Asset_SetModifyTime(asset, index);
    EXPECT_EQ(errcode, RDB_OK);
    errcode = OH_Data_Asset_SetSize(asset, index);
    EXPECT_EQ(errcode, RDB_OK);
    errcode = OH_Data_Asset_SetStatus(asset, Data_AssetStatus::ASSET_NORMAL);
    EXPECT_EQ(errcode, RDB_OK);
}

void RdbTransactionQueryWithoutRowCountTest::CheckAndDestroyCursor(OH_Cursor *cursor)
{
    int count = 0;
    while (cursor->goToNextRow(cursor) == RDB_OK) {
        count++;
        if (count == 1) { // count is 1
            int columnCount = 0;
            cursor->getColumnCount(cursor, &columnCount);
            EXPECT_EQ(columnCount, 4); // columnCount is 4

            size_t size = 0;
            cursor->getSize(cursor, 0, &size);
            EXPECT_EQ(size, 9); // the size of text is 9
            char data1Value[size];
            cursor->getText(cursor, 0, data1Value, size);
            EXPECT_EQ(strcmp(data1Value, "zhangSan"), 0);

            int64_t data2Value;
            cursor->getInt64(cursor, 1, &data2Value);
            EXPECT_EQ(data2Value, 12800); // the value of data2 is 12800

            double data3Value;
            cursor->getReal(cursor, 2, &data3Value); // columnIndex is 2
            EXPECT_DOUBLE_EQ(data3Value, 100.1); // the value of data3 is 100.1

            cursor->getSize(cursor, 3, &size); // columnIndex is 3
            EXPECT_EQ(size, 5); // the size of blob is 5
            unsigned char data4Value[size];
            cursor->getBlob(cursor, 3, data4Value, size); // columnIndex is 3
            EXPECT_EQ(data4Value[0], 1); // the value of data4Value[0] is 1
            EXPECT_EQ(data4Value[1], 2); // the value of data4Value[1] is 2
        }
        if (count == 2) { // count is 2
            size_t size = 0;
            cursor->getSize(cursor, 0, &size);
            EXPECT_EQ(size, 5); // the size of text is 5
            char data1Value1[size];
            cursor->getText(cursor, 0, data1Value1, size);
            EXPECT_EQ(strcmp(data1Value1, "liSi"), 0);

            int64_t data2Value;
            cursor->getInt64(cursor, 1, &data2Value);
            EXPECT_EQ(data2Value, 13800); // the value of data2 is 13800

            double data3Value;
            cursor->getReal(cursor, 2, &data3Value); // columnIndex is 2
            EXPECT_DOUBLE_EQ(data3Value, 200.1); // the value of data3 is 200.1
        }
    }
    EXPECT_EQ(count, 2); // count is 2
}

void RdbTransactionQueryWithoutRowCountTest::CheckAllAndDestroyCursor(OH_Cursor *cursor)
{
    cursor->goToNextRow(cursor);

    int columnCount = 0;
    cursor->getColumnCount(cursor, &columnCount);
    EXPECT_EQ(columnCount, 5); // columnCount is 5

    int64_t id;
    cursor->getInt64(cursor, 0, &id);
    EXPECT_EQ(id, 1);

    size_t size = 0;
    cursor->getSize(cursor, 1, &size);
    EXPECT_EQ(size, 9); // the size of text is 9
    char data1Value[size];
    cursor->getText(cursor, 1, data1Value, size);
    EXPECT_EQ(strcmp(data1Value, "zhangSan"), 0);

    int64_t data2Value;
    cursor->getInt64(cursor, 2, &data2Value); // columnIndex is 2
    EXPECT_EQ(data2Value, 12800); // the value of data2 is 12800

    double data3Value;
    cursor->getReal(cursor, 3, &data3Value); // columnIndex is 3
    EXPECT_DOUBLE_EQ(data3Value, 100.1); // the value of data3 is 100.1

    cursor->getSize(cursor, 4, &size); // columnIndex is 4
    EXPECT_EQ(size, 5); // the size of blob is 5
    unsigned char data4Value[size];
    cursor->getBlob(cursor, 4, data4Value, size); // columnIndex is 4
    EXPECT_EQ(data4Value[0], 1); // the value of data4Value[0] is 1
    EXPECT_EQ(data4Value[1], 2); // the value of data4Value[1] is 2

    cursor->goToNextRow(cursor);

    cursor->getInt64(cursor, 0, &id);
    EXPECT_EQ(id, 2); // the value of id is 2

    cursor->getSize(cursor, 1, &size);
    EXPECT_EQ(size, 5); // the size of text is 5
    char data1Value1[size];
    cursor->getText(cursor, 1, data1Value1, size);
    EXPECT_EQ(strcmp(data1Value1, "liSi"), 0);

    cursor->getInt64(cursor, 2, &data2Value); // columnIndex is 2
    EXPECT_EQ(data2Value, 13800); // the value of data2 is 13800

    cursor->getReal(cursor, 3, &data3Value); // columnIndex is 3
    EXPECT_DOUBLE_EQ(data3Value, 200.1); // the value of data3 is 200.1
    cursor->destroy(cursor);
}

void RdbTransactionQueryWithoutRowCountTest::CheckErrAndDestroyCursor(OH_Cursor *cursor)
{
    cursor->goToNextRow(cursor);

    size_t size = 0;
    // cursor is nullptr
    int errCode = cursor->getSize(nullptr, 1, &size);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // size is nullptr
    errCode = cursor->getSize(cursor, 1, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // columnIndex out of range
    errCode = cursor->getSize(cursor, -1, &size);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_COLUMN_INDEX);
    errCode = cursor->getSize(cursor, 5, &size); // columnIndex is 5
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_COLUMN_INDEX);

    errCode = cursor->getSize(cursor, 1, &size);

    char data1Value[size];
    // cursor is nullptr
    errCode = cursor->getText(nullptr, 1, data1Value, size);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // columnIndex out of range
    errCode = cursor->getText(cursor, -1, data1Value, size);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_COLUMN_INDEX);
    errCode = cursor->getText(cursor, 5, data1Value, size); // columnIndex is 5
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_COLUMN_INDEX);
    // value is nullptr
    errCode = cursor->getText(cursor, 1, nullptr, size);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // the size is invalid
    errCode = cursor->getText(cursor, 1, data1Value, 0);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    int64_t data2Value;
    // cursor is nullptr
    errCode = cursor->getInt64(nullptr, 2, &data2Value); // columnIndex is 2
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // value is nullptr
    errCode = cursor->getInt64(cursor, 2, nullptr); // columnIndex is 2
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    // columnIndex out of range
    errCode = cursor->getInt64(cursor, -1, &data2Value);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_COLUMN_INDEX);
    errCode = cursor->getInt64(cursor, 5, &data2Value); // columnIndex is 5
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_COLUMN_INDEX);

    cursor->destroy(cursor);
}
void RdbTransactionQueryWithoutRowCountTest::CheckErrnoAndDestroyCursor(OH_Cursor *cursor)
{
    cursor->goToNextRow(cursor);

    double data3Value;
    // cursor is nullptr
    int errCode = cursor->getReal(nullptr, 3, &data3Value);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // value is nullptr
    errCode = cursor->getReal(cursor, 3, nullptr); // columnIndex is 3
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // columnIndex out of range
    errCode = cursor->getReal(cursor, -1, &data3Value);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_COLUMN_INDEX);
    errCode = cursor->getReal(cursor, 5, &data3Value); // columnIndex is 5
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_COLUMN_INDEX);

    size_t size = 0;
    errCode = cursor->getSize(cursor, 4, &size); // columnIndex is 4
    unsigned char data4Value[size];
    // cursor is nullptr
    errCode = cursor->getBlob(nullptr, 4, data4Value, size); // columnIndex is 4
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // value is nullptr
    errCode = cursor->getBlob(cursor, 4, nullptr, size); // columnIndex is 4
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // the size is invalid
    errCode = cursor->getBlob(cursor, 4, data4Value, 0); // columnIndex is 4
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // columnIndex out of range
    errCode = cursor->getBlob(cursor, -1, data4Value, size);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_COLUMN_INDEX);

    errCode = cursor->getBlob(cursor, 5, data4Value, size); // columnIndex is 5
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_COLUMN_INDEX);

    bool isNull = false;
    // cursor is nullptr
    errCode = cursor->isNull(nullptr, 1, &isNull);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = cursor->isNull(cursor, 1, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    errCode = cursor->destroy(nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    cursor->destroy(cursor);
}

void RdbTransactionQueryWithoutRowCountTest::CheckResultSetForGetAssert(OH_Cursor *cursor)
{
    cursor->goToNextRow(cursor);

    OH_ColumnType type;
    int errCode = cursor->getColumnType(cursor, 1, &type);
    EXPECT_EQ(type, OH_ColumnType::TYPE_ASSET);
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    errCode = cursor->getAsset(cursor, 1, asset);
    ASSERT_NE(asset, nullptr);
    char name[10] = "";
    size_t nameLength = 10;
    errCode = OH_Data_Asset_GetName(asset, name, &nameLength);
    EXPECT_EQ(strcmp(name, "name1"), 0);

    char uri[10] = "";
    size_t uriLength = 10;
    errCode = OH_Data_Asset_GetUri(asset, uri, &uriLength);
    EXPECT_EQ(strcmp(uri, "uri1"), 0);

    char path[10] = "";
    size_t pathLength = 10;
    errCode = OH_Data_Asset_GetPath(asset, path, &pathLength);
    EXPECT_EQ(strcmp(path, "path1"), 0);

    int64_t createTime = 0;
    errCode = OH_Data_Asset_GetCreateTime(asset, &createTime);
    EXPECT_EQ(createTime, 1);

    int64_t modifyTime = 0;
    errCode = OH_Data_Asset_GetModifyTime(asset, &modifyTime);
    EXPECT_EQ(modifyTime, 1);

    size_t size = 0;
    errCode = OH_Data_Asset_GetSize(asset, &size);
    EXPECT_EQ(size, 1);

    Data_AssetStatus status = Data_AssetStatus::ASSET_NULL;
    errCode = OH_Data_Asset_GetStatus(asset, &status);
    EXPECT_EQ(status, ASSET_INSERT);

    OH_Data_Asset_DestroyOne(asset);
    cursor->destroy(cursor);
}
void RdbTransactionQueryWithoutRowCountTest::CheckResultSetForGetAsserts(OH_Cursor *cursor)
{
    cursor->goToNextRow(cursor);

    OH_ColumnType type;
    int errCode = cursor->getColumnType(cursor, 2, &type);
    EXPECT_EQ(type, OH_ColumnType::TYPE_ASSETS);
    uint32_t assetCount = 0;
    errCode = cursor->getAssets(cursor, 2, nullptr, &assetCount); // columnIndex is 2
    EXPECT_EQ(assetCount, 2); // assetCount is 2
    Data_Asset **assets = OH_Data_Asset_CreateMultiple(assetCount);
    errCode = cursor->getAssets(cursor, 2, assets, &assetCount); // columnIndex is 2
    EXPECT_EQ(assetCount, 2); // assetCount is 2
    Data_Asset *asset = assets[1];
    ASSERT_NE(asset, NULL);

    char name[10] = "";
    size_t nameLength = 10;
    errCode = OH_Data_Asset_GetName(asset, name, &nameLength);
    EXPECT_EQ(strcmp(name, "name2"), 0);

    char uri[10] = "";
    size_t uriLength = 10;
    errCode = OH_Data_Asset_GetUri(asset, uri, &uriLength);
    EXPECT_EQ(strcmp(uri, "uri2"), 0);

    char path[10] = "";
    size_t pathLength = 10;
    errCode = OH_Data_Asset_GetPath(asset, path, &pathLength);
    EXPECT_EQ(strcmp(path, "path2"), 0);

    int64_t createTime = 0;
    errCode = OH_Data_Asset_GetCreateTime(asset, &createTime);
    EXPECT_EQ(createTime, 2); // the value of createTime is 2

    int64_t modifyTime = 0;
    errCode = OH_Data_Asset_GetModifyTime(asset, &modifyTime);
    EXPECT_EQ(modifyTime, 2); // the value of modifyTime is 2

    size_t size = 0;
    errCode = OH_Data_Asset_GetSize(asset, &size);
    EXPECT_EQ(size, 2); // the size of asset is 2

    Data_AssetStatus status = Data_AssetStatus::ASSET_NULL;
    errCode = OH_Data_Asset_GetStatus(asset, &status);
    EXPECT_EQ(status, ASSET_INSERT);

    OH_Data_Asset_DestroyMultiple(assets, assetCount);
    cursor->destroy(cursor);
}

/**
 * @tc.name: RdbTrans_QueryWithoutRowCount_001_Normal_Get
 * @tc.desc: Normal testCase of store for OH_RdbTrans_QueryWithoutRowCount, getColumnCount, getXXX.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionQueryWithoutRowCountTest, RdbTrans_QueryWithoutRowCount_001_Normal_Get, TestSize.Level0)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    ASSERT_NE(predicates, NULL);
    const char *columnNames[] = { "data1", "data2", "data3", "data4" };
    int len = sizeof(columnNames) / sizeof(columnNames[0]);
    OH_Cursor *cursor = OH_RdbTrans_QueryWithoutRowCount(trans, predicates, columnNames, len);
    predicates->destroy(predicates);
    ASSERT_NE(cursor, NULL);

    CheckAndDestroyCursor(cursor);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RdbTrans_QueryWithoutRowCount_002_Normal_Get
 * @tc.desc: Normal testCase of store for OH_RdbTrans_QueryWithoutRowCount, getColumnCount, getXXX.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionQueryWithoutRowCountTest, RdbTrans_QueryWithoutRowCount_002_Normal_Get, TestSize.Level0)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    ASSERT_NE(predicates, NULL);
    // columnNames is nullptr
    OH_Cursor *cursor = OH_RdbTrans_QueryWithoutRowCount(trans, predicates, NULL, 0);
    predicates->destroy(predicates);
    ASSERT_NE(cursor, NULL);

    CheckAllAndDestroyCursor(cursor);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RdbTrans_QueryWithoutRowCount_003_Abnormal_InvalidArgs
 * @tc.desc: Abnormal testCase of store for InvalidArgs.
 * @tc.type: FUNC
 */
HWTEST_F(
    RdbTransactionQueryWithoutRowCountTest, RdbTrans_QueryWithoutRowCount_003_Abnormal_InvalidArgs, TestSize.Level0)
{
    const char *columnNames[] = { "data1", "data2", "data3", "data4" };
    int len = sizeof(columnNames) / sizeof(columnNames[0]);
    // trans is nullptr
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    ASSERT_NE(predicates, NULL);
    OH_Cursor *cursor = OH_RdbTrans_QueryWithoutRowCount(nullptr, predicates, columnNames, len);
    predicates->destroy(predicates);
    ASSERT_EQ(cursor, NULL);

    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    // predicates is nullptr
    cursor = OH_RdbTrans_QueryWithoutRowCount(trans, nullptr, columnNames, len);
    ASSERT_EQ(cursor, NULL);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RdbTrans_QueryWithoutRowCount_004_Abnormal_InvalidArgs
 * @tc.desc: Abnormal testCase of store for InvalidArgs
 *           the size of columnNames is different from that of len columnNames
 * @tc.type: FUNC
 */
HWTEST_F(
    RdbTransactionQueryWithoutRowCountTest, RdbTrans_QueryWithoutRowCount_004_Abnormal_InvalidArgs, TestSize.Level0)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    ASSERT_NE(predicates, NULL);
    const char *columnNames[] = { "data1", "data2", "data3", "data4" };
    // the size of columnNames is greater than len, the size of columnNames is 2
    OH_Cursor *cursor = OH_RdbTrans_QueryWithoutRowCount(trans, predicates, columnNames, 2);
    predicates->destroy(predicates);
    ASSERT_NE(cursor, NULL);

    cursor->goToNextRow(cursor);

    int columnCount = 0;
    cursor->getColumnCount(cursor, &columnCount);
    EXPECT_EQ(columnCount, 2);

    size_t size = 0;
    cursor->getSize(cursor, 0, &size);
    EXPECT_EQ(size, 9);
    char data1Value[size];
    cursor->getText(cursor, 0, data1Value, size);
    EXPECT_EQ(strcmp(data1Value, "zhangSan"), 0);

    int64_t data2Value;
    cursor->getInt64(cursor, 1, &data2Value);
    EXPECT_EQ(data2Value, 12800);

    double data3Value;
    int errCode = cursor->getReal(cursor, 2, &data3Value);
    EXPECT_EQ(errCode, RDB_E_INVALID_COLUMN_INDEX);

    errCode = cursor->getSize(cursor, 3, &size);
    EXPECT_EQ(errCode, RDB_E_INVALID_COLUMN_INDEX);
    size = 5;
    unsigned char data4Value[size];
    errCode = cursor->getBlob(cursor, 3, data4Value, size);
    EXPECT_EQ(errCode, RDB_E_INVALID_COLUMN_INDEX);

    cursor->goToNextRow(cursor);

    cursor->getSize(cursor, 0, &size);
    EXPECT_EQ(size, 5);
    char data1Value1[size];
    cursor->getText(cursor, 0, data1Value1, size);
    EXPECT_EQ(strcmp(data1Value1, "liSi"), 0);

    cursor->getInt64(cursor, 1, &data2Value);
    EXPECT_EQ(data2Value, 13800);

    errCode = cursor->getReal(cursor, 2, &data3Value);
    EXPECT_EQ(errCode, RDB_E_INVALID_COLUMN_INDEX);

    cursor->destroy(cursor);
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RdbTrans_QueryWithoutRowCount_005_Abnormal_InvalidArgs
 * @tc.desc: Abnormal testCase of store for InvalidArgs
 *           the size of columnNames is different from that of len columnNames
 * @tc.type: FUNC
 */
HWTEST_F(
    RdbTransactionQueryWithoutRowCountTest, RdbTrans_QueryWithoutRowCount_005_Abnormal_InvalidArgs, TestSize.Level0)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    ASSERT_NE(predicates, NULL);
    const char *columnNames[] = { "data1", "data2", "data3", "data4", "data5" };
    // the size of columnNames is greater than len, the size of columnNames is 5
    OH_Cursor *cursor = OH_RdbTrans_QueryWithoutRowCount(trans, predicates, columnNames, 5);
    ASSERT_NE(cursor, NULL);

    int errCode = cursor->goToNextRow(cursor);;
    // An error is reported when a field in a location is added.
    EXPECT_EQ(errCode, RDB_E_SQLITE_ERROR);
    cursor->destroy(cursor);
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RdbTrans_QueryWithoutRowCount_006_Abnormal_InvalidArgs
 * @tc.desc: Abnormal testCase of store for InvalidArgs, the field in columnNames has nullptr
 * @tc.type: FUNC
 */
HWTEST_F(
    RdbTransactionQueryWithoutRowCountTest, RdbTrans_QueryWithoutRowCount_006_Abnormal_InvalidArgs, TestSize.Level0)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    ASSERT_NE(predicates, NULL);
    const char *columnNames[] = { nullptr, "data2", "data3", "data4" };
    int len = sizeof(columnNames) / sizeof(columnNames[0]);
    OH_Cursor *cursor = OH_RdbTrans_QueryWithoutRowCount(trans, predicates, columnNames, len);
    predicates->destroy(predicates);
    ASSERT_EQ(cursor, NULL);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RdbTrans_QueryWithoutRowCount_007_Abnormal_InvalidArgs
 * @tc.desc: Abnormal testCase of store for InvalidArgs, the columnNames contains an empty string
 * @tc.type: FUNC
 */
HWTEST_F(
    RdbTransactionQueryWithoutRowCountTest, RdbTrans_QueryWithoutRowCount_007_Abnormal_InvalidArgs, TestSize.Level0)
{
    const char *columnNames[] = { "", "data1", "data2", "data3", "data4" };
    int len = sizeof(columnNames) / sizeof(columnNames[0]);
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    ASSERT_NE(predicates, NULL);
    OH_Cursor *cursor = OH_RdbTrans_QueryWithoutRowCount(trans, predicates, columnNames, len);
    predicates->destroy(predicates);
    ASSERT_NE(cursor, NULL);

    cursor->goToNextRow(cursor);

    int columnCount = 0;
    cursor->getColumnCount(cursor, &columnCount);
    EXPECT_EQ(columnCount, 4);

    size_t size = 0;
    cursor->getSize(cursor, 0, &size);
    EXPECT_EQ(size, 9);
    char data1Value[size];
    cursor->getText(cursor, 0, data1Value, size);
    EXPECT_EQ(strcmp(data1Value, "zhangSan"), 0);

    int64_t data2Value;
    cursor->getInt64(cursor, 1, &data2Value);
    EXPECT_EQ(data2Value, 12800);

    double data3Value;
    cursor->getReal(cursor, 2, &data3Value);
    EXPECT_DOUBLE_EQ(data3Value, 100.1);

    cursor->getSize(cursor, 3, &size);
    EXPECT_EQ(size, 5);
    unsigned char data4Value[size];
    cursor->getBlob(cursor, 3, data4Value, size);
    EXPECT_EQ(data4Value[0], 1);
    EXPECT_EQ(data4Value[1], 2);

    cursor->goToNextRow(cursor);

    cursor->getSize(cursor, 0, &size);
    EXPECT_EQ(size, 5);
    char data1Value1[size];
    cursor->getText(cursor, 0, data1Value1, size);
    EXPECT_EQ(strcmp(data1Value1, "liSi"), 0);

    cursor->getInt64(cursor, 1, &data2Value);
    EXPECT_EQ(data2Value, 13800);

    cursor->getReal(cursor, 2, &data3Value);
    EXPECT_DOUBLE_EQ(data3Value, 200.1);

    cursor->destroy(cursor);
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RdbTrans_QueryWithoutRowCount_008_Normal_GetColumnType
 * @tc.desc: Normal testCase of cursor for GetColumnType.
 * @tc.type: FUNC
 */
HWTEST_F(
    RdbTransactionQueryWithoutRowCountTest, RdbTrans_QueryWithoutRowCount_008_Normal_GetColumnType, TestSize.Level0)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    ASSERT_NE(predicates, NULL);
    OH_Cursor *cursor = OH_RdbTrans_QueryWithoutRowCount(trans, predicates, NULL, 0);
    predicates->destroy(predicates);
    ASSERT_NE(cursor, NULL);
    cursor->goToNextRow(cursor);

    OH_ColumnType type;
    errCode = cursor->getColumnType(cursor, 0, &type);
    EXPECT_EQ(type, OH_ColumnType::TYPE_INT64);
    errCode = cursor->getColumnType(cursor, 1, &type);
    EXPECT_EQ(type, OH_ColumnType::TYPE_TEXT);
    errCode = cursor->getColumnType(cursor, 2, &type);
    EXPECT_EQ(type, OH_ColumnType::TYPE_INT64);
    errCode = cursor->getColumnType(cursor, 3, &type);
    EXPECT_EQ(type, OH_ColumnType::TYPE_REAL);
    errCode = cursor->getColumnType(cursor, 4, &type);
    EXPECT_EQ(type, OH_ColumnType::TYPE_BLOB);
    cursor->destroy(cursor);

    predicates = OH_Rdb_CreatePredicates("asset_table");
    ASSERT_NE(predicates, NULL);
    cursor = OH_Rdb_QueryWithoutRowCount(rdbStore_, predicates, NULL, 0);
    predicates->destroy(predicates);
    ASSERT_NE(cursor, NULL);
    cursor->goToNextRow(cursor);
    errCode = cursor->getColumnType(cursor, 1, &type);
    EXPECT_EQ(type, OH_ColumnType::TYPE_ASSET);
    errCode = cursor->getColumnType(cursor, 2, &type);
    EXPECT_EQ(type, OH_ColumnType::TYPE_ASSETS);
    cursor->destroy(cursor);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RdbTrans_QueryWithoutRowCount_009_Abnormal_GetColumnType
 * @tc.desc: Abnormal testCase of cursor for GetColumnType.
 * @tc.type: FUNC
 */
HWTEST_F(
    RdbTransactionQueryWithoutRowCountTest, RdbTrans_QueryWithoutRowCount_009_Abnormal_GetColumnType, TestSize.Level0)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    ASSERT_NE(predicates, NULL);
    OH_Cursor *cursor = OH_RdbTrans_QueryWithoutRowCount(trans, predicates, NULL, 0);
    predicates->destroy(predicates);
    ASSERT_NE(cursor, NULL);

    OH_ColumnType type;
    // row out of bounds
    errCode = cursor->getColumnType(cursor, 4, &type);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_STEP_RESULT_IS_AFTER_LAST);

    cursor->goToNextRow(cursor);

    // cursor is nullptr
    errCode = cursor->getColumnType(nullptr, 4, &type);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // columnIndex out of range
    errCode = cursor->getColumnType(cursor, -1, &type);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = cursor->getColumnType(cursor, 5, &type);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_COLUMN_INDEX);
    // columnType is nullptr
    errCode = cursor->getColumnType(cursor, 4, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    cursor->destroy(cursor);
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RdbTrans_QueryWithoutRowCount_010_Normal_GetColumnIndex
 * @tc.desc: Normal testCase of cursor for GetColumnIndex.
 * @tc.type: FUNC
 */
HWTEST_F(
    RdbTransactionQueryWithoutRowCountTest, RdbTrans_QueryWithoutRowCount_010_Normal_GetColumnIndex, TestSize.Level0)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    ASSERT_NE(predicates, NULL);
    OH_Cursor *cursor = OH_RdbTrans_QueryWithoutRowCount(trans, predicates, NULL, 0);
    predicates->destroy(predicates);
    ASSERT_NE(cursor, NULL);

    int columnIndex;
    errCode = cursor->getColumnIndex(cursor, "id", &columnIndex);
    EXPECT_EQ(columnIndex, 0);
    errCode = cursor->getColumnIndex(cursor, "data1", &columnIndex);
    EXPECT_EQ(columnIndex, 1);
    errCode = cursor->getColumnIndex(cursor, "data2", &columnIndex);
    EXPECT_EQ(columnIndex, 2);
    errCode = cursor->getColumnIndex(cursor, "data3", &columnIndex);
    EXPECT_EQ(columnIndex, 3);
    errCode = cursor->getColumnIndex(cursor, "data4", &columnIndex);
    EXPECT_EQ(columnIndex, 4);
    cursor->destroy(cursor);

    predicates = OH_Rdb_CreatePredicates("asset_table");
    ASSERT_NE(predicates, NULL);
    cursor = OH_Rdb_QueryWithoutRowCount(rdbStore_, predicates, NULL, 0);
    predicates->destroy(predicates);
    ASSERT_NE(cursor, NULL);
    errCode = cursor->getColumnIndex(cursor, "data1", &columnIndex);
    EXPECT_EQ(columnIndex, 1);
    errCode = cursor->getColumnIndex(cursor, "data2", &columnIndex);
    EXPECT_EQ(columnIndex, 2);
    cursor->destroy(cursor);
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RdbTrans_QueryWithoutRowCount_011_Abnormal_GetColumnIndex
 * @tc.desc: Abnormal testCase of cursor for GetColumnIndex.
 * @tc.type: FUNC
 */
HWTEST_F(
    RdbTransactionQueryWithoutRowCountTest, RdbTrans_QueryWithoutRowCount_011_Abnormal_GetColumnIndex, TestSize.Level0)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    ASSERT_NE(predicates, NULL);
    OH_Cursor *cursor = OH_RdbTrans_QueryWithoutRowCount(trans, predicates, NULL, 0);
    predicates->destroy(predicates);
    ASSERT_NE(cursor, NULL);

    int columnIndex;
    // cursor is nullptr
    errCode = cursor->getColumnIndex(nullptr, "data4", &columnIndex);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // columnName is nullptr
    errCode = cursor->getColumnIndex(cursor, nullptr, &columnIndex);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // columnName is not exists
    errCode = cursor->getColumnIndex(nullptr, "data5", &columnIndex);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // columnIndex is nullptr
    errCode = cursor->getColumnIndex(cursor, "data4", nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    cursor->destroy(cursor);
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RdbTrans_QueryWithoutRowCount_012_Normal_GetColumnName
 * @tc.desc: Normal testCase of cursor for GetColumnName.
 * @tc.type: FUNC
 */
HWTEST_F(
    RdbTransactionQueryWithoutRowCountTest, RdbTrans_QueryWithoutRowCount_012_Normal_GetColumnName, TestSize.Level0)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    ASSERT_NE(predicates, NULL);
    OH_Cursor *cursor = OH_RdbTrans_QueryWithoutRowCount(trans, predicates, NULL, 0);
    predicates->destroy(predicates);
    ASSERT_NE(cursor, NULL);

    char name[6];
    errCode = cursor->getColumnName(cursor, 0, name, 3);
    EXPECT_EQ(strcmp(name, "id"), 0);
    errCode = cursor->getColumnName(cursor, 1, name, 6);
    EXPECT_EQ(strcmp(name, "data1"), 0);
    errCode = cursor->getColumnName(cursor, 2, name, 6);
    EXPECT_EQ(strcmp(name, "data2"), 0);
    errCode = cursor->getColumnName(cursor, 3, name, 6);
    EXPECT_EQ(strcmp(name, "data3"), 0);
    errCode = cursor->getColumnName(cursor, 4, name, 6);
    EXPECT_EQ(strcmp(name, "data4"), 0);
    cursor->destroy(cursor);

    predicates = OH_Rdb_CreatePredicates("asset_table");
    ASSERT_NE(predicates, NULL);
    cursor = OH_Rdb_QueryWithoutRowCount(rdbStore_, predicates, NULL, 0);
    predicates->destroy(predicates);
    ASSERT_NE(cursor, NULL);
    errCode = cursor->getColumnName(cursor, 1, name, 6);
    EXPECT_EQ(strcmp(name, "data1"), 0);
    errCode = cursor->getColumnName(cursor, 2, name, 6);
    EXPECT_EQ(strcmp(name, "data2"), 0);
    cursor->destroy(cursor);
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RdbTrans_QueryWithoutRowCount_013_Abnormal_GetColumnName
 * @tc.desc: Abnormal testCase of cursor for GetColumnName.
 * @tc.type: FUNC
 */
HWTEST_F(
    RdbTransactionQueryWithoutRowCountTest, RdbTrans_QueryWithoutRowCount_013_Abnormal_GetColumnName, TestSize.Level0)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    ASSERT_NE(predicates, NULL);
    OH_Cursor *cursor = OH_RdbTrans_QueryWithoutRowCount(trans, predicates, NULL, 0);
    predicates->destroy(predicates);
    ASSERT_NE(cursor, NULL);

    char name[6];
    // cursor is nullptr
    errCode = cursor->getColumnName(nullptr, 4, name, 6);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // columnIndex out of range
    errCode = cursor->getColumnName(cursor, 5, name, 6);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_COLUMN_INDEX);
    errCode = cursor->getColumnName(cursor, -1, name, 6);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_COLUMN_INDEX);
    // columnName is nullptr
    errCode = cursor->getColumnName(cursor, 4, nullptr, 6);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // the size of columnName is invalid
    errCode = cursor->getColumnName(cursor, 4, name, 0);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    cursor->destroy(cursor);
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RdbTrans_QueryWithoutRowCount_014_Abnormal_GetColumnCount
 * @tc.desc: Abnormal testCase of cursor for GetColumnCount.
 * @tc.type: FUNC
 */
HWTEST_F(
    RdbTransactionQueryWithoutRowCountTest, RdbTrans_QueryWithoutRowCount_014_Abnormal_GetColumnCount, TestSize.Level0)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    ASSERT_NE(predicates, NULL);
    OH_Cursor *cursor = OH_RdbTrans_QueryWithoutRowCount(trans, predicates, NULL, 0);
    predicates->destroy(predicates);
    ASSERT_NE(cursor, NULL);

    int columnCount = 0;
    // cursor is nullptr
    errCode = cursor->getColumnCount(nullptr, &columnCount);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // columnCount is nullptr
    errCode = cursor->getColumnCount(cursor, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    cursor->destroy(cursor);
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RdbTrans_QueryWithoutRowCount_015_Abnormal_GetRowCount
 * @tc.desc: Abnormal testCase of cursor for GetRowCount.
 * @tc.type: FUNC
 */
HWTEST_F(
    RdbTransactionQueryWithoutRowCountTest, RdbTrans_QueryWithoutRowCount_015_Abnormal_GetRowCount, TestSize.Level0)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    ASSERT_NE(predicates, NULL);
    OH_Cursor *cursor = OH_RdbTrans_QueryWithoutRowCount(trans, predicates, NULL, 0);
    predicates->destroy(predicates);
    ASSERT_NE(cursor, NULL);

    int rowCount = 0;
    // getrowCount is not support
    errCode = cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_NOT_SUPPORTED);

    cursor->destroy(cursor);
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RdbTrans_QueryWithoutRowCount_016_Abnormal_GetRowCount
 * @tc.desc: Abnormal testCase of cursor for GetXXX.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionQueryWithoutRowCountTest, RdbTrans_QueryWithoutRowCount_016_Abnormal_Get, TestSize.Level0)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    ASSERT_NE(predicates, NULL);
    OH_Cursor *cursor = OH_RdbTrans_QueryWithoutRowCount(trans, predicates, NULL, 0);
    predicates->destroy(predicates);
    ASSERT_NE(cursor, NULL);
    // cursor is nullptr
    errCode = cursor->goToNextRow(nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    CheckErrAndDestroyCursor(cursor);
    
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RdbTrans_QueryWithoutRowCount_017_Abnormal_Get
 * @tc.desc: Abnormal testCase of cursor for GetXXX.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionQueryWithoutRowCountTest, RdbTrans_QueryWithoutRowCount_017_Abnormal_Get, TestSize.Level0)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");
    ASSERT_NE(predicates, NULL);
    OH_Cursor *cursor = OH_RdbTrans_QueryWithoutRowCount(trans, predicates, NULL, 0);
    predicates->destroy(predicates);
    ASSERT_NE(cursor, NULL);

    CheckErrnoAndDestroyCursor(cursor);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}


/**
 * @tc.name: RdbTrans_QueryWithoutRowCount_018_Normal_GetAssert
 * @tc.desc: Normal testCase of cursor for GetAssert.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionQueryWithoutRowCountTest, RdbTrans_QueryWithoutRowCount_018_Normal_GetAssert, TestSize.Level0)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("asset_table");
    ASSERT_NE(predicates, NULL);
    OH_Cursor *cursor = OH_RdbTrans_QueryWithoutRowCount(trans, predicates, NULL, 0);
    predicates->destroy(predicates);
    ASSERT_NE(cursor, NULL);

    CheckResultSetForGetAssert(cursor);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RdbTrans_QueryWithoutRowCount_019_Normal_GetAsserts
 * @tc.desc: Normal testCase of cursor for getAssets.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionQueryWithoutRowCountTest, RdbTrans_QueryWithoutRowCount_019_Normal_GetAsserts, TestSize.Level0)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    OH_Predicates *predicates = OH_Rdb_CreatePredicates("asset_table");
    ASSERT_NE(predicates, NULL);
    OH_Cursor *cursor = OH_RdbTrans_QueryWithoutRowCount(trans, predicates, NULL, 0);
    predicates->destroy(predicates);
    ASSERT_NE(cursor, NULL);

    CheckResultSetForGetAsserts(cursor);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RdbTrans_QuerySqlWithoutRowCount_001_Normal_Get
 * @tc.desc: Normal testCase of store for OH_RdbTrans_QueryWithNoCount, getColumnCount, getXXX.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionQueryWithoutRowCountTest, RdbTrans_QuerySqlWithoutRowCount_001_Normal_Get, TestSize.Level0)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    char querySql[] = "select data1, data2, data3, data4 from test;";
    OH_Cursor *cursor = OH_RdbTrans_QuerySqlWithoutRowCount(trans, querySql, nullptr);
    ASSERT_NE(cursor, NULL);

    CheckAndDestroyCursor(cursor);

    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RdbTrans_QuerySqlWithoutRowCount_002_Normal_Get
 * @tc.desc: Normal testCase of store for OH_RdbTrans_QueryWithNoCount, getColumnCount, getXXX.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionQueryWithoutRowCountTest, RdbTrans_QuerySqlWithoutRowCount_002_Normal_Get, TestSize.Level0)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    char querySql[] = "select * from test where id = ?;";
    OH_Data_Values *values = OH_Values_Create();
    ret = OH_Values_PutInt(values, 1); // Add int value 1 to values
    EXPECT_EQ(ret, RDB_OK);
    OH_Cursor *cursor = OH_RdbTrans_QuerySqlWithoutRowCount(trans, querySql, values);
    ret = OH_Values_Destroy(values);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(cursor, NULL);

    cursor->goToNextRow(cursor);

    int columnCount = 0;
    cursor->getColumnCount(cursor, &columnCount);
    EXPECT_EQ(columnCount, 5);

    int64_t id;
    cursor->getInt64(cursor, 0, &id);
    EXPECT_EQ(id, 1);

    size_t size = 0;
    cursor->getSize(cursor, 1, &size);
    EXPECT_EQ(size, 9);
    char data1Value[size];
    cursor->getText(cursor, 1, data1Value, size);
    EXPECT_EQ(strcmp(data1Value, "zhangSan"), 0);

    int64_t data2Value;
    cursor->getInt64(cursor, 2, &data2Value);
    EXPECT_EQ(data2Value, 12800);

    double data3Value;
    cursor->getReal(cursor, 3, &data3Value);
    EXPECT_DOUBLE_EQ(data3Value, 100.1);

    cursor->getSize(cursor, 4, &size);
    EXPECT_EQ(size, 5);
    unsigned char data4Value[size];
    cursor->getBlob(cursor, 4, data4Value, size);
    EXPECT_EQ(data4Value[0], 1);
    EXPECT_EQ(data4Value[1], 2);

    cursor->destroy(cursor);
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}

/**
 * @tc.name: RdbTrans_QuerySqlWithoutRowCount_003_Abnormal_InvalidArgs
 * @tc.desc: Abnormal testCase of store for InvalidArgs.
 * @tc.type: FUNC
 */
HWTEST_F(
    RdbTransactionQueryWithoutRowCountTest, RdbTrans_QuerySqlWithoutRowCount_003_Abnormal_InvalidArgs, TestSize.Level0)
{
    OH_Rdb_Transaction *trans = nullptr;
    int ret = OH_Rdb_CreateTransaction(rdbStore_, options_, &trans);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_NE(trans, nullptr);

    char querySql[] = "select * from test;";
    // store is nullptr
    OH_Cursor *cursor = OH_RdbTrans_QuerySqlWithoutRowCount(nullptr, querySql, {});
    ASSERT_EQ(cursor, NULL);

    // sql is nullptr
    cursor = OH_RdbTrans_QuerySqlWithoutRowCount(trans, nullptr, {});
    ASSERT_EQ(cursor, NULL);

    char querySql1[] = "select * from test where id = ?;";
    // the args of value is nullptr
    OH_Data_Values *values = OH_Values_Create();
    cursor = OH_RdbTrans_QuerySqlWithoutRowCount(trans, querySql1, values);
    ASSERT_NE(cursor, NULL);

    // the SQL statement needs to bind parameters, but the parameters are not transferred
    cursor = OH_RdbTrans_QuerySqlWithoutRowCount(trans, querySql1, {});
    ASSERT_NE(cursor, NULL);
    // the SQL statement does not need to be bound to parameters, but the parameter is transferred
    ret = OH_Values_PutInt(values, 1); // Add int value 1 to values
    EXPECT_EQ(ret, RDB_OK);
    cursor = OH_RdbTrans_QuerySqlWithoutRowCount(trans, querySql, values);
    ASSERT_NE(cursor, NULL);

    cursor->destroy(cursor);
    ret = OH_Values_Destroy(values);
    EXPECT_EQ(ret, RDB_OK);
    ret = OH_RdbTrans_Destroy(trans);
    EXPECT_EQ(ret, RDB_OK);
}
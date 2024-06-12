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

class RdbNativeCursorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static void InitRdbConfig()
    {
        config_.dataBaseDir = RDB_TEST_PATH;
        config_.storeName = "rdb_cursor_test.db";
        config_.bundleName = "com.ohos.example.distributedndk";
        config_.moduleName = "";
        config_.securityLevel = OH_Rdb_SecurityLevel::S1;
        config_.isEncrypt = false;
        config_.area = Rdb_SecurityArea::RDB_SECURITY_AREA_EL1;
        config_.selfSize = sizeof(OH_Rdb_Config);
    }
    static void CreateAssetTable();
    static void SetAsset(Data_Asset *asset, int index);
    static OH_Rdb_Config config_;
};

OH_Rdb_Store *cursorTestRdbStore_;
OH_Rdb_Config RdbNativeCursorTest::config_ = { 0 };
void RdbNativeCursorTest::SetUpTestCase(void)
{
    InitRdbConfig();
    mkdir(config_.dataBaseDir, 0770);
    int errCode = 0;
    char table[] = "test";
    cursorTestRdbStore_ = OH_Rdb_GetOrOpen(&config_, &errCode);
    EXPECT_NE(cursorTestRdbStore_, NULL);
    char createTableSql[] = "CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    errCode = OH_Rdb_Execute(cursorTestRdbStore_, createTableSql);

    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 1);
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    valueBucket->putInt64(valueBucket, "data2", 12800);
    valueBucket->putReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = { 1, 2, 3, 4, 5 };
    int len = sizeof(arr) / sizeof(arr[0]);
    valueBucket->putBlob(valueBucket, "data4", arr, len);
    valueBucket->putText(valueBucket, "data5", "ABCDEFG");
    errCode = OH_Rdb_Insert(cursorTestRdbStore_, table, valueBucket);
    EXPECT_EQ(errCode, 1);

    valueBucket->clear(valueBucket);
    valueBucket->putInt64(valueBucket, "id", 2);
    valueBucket->putText(valueBucket, "data1", "liSi");
    valueBucket->putInt64(valueBucket, "data2", 13800);
    valueBucket->putReal(valueBucket, "data3", 200.1);
    valueBucket->putText(valueBucket, "data5", "ABCDEFGH");
    errCode = OH_Rdb_Insert(cursorTestRdbStore_, table, valueBucket);
    EXPECT_EQ(errCode, 2);

    valueBucket->clear(valueBucket);
    valueBucket->putInt64(valueBucket, "id", 3);
    valueBucket->putText(valueBucket, "data1", "wangWu");
    valueBucket->putInt64(valueBucket, "data2", 14800);
    valueBucket->putReal(valueBucket, "data3", 300.1);
    valueBucket->putText(valueBucket, "data5", "ABCDEFGHI");
    errCode = OH_Rdb_Insert(cursorTestRdbStore_, table, valueBucket);
    EXPECT_EQ(errCode, 3);

    valueBucket->destroy(valueBucket);
    CreateAssetTable();
}

void RdbNativeCursorTest::TearDownTestCase(void)
{
    delete cursorTestRdbStore_;
    cursorTestRdbStore_ = NULL;
    OH_Rdb_DeleteStore(&config_);
}

void RdbNativeCursorTest::SetUp(void) {}

void RdbNativeCursorTest::TearDown(void) {}

void RdbNativeCursorTest::CreateAssetTable()
{
    char createTableSql[] = "CREATE TABLE IF NOT EXISTS asset_table (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 "
                            "asset, data2 assets );";
    int errCode = OH_Rdb_Execute(cursorTestRdbStore_, createTableSql);
    EXPECT_EQ(errCode, RDB_OK);
    char table[] = "asset_table";
    int assetsCount = 2;
    int curRow = 1;
    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    Data_Asset *asset1 = OH_Data_Asset_CreateOne();
    SetAsset(asset1, 1);
    Data_Asset *asset2 = OH_Data_Asset_CreateOne();
    SetAsset(asset2, 2);

    valueBucket->putInt64(valueBucket, "id", curRow);
    OH_VBucket_PutAsset(valueBucket, "data1", asset1);
    Data_Asset **assets1 = OH_Data_Asset_CreateMultiple(assetsCount);
    SetAsset(assets1[0], 1);
    SetAsset(assets1[1], 2);
    errCode = OH_VBucket_PutAssets(valueBucket, "data2", assets1, assetsCount);
    int rowID = OH_Rdb_Insert(cursorTestRdbStore_, table, valueBucket);
    EXPECT_EQ(rowID, curRow);
    curRow++;

    valueBucket->clear(valueBucket);
    valueBucket->putInt64(valueBucket, "id", curRow);
    OH_VBucket_PutAsset(valueBucket, "data1", asset2);
    Data_Asset **assets2 = OH_Data_Asset_CreateMultiple(assetsCount);
    SetAsset(assets2[0], 1);
    SetAsset(assets2[1], 3);
    errCode = OH_VBucket_PutAssets(valueBucket, "data2", assets2, assetsCount);
    rowID = OH_Rdb_Insert(cursorTestRdbStore_, table, valueBucket);
    EXPECT_EQ(rowID, curRow);

    OH_Data_Asset_DestroyMultiple(assets1, assetsCount);
    OH_Data_Asset_DestroyMultiple(assets2, assetsCount);
    OH_Data_Asset_DestroyOne(asset1);
    OH_Data_Asset_DestroyOne(asset2);
    valueBucket->destroy(valueBucket);
}

void RdbNativeCursorTest::SetAsset(Data_Asset *asset, int index)
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

/**
 * @tc.name: RDB_Native_cursor_test_001
 * @tc.desc: Normal testCase of cursor for GetColumnType.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeCursorTest, RDB_Native_cursor_test_001, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");

    OH_Cursor *cursor = OH_Rdb_Query(cursorTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
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

    errCode = cursor->getColumnType(cursor, 5, &type);
    EXPECT_EQ(type, OH_ColumnType::TYPE_TEXT);

    errCode = cursor->getColumnType(nullptr, 5, &type);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = cursor->getColumnType(cursor, -1, &type);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = cursor->getColumnType(cursor, 5, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    predicates->destroy(predicates);
    cursor->destroy(cursor);
}

/**
 * @tc.name: RDB_Native_cursor_test_002
 * @tc.desc: Normal testCase of cursor for GetColumnIndex.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeCursorTest, RDB_Native_cursor_test_002, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");

    OH_Cursor *cursor = OH_Rdb_Query(cursorTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);

    int columnIndex;
    errCode = cursor->getColumnIndex(cursor, "data1", &columnIndex);
    EXPECT_EQ(columnIndex, 1);

    errCode = cursor->getColumnIndex(cursor, "data2", &columnIndex);
    EXPECT_EQ(columnIndex, 2);

    errCode = cursor->getColumnIndex(cursor, "data3", &columnIndex);
    EXPECT_EQ(columnIndex, 3);

    errCode = cursor->getColumnIndex(cursor, "data4", &columnIndex);
    EXPECT_EQ(columnIndex, 4);

    errCode = cursor->getColumnIndex(cursor, "data5", &columnIndex);
    EXPECT_EQ(columnIndex, 5);

    errCode = cursor->getColumnIndex(nullptr, "data5", &columnIndex);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = cursor->getColumnIndex(cursor, nullptr, &columnIndex);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = cursor->getColumnIndex(cursor, "data5", nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    predicates->destroy(predicates);
    cursor->destroy(cursor);
}

/**
 * @tc.name: RDB_Native_cursor_test_003
 * @tc.desc: Normal testCase of cursor for GetColumnName.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeCursorTest, RDB_Native_cursor_test_003, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");

    OH_Cursor *cursor = OH_Rdb_Query(cursorTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);

    char name[10];
    errCode = cursor->getColumnName(cursor, 1, name, 10);
    EXPECT_EQ(strcmp(name, "data1"), 0);

    errCode = cursor->getColumnName(cursor, 2, name, 6);
    EXPECT_EQ(strcmp(name, "data2"), 0);

    errCode = cursor->getColumnName(cursor, 3, name, 6);
    EXPECT_EQ(strcmp(name, "data3"), 0);

    errCode = cursor->getColumnName(cursor, 4, name, 6);
    EXPECT_EQ(strcmp(name, "data4"), 0);

    errCode = cursor->getColumnName(cursor, 5, name, 6);
    EXPECT_EQ(strcmp(name, "data5"), 0);

    errCode = cursor->getColumnName(nullptr, 5, name, 6);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = cursor->getColumnName(cursor, 5, nullptr, 6);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = cursor->getColumnName(cursor, 5, name, 0);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    predicates->destroy(predicates);
    cursor->destroy(cursor);
}

/**
 * @tc.name: RDB_Native_cursor_test_004
 * @tc.desc: Normal testCase of cursor for Getxxx.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeCursorTest, RDB_Native_cursor_test_004, TestSize.Level1)
{
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");

    const char *columnNames[] = { "data1", "data2", "data3", "data4" };
    int len = sizeof(columnNames) / sizeof(columnNames[0]);
    OH_Cursor *cursor = OH_Rdb_Query(cursorTestRdbStore_, predicates, columnNames, len);
    EXPECT_NE(cursor, NULL);

    int rowCount = 0;
    cursor->getRowCount(cursor, &rowCount);
    EXPECT_EQ(rowCount, 3);

    cursor->goToNextRow(cursor);

    int columnCount = 0;
    cursor->getColumnCount(cursor, &columnCount);
    EXPECT_EQ(columnCount, 4);

    size_t size = 0;
    cursor->getSize(cursor, 0, &size);
    char data1Value[size + 1];
    cursor->getText(cursor, 0, data1Value, size + 1);
    EXPECT_EQ(strcmp(data1Value, "zhangSan"), 0);

    int64_t data2Value;
    cursor->getInt64(cursor, 1, &data2Value);
    EXPECT_EQ(data2Value, 12800);

    double data3Value;
    cursor->getReal(cursor, 2, &data3Value);
    EXPECT_EQ(data3Value, 100.1);

    cursor->getSize(cursor, 3, &size);
    unsigned char data4Value[size];
    cursor->getBlob(cursor, 3, data4Value, size);
    EXPECT_EQ(data4Value[0], 1);
    EXPECT_EQ(data4Value[1], 2);

    cursor->goToNextRow(cursor);

    cursor->getSize(cursor, 0, &size);
    char data1Value_1[size + 1];
    cursor->getText(cursor, 0, data1Value_1, size + 1);
    EXPECT_EQ(strcmp(data1Value_1, "liSi"), 0);

    cursor->getInt64(cursor, 1, &data2Value);
    EXPECT_EQ(data2Value, 13800);

    cursor->getReal(cursor, 2, &data3Value);
    EXPECT_EQ(data3Value, 200.1);

    bool isNull = false;
    cursor->isNull(cursor, 3, &isNull);
    EXPECT_EQ(isNull, true);

    predicates->destroy(predicates);
    cursor->destroy(cursor);
}

/**
 * @tc.name: RDB_Native_cursor_test_005
 * @tc.desc: Normal testCase of cursor for anomalous branch.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeCursorTest, RDB_Native_cursor_test_005, TestSize.Level1)
{
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");

    const char *columnNames[] = { "data1", "data2", "data3", "data4" };
    int len = sizeof(columnNames) / sizeof(columnNames[0]);
    OH_Cursor *cursor = OH_Rdb_Query(cursorTestRdbStore_, predicates, columnNames, len);
    EXPECT_NE(cursor, NULL);

    int rowCount = 0;
    int errCode = cursor->getRowCount(nullptr, &rowCount);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = cursor->getRowCount(cursor, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    int columnCount = 0;
    errCode = cursor->getColumnCount(nullptr, &columnCount);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = cursor->getColumnCount(cursor, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    errCode = cursor->goToNextRow(nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    size_t size = 0;
    errCode = cursor->getSize(nullptr, 0, &size);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = cursor->getSize(cursor, 0, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    char data1Value[size + 1];
    errCode = cursor->getText(nullptr, 0, data1Value, size + 1);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = cursor->getText(cursor, 0, nullptr, size + 1);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = cursor->getText(cursor, 0, data1Value, 0);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    predicates->destroy(predicates);
    cursor->destroy(cursor);
}

/**
 * @tc.name: RDB_Native_cursor_test_006
 * @tc.desc: Normal testCase of cursor for anomalous branch.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeCursorTest, RDB_Native_cursor_test_006, TestSize.Level1)
{
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("test");

    const char *columnNames[] = {"data1", "data2", "data3", "data4"};
    int len = sizeof(columnNames) / sizeof(columnNames[0]);
    OH_Cursor *cursor = OH_Rdb_Query(cursorTestRdbStore_, predicates, columnNames, len);
    EXPECT_NE(cursor, NULL);

    int64_t data2Value;
    int errCode = cursor->getInt64(nullptr, 1, &data2Value);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = cursor->getInt64(cursor, 1, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    double data3Value;
    errCode = cursor->getReal(nullptr, 2, &data3Value);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = cursor->getReal(cursor, 2, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    size_t size = 0;
    unsigned char data4Value[size];
    errCode = cursor->getBlob(nullptr, 3, data4Value, size);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = cursor->getBlob(cursor, 3, nullptr, size);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = cursor->getBlob(cursor, 3, data4Value, 0);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    bool isNull = false;
    errCode = cursor->isNull(nullptr, 3, &isNull);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = cursor->isNull(cursor, 3, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    errCode = cursor->destroy(nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    predicates->destroy(predicates);
    cursor->destroy(cursor);
}

/**
 * @tc.name: RDB_Native_cursor_test_007
 * @tc.desc: Normal testCase of cursor for anomalous branch.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeCursorTest, RDB_Native_cursor_test_007, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("asset_table");

    OH_Cursor *cursor = OH_Rdb_Query(cursorTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    cursor->goToNextRow(cursor);

    OH_ColumnType type;
    errCode = cursor->getColumnType(cursor, 0, &type);
    EXPECT_EQ(type, OH_ColumnType::TYPE_INT64);

    errCode = cursor->getColumnType(cursor, 1, &type);
    EXPECT_EQ(type, OH_ColumnType::TYPE_ASSET);

    errCode = cursor->getColumnType(cursor, 2, &type);
    EXPECT_EQ(type, OH_ColumnType::TYPE_ASSETS);

    predicates->destroy(predicates);
    cursor->destroy(cursor);
}

/**
 * @tc.name: RDB_Native_cursor_test_008
 * @tc.desc: Normal testCase of cursor for anomalous branch.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeCursorTest, RDB_Native_cursor_test_008, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("asset_table");

    OH_Cursor *cursor = OH_Rdb_Query(cursorTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    cursor->goToNextRow(cursor);

    OH_ColumnType type;
    errCode = cursor->getColumnType(cursor, 0, &type);
    EXPECT_EQ(type, OH_ColumnType::TYPE_INT64);
    int64_t id;
    errCode = cursor->getInt64(cursor, 0, &id);
    EXPECT_EQ(id, 1);

    errCode = cursor->getColumnType(cursor, 1, &type);
    EXPECT_EQ(type, OH_ColumnType::TYPE_ASSET);
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    errCode = cursor->getAsset(cursor, 1, asset);
    EXPECT_NE(asset, nullptr);
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

    predicates->destroy(predicates);
    OH_Data_Asset_DestroyOne(asset);
    cursor->destroy(cursor);
}

/**
 * @tc.name: RDB_Native_cursor_test_009
 * @tc.desc: Normal testCase of cursor for getAssets.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeCursorTest, RDB_Native_cursor_test_009, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("asset_table");

    OH_Cursor *cursor = OH_Rdb_Query(cursorTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    cursor->goToNextRow(cursor);

    OH_ColumnType type;
    errCode = cursor->getColumnType(cursor, 0, &type);
    EXPECT_EQ(type, OH_ColumnType::TYPE_INT64);
    int64_t id;
    errCode = cursor->getInt64(cursor, 0, &id);
    EXPECT_EQ(id, 1);

    errCode = cursor->getColumnType(cursor, 2, &type);
    EXPECT_EQ(type, OH_ColumnType::TYPE_ASSETS);
    uint32_t assetCount = 0;
    errCode = cursor->getAssets(cursor, 2, nullptr, &assetCount);
    EXPECT_EQ(assetCount, 2);
    Data_Asset **assets = OH_Data_Asset_CreateMultiple(assetCount);
    errCode = cursor->getAssets(cursor, 2, assets, &assetCount);
    EXPECT_EQ(assetCount, 2);
    Data_Asset *asset = assets[1];
    EXPECT_NE(asset, NULL);

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
    EXPECT_EQ(createTime, 2);

    int64_t modifyTime = 0;
    errCode = OH_Data_Asset_GetModifyTime(asset, &modifyTime);
    EXPECT_EQ(modifyTime, 2);

    size_t size = 0;
    errCode = OH_Data_Asset_GetSize(asset, &size);
    EXPECT_EQ(size, 2);

    Data_AssetStatus status = Data_AssetStatus::ASSET_NULL;
    errCode = OH_Data_Asset_GetStatus(asset, &status);
    EXPECT_EQ(status, ASSET_INSERT);

    predicates->destroy(predicates);
    OH_Data_Asset_DestroyMultiple(assets, assetCount);
    cursor->destroy(cursor);
}

/**
 * @tc.name: Abnormal_RDB_cursor_test_010
 * @tc.desc: Abnormal testCase of cursor for OH_VBucket_PutAssets, OH_VBucket_PutAsset.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeCursorTest, Abnormal_cursor_PutAssets_test_010, TestSize.Level1)
{
    char table[] = "asset_table";
    int assetsCount = 2;
    int curRow = 3;

    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();

    Data_Asset *asset = OH_Data_Asset_CreateOne();
    SetAsset(asset, 1);

    valueBucket->putInt64(valueBucket, "id", curRow);

    int errCode = OH_VBucket_PutAsset(nullptr, "data1", asset);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_ErrCode::RDB_OK;
    errCode = OH_VBucket_PutAsset(valueBucket, nullptr, asset);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_ErrCode::RDB_OK;
    errCode = OH_VBucket_PutAsset(valueBucket, "data1", nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_VBucket_PutAsset(valueBucket, "data1", asset);
    Data_Asset **assets = OH_Data_Asset_CreateMultiple(assetsCount);
    SetAsset(assets[0], 1);
    SetAsset(assets[1], 2);

    errCode = OH_Rdb_ErrCode::RDB_OK;
    errCode = OH_VBucket_PutAssets(nullptr, "data2", assets, assetsCount);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    errCode = OH_Rdb_ErrCode::RDB_OK;
    errCode = OH_VBucket_PutAssets(valueBucket, nullptr, assets, assetsCount);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    errCode = OH_VBucket_PutAssets(valueBucket, "data2", assets, assetsCount);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_OK);
    int rowID = OH_Rdb_Insert(cursorTestRdbStore_, table, valueBucket);
    EXPECT_EQ(rowID, curRow);

    free(assets[1]);
    assets[1] = nullptr;
    errCode = OH_VBucket_PutAssets(valueBucket, nullptr, assets, assetsCount);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    OH_Data_Asset_DestroyMultiple(assets, assetsCount);
    OH_Data_Asset_DestroyOne(asset);
    valueBucket->destroy(valueBucket);
}

/**
 * @tc.name: Abnormal_cursor_GetAssets_test_011
 * @tc.desc: Abnormal testCase of cursor for getAssets, getAsset.
 * @tc.type: FUNC
 */
HWTEST_F(RdbNativeCursorTest, Abnormal_cursor_GetAssets_test_011, TestSize.Level1)
{
    int errCode = 0;
    OH_Predicates *predicates = OH_Rdb_CreatePredicates("asset_table");

    OH_Cursor *cursor = OH_Rdb_Query(cursorTestRdbStore_, predicates, NULL, 0);
    EXPECT_NE(cursor, NULL);
    cursor->goToNextRow(cursor);

    OH_ColumnType type;
    errCode = cursor->getColumnType(cursor, 1, &type);
    EXPECT_EQ(type, OH_ColumnType::TYPE_ASSET);
    errCode = cursor->getColumnType(cursor, 2, &type);
    EXPECT_EQ(type, OH_ColumnType::TYPE_ASSETS);

    uint32_t assetCount = 0;
    // if cursor is nullptr
    errCode = cursor->getAssets(nullptr, 2, nullptr, &assetCount);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // if cursor is empty
    OH_Cursor emptyCursor;
    errCode = cursor->getAssets(&emptyCursor, 2, nullptr, &assetCount);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // if index is nullpry
    errCode = cursor->getAssets(cursor, 2, nullptr, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // if columnIndex < 0
    errCode = cursor->getAssets(cursor, -1, nullptr, &assetCount);
    EXPECT_NE(errCode, OH_Rdb_ErrCode::RDB_OK);

    Data_Asset *asset = OH_Data_Asset_CreateOne();
    EXPECT_NE(asset, NULL);
    // if cursor is nullptr
    errCode = cursor->getAsset(nullptr, 1, asset);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // if cursor is empry
    errCode = cursor->getAsset(&emptyCursor, 1, asset);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // if asset is nullptr
    errCode = cursor->getAsset(cursor, 1, nullptr);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    // if columnIndex is < 0
    errCode = cursor->getAsset(cursor, -1, asset);
    EXPECT_EQ(errCode, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);

    predicates->destroy(predicates);
    OH_Data_Asset_DestroyOne(asset);
    cursor->destroy(cursor);
}

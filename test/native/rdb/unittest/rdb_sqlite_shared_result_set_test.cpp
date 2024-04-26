/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "shared_block.h"
#include "sqlite_shared_result_set.h"
#include "value_object.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using Asset = ValueObject::Asset;
using Assets = ValueObject::Assets;
class RdbSqliteSharedResultSetTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void GenerateDefaultTable();
    void GenerateAssetsTable();
    void GenerateTimeoutTable();
    void CheckResultSetAttribute(std::shared_ptr<ResultSet> rstSet, int pos, bool isStart, bool isAtFirstRow,
        bool isEnded);

    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;
};

const std::string RdbSqliteSharedResultSetTest::DATABASE_NAME = RDB_TEST_PATH + "shared_test.db";
std::shared_ptr<RdbStore> RdbSqliteSharedResultSetTest::store = nullptr;

class SqliteSharedOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &rdbStore) override;
    int OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

std::string const SqliteSharedOpenCallback::CREATE_TABLE_TEST = "CREATE TABLE test (id INTEGER PRIMARY KEY "
                                                                "AUTOINCREMENT, data1 TEXT,data2 INTEGER, data3 "
                                                                "FLOAT, data4 BLOB, data5 ASSET, data6 ASSETS);";

int SqliteSharedOpenCallback::OnCreate(RdbStore &rdbStore)
{
    return rdbStore.ExecuteSql(CREATE_TABLE_TEST);
}

int SqliteSharedOpenCallback::OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbSqliteSharedResultSetTest::SetUpTestCase(void)
{
    RdbStoreConfig sqliteSharedRstConfig(RdbSqliteSharedResultSetTest::DATABASE_NAME);
    SqliteSharedOpenCallback sqliteSharedRstHelper;
    int errCode = E_OK;
    RdbSqliteSharedResultSetTest::store =
        RdbHelper::GetRdbStore(sqliteSharedRstConfig, 1, sqliteSharedRstHelper, errCode);
    EXPECT_NE(RdbSqliteSharedResultSetTest::store, nullptr);
}

void RdbSqliteSharedResultSetTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(RdbSqliteSharedResultSetTest::DATABASE_NAME);
}

void RdbSqliteSharedResultSetTest::SetUp()
{
    store->ExecuteSql("DELETE FROM test");
}

void RdbSqliteSharedResultSetTest::TearDown()
{}

void RdbSqliteSharedResultSetTest::GenerateDefaultTable()
{
    std::shared_ptr<RdbStore> &store = RdbSqliteSharedResultSetTest::store;

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("data1", std::string("hello"));
    values.PutInt("data2", 10);
    values.PutDouble("data3", 1.0);
    values.PutBlob("data4", std::vector<uint8_t> { 66 });
    store->Insert(id, "test", values);

    values.Clear();
    values.PutInt("id", 2);
    values.PutString("data1", std::string("2"));
    values.PutInt("data2", -5);
    values.PutDouble("data3", 2.5);
    values.PutBlob("data4", std::vector<uint8_t> {});
    store->Insert(id, "test", values);

    values.Clear();
    values.PutInt("id", 3);
    values.PutString("data1", std::string("hello world"));
    values.PutInt("data2", 3);
    values.PutDouble("data3", 1.8);
    values.PutBlob("data4", std::vector<uint8_t> {});
    store->Insert(id, "test", values);
}

void RdbSqliteSharedResultSetTest::GenerateAssetsTable()
{
    std::shared_ptr<RdbStore> &store = RdbSqliteSharedResultSetTest::store;
    int64_t id;
    ValuesBucket values;
    Asset assetValue1 = Asset{ 1, Asset::STATUS_DOWNLOADING, 1, "1", "name1", "uri1", "createTime1", "modifyTime1",
        "size1", "hash1", "path1" };
    Asset assetValue2 = Asset{ 2, Asset::STATUS_DOWNLOADING, 2, "2", "name2", "uri2", "createTime2", "modifyTime2",
        "size2", "hash2", "path2" };

    Assets assets = Assets{ assetValue1 };
    values.PutInt("id", 1);
    values.Put("data5", ValueObject(assetValue1));
    values.Put("data6", ValueObject(assets));
    store->Insert(id, "test", values);

    values.Clear();
    Assets assets1 = Assets{ assetValue2 };
    values.PutInt("id", 2);
    values.Put("data5", ValueObject(assetValue2));
    values.Put("data6", ValueObject(assets1));
    store->Insert(id, "test", values);
}

void RdbSqliteSharedResultSetTest::GenerateTimeoutTable()
{
    std::shared_ptr<RdbStore> &store = RdbSqliteSharedResultSetTest::store;
    int64_t id;
    ValuesBucket values;
    auto timeout = static_cast<uint64_t>(
        (std::chrono::steady_clock::now() - std::chrono::seconds(10)).time_since_epoch().count());

    Asset assetValue1 = Asset{
        1,
        Asset::STATUS_DOWNLOADING,
        timeout,
        "id",
        "name1",
        "uri1",
        "createTime1",
        "modifyTime1",
        "size1",
        "hash1",
        "path1",
    };

    Assets assets = Assets{ assetValue1 };
    values.PutInt("id", 1);
    values.Put("data5", ValueObject(assetValue1));
    values.Put("data6", ValueObject(assets));
    store->Insert(id, "test", values);
}

void RdbSqliteSharedResultSetTest::CheckResultSetAttribute(std::shared_ptr<ResultSet> rstSet, int pos, bool isStart,
    bool isAtFirstRow, bool isEnded)
{
    int position = -1;
    int iRet = rstSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(pos, position);

    bool bResultSet = !isStart;
    iRet = rstSet->IsStarted(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(isStart, bResultSet);

    bResultSet = !isAtFirstRow;
    iRet = rstSet->IsAtFirstRow(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(isAtFirstRow, bResultSet);

    bResultSet = !isEnded;
    iRet = rstSet->IsEnded(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(isEnded, bResultSet);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_Asset_Timeout
 * @tc.desc: normal testcase of SqliteSharedResultSet for move
 * @tc.type: FUNC
 * @tc.require: AR000134UL
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_Asset_Timeout, TestSize.Level1)
{
    GenerateTimeoutTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<ResultSet> rstSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    int ret = rstSet->GoToRow(0);
    EXPECT_EQ(ret, E_OK);

    int rowCnt = -1;
    ret = rstSet->GetRowCount(rowCnt);
    EXPECT_EQ(rowCnt, 1);

    Asset asset;
    rstSet->GetAsset(5, asset);
    EXPECT_EQ(asset.version, 1);
    EXPECT_EQ(asset.name, "name1");
    EXPECT_EQ(asset.uri, "uri1");
    EXPECT_EQ(asset.status, Asset::STATUS_INSERT);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_Asset
 * @tc.desc: normal testcase of SqliteSharedResultSet for asset and assets
 * @tc.type: FUNC
 * @tc.require: AR000134UL
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_Asset, TestSize.Level1)
{
    GenerateAssetsTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<ResultSet> rstSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    int ret = rstSet->GoToRow(0);
    EXPECT_EQ(ret, E_OK);

    int rowCnt = -1;
    ret = rstSet->GetRowCount(rowCnt);
    EXPECT_EQ(rowCnt, 2);

    std::string colName = "";
    rstSet->GetColumnName(5, colName);
    EXPECT_EQ(colName, "data5");

    rstSet->GetColumnName(6, colName);
    EXPECT_EQ(colName, "data6");

    Asset asset;
    rstSet->GetAsset(5, asset);
    EXPECT_EQ(asset.version, 1);
    EXPECT_EQ(asset.name, "name1");
    EXPECT_EQ(asset.uri, "uri1");
    EXPECT_EQ(asset.status, AssetValue::STATUS_INSERT);

    Assets assets;
    rstSet->GetAssets(6, assets);
    EXPECT_EQ(assets.size(), 1);
    auto it = assets.begin();
    EXPECT_EQ(it->version, 1);
    EXPECT_EQ(it->name, "name1");
    EXPECT_EQ(it->uri, "uri1");
    EXPECT_EQ(it->status, AssetValue::STATUS_INSERT);

    ret = rstSet->GoToRow(1);
    EXPECT_EQ(ret, E_OK);

    rstSet->GetAsset(5, asset);
    EXPECT_EQ(asset.version, 2);
    EXPECT_EQ(asset.name, "name2");
    EXPECT_EQ(asset.uri, "uri2");
    EXPECT_EQ(asset.status, AssetValue::STATUS_INSERT);

    rstSet->GetAssets(6, assets);
    EXPECT_EQ(assets.size(), 1);
    it = assets.begin();
    EXPECT_EQ(it->version, 2);
    EXPECT_EQ(it->name, "name2");
    EXPECT_EQ(it->uri, "uri2");
    EXPECT_EQ(it->status, AssetValue::STATUS_INSERT);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: RdbStore_Delete_001
 * @tc.desc: normal testcase of SqliteSharedResultSet for move
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_001, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<ResultSet> rstSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    int ret = rstSet->GoToRow(1);
    EXPECT_EQ(ret, E_OK);

    int rowCnt = -1;
    ret = rstSet->GetRowCount(rowCnt);
    EXPECT_EQ(rowCnt, 3);

    std::string colName = "";
    rstSet->GetColumnName(1, colName);
    EXPECT_EQ(colName, "data1");

    rstSet->GetColumnName(2, colName);
    EXPECT_EQ(colName, "data2");

    rstSet->GetColumnName(3, colName);
    EXPECT_EQ(colName, "data3");

    rstSet->GetColumnName(4, colName);
    EXPECT_EQ(colName, "data4");

    std::string valueStr = "";
    rstSet->GetString(0, valueStr);
    EXPECT_EQ(valueStr, "2");

    rstSet->GetString(1, valueStr);
    EXPECT_EQ(valueStr, "2");

    int64_t valuelg = 0;
    rstSet->GetLong(2, valuelg);
    EXPECT_EQ(valuelg, -5);

    double valueDb = 0.0;
    rstSet->GetDouble(3, valueDb);
    EXPECT_EQ(valueDb, 2.5);

    std::vector<uint8_t> blob;
    rstSet->GetBlob(4, blob);
    int sz = blob.size();
    EXPECT_EQ(sz, 0);

    rstSet->GoTo(1);
    rstSet->GetString(0, valueStr);
    EXPECT_EQ(valueStr, "3");

    rstSet->GetString(1, valueStr);
    EXPECT_EQ(valueStr, "hello world");

    rstSet->GetLong(2, valuelg);
    EXPECT_EQ(valuelg, 3);

    rstSet->GetDouble(3, valueDb);
    EXPECT_EQ(valueDb, 1.8);

    rstSet->GetBlob(4, blob);
    sz = blob.size();
    EXPECT_EQ(sz, 0);

    bool isNull = false;
    rstSet->IsColumnNull(4, isNull);
    EXPECT_EQ(isNull, true);

    ret = -1;
    ret = rstSet->GoToPreviousRow();
    EXPECT_EQ(ret, E_OK);
    ret = -1;
    ret = rstSet->GoToPreviousRow();
    EXPECT_EQ(ret, E_OK);

    rstSet->GetString(0, valueStr);
    EXPECT_EQ(valueStr, "1");

    rstSet->GetString(1, valueStr);
    EXPECT_EQ(valueStr, "hello");

    rstSet->GetLong(2, valuelg);
    EXPECT_EQ(valuelg, 10);

    rstSet->GetDouble(3, valueDb);
    EXPECT_EQ(valueDb, 1.0);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_002
 * @tc.desc: normal testcase of SqliteSharedResultSet for goToNextRow
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_002, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<ResultSet> rstSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    CheckResultSetAttribute(rstSet, -1, false, false, false);

    EXPECT_EQ(rstSet->GoToNextRow(), E_OK);
    CheckResultSetAttribute(rstSet, 0, true, true, false);

    EXPECT_EQ(rstSet->GoToNextRow(), E_OK);
    CheckResultSetAttribute(rstSet, 1, true, false, false);

    EXPECT_EQ(rstSet->GoToNextRow(), E_OK);
    CheckResultSetAttribute(rstSet, 2, true, false, false);
    bool isAtLastRow = false;
    rstSet->IsAtLastRow(isAtLastRow);
    EXPECT_EQ(isAtLastRow, true);
    
    EXPECT_EQ(rstSet->GoToNextRow(), E_ROW_OUT_RANGE);
    CheckResultSetAttribute(rstSet, 3, true, false, true);

    rstSet->Close();
    EXPECT_EQ(rstSet->IsClosed(), true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_003
 * @tc.desc: normal testcase of SqliteSharedResultSet for moveFirst
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_003, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<ResultSet> rstSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    int retF = rstSet->GoToFirstRow();
    EXPECT_EQ(retF, E_OK);
    int index = -1;
    rstSet->GetRowIndex(index);
    EXPECT_EQ(index, 0);
    bool isAtFirstRow = false;
    rstSet->IsAtFirstRow(isAtFirstRow);
    EXPECT_EQ(isAtFirstRow, true);
    bool isStd = false;
    rstSet->IsStarted(isStd);
    EXPECT_EQ(isStd, true);

    int retN = rstSet->GoToNextRow();
    EXPECT_EQ(retN, E_OK);
    rstSet->GetRowIndex(index);
    EXPECT_EQ(index, 1);
    isAtFirstRow = true;
    rstSet->IsAtFirstRow(isAtFirstRow);
    EXPECT_EQ(isAtFirstRow, false);
    isStd = false;
    rstSet->IsStarted(isStd);
    EXPECT_EQ(isStd, true);

    int retGf = rstSet->GoToFirstRow();
    EXPECT_EQ(retGf, E_OK);
    rstSet->GetRowIndex(index);
    EXPECT_EQ(index, 0);
    isAtFirstRow = false;
    rstSet->IsAtFirstRow(isAtFirstRow);
    EXPECT_EQ(isAtFirstRow, true);
    isStd = false;
    rstSet->IsStarted(isStd);
    EXPECT_EQ(isStd, true);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_004
 * @tc.desc: normal testcase of SqliteSharedResultSet for getInt
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_004, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<ResultSet> rstSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    int64_t valueInt = 0;
    int ret = rstSet->GetLong(0, valueInt);
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    int retF = rstSet->GoToFirstRow();
    EXPECT_EQ(retF, E_OK);
    rstSet->GetLong(0, valueInt);
    EXPECT_EQ(valueInt, 1);
    rstSet->GetLong(2, valueInt);
    EXPECT_EQ(valueInt, 10);
    rstSet->GetLong(3, valueInt);
    EXPECT_EQ(valueInt, 1);

    int retN = rstSet->GoToNextRow();
    EXPECT_EQ(retN, E_OK);
    rstSet->GetLong(0, valueInt);
    EXPECT_EQ(valueInt, 2);
    valueInt = 0;
    rstSet->GetLong(0, valueInt);
    EXPECT_EQ(valueInt, 2);
    valueInt = 0;
    rstSet->GetLong(1, valueInt);
    EXPECT_EQ(valueInt, 2);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_005
 * @tc.desc: normal testcase of SqliteSharedResultSet for getString
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */

HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_005, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<ResultSet> rstSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    std::string valueStr = "";
    int ret1 = rstSet->GetString(0, valueStr);
    EXPECT_EQ(ret1, E_ROW_OUT_RANGE);

    int retF = rstSet->GoToFirstRow();
    EXPECT_EQ(retF, E_OK);
    valueStr = "";
    rstSet->GetString(1, valueStr);
    EXPECT_EQ(valueStr, "hello");
    rstSet->GetString(2, valueStr);
    EXPECT_EQ(valueStr, "10");
    rstSet->GetString(3, valueStr);
    EXPECT_EQ(valueStr, "1");

    int ret2 = rstSet->GetString(4, valueStr);
    EXPECT_EQ(ret2, E_OK);

    valueStr = "";
    int colCnt = 0;
    rstSet->GetColumnCount(colCnt);
    int ret3 = rstSet->GetString(colCnt, valueStr);
    EXPECT_EQ(ret3, E_COLUMN_OUT_RANGE);

    int retN = rstSet->GoToNextRow();
    EXPECT_EQ(retN, E_OK);
    rstSet->GetString(0, valueStr);
    EXPECT_EQ(valueStr, "2");
    valueStr = "";
    rstSet->GetString(1, valueStr);
    EXPECT_EQ(valueStr, "2");
    rstSet->GetString(2, valueStr);
    EXPECT_EQ(valueStr, "-5");
    rstSet->GetString(3, valueStr);
    EXPECT_EQ(valueStr, "2.5");

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_006
 * @tc.desc: normal testcase of SqliteSharedResultSet for getDouble
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_006, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<ResultSet> rstSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    double valueDb = 0.0;
    int ret = rstSet->GetDouble(0, valueDb);
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    int retF = rstSet->GoToFirstRow();
    EXPECT_EQ(retF, E_OK);
    rstSet->GetDouble(0, valueDb);
    EXPECT_EQ(valueDb, 1.0);
    std::string valueStr = "";
    rstSet->GetString(1, valueStr);
    EXPECT_EQ(valueStr, "hello");
    rstSet->GetDouble(2, valueDb);
    EXPECT_EQ(valueDb, 10.0);
    rstSet->GetDouble(3, valueDb);
    EXPECT_EQ(valueDb, 1.0);

    int colCnt = 0;
    rstSet->GetColumnCount(colCnt);
    int ret1 = rstSet->GetDouble(colCnt, valueDb);
    EXPECT_EQ(ret1, E_COLUMN_OUT_RANGE);

    int retN = rstSet->GoToNextRow();
    EXPECT_EQ(retN, E_OK);
    rstSet->GetDouble(0, valueDb);
    EXPECT_EQ(valueDb, 2.0);
    valueDb = 0.0;
    rstSet->GetDouble(1, valueDb);
    EXPECT_EQ(valueDb, 2.0);

    rstSet->GetDouble(2, valueDb);
    EXPECT_EQ(valueDb, -5.0);
    rstSet->GetDouble(3, valueDb);
    EXPECT_EQ(valueDb, 2.5);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_007
 * @tc.desc: normal testcase of SqliteSharedResultSet for getBlob
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_007, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<ResultSet> rstSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    int retF = rstSet->GoToFirstRow();
    EXPECT_EQ(retF, E_OK);

    std::vector<uint8_t> blobVec;
    rstSet->GetBlob(4, blobVec);
    EXPECT_EQ(blobVec[0], 66);

    int retN = rstSet->GoToNextRow();
    EXPECT_EQ(retN, E_OK);
    blobVec.clear();
    rstSet->GetBlob(4, blobVec);
    int blobSz = blobVec.size();
    EXPECT_EQ(blobSz, 0);

    int retN1 = rstSet->GoToNextRow();
    EXPECT_EQ(retN1, E_OK);
    blobVec.clear();
    rstSet->GetBlob(4, blobVec);
    EXPECT_EQ(blobSz, 0);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_008
 * @tc.desc: normal testcase of SqliteSharedResultSet for getColumnTypeForIndex
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */

HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_008, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<ResultSet> rstSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    ColumnType colType;
    int ret = rstSet->GetColumnType(0, colType);
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);
    int retF = rstSet->GoToFirstRow();
    EXPECT_EQ(retF, E_OK);

    rstSet->GetColumnType(0, colType);
    EXPECT_EQ(colType, ColumnType::TYPE_INTEGER);

    bool isColNull = true;
    rstSet->IsColumnNull(0, isColNull);
    EXPECT_EQ(isColNull, false);

    rstSet->GetColumnType(1, colType);
    EXPECT_EQ(colType, ColumnType::TYPE_STRING);

    isColNull = true;
    rstSet->IsColumnNull(0, isColNull);
    EXPECT_EQ(isColNull, false);

    rstSet->GetColumnType(2, colType);
    EXPECT_EQ(colType, ColumnType::TYPE_INTEGER);
    rstSet->GetColumnType(3, colType);
    EXPECT_EQ(colType, ColumnType::TYPE_FLOAT);
    rstSet->GetColumnType(4, colType);
    EXPECT_EQ(colType, ColumnType::TYPE_BLOB);

    int colCnt = 0;
    rstSet->GetColumnCount(colCnt);
    int ret1 = rstSet->GetColumnType(colCnt, colType);
    EXPECT_EQ(ret1, E_COLUMN_OUT_RANGE);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_009
 * @tc.desc:  normal testcase of SqliteSharedResultSet for getColumnIndexForName
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_009, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<ResultSet> rstSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    int colIndex = 0;
    rstSet->GetColumnIndex("data1", colIndex);
    EXPECT_EQ(colIndex, 1);

    rstSet->GetColumnIndex("data2", colIndex);
    EXPECT_EQ(colIndex, 2);

    rstSet->GetColumnIndex("data3", colIndex);
    EXPECT_EQ(colIndex, 3);

    rstSet->GetColumnIndex("data4", colIndex);
    EXPECT_EQ(colIndex, 4);

    rstSet->GetColumnIndex("datax", colIndex);
    EXPECT_EQ(colIndex, -1);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_010
 * @tc.desc:  normal testcase of SqliteSharedResultSet for getColumnNameForIndex
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_010, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<ResultSet> rstSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    std::vector<std::string> allColNamesVec;
    rstSet->GetAllColumnNames(allColNamesVec);

    std::string colName = "";
    rstSet->GetColumnName(1, colName);
    EXPECT_EQ(colName, "data1");
    EXPECT_EQ(allColNamesVec[1], colName);

    rstSet->GetColumnName(2, colName);
    EXPECT_EQ(colName, "data2");
    EXPECT_EQ(allColNamesVec[2], colName);

    rstSet->GetColumnName(3, colName);
    EXPECT_EQ(colName, "data3");
    rstSet->GetColumnName(4, colName);
    EXPECT_EQ(colName, "data4");

    int colCnt = 0;
    rstSet->GetColumnCount(colCnt);
    int ret = rstSet->GetColumnName(colCnt, colName);
    EXPECT_EQ(ret, E_COLUMN_OUT_RANGE);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_011
 * @tc.desc:  normal testcase of SqliteSharedResultSet
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_011, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<ResultSet> rstSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    int retF = rstSet->GoToFirstRow();
    EXPECT_EQ(retF, E_OK);

    bool isAtFrtRow = false;
    rstSet->IsAtFirstRow(isAtFrtRow);
    EXPECT_EQ(isAtFrtRow, true);

    bool isStarted = false;
    rstSet->IsStarted(isStarted);
    EXPECT_EQ(isStarted, true);

    int64_t valueInt = 0;
    rstSet->GetLong(2, valueInt);
    EXPECT_EQ(valueInt, 10);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_012
 * @tc.desc: normal testcase of SqliteSharedResultSet for getLong
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_012, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<ResultSet> rstSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    int64_t valueInt = 0;
    int ret = rstSet->GetLong(0, valueInt);
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    int retF = rstSet->GoToFirstRow();
    EXPECT_EQ(retF, E_OK);
    rstSet->GetLong(0, valueInt);
    EXPECT_EQ(valueInt, 1.0);
    std::string  valueStr = "";
    rstSet->GetString(1, valueStr);
    EXPECT_EQ(valueStr, "hello");
    rstSet->GetLong(2, valueInt);
    EXPECT_EQ(valueInt, 10.0);
    rstSet->GetLong(3, valueInt);
    EXPECT_EQ(valueInt, 1.0);

    int colCnt = 0;
    rstSet->GetColumnCount(colCnt);
    int ret1 = rstSet->GetLong(colCnt, valueInt);
    EXPECT_EQ(ret1, E_COLUMN_OUT_RANGE);

    int retN = rstSet->GoToNextRow();
    EXPECT_EQ(retN, E_OK);
    rstSet->GetLong(0, valueInt);
    EXPECT_EQ(valueInt, 2.0);
    valueInt = 0;
    rstSet->GetLong(1, valueInt);
    EXPECT_EQ(valueInt, 2.0);
    rstSet->GetLong(2, valueInt);
    EXPECT_EQ(valueInt, -5.0);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_013
 * @tc.desc: normal testcase of SqliteSharedResultSet for fillBlock
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_013, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<ResultSet> rstSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    SqliteSharedResultSet *pSqlSharedRstSet = static_cast<SqliteSharedResultSet *>(rstSet.get());
    bool isBk = pSqlSharedRstSet->HasBlock();
    EXPECT_EQ(isBk, true);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}
/* *
 * @tc.name: Sqlite_Shared_Result_Set_014
 * @tc.desc: normal testcase of SqliteSharedResultSet for getBlock
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_014, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<ResultSet> rstSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    SqliteSharedResultSet *pSqlSharedRstSet = static_cast<SqliteSharedResultSet *>(rstSet.get());
    bool isBk = pSqlSharedRstSet->HasBlock();
    EXPECT_EQ(isBk, true);

    int retF = rstSet->GoToFirstRow();
    EXPECT_EQ(retF, E_OK);
    auto pBk = pSqlSharedRstSet->GetBlock();
    EXPECT_NE(pBk, nullptr);

    std::string path = RdbSqliteSharedResultSetTest::store->GetPath();
    std::string path1 = pBk->Name();

    EXPECT_EQ(path,  "/data/test/shared_test.db");
    EXPECT_EQ(path1, "/data/test/shared_test.db");

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}
/* *
 * @tc.name: Sqlite_Shared_Result_Set_015
 * @tc.desc: normal testcase of SqliteSharedResultSet for setBlock
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_015, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<ResultSet> rstSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    SqliteSharedResultSet *pSqlSharedRstSet = static_cast<SqliteSharedResultSet *>(rstSet.get());
    bool isBk = pSqlSharedRstSet->HasBlock();
    EXPECT_EQ(isBk, true);

    int retN = rstSet->GoToNextRow();
    EXPECT_EQ(retN, E_OK);

    std::string path = RdbSqliteSharedResultSetTest::store->GetPath();
    auto pBk = pSqlSharedRstSet->GetBlock();
    std::string path1 = pBk->Name();

    EXPECT_EQ(path,  "/data/test/shared_test.db");
    EXPECT_EQ(path1, "/data/test/shared_test.db");

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_016
 * @tc.desc: normal testcase of SqliteSharedResultSet for setFillWindowForwardOnly
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_016, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<ResultSet> rstSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    SqliteSharedResultSet *pSqlSharedRstSet = static_cast<SqliteSharedResultSet *>(rstSet.get());
    bool isBk = pSqlSharedRstSet->HasBlock();
    EXPECT_EQ(isBk, true);

    pSqlSharedRstSet->PickFillBlockStartPosition(0, 0);
    pSqlSharedRstSet->SetFillBlockForwardOnly(true);
    pSqlSharedRstSet->GoToFirstRow();

    auto pBk = pSqlSharedRstSet->GetBlock();
    EXPECT_NE(pBk, nullptr);
    std::string path = RdbSqliteSharedResultSetTest::store->GetPath();
    std::string path1 = pBk->Name();

    EXPECT_EQ(path,  "/data/test/shared_test.db");
    EXPECT_EQ(path1, "/data/test/shared_test.db");

    int rowCnt = 0;
    pSqlSharedRstSet->GetRowCount(rowCnt);
    int rowCntBk = pBk->GetRowNum();

    EXPECT_EQ(rowCnt, rowCntBk);

    rstSet->Close();
    bool isClosedFlag = rstSet->IsClosed();
    EXPECT_EQ(isClosedFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_017
 * @tc.desc: normal testcase of SqliteSharedResultSet for setExtensions and getExtensions
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_017, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<ResultSet> rstSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    int rowCnt = 0;
    rstSet->GetRowCount(rowCnt);
    EXPECT_EQ(rowCnt, 3);
    int ret = rstSet->GoToLastRow();
    EXPECT_EQ(ret, E_OK);
}


/* *
 * @tc.name: Sqlite_Shared_Result_Set_018
 * @tc.desc:  frequency testcase of SqliteSharedResultSet for getColumnIndexForName
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_018, TestSize.Level1)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    int columnIndex = 0;
    for (int i = 0; i < 100; i++) {
        resultSet->GetColumnIndex("datax", columnIndex);
        EXPECT_EQ(columnIndex, -1);

        resultSet->GetColumnIndex("data4", columnIndex);
        EXPECT_EQ(columnIndex, 4);

        resultSet->GetColumnIndex("data3", columnIndex);
        EXPECT_EQ(columnIndex, 3);

        resultSet->GetColumnIndex("data2", columnIndex);
        EXPECT_EQ(columnIndex, 2);

        resultSet->GetColumnIndex("data1", columnIndex);
        EXPECT_EQ(columnIndex, 1);
    }

    resultSet->Close();
    bool closeFlag = resultSet->IsClosed();
    EXPECT_EQ(closeFlag, true);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_019
 * @tc.desc: normal testcase of SqliteSharedResultSet for GetRow
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_019, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<AbsResultSet> resultSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(resultSet, nullptr);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());

    int iRet = E_ERROR;
    RowEntity rowEntity;
    iRet = resultSet->GetRow(rowEntity);
    EXPECT_EQ(E_OK, iRet);

    int idValue = rowEntity.Get("id");
    std::string data1Value = rowEntity.Get("data1");
    int data2Value = rowEntity.Get("data2");
    double data3Value = rowEntity.Get("data3");
    std::vector<uint8_t> data4Value = rowEntity.Get("data4");
    EXPECT_EQ(1, idValue);
    EXPECT_EQ("hello", data1Value);
    EXPECT_EQ(10, data2Value);
    EXPECT_EQ(1.0, data3Value);
    EXPECT_EQ(66, data4Value[0]);

    int idValueByIndex = rowEntity.Get(0);
    std::string data1ValueByIndex = rowEntity.Get(1);
    int data2ValueByIndex = rowEntity.Get(2);
    double data3ValueByIndex = rowEntity.Get(3);
    std::vector<uint8_t> data4ValueByIndex = rowEntity.Get(4);
    EXPECT_EQ(1, idValueByIndex);
    EXPECT_EQ("hello", data1ValueByIndex);
    EXPECT_EQ(10, data2ValueByIndex);
    EXPECT_EQ(1.0, data3ValueByIndex);
    EXPECT_EQ(66, data4ValueByIndex[0]);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_020
 * @tc.desc: normal testcase of SqliteSharedResultSet for GetRow
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_020, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<AbsResultSet> resultSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT data1, data2 FROM test", selectionArgs);
    EXPECT_NE(resultSet, nullptr);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());

    int iRet = E_ERROR;
    RowEntity rowEntity;
    iRet = resultSet->GetRow(rowEntity);
    EXPECT_EQ(E_OK, iRet);

    std::string data1Value = rowEntity.Get("data1");
    EXPECT_EQ("hello", data1Value);

    std::string data1ValueByIndex = rowEntity.Get(0);
    EXPECT_EQ("hello", data1ValueByIndex);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_021
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for PrepareStep, if len(qrySql) is less than 3
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_021, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<AbsResultSet> resultSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SE", selectionArgs);
    EXPECT_NE(resultSet, nullptr);

    std::vector<std::string> columnNames;
    int ret = resultSet->GetAllColumnNames(columnNames);
    EXPECT_EQ(E_NOT_SELECT, ret);
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_022
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for PrepareStep, if qrySql is invalid
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_022, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<AbsResultSet> resultSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT FROM", selectionArgs);
    EXPECT_NE(resultSet, nullptr);

    std::vector<std::string> columnNames;
    int ret = resultSet->GetAllColumnNames(columnNames);
    EXPECT_EQ(E_ERROR, ret);
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_023
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for GetAllColumnNames, if resultSet is closed
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_023, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<AbsResultSet> resultSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(resultSet, nullptr);

    resultSet->Close();

    std::vector<std::string> columnNames;
    int ret = resultSet->GetAllColumnNames(columnNames);
    EXPECT_EQ(E_ALREADY_CLOSED, ret);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_024
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for GetRowCount, if resultSet is closed
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_024, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<AbsResultSet> resultSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(resultSet, nullptr);

    resultSet->Close();

    int count = 0;
    int ret = resultSet->GetRowCount(count);
    EXPECT_EQ(E_ALREADY_CLOSED, ret);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_025
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for GoToRow, if position is less than 0
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_025, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<AbsResultSet> resultSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(resultSet, nullptr);

    int ret = resultSet->GoToRow(-10);
    EXPECT_EQ(E_ERROR, ret);
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_026
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for GetBlob, if position is less than 0
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_026, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<AbsResultSet> resultSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(resultSet, nullptr);

    resultSet->GoToFirstRow();

    std::vector<uint8_t> blob;
    int ret = resultSet->GetBlob(-10, blob);
    EXPECT_EQ(E_COLUMN_OUT_RANGE, ret);
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_027
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for GetAsset, if col is less than 0
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_027, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<AbsResultSet> resultSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(resultSet, nullptr);

    resultSet->GoToFirstRow();

    ValueObject::Asset value;
    int ret = resultSet->GetAsset(-10, value);
    EXPECT_EQ(E_COLUMN_OUT_RANGE, ret);
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_028
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for GetAssets, if col is less than 0
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_028, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<AbsResultSet> resultSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(resultSet, nullptr);

    resultSet->GoToFirstRow();

    ValueObject::Assets value;
    int ret = resultSet->GetAssets(-10, value);
    EXPECT_EQ(E_COLUMN_OUT_RANGE, ret);
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_029
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for GetSize, if columnIndex is less than 0
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_029, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<AbsResultSet> resultSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(resultSet, nullptr);

    resultSet->GoToFirstRow();

    size_t size;
    int ret = resultSet->GetSize(-10, size);
    EXPECT_EQ(E_COLUMN_OUT_RANGE, ret);
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_030
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for IsColumnNull, if columnIndex is less than 0
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_030, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<AbsResultSet> resultSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(resultSet, nullptr);

    resultSet->GoToFirstRow();

    bool isNUll;
    int ret = resultSet->IsColumnNull(-10, isNUll);
    EXPECT_EQ(E_COLUMN_OUT_RANGE, ret);
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_031
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for Close, if close resultSet twice
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_031, TestSize.Level2)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<AbsResultSet> resultSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(resultSet, nullptr);

    EXPECT_EQ(E_OK, resultSet->Close());
    EXPECT_EQ(true, resultSet->IsClosed());
    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GoToLastRow());

    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GoToPreviousRow());
    
    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GoToFirstRow());

    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GoToRow(1));

    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GoToPreviousRow());
    
    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GoToFirstRow());

    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GoToRow(1));

    bool isExpectResult = true;
    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->IsAtLastRow(isExpectResult));
    EXPECT_NE(false, isExpectResult);

    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->IsEnded(isExpectResult));
    EXPECT_NE(false, isExpectResult);

    int columnCount;
    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GetColumnCount(columnCount));

    std::string columnName;
    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GetColumnName(1, columnName));

    EXPECT_EQ(E_OK, resultSet->Close());
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_032
 * @tc.desc: Normal testcase of SqliteSharedResultSet for GetRow
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_032, TestSize.Level1)
{
    GenerateAssetsTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<AbsResultSet> resultSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(resultSet, nullptr);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());

    int iRet = E_ERROR;
    RowEntity rowEntity;
    iRet = resultSet->GetRow(rowEntity);
    EXPECT_EQ(E_OK, iRet);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_033
 * @tc.desc: Normal testcase of SqliteSharedResultSet for GoToNestRow when some rows are close to 2M in size
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_033, TestSize.Level1)
{
    constexpr int INSERT_NUM = 10;
    std::vector<ValuesBucket> vbs;
    vbs.reserve(10);
    ValuesBucket vb;
    for (int i = 0; i < INSERT_NUM; i++) {
        vb.PutInt("id", i);
        // this row must exclusive shared memory
        if (i == 4) {
            vb.PutString("data1", std::string(3 * 512 * 1024 + 5000, 'a'));
        }
        vb.PutString("data1", std::string(512 * 1024 - 2000, 'b'));
        vbs.push_back(std::move(vb));
    }
    int64_t insertNum = 0;
    EXPECT_EQ(E_OK, store->BatchInsert(insertNum, "test", vbs));
    EXPECT_EQ(insertNum, INSERT_NUM);
    std::vector<std::string> selectionArgs;
    std::shared_ptr<AbsResultSet> resultSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test ORDER BY id ASC", selectionArgs);
    ASSERT_NE(resultSet, nullptr);
    for (int i = 0; i < INSERT_NUM; i++) {
        ASSERT_EQ(E_OK, resultSet->GoToRow(i)) << "Current position:" << i;
        int position = -1;
        ASSERT_EQ(E_OK, resultSet->GetRowIndex(position)) << "Current position:" << i;
        EXPECT_EQ(position, i);
        int count = -1;
        ASSERT_EQ(E_OK, resultSet->GetRowCount(count)) << "Current position:" << i;
        EXPECT_EQ(count, INSERT_NUM) << "Current position:" << i;
        int columnIndex = 0;
        EXPECT_EQ(E_OK, resultSet->GetColumnIndex("id", columnIndex)) << "Current position:" << i;
        int id;
        EXPECT_EQ(E_OK, resultSet->GetInt(columnIndex, id)) << "Current position:" << i;
        EXPECT_EQ(id, i);

        ASSERT_EQ(E_OK, resultSet->GetColumnIndex("data1", columnIndex)) << "Current position:" << i;
        std::string value;
        EXPECT_EQ(E_OK, resultSet->GetString(columnIndex, value)) << "Current position:" << i;
        if (i == 4) {
            EXPECT_EQ(value.size(), 3 * 512 * 1024 + 5000) << "Current position:" << i;
        } else {
            EXPECT_EQ(value.size(), 512 * 1024 - 2000) << "Current position:" << i;
        }
    }
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_034
 * @tc.desc: Normal testcase of SqliteSharedResultSet for GoTo when moving back and forth
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_034, TestSize.Level1)
{
    constexpr int INSERT_NUM = 20;
    std::vector<ValuesBucket> vbs;
    vbs.reserve(10);
    ValuesBucket vb;
    for (int i = 0; i < INSERT_NUM; i++) {
        vb.PutInt("id", i);
        vb.PutString("data1", std::string(i * 100 * 1024, 'a'));
        vbs.push_back(std::move(vb));
    }
    int64_t insertNum = 0;
    EXPECT_EQ(E_OK, store->BatchInsert(insertNum, "test", vbs));
    EXPECT_EQ(insertNum, INSERT_NUM);
    std::vector<std::string> selectionArgs;
    std::shared_ptr<AbsResultSet> resultSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test ORDER BY id ASC", selectionArgs);
    ASSERT_NE(resultSet, nullptr);
    int position = -1;
    int count = -1;
    int columnIndex = 0;
    int id;
    int target = INSERT_NUM / 2;
    std::string value;
    ASSERT_EQ(E_OK, resultSet->GoToRow(target));
    ASSERT_EQ(E_OK, resultSet->GetRowIndex(position));
    ASSERT_EQ(target, position);
    for (int i = 1; i < INSERT_NUM; i++) {
        target = INSERT_NUM - position - i & 0x1;
        ASSERT_EQ(E_OK, resultSet->GoToRow(target)) << "Current position:" << position << ", go to:" << target;
        ASSERT_EQ(E_OK, resultSet->GetRowIndex(position));
        ASSERT_EQ(target, position);
        ASSERT_EQ(E_OK, resultSet->GetRowCount(count)) << "Current position:" << position;
        EXPECT_EQ(count, INSERT_NUM) << "Current position:" << position;
        EXPECT_EQ(E_OK, resultSet->GetColumnIndex("id", columnIndex)) << "Current position:" << position;
        EXPECT_EQ(E_OK, resultSet->GetInt(columnIndex, id)) << "Current position:" << position;
        EXPECT_EQ(id, position);
        ASSERT_EQ(E_OK, resultSet->GetColumnIndex("data1", columnIndex)) << "Current position:" << i;
        EXPECT_EQ(E_OK, resultSet->GetString(columnIndex, value)) << "Current position:" << i;
        EXPECT_EQ(value.size(), position * 100 * 1024) << "Current position:" << i;
    }
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_035
 * @tc.desc: normal testcase of SqliteSharedResultSet for qrySql is WITH
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_035, TestSize.Level1)
{
    GenerateDefaultTable();
    std::vector<std::string> selectionArgs;
    std::shared_ptr<AbsResultSet> resultSet =RdbSqliteSharedResultSetTest::store->QuerySql(
        "WITH tem AS ( SELECT * FROM test) SELECT * FROM tem");
    EXPECT_NE(resultSet, nullptr);

    std::vector<std::string> columnNames;
    int ret = resultSet->GetAllColumnNames(columnNames);
    EXPECT_EQ(E_OK, ret);

    std::string colName = "";
    resultSet->GetColumnName(1, colName);
    EXPECT_EQ(colName, "data1");
    EXPECT_EQ(columnNames[1], colName);

    resultSet->GetColumnName(2, colName);
    EXPECT_EQ(colName, "data2");
    EXPECT_EQ(columnNames[2], colName);

    resultSet->GetColumnName(3, colName);
    EXPECT_EQ(colName, "data3");
    resultSet->GetColumnName(4, colName);
    EXPECT_EQ(colName, "data4");

    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_036
 * @tc.desc: normal testcase of SqliteSharedResultSet for moveFirst
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqliteSharedResultSetTest, Sqlite_Shared_Result_Set_036, TestSize.Level1)
{
    std::vector<std::string> selectionArgs;
    std::shared_ptr<ResultSet> rstSet =
        RdbSqliteSharedResultSetTest::store->QuerySql("SELECT * FROM test", selectionArgs);
    EXPECT_NE(rstSet, nullptr);

    int ret = rstSet->GoToFirstRow();
    EXPECT_EQ(ret, E_ERROR);
    ret = rstSet->GoToLastRow();
    EXPECT_EQ(ret, E_ERROR);
}
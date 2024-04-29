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
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "sqlite_sql_builder.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbStoreUpdateTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    static void ExpectValue(const std::shared_ptr<OHOS::NativeRdb::ResultSet> &resultSet,
        const RowData &expect);
    void SetUp();
    void TearDown();

    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;
};

const std::string RdbStoreUpdateTest::DATABASE_NAME = RDB_TEST_PATH + "update_test.db";
std::shared_ptr<RdbStore> RdbStoreUpdateTest::store = nullptr;

class UpdateTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

const std::string UpdateTestOpenCallback::CREATE_TABLE_TEST = std::string("CREATE TABLE IF NOT EXISTS test ")
                                                              + std::string("(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                            "name TEXT UNIQUE, age INTEGER, salary "
                                                                            "REAL, blobType BLOB)");

int UpdateTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int UpdateTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbStoreUpdateTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
    RdbStoreConfig config(RdbStoreUpdateTest::DATABASE_NAME);
    UpdateTestOpenCallback helper;
    RdbStoreUpdateTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbStoreUpdateTest::store, nullptr);
}

void RdbStoreUpdateTest::TearDownTestCase(void)
{
    store = nullptr;
    RdbHelper::DeleteRdbStore(RdbStoreUpdateTest::DATABASE_NAME);
}

void RdbStoreUpdateTest::SetUp(void)
{
    store->ExecuteSql("DELETE FROM test");
}

void RdbStoreUpdateTest::TearDown(void)
{
    RdbHelper::ClearCache();
}

/**
 * @tc.name: RdbStore_Update_001
 * @tc.desc: test RdbStore update, select id and update one row
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreUpdateTest, RdbStore_Update_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreUpdateTest::store;

    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 2);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store->Update(changedRows, "test", values, "id = ?",
                std::vector<std::string>{ "1" });
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{2, "lisi", 20, 200.5, std::vector<uint8_t>{ 4, 5, 6 }});

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Update_002
 * @tc.desc: test RdbStore update, no select and update all rows
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreUpdateTest, RdbStore_Update_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreUpdateTest::store;

    int64_t id;
    ValuesBucket values;
    int changedRows;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    values.Clear();
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store->Update(changedRows, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, changedRows);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{1, "zhangsan", 18, 300.5, std::vector<uint8_t>{ 4, 5, 6 }});

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{2, "lisi", 19, 300.5, std::vector<uint8_t>{ 4, 5, 6 }});

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Update_003
 * @tc.desc: test RdbStore update
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreUpdateTest, RdbStore_Update_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreUpdateTest::store;

    int changedRows;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Update(changedRows, "", values, "", std::vector<std::string>()); // empty table name
    EXPECT_EQ(ret, E_EMPTY_TABLE_NAME);

    ret = store->Update(changedRows, "wrongTable", values, "", std::vector<std::string>()); // no such table
    EXPECT_EQ(ret, E_SQLITE_ERROR);
}

/**
 * @tc.name: RdbStore_Update_004
 * @tc.desc: test RdbStore insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreUpdateTest, RdbStore_Update_004, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreUpdateTest::store;

    int changedRows;
    ValuesBucket emptyBucket;
    int ret = store->Update(changedRows, "test", emptyBucket);
    EXPECT_EQ(ret, E_EMPTY_VALUES_BUCKET);

    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("wrongColumn", 100.5); // no such column
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Update(changedRows, "test", values, "", std::vector<std::string>());
    EXPECT_EQ(ret, E_SQLITE_ERROR);
}

/**
 * @tc.name: RdbStore_Update_005
 * @tc.desc: test RdbStore insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreUpdateTest, RdbStore_Update_005, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreUpdateTest::store;

    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Update(changedRows, "test", values, "id = ?",
        std::vector<std::string>{ "1" });
    EXPECT_EQ(ret, E_EMPTY_VALUES_BUCKET);
}

/**
 * @tc.name: RdbStore_Update_006
 * @tc.desc: test RdbStore insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreUpdateTest, RdbStore_Update_006, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreUpdateTest::store;

    ValuesBucket values;
    int changedRows;
    int64_t id;

    values.Clear();
    values.PutString("id", "2");
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Update(changedRows, "test", values, "id = ?",
        std::vector<std::string>{ "1" });
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{2, "lisi", 20, 200.5, std::vector<uint8_t>{ 4, 5, 6 }});

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_UpdateWithConflictResolution_001
 * @tc.desc: test RdbStore UpdateWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreUpdateTest, RdbStore_UpdateWithConflictResolution_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreUpdateTest::store;

    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    // update lisi age=19 to wangjing age=20
    values.PutInt("id", 3);
    values.PutString("name", std::string("wangjing"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store->UpdateWithConflictResolution(changedRows, "test", values, "age = 19");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{1, "zhangsan", 18, 100.5, std::vector<uint8_t>{ 1, 2, 3 }});

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{3, "wangjing", 20, 300.5, std::vector<uint8_t>{ 7, 8, 9 }});

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_UpdateWithConflictResolution_002
 * @tc.desc: test RdbStore UpdateWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreUpdateTest, RdbStore_UpdateWithConflictResolution_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreUpdateTest::store;

    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    // update lisi age=19 to zhangsan age=20
    values.PutInt("id", 3);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store->UpdateWithConflictResolution(changedRows, "test", values, "age = ?",
        std::vector<std::string>{ "19" }, ConflictResolution::ON_CONFLICT_NONE);
    EXPECT_EQ(ret, E_SQLITE_CONSTRAINT);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{1, "zhangsan", 18, 100.5, std::vector<uint8_t>{ 1, 2, 3 }});

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{2, "lisi", 19, 200.5, std::vector<uint8_t>{ 4, 5, 6 }});

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_UpdateWithConflictResolution_003
 * @tc.desc: test RdbStore UpdateWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreUpdateTest, RdbStore_UpdateWithConflictResolution_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreUpdateTest::store;

    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    // update lisi age=19 to wangjing age=20
    values.PutInt("id", 3);
    values.PutString("name", std::string("wangjing"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store->UpdateWithConflictResolution(changedRows, "test", values, "age = ?",
        std::vector<std::string>{ "19" }, ConflictResolution::ON_CONFLICT_ROLLBACK);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{1, "zhangsan", 18, 100.5, std::vector<uint8_t>{ 1, 2, 3 }});

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{3, "wangjing", 20, 300.5, std::vector<uint8_t>{ 7, 8, 9 }});

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_UpdateWithConflictResolution_004
 * @tc.desc: test RdbStore UpdateWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreUpdateTest, RdbStore_UpdateWithConflictResolution_004, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreUpdateTest::store;

    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    // update lisi age=19 to zhangsan age=20
    values.PutInt("id", 3);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store->UpdateWithConflictResolution(changedRows, "test", values, "age = ?",
        std::vector<std::string>{ "19" }, ConflictResolution::ON_CONFLICT_ROLLBACK);
    EXPECT_EQ(ret, E_SQLITE_CONSTRAINT);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{1, "zhangsan", 18, 100.5, std::vector<uint8_t>{ 1, 2, 3 }});

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{2, "lisi", 19, 200.5, std::vector<uint8_t>{ 4, 5, 6 }});

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_UpdateWithConflictResolution_005
 * @tc.desc: test RdbStore UpdateWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreUpdateTest, RdbStore_UpdateWithConflictResolution_005, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreUpdateTest::store;

    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    // update lisi age=19 to wangjing age=20
    values.PutInt("id", 3);
    values.PutString("name", std::string("wangjing"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store->UpdateWithConflictResolution(changedRows, "test", values, "age = ?",
        std::vector<std::string>{ "19" }, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{1, "zhangsan", 18, 100.5, std::vector<uint8_t>{ 1, 2, 3 }});

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{3, "wangjing", 20, 300.5, std::vector<uint8_t>{ 7, 8, 9 }});

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_UpdateWithConflictResolution_006
 * @tc.desc: test RdbStore UpdateWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreUpdateTest, RdbStore_UpdateWithConflictResolution_006, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbStoreUpdateTest::store;

    ValuesBucket values;
    int changedRows;
    int64_t id;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    // update lisi age=19 to zhangsan age=20
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    ret = store->UpdateWithConflictResolution(changedRows, "test", values, "age = ?",
        std::vector<std::string>{ "19" }, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(changedRows, 1);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);

    RdbStoreUpdateTest::ExpectValue(resultSet, RowData{2, "zhangsan", 20, 300.5, std::vector<uint8_t>{ 4, 5, 6 }});

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_UpdateSqlBuilder_001
 * @tc.desc: test RdbStore UpdateSqlBuilder
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreUpdateTest, RdbStore_UpdateSqlBuilder_001, TestSize.Level1)
{
    ValuesBucket values;
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);

    std::vector<ValueObject> bindArgs;
    std::string updateSql = SqliteSqlBuilder::BuildUpdateString(values, "test", std::vector<std::string>{ "19" },
        "", "age = ?", "", "", INT_MIN, INT_MIN, bindArgs, ConflictResolution::ON_CONFLICT_NONE);
    EXPECT_EQ(updateSql, "UPDATE test SET age=?,name=?,salary=? WHERE age = ?");

    updateSql = SqliteSqlBuilder::BuildUpdateString(values, "test", std::vector<std::string>{},
        "", "", "", "", INT_MIN, INT_MIN, bindArgs, ConflictResolution::ON_CONFLICT_NONE);
    EXPECT_EQ(updateSql, "UPDATE test SET age=?,name=?,salary=?");
}

void RdbStoreUpdateTest::ExpectValue(const std::shared_ptr<OHOS::NativeRdb::ResultSet> &resultSet,
    const RowData &expect)
{
    EXPECT_NE(nullptr, resultSet);
    int columnIndex;
    int intVal;
    int ret;

    if (expect.id != -1) {
        ret = resultSet->GetColumnIndex("id", columnIndex);
        EXPECT_EQ(ret, E_OK);
        ret = resultSet->GetInt(columnIndex, intVal);
        EXPECT_EQ(ret, E_OK);
        EXPECT_EQ(expect.id, intVal);
    }
    if (expect.name != "") {
        std::string strVal;
        ret = resultSet->GetColumnIndex("name", columnIndex);
        EXPECT_EQ(ret, E_OK);
        ret = resultSet->GetString(columnIndex, strVal);
        EXPECT_EQ(ret, E_OK);
        EXPECT_EQ(expect.name, strVal);
    }
    if (expect.age != -1) {
        ret = resultSet->GetColumnIndex("age", columnIndex);
        EXPECT_EQ(ret, E_OK);
        ret = resultSet->GetInt(columnIndex, intVal);
        EXPECT_EQ(ret, E_OK);
        EXPECT_EQ(expect.age, intVal);
    }
    if (expect.salary != -1) {
        double dVal;
        ret = resultSet->GetColumnIndex("salary", columnIndex);
        EXPECT_EQ(ret, E_OK);
        ret = resultSet->GetDouble(columnIndex, dVal);
        EXPECT_EQ(ret, E_OK);
        EXPECT_EQ(expect.salary, dVal);
    }
    if (expect.blobType.size() != 0) {
        std::vector<uint8_t> blob;
        ret = resultSet->GetColumnIndex("blobType", columnIndex);
        EXPECT_EQ(ret, E_OK);
        ret = resultSet->GetBlob(columnIndex, blob);
        EXPECT_EQ(ret, E_OK);
        EXPECT_EQ(expect.blobType.size(), static_cast<int>(blob.size()));
        for (int i = 0; i < expect.blobType.size(); i++) {
            EXPECT_EQ(expect.blobType[i], blob[i]);
        }
    }
}
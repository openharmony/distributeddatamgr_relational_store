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

using namespace testing::ext;
using namespace OHOS::NativeRdb;
namespace OHOS::RdbStoreInsertTest {
struct RdbTestParam {
    std::shared_ptr<RdbStore> store;
    operator std::shared_ptr<RdbStore>()
    {
        return store;
    }
};
static RdbTestParam g_store;
static RdbTestParam g_memDb;

class RdbStoreInsertTest : public testing::TestWithParam<RdbTestParam *> {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static void CheckResultSet(std::shared_ptr<RdbStore> &store);
    static void CheckAge(std::shared_ptr<ResultSet> &resultSet);
    static void CheckSalary(std::shared_ptr<ResultSet> &resultSet);
    static void CheckBlob(std::shared_ptr<ResultSet> &resultSet);
    std::shared_ptr<RdbStore> store_;

    static const std::string DATABASE_NAME;
};

const std::string RdbStoreInsertTest::DATABASE_NAME = RDB_TEST_PATH + "insert_test.db";

class InsertTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

const std::string InsertTestOpenCallback::CREATE_TABLE_TEST =
    std::string("CREATE TABLE IF NOT EXISTS test ") + std::string("(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                  "name TEXT NOT NULL, age INTEGER, salary "
                                                                  "REAL, blobType BLOB)");

int InsertTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int InsertTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbStoreInsertTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
    RdbStoreConfig config(RdbStoreInsertTest::DATABASE_NAME);
    InsertTestOpenCallback helper;
    g_store.store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(g_store.store, nullptr);

    config.SetStorageMode(StorageMode::MODE_MEMORY);
    g_memDb.store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(g_memDb.store, nullptr);
}

void RdbStoreInsertTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(RdbStoreInsertTest::DATABASE_NAME);
    RdbStoreConfig config(RdbStoreInsertTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    RdbHelper::DeleteRdbStore(config);
}

void RdbStoreInsertTest::SetUp(void)
{
    store_ = *GetParam();
    store_->ExecuteSql("DELETE FROM test");
}

void RdbStoreInsertTest::TearDown(void)
{
}

/**
 * @tc.name: RdbStore_Insert_001
 * @tc.desc: test RdbStore insert
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_Insert_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> store = *GetParam();

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 2);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    values.Clear();
    values.PutInt("id", 3);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 20L);
    values.PutDouble("salary", 100.5f);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    RdbStoreInsertTest::CheckResultSet(store);
}

void RdbStoreInsertTest::CheckResultSet(std::shared_ptr<RdbStore> &store)
{
    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test WHERE name = ?", std::vector<std::string>{ "zhangsan" });
    EXPECT_NE(resultSet, nullptr);

    int columnIndex;
    int intVal;
    std::string strVal;
    ColumnType columnType;
    int position;
    int ret = resultSet->GetRowIndex(position);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(position, -1);

    ret = resultSet->GetColumnType(0, columnType);
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);

    ret = resultSet->GetColumnIndex("id", columnIndex);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnIndex, 0);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_INTEGER);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, intVal);

    ret = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_STRING);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ("zhangsan", strVal);

    RdbStoreInsertTest::CheckAge(resultSet);
    RdbStoreInsertTest::CheckSalary(resultSet);
    RdbStoreInsertTest::CheckBlob(resultSet);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

void RdbStoreInsertTest::CheckAge(std::shared_ptr<ResultSet> &resultSet)
{
    int columnIndex;
    int intVal;
    ColumnType columnType;
    int ret = resultSet->GetColumnIndex("age", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_INTEGER);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(18, intVal);
}

void RdbStoreInsertTest::CheckSalary(std::shared_ptr<ResultSet> &resultSet)
{
    int columnIndex;
    double dVal;
    ColumnType columnType;
    int ret = resultSet->GetColumnIndex("salary", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_FLOAT);
    ret = resultSet->GetDouble(columnIndex, dVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(100.5, dVal);
}

void RdbStoreInsertTest::CheckBlob(std::shared_ptr<ResultSet> &resultSet)
{
    int columnIndex;
    std::vector<uint8_t> blob;
    ColumnType columnType;
    int ret = resultSet->GetColumnIndex("blobType", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_BLOB);
    ret = resultSet->GetBlob(columnIndex, blob);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, static_cast<int>(blob.size()));
    EXPECT_EQ(1, blob[0]);
    EXPECT_EQ(2, blob[1]);
    EXPECT_EQ(3, blob[2]);
}

/**
 * @tc.name: RdbStore_Insert_002
 * @tc.desc: test RdbStore insert
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_Insert_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> store = *GetParam();

    int64_t id;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "", values); // empty table name
    EXPECT_EQ(ret, E_EMPTY_TABLE_NAME);

    ret = store->Insert(id, "wrongTable", values); // no such table
    EXPECT_EQ(ret, E_SQLITE_ERROR);
}

/**
 * @tc.name: RdbStore_Insert_003
 * @tc.desc: test RdbStore insert
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_Insert_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> store = *GetParam();

    int64_t id;
    ValuesBucket emptyBucket;
    int ret = store->Insert(id, "test", emptyBucket);
    EXPECT_EQ(ret, E_EMPTY_VALUES_BUCKET);

    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("wrongColumn", 100.5); // no such column
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_SQLITE_ERROR);
}

/**
 * @tc.name: RdbStore_Replace_001
 * @tc.desc: test RdbStore replace
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_Replace_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> store = *GetParam();

    int64_t id;
    ValuesBucket values;

    int ret = store->Replace(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);

    int columnIndex;
    int intVal;
    std::string strVal;

    ret = resultSet->GetColumnIndex("id", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, intVal);

    ret = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ("zhangsan", strVal);

    ret = resultSet->GetColumnIndex("age", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(18, intVal);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Replace_002
 * @tc.desc: test RdbStore replace
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_Replace_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> store = *GetParam();

    int64_t id;
    ValuesBucket values;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Replace(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);

    int columnIndex;
    int intVal;
    std::string strVal;

    ret = resultSet->GetColumnIndex("id", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, intVal);

    ret = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ("zhangsan", strVal);

    ret = resultSet->GetColumnIndex("age", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(18, intVal);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Replace_003
 * @tc.desc: test RdbStore Replace
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_Replace_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> store = *GetParam();

    int64_t id;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Replace(id, "", values); // empty table name
    EXPECT_EQ(ret, E_EMPTY_TABLE_NAME);

    ret = store->Replace(id, "wrongTable", values); // no such table
    EXPECT_EQ(ret, E_SQLITE_ERROR);
}

/**
 * @tc.name: RdbStore_Replace_004
 * @tc.desc: test RdbStore Replace
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_Replace_004, TestSize.Level1)
{
    std::shared_ptr<RdbStore> store = *GetParam();

    int64_t id;
    ValuesBucket emptyBucket;
    int ret = store->Replace(id, "test", emptyBucket);
    EXPECT_EQ(ret, E_EMPTY_VALUES_BUCKET);

    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("wrongColumn", 100.5); // no such column
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Replace(id, "test", values);
    EXPECT_EQ(ret, E_SQLITE_ERROR);
}

/**
 * @tc.name: RdbStore_Replace_005
 * @tc.desc: test RdbStore replace
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_Replace_005, TestSize.Level1)
{
    std::shared_ptr<RdbStore> store = *GetParam();

    int64_t id;

    int ret = store->Replace(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);

    int columnIndex;
    double dVal;
    std::vector<uint8_t> blob;

    ret = resultSet->GetColumnIndex("salary", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetDouble(columnIndex, dVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(100.5, dVal);

    ret = resultSet->GetColumnIndex("blobType", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetBlob(columnIndex, blob);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, static_cast<int>(blob.size()));
    EXPECT_EQ(1, blob[0]);
    EXPECT_EQ(2, blob[1]);
    EXPECT_EQ(3, blob[2]);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Replace_006
 * @tc.desc: test RdbStore replace
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_Replace_006, TestSize.Level1)
{
    std::shared_ptr<RdbStore> store = *GetParam();

    int64_t id;
    ValuesBucket values;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Replace(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);

    int columnIndex;
    double dVal;
    std::vector<uint8_t> blob;

    ret = resultSet->GetColumnIndex("salary", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetDouble(columnIndex, dVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(200.5, dVal);

    ret = resultSet->GetColumnIndex("blobType", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetBlob(columnIndex, blob);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, static_cast<int>(blob.size()));
    EXPECT_EQ(1, blob[0]);
    EXPECT_EQ(2, blob[1]);
    EXPECT_EQ(3, blob[2]);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_InsertWithConflictResolution_001_002
 * @tc.desc: test RdbStore InsertWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_InsertWithConflictResolution_001_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> store = *GetParam();

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });

    // default is ConflictResolution::ON_CONFLICT_NONE
    int ret = store->InsertWithConflictResolution(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->InsertWithConflictResolution(id, "test", values);
    EXPECT_EQ(ret, E_SQLITE_CONSTRAINT);
}

/**
 * @tc.name: RdbStore_InsertWithConflictResolution_003_004
 * @tc.desc: test RdbStore InsertWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_InsertWithConflictResolution_003_004, TestSize.Level1)
{
    std::shared_ptr<RdbStore> store = *GetParam();

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->InsertWithConflictResolution(id, "test", values, ConflictResolution::ON_CONFLICT_ROLLBACK);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->InsertWithConflictResolution(id, "test", values, ConflictResolution::ON_CONFLICT_ROLLBACK);
    EXPECT_EQ(ret, E_SQLITE_CONSTRAINT);
}

/**
 * @tc.name: RdbStore_InsertWithConflictResolution_005
 * @tc.desc: test RdbStore InsertWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_InsertWithConflictResolution_005, TestSize.Level1)
{
    std::shared_ptr<RdbStore> store = *GetParam();

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->InsertWithConflictResolution(id, "test", values, ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->InsertWithConflictResolution(id, "test", values, ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(id, -1);
}

/**
 * @tc.name: RdbStore_InsertWithConflictResolution_006
 * @tc.desc: test RdbStore InsertWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_InsertWithConflictResolution_006, TestSize.Level1)
{
    std::shared_ptr<RdbStore> store = *GetParam();

    int64_t id;
    ValuesBucket values;

    int ret = store->InsertWithConflictResolution(
        id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]), ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store->InsertWithConflictResolution(id, "test", values, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(id, 1);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);

    int columnIndex;
    int intVal;
    std::string strVal;

    ret = resultSet->GetColumnIndex("id", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, intVal);

    ret = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ("zhangsan", strVal);

    ret = resultSet->GetColumnIndex("age", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(18, intVal);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_InsertWithConflictResolution_007
 * @tc.desc: test RdbStore InsertWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_InsertWithConflictResolution_007, TestSize.Level1)
{
    std::shared_ptr<RdbStore> store = *GetParam();

    int64_t id;
    ValuesBucket values;

    int ret = store->InsertWithConflictResolution(
        id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]), ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store->InsertWithConflictResolution(id, "test", values, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(id, 1);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);

    int columnIndex;
    double dVal;
    std::vector<uint8_t> blob;

    ret = resultSet->GetColumnIndex("salary", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetDouble(columnIndex, dVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(200.5, dVal);

    ret = resultSet->GetColumnIndex("blobType", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetBlob(columnIndex, blob);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, static_cast<int>(blob.size()));
    EXPECT_EQ(4, blob[0]);
    EXPECT_EQ(5, blob[1]);
    EXPECT_EQ(6, blob[2]);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_InsertWithConflictResolution_008
 * @tc.desc: Abnormal testCase of InsertWithConflictResolution, if conflictResolution is invalid
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_InsertWithConflictResolution_008, TestSize.Level1)
{
    std::shared_ptr<RdbStore> store = *GetParam();

    int64_t id = 0;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutInt("age", 18);
    int ret = store->InsertWithConflictResolution(id, "test", values, static_cast<ConflictResolution>(6));
    EXPECT_EQ(E_INVALID_CONFLICT_FLAG, ret);
    EXPECT_EQ(0, id);

    values.Clear();
    values.PutInt("id", 1);
    values.PutInt("age", 18);
    ret = store->InsertWithConflictResolution(id, "test", values, static_cast<ConflictResolution>(-1));
    EXPECT_EQ(E_INVALID_CONFLICT_FLAG, ret);
    EXPECT_EQ(0, id);
}

/**
 * @tc.name: OverLimitWithInsert_001
 * @tc.desc: over limit
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
*/
HWTEST_P(RdbStoreInsertTest, OverLimitWithInsert_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> store = *GetParam();
    auto [code, maxPageCount] = store->Execute("PRAGMA max_page_count;");
    auto recover = std::shared_ptr<const char>("recover", [defPageCount = maxPageCount, store](const char *) {
        store->Execute("PRAGMA max_page_count = " + static_cast<std::string>(defPageCount) + ";");
    });
    std::tie(code, maxPageCount) = store->Execute("PRAGMA max_page_count = 256;");

    ValuesBucket row;
    row.Put("name", std::string(1024 * 1024, 'e'));
    auto result = store->Insert("test", row, ConflictResolution::ON_CONFLICT_NONE);
    ASSERT_EQ(result.first, E_SQLITE_FULL);
}

INSTANTIATE_TEST_SUITE_P(InsertTest, RdbStoreInsertTest, testing::Values(&g_store, &g_memDb));
} // namespace OHOS::RdbStoreInsertTest
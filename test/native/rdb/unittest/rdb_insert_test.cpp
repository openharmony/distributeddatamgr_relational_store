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
#include "result_set.h"
#include "values_buckets.h"

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

std::vector<ValueObject> GetColumnValues(std::shared_ptr<ResultSet> resultSet, const std::string &filed)
{
    std::vector<ValueObject> res;
    if (resultSet->GoToFirstRow() != E_OK) {
        return res;
    }
    int32_t colIndex = -1;
    if (resultSet->GetColumnIndex(filed, colIndex) != E_OK) {
        return res;
    }
    do {
        ValueObject value;
        EXPECT_EQ(resultSet->Get(colIndex, value), E_OK);
        res.push_back(value);
    } while (resultSet->GoToNextRow() == E_OK);
    return res;
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
    ASSERT_NE(store_, nullptr);
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
HWTEST_P(RdbStoreInsertTest, RdbStore_Insert_001, TestSize.Level0)
{
    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store_->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 2);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store_->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    values.Clear();
    values.PutInt("id", 3);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 20L);
    values.PutDouble("salary", 100.5f);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store_->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    RdbStoreInsertTest::CheckResultSet(store_);
}

void RdbStoreInsertTest::CheckResultSet(std::shared_ptr<RdbStore> &store)
{
    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test WHERE name = ?", std::vector<std::string>{ "zhangsan" });
    ASSERT_NE(resultSet, nullptr);

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
HWTEST_P(RdbStoreInsertTest, RdbStore_Insert_002, TestSize.Level0)
{
    int64_t id;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store_->Insert(id, "", values); // empty table name
    EXPECT_EQ(ret, E_EMPTY_TABLE_NAME);

    ret = store_->Insert(id, "wrongTable", values); // no such table
    EXPECT_EQ(ret, E_SQLITE_ERROR);
}

/**
 * @tc.name: RdbStore_Insert_003
 * @tc.desc: test RdbStore insert
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_Insert_003, TestSize.Level0)
{
    int64_t id;
    ValuesBucket emptyBucket;
    int ret = store_->Insert(id, "test", emptyBucket);
    EXPECT_EQ(ret, E_EMPTY_VALUES_BUCKET);

    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("wrongColumn", 100.5); // no such column
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store_->Insert(id, "test", values);
    EXPECT_EQ(ret, E_SQLITE_ERROR);
}

/**
 * @tc.name: RdbStore_Replace_001
 * @tc.desc: test RdbStore replace
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_Replace_001, TestSize.Level0)
{
    int64_t id;
    ValuesBucket values;

    int ret = store_->Replace(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    std::shared_ptr<ResultSet> resultSet = store_->QuerySql("SELECT * FROM test");
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
HWTEST_P(RdbStoreInsertTest, RdbStore_Replace_002, TestSize.Level0)
{
    int64_t id;
    ValuesBucket values;

    int ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store_->Replace(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    std::shared_ptr<ResultSet> resultSet = store_->QuerySql("SELECT * FROM test");
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
HWTEST_P(RdbStoreInsertTest, RdbStore_Replace_003, TestSize.Level0)
{
    int64_t id;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store_->Replace(id, "", values); // empty table name
    EXPECT_EQ(ret, E_EMPTY_TABLE_NAME);

    ret = store_->Replace(id, "wrongTable", values); // no such table
    EXPECT_EQ(ret, E_SQLITE_ERROR);
}

/**
 * @tc.name: RdbStore_Replace_004
 * @tc.desc: test RdbStore Replace
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_Replace_004, TestSize.Level0)
{
    int64_t id;
    ValuesBucket emptyBucket;
    int ret = store_->Replace(id, "test", emptyBucket);
    EXPECT_EQ(ret, E_EMPTY_VALUES_BUCKET);

    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("wrongColumn", 100.5); // no such column
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store_->Replace(id, "test", values);
    EXPECT_EQ(ret, E_SQLITE_ERROR);
}

/**
 * @tc.name: RdbStore_Replace_005
 * @tc.desc: test RdbStore replace
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_Replace_005, TestSize.Level0)
{
    int64_t id;

    int ret = store_->Replace(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    std::shared_ptr<ResultSet> resultSet = store_->QuerySql("SELECT * FROM test");
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
HWTEST_P(RdbStoreInsertTest, RdbStore_Replace_006, TestSize.Level0)
{
    int64_t id;
    ValuesBucket values;

    int ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store_->Replace(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    std::shared_ptr<ResultSet> resultSet = store_->QuerySql("SELECT * FROM test");
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
HWTEST_P(RdbStoreInsertTest, RdbStore_InsertWithConflictResolution_001_002, TestSize.Level0)
{
    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });

    // default is ConflictResolution::ON_CONFLICT_NONE
    int ret = store_->InsertWithConflictResolution(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store_->InsertWithConflictResolution(id, "test", values);
    EXPECT_EQ(ret, E_SQLITE_CONSTRAINT);
}

/**
 * @tc.name: RdbStore_InsertWithConflictResolution_003_004
 * @tc.desc: test RdbStore InsertWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_InsertWithConflictResolution_003_004, TestSize.Level0)
{
    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store_->InsertWithConflictResolution(id, "test", values, ConflictResolution::ON_CONFLICT_ROLLBACK);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store_->InsertWithConflictResolution(id, "test", values, ConflictResolution::ON_CONFLICT_ROLLBACK);
    EXPECT_EQ(ret, E_SQLITE_CONSTRAINT);
}

/**
 * @tc.name: RdbStore_InsertWithConflictResolution_005
 * @tc.desc: test RdbStore InsertWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_InsertWithConflictResolution_005, TestSize.Level0)
{
    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store_->InsertWithConflictResolution(id, "test", values, ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store_->InsertWithConflictResolution(id, "test", values, ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(id, -1);
}

/**
 * @tc.name: RdbStore_InsertWithConflictResolution_006
 * @tc.desc: test RdbStore InsertWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_P(RdbStoreInsertTest, RdbStore_InsertWithConflictResolution_006, TestSize.Level0)
{
    int64_t id;
    ValuesBucket values;

    int ret = store_->InsertWithConflictResolution(
        id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]), ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store_->InsertWithConflictResolution(id, "test", values, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(id, 1);

    std::shared_ptr<ResultSet> resultSet = store_->QuerySql("SELECT * FROM test");
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
HWTEST_P(RdbStoreInsertTest, RdbStore_InsertWithConflictResolution_007, TestSize.Level0)
{
    int64_t id;
    ValuesBucket values;

    int ret = store_->InsertWithConflictResolution(
        id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]), ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store_->InsertWithConflictResolution(id, "test", values, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(id, 1);

    std::shared_ptr<ResultSet> resultSet = store_->QuerySql("SELECT * FROM test");
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
HWTEST_P(RdbStoreInsertTest, RdbStore_InsertWithConflictResolution_008, TestSize.Level0)
{
    int64_t id = 0;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutInt("age", 18);
    int ret = store_->InsertWithConflictResolution(id, "test", values, static_cast<ConflictResolution>(6));
    EXPECT_EQ(E_INVALID_CONFLICT_FLAG, ret);
    EXPECT_EQ(0, id);

    values.Clear();
    values.PutInt("id", 1);
    values.PutInt("age", 18);
    ret = store_->InsertWithConflictResolution(id, "test", values, static_cast<ConflictResolution>(-1));
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
HWTEST_P(RdbStoreInsertTest, OverLimitWithInsert_001, TestSize.Level0)
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

/**
 * @tc.name: BatchInsert_001
 * @tc.desc: normal test
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
*/
HWTEST_P(RdbStoreInsertTest, BatchInsert_001, TestSize.Level0)
{
    ValuesBuckets rows;
    for (int i = 0; i < 5; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(row);
    }
    auto [status, result] = store_->BatchInsert("test", rows, { "id" });
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 5);
    ASSERT_NE(result.results, nullptr);
    int32_t count = 0;
    ASSERT_EQ(result.results->GetRowCount(count), E_OK);
    ASSERT_EQ(count, 5);
    auto values = GetColumnValues(result.results, "id");
    ASSERT_EQ(values.size(), 5);
    for (int i = 0; i < 5; i++) {
        int val = -1;
        EXPECT_EQ(values[i].GetInt(val), E_OK);
        EXPECT_EQ(val, i);
    }
}

/**
 * @tc.name: BatchInsert_002
 * @tc.desc: abnormal test. batch insert with returning and conflict IGNORE
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
*/
HWTEST_P(RdbStoreInsertTest, BatchInsert_002, TestSize.Level0)
{
    ValuesBuckets rows;
    for (int i = 0; i < 5; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(row);
    }
    ValuesBucket row;
    row.Put("id", 2);
    row.Put("name", "Jim");
    auto res = store_->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);
    ASSERT_EQ(res.second, 2);
    std::string returningField = "id";
    auto [status, result] =
        store_->BatchInsert("test", rows, { returningField }, ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 4);
    ASSERT_NE(result.results, nullptr);
    int32_t count = 0;
    ASSERT_EQ(result.results->GetRowCount(count), E_OK);
    ASSERT_EQ(count, 4);
    auto values = GetColumnValues(result.results, returningField);
    ASSERT_EQ(values.size(), 4);
    for (size_t i = 0; i < values.size(); i++) {
        int val = -1;
        EXPECT_EQ(values[i].GetInt(val), E_OK);
        EXPECT_EQ(val, i + (i >= 2));
    }
}

/**
 * @tc.name: BatchInsert_003
 * @tc.desc: abnormal test. batch insert with returning and conflict fail.
 * When using the fail strategy, if the constraint is violated, the correct result cannot be obtained
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
*/
HWTEST_P(RdbStoreInsertTest, BatchInsert_003, TestSize.Level0)
{
    std::vector<ValuesBucket> rows;
    for (int i = 0; i < 5; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.push_back(std::move(row));
    }
    ValuesBucket row;
    row.Put("id", 2);
    row.Put("name", "Jim");
    auto res = store_->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);
    ASSERT_EQ(res.second, 2);
    auto [status, result] = store_->BatchInsert("test", rows, { "id" }, ConflictResolution::ON_CONFLICT_FAIL);
    EXPECT_EQ(status, E_SQLITE_CONSTRAINT);
    EXPECT_EQ(result.changed, 2);
    EXPECT_EQ(result.results, nullptr);
}

/**
 * @tc.name: BatchInsert_004
 * @tc.desc: abnormal test. batch insert with returning and conflict replace
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
*/
HWTEST_P(RdbStoreInsertTest, BatchInsert_004, TestSize.Level0)
{
    std::vector<ValuesBucket> rows;
    for (int i = 0; i < 5; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.push_back(std::move(row));
    }
    ValuesBucket row;
    row.Put("id", 2);
    row.Put("name", "Jim");
    auto res = store_->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);
    ASSERT_EQ(res.second, 2);
    std::string returningField = "id";
    auto [status, result] = store_->BatchInsert(
        "test", ValuesBuckets(std::move(rows)), { returningField }, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 5);
    ASSERT_NE(result.results, nullptr);
    int32_t count = 0;
    ASSERT_EQ(result.results->GetRowCount(count), E_OK);
    ASSERT_EQ(count, 5);
    auto values = GetColumnValues(result.results, returningField);
    ASSERT_EQ(values.size(), 5);
    for (size_t i = 0; i < 5; i++) {
        int val = -1;
        EXPECT_EQ(values[i].GetInt(val), E_OK);
        EXPECT_EQ(val, i);
    }
}

/**
 * @tc.name: BatchInsert_005
 * @tc.desc: abnormal test. batch insert with over returning limit
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
*/
HWTEST_P(RdbStoreInsertTest, BatchInsert_005, TestSize.Level0)
{
    ValuesBuckets rows;
    rows.Reserve(1025);
    for (int i = 0; i < 1025; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(std::move(row));
    }
    auto [status, result] = store_->BatchInsert("test", rows, { "id" }, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1025);
    ASSERT_NE(result.results, nullptr);
    int32_t count = 0;
    ASSERT_EQ(result.results->GetRowCount(count), E_OK);
    ASSERT_EQ(count, 1024);
    auto values = GetColumnValues(result.results, "id");
    ASSERT_EQ(values.size(), 1024);
    for (size_t i = 0; i < 1024; i++) {
        EXPECT_EQ(int(values[i]), i);
    }
}

/**
 * @tc.name: BatchInsert_006
 * @tc.desc: abnormal test. batch insert with returning non-existent fields
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
*/
HWTEST_P(RdbStoreInsertTest, BatchInsert_006, TestSize.Level0)
{
    ValuesBuckets rows;
    for (int i = 0; i < 5; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(std::move(row));
    }
    std::string returningField = "notExist";
    auto [status, result] =
        store_->BatchInsert("test", rows, { returningField }, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(status, E_SQLITE_ERROR);
    EXPECT_EQ(result.changed, -1);
    ASSERT_EQ(result.results, nullptr);
}

/**
 * @tc.name: BatchInsert_007
 * @tc.desc: abnormal test. batch insert with returning and no changed rows
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
*/
HWTEST_P(RdbStoreInsertTest, BatchInsert_007, TestSize.Level0)
{
    ValuesBuckets rows;
    ValuesBucket row;
    row.Put("id", 2);
    row.Put("name", "Jim");
    auto res = store_->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);
    ASSERT_EQ(res.second, 2);
    rows.Put(std::move(row));
    auto [status, result] = store_->BatchInsert("test", rows, { "id" }, ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 0);
    ASSERT_NE(result.results, nullptr);
    int32_t count = 0;
    ASSERT_EQ(result.results->GetRowCount(count), E_OK);
    ASSERT_EQ(count, 0);
}

/**
 * @tc.name: BatchInsert_008
 * @tc.desc: normal test. batch insert with returning rowId
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
*/
HWTEST_P(RdbStoreInsertTest, BatchInsert_008, TestSize.Level0)
{
    ValuesBuckets rows;
    ValuesBucket row;
    row.Put("id", 2);
    row.Put("name", "Jim");
    rows.Put(std::move(row));
    // rowId can use in retuning, but get column not include rowId
    auto [status, result] = store_->BatchInsert("test", rows, { "rowId", "rowid", "RowId", "id" });
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1);
    ASSERT_NE(result.results, nullptr);
    int32_t count = 0;
    ASSERT_EQ(result.results->GetRowCount(count), E_OK);
    ASSERT_EQ(count, 1);
    RowEntity rowEntity;
    EXPECT_EQ(result.results->GetRow(rowEntity), E_OK);
    EXPECT_EQ(int(rowEntity.Get("id")), 2);
}

/**
 * @tc.name: BatchInsert_009
 * @tc.desc: normal test. batch insert with returning *
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
*/
HWTEST_P(RdbStoreInsertTest, BatchInsert_009, TestSize.Level0)
{
    ValuesBuckets rows;
    ValuesBucket row;
    row.Put("id", 2);
    row.Put("name", "Jim");
    row.Put("age", 18);
    row.PutDouble("salary", 100.5);
    std::vector<uint8_t> blob{ 1, 2, 3 };
    row.PutBlob("blobType", blob);
    rows.Put(std::move(row));
    auto [status, result] =
        store_->BatchInsert("test", rows, { "*" }, NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1);
    ASSERT_NE(result.results, nullptr);
    int32_t count = 0;
    ASSERT_EQ(result.results->GetRowCount(count), E_OK);
    ASSERT_EQ(count, 1);
    RowEntity rowEntity;
    EXPECT_EQ(result.results->GetRow(rowEntity), E_OK);
    EXPECT_EQ(int(rowEntity.Get("id")), 2);
    EXPECT_EQ(std::string(rowEntity.Get("name")), "Jim");
    EXPECT_EQ(int(rowEntity.Get("age")), 18);
    EXPECT_NEAR(double(rowEntity.Get("salary")), 100.5, std::numeric_limits<double>::epsilon());
    EXPECT_EQ(std::vector<uint8_t>(rowEntity.Get("blobType")), blob);
}

/**
 * @tc.name: BatchInsert_010
 * @tc.desc: normal test. batch insert with returning complex field
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
*/
HWTEST_P(RdbStoreInsertTest, BatchInsert_010, TestSize.Level0)
{
    ValuesBuckets rows;
    ValuesBucket row;
    row.Put("id", 2);
    row.Put("name", "Jim");
    row.PutDouble("salary", 100.5);
    rows.Put(std::move(row));
    auto [status, result] = store_->BatchInsert("test", rows, { "id", "name", "salary * 1.1 AS bonusSalary" },
        NativeRdb::ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1);
    ASSERT_NE(result.results, nullptr);
    int32_t count = 0;
    ASSERT_EQ(result.results->GetRowCount(count), E_OK);
    ASSERT_EQ(count, 1);
    RowEntity rowEntity;
    EXPECT_EQ(result.results->GetRow(rowEntity), E_OK);
    EXPECT_EQ(int(rowEntity.Get("id")), 2);
    EXPECT_EQ(std::string(rowEntity.Get("name")), "Jim");
    EXPECT_NEAR(double(rowEntity.Get("bonusSalary")), 100.5 * 1.1, std::numeric_limits<double>::epsilon());
}

/**
 * @tc.name: BatchInsert_011
 * @tc.desc: normal test. batch insert with returning complex field
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
*/
HWTEST_P(RdbStoreInsertTest, BatchInsert_011, TestSize.Level1)
{
    ValuesBuckets rows;
    ValuesBucket row;
    row.Put("id", 1);
    row.Put("name", "Jim");
    row.Put("age", 18);
    row.PutDouble("salary", 110.5);
    rows.Put(std::move(row));
    row.Clear();
    row.Put("id", 2);
    row.Put("name", "Bob");
    row.Put("age", 22);
    row.PutDouble("salary", 90);
    rows.Put(std::move(row));
    auto [status, result] = store_->BatchInsert("test", rows,
        { "id", "name", "(salary < 100) AS lowSalary", "age > 18 as adult" },
        NativeRdb::ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 2);
    ASSERT_NE(result.results, nullptr);
    int32_t count = 0;
    ASSERT_EQ(result.results->GetRowCount(count), E_OK);
    ASSERT_EQ(count, 2);
    RowEntity rowEntity;
    EXPECT_EQ(result.results->GetRow(rowEntity), E_OK);
    EXPECT_EQ(int(rowEntity.Get("id")), 1);
    EXPECT_EQ(std::string(rowEntity.Get("name")), "Jim");
    EXPECT_EQ(bool(rowEntity.Get("lowSalary")), false);
    EXPECT_EQ(bool(rowEntity.Get("adult")), false);

    EXPECT_EQ(result.results->GoToNextRow(), E_OK);
    EXPECT_EQ(result.results->GetRow(rowEntity), E_OK);
    EXPECT_EQ(int(rowEntity.Get("id")), 2);
    EXPECT_EQ(std::string(rowEntity.Get("name")), "Bob");
    EXPECT_EQ(bool(rowEntity.Get("lowSalary")), true);
    EXPECT_EQ(bool(rowEntity.Get("adult")), true);
}

/**
 * @tc.name: BatchInsert_012
 * @tc.desc: normal test. batch insert with returning function
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
*/
HWTEST_P(RdbStoreInsertTest, BatchInsert_012, TestSize.Level1)
{
    ValuesBuckets rows;
    ValuesBucket row;
    row.Put("id", 20);
    row.Put("name", "Jim");
    row.PutDouble("salary", 100.5);
    rows.Put(std::move(row));
    auto [status, result] = store_->BatchInsert("test", rows, { "id", "name", "datetime('now') AS createdTime" },
        NativeRdb::ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1);
    ASSERT_NE(result.results, nullptr);
    int32_t count = 0;
    ASSERT_EQ(result.results->GetRowCount(count), E_OK);
    ASSERT_EQ(count, 1);
    RowEntity rowEntity;
    EXPECT_EQ(result.results->GetRow(rowEntity), E_OK);
    EXPECT_EQ(int(rowEntity.Get("id")), 20);
    EXPECT_EQ(std::string(rowEntity.Get("name")), "Jim");
    EXPECT_EQ(rowEntity.Get("createdTime").GetType(), ValueObject::TYPE_STRING);
    EXPECT_FALSE(std::string(rowEntity.Get("createdTime")).empty());
}

/**
 * @tc.name: BatchInsert_013
 * @tc.desc: normal test. batch insert into virtual table with returning
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
*/
HWTEST_P(RdbStoreInsertTest, BatchInsert_013, TestSize.Level1)
{
    store_->Execute("CREATE VIRTUAL TABLE IF NOT EXISTS articles USING fts5(title, content);");
    ValuesBuckets rows;
    ValuesBucket row;
    row.Put("title", "fts5");
    row.Put("content", "test virtual tables");
    rows.Put(std::move(row));
    auto [status, result] =
        store_->BatchInsert("articles", rows, { "title" }, NativeRdb::ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1);
    ASSERT_NE(result.results, nullptr);
    int32_t count = 0;
    ASSERT_EQ(result.results->GetRowCount(count), E_OK);
    ASSERT_EQ(count, 1);
    RowEntity rowEntity;
    EXPECT_EQ(result.results->GetRow(rowEntity), E_OK);
    EXPECT_EQ(std::string(rowEntity.Get("title")), "fts5");
    store_->Execute("Drop TABLE articles");
}

/**
 * @tc.name: BatchInsert_014
 * @tc.desc: normal test. batch insert with returning and trigger
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
*/
HWTEST_P(RdbStoreInsertTest, BatchInsert_014, TestSize.Level1)
{
    auto [code, result1] = store_->Execute("CREATE TRIGGER after_name_insert AFTER INSERT ON test"
                    " BEGIN UPDATE test SET name = 'after trigger' WHERE name = 'BatchInsert_014'; END");

    EXPECT_EQ(code, E_OK);

    ValuesBuckets rows;
    ValuesBucket row;
    row.Put("id", 200);
    row.Put("name", "BatchInsert_014");
    rows.Put(std::move(row));
    auto [status, result] =
        store_->BatchInsert("test", rows, { "name" }, NativeRdb::ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1);
    ASSERT_NE(result.results, nullptr);
    int32_t count = 0;
    ASSERT_EQ(result.results->GetRowCount(count), E_OK);
    ASSERT_EQ(count, 1);
    RowEntity rowEntity;
    EXPECT_EQ(result.results->GetRow(rowEntity), E_OK);
    EXPECT_EQ(std::string(rowEntity.Get("name")), "BatchInsert_014");

    auto resultSet = store_->QuerySql("select name from test where id = 200");
    int rowCount = -1;
    resultSet->GetRowCount(rowCount);
    resultSet->GoToFirstRow();
    EXPECT_EQ(resultSet->GetRow(rowEntity), E_OK);
    EXPECT_EQ(std::string(rowEntity.Get("name")), "after trigger");
    store_->Execute("DROP TRIGGER IF EXISTS after_name_insert");
}

/**
 * @tc.name: BatchInsert_015
 * @tc.desc: normal test. batch insert with returning and sub query
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
*/
HWTEST_P(RdbStoreInsertTest, BatchInsert_015, TestSize.Level1)
{
    store_->Execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT);");
    store_->Execute("CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY, action TEXT);");
    ValuesBuckets rows;
    ValuesBucket row;
    row.Put("id", 200);
    row.Put("action", "BatchInsert_015");
    rows.Put(std::move(row));
    auto [status, changed] = store_->BatchInsert("logs", rows);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(changed, 1);
    Results result{ -1 };
    row.Clear();
    rows.Clear();
    row.Put("id", 1);
    row.Put("name", "BatchInsert_015");
    rows.Put(std::move(row));
    std::tie(status, result) = store_->BatchInsert("users", rows,
        { "(SELECT COUNT(*) FROM logs WHERE action = name) AS count" },
        NativeRdb::ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1);
    ASSERT_NE(result.results, nullptr);
    int32_t count = 0;
    ASSERT_EQ(result.results->GetRowCount(count), E_OK);
    ASSERT_EQ(count, 1);
    RowEntity rowEntity;
    EXPECT_EQ(result.results->GetRow(rowEntity), E_OK);
    EXPECT_EQ(int(rowEntity.Get("count")), 1);
    store_->Execute("DROP TABLE users");
    store_->Execute("DROP TABLE logs");
}

/**
 * @tc.name: BatchInsert_016
 * @tc.desc: abnormal test. batch insert with max returning limit
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
*/
HWTEST_P(RdbStoreInsertTest, BatchInsert_016, TestSize.Level0)
{
    int maxRowCount = 1024;
    ValuesBuckets rows;
    rows.Reserve(maxRowCount);
    for (int i = 0; i < maxRowCount; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(std::move(row));
    }
    auto [status, result] =
        store_->BatchInsert("test", ValuesBuckets(rows), {"id", "name"}, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, maxRowCount);
    ASSERT_NE(result.results, nullptr);
    int32_t count = 0;
    ASSERT_EQ(result.results->GetRowCount(count), E_OK);
    ASSERT_EQ(count, maxRowCount);
    for (size_t i = 0; i < maxRowCount; i++) {
        RowEntity rowEntity;
        EXPECT_EQ(result.results->GetRow(rowEntity), E_OK);
        EXPECT_EQ(int(rowEntity.Get("id")), i);
        EXPECT_EQ(std::string(rowEntity.Get("name")), "Jim");
        if (i != maxRowCount - 1) {
            ASSERT_EQ(result.results->GoToNextRow(), E_OK);
        }
    }
}

/**
 * @tc.name: BatchInsert_017
 * @tc.desc: abnormal test. batch insert with max returning limit
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
*/
HWTEST_P(RdbStoreInsertTest, BatchInsert_017, TestSize.Level0)
{
    int maxRowCount = 1024;
    ValuesBuckets rows;
    rows.Reserve(maxRowCount);
    for (int i = 0; i < maxRowCount; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(std::move(row));
    }
    auto [status, result] =
        store_->BatchInsert("test", ValuesBuckets(rows), {"id", "name"}, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, maxRowCount);
    int32_t count = 0;
    ASSERT_EQ(result.results->GetRowCount(count), E_OK);
    ASSERT_EQ(count, maxRowCount);

    std::tie(status, result) =
        store_->ExecuteExt("UPDATE test SET name = 'Tim' WHERE name = 'Jim' RETURNING id, name");

    EXPECT_EQ(result.changed, maxRowCount);
    count = 0;
    EXPECT_EQ(result.results->GetRowCount(count), E_OK);
    EXPECT_EQ(count, maxRowCount);
    for (size_t i = 0; i < maxRowCount; i++) {
        RowEntity rowEntity;
        EXPECT_EQ(result.results->GetRow(rowEntity), E_OK);
        EXPECT_EQ(int(rowEntity.Get("id")), i);
        EXPECT_EQ(std::string(rowEntity.Get("name")), "Tim");
        if (i != maxRowCount - 1) {
            ASSERT_EQ(result.results->GoToNextRow(), E_OK);
        }
    }
}

/**
 * @tc.name: BatchInsert_018
 * @tc.desc: abnormal test. batch insert with max returning limit
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
*/
HWTEST_P(RdbStoreInsertTest, BatchInsert_018, TestSize.Level0)
{
    int maxRowCount = 1024;
    ValuesBuckets rows;
    rows.Reserve(maxRowCount);
    for (int i = 0; i < maxRowCount; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(std::move(row));
    }
    auto [status, result] =
        store_->BatchInsert("test", ValuesBuckets(rows), {"id", "name"}, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, maxRowCount);

    std::tie(status, result) =
        store_->ExecuteExt("update test set name = ? where name = ?", { "Tim", "Jim" });

    EXPECT_NE(result.results, nullptr);
    EXPECT_EQ(result.changed, maxRowCount);
    int32_t count = 0;
    EXPECT_EQ(result.results->GetRowCount(count), E_OK);
    EXPECT_EQ(count, 0);
}
/**
 * @tc.name: BatchInsert_019
 * @tc.desc: normal test. batch insert with returning and trigger
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
*/
HWTEST_P(RdbStoreInsertTest, BatchInsert_019, TestSize.Level1)
{
    auto [code, result1] = store_->Execute("CREATE TRIGGER after_name_insert AFTER INSERT ON test"
                    " BEGIN UPDATE test SET name = 'after trigger' WHERE name = 'BatchInsert_014'; END");

    EXPECT_EQ(code, E_OK);

    auto [status, result] =
        store_->ExecuteExt("INSERT INTO test (id, name) VALUES (200, 'BatchInsert_014') RETURNING name;");

    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1);
    ASSERT_NE(result.results, nullptr);
    int32_t count = 0;
    ASSERT_EQ(result.results->GetRowCount(count), E_OK);
    ASSERT_EQ(count, 1);
    RowEntity rowEntity;
    EXPECT_EQ(result.results->GetRow(rowEntity), E_OK);
    EXPECT_EQ(std::string(rowEntity.Get("name")), "BatchInsert_014");

    auto resultSet = store_->QuerySql("select name from test where id = 200");
    int rowCount = -1;
    resultSet->GetRowCount(rowCount);
    resultSet->GoToFirstRow();
    EXPECT_EQ(resultSet->GetRow(rowEntity), E_OK);
    EXPECT_EQ(std::string(rowEntity.Get("name")), "after trigger");
    store_->Execute("DROP TRIGGER IF EXISTS after_name_insert");
}
// RDB_TEST_PATH + "insert_test_slave.db";
/**
 * @tc.name: BatchInsert_020
 * @tc.desc: abnormal test. The conflict mode is ABORT. When there is a conflict during batch insertion, it will not be
 * rolled back, and the backup database will also insert the corresponding inserted data
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
*/
HWTEST_P(RdbStoreInsertTest, BatchInsert_020, TestSize.Level0)
{
    std::vector<ValuesBucket> rows;
    for (int i = 0; i < 3; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.push_back(std::move(row));
    }
    ValuesBucket row;
    row.Put("id", 1);
    row.Put("name", "bob");
    RdbStoreConfig config(RDB_TEST_PATH + "returning_test.db");
    InsertTestOpenCallback helper;
    int errCode = E_OK;
    config.SetHaMode(true);
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    auto res = store->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);
    ASSERT_EQ(res.second, 1);
    auto [status, result] = store->BatchInsert("test", rows, { "id" }, ConflictResolution::ON_CONFLICT_FAIL);
    EXPECT_EQ(status, E_SQLITE_CONSTRAINT);
    EXPECT_EQ(result.changed, 1);
    EXPECT_EQ(result.results, nullptr);
    RdbStoreConfig slaveConfig(RDB_TEST_PATH + "returning_test_slave.db");
    auto slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, helper, errCode);
    ASSERT_NE(slaveStore, nullptr);
    auto resultSet = slaveStore->QueryByStep("select * from test");
    int count = 0;
    resultSet->GetRowCount(count);
    EXPECT_EQ(count, 2);
    RowEntity resRow;
    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());
    EXPECT_EQ(E_OK, resultSet->GetRow(resRow));
    EXPECT_EQ(resRow.Get().at("id"), ValueObject(0));
    EXPECT_EQ(resRow.Get().at("name"), ValueObject("Jim"));
    EXPECT_EQ(E_OK, resultSet->GoToNextRow());
    EXPECT_EQ(E_OK, resultSet->GetRow(resRow));
    EXPECT_EQ(resRow.Get().at("id"), ValueObject(1));
    EXPECT_EQ(resRow.Get().at("name"), ValueObject("bob"));
    RdbHelper::DeleteRdbStore(RDB_TEST_PATH + "returning_test.db");
}
INSTANTIATE_TEST_SUITE_P(InsertTest, RdbStoreInsertTest, testing::Values(&g_store, &g_memDb));
} // namespace OHOS::RdbStoreInsertTest
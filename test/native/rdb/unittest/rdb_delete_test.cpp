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

#include <numeric>
#include <string>

#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
namespace OHOS::RdbDeleteTest {
struct RdbTestParam {
    std::shared_ptr<RdbStore> store;
    operator std::shared_ptr<RdbStore>()
    {
        return store;
    }
};
static RdbTestParam g_store;
static RdbTestParam g_memDb;

class RdbDeleteTest : public testing::TestWithParam<RdbTestParam *> {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::shared_ptr<RdbStore> store_;
    static const std::string DATABASE_NAME;
};

const std::string RdbDeleteTest::DATABASE_NAME = RDB_TEST_PATH + "delete_test.db";

class DeleteTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};
constexpr const char *CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test"
                                    "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                    "name TEXT NOT NULL, age INTEGER, salary "
                                    "REAL, blobType BLOB)";
int DeleteTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int DeleteTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbDeleteTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
    RdbStoreConfig config(RdbDeleteTest::DATABASE_NAME);
    DeleteTestOpenCallback helper;
    g_store.store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(g_store.store, nullptr);

    config.SetStorageMode(StorageMode::MODE_MEMORY);
    g_memDb.store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(g_memDb.store, nullptr);
}

void RdbDeleteTest::TearDownTestCase(void)
{
    RdbStoreConfig config(RdbDeleteTest::DATABASE_NAME);
    RdbHelper::DeleteRdbStore(config);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    RdbHelper::DeleteRdbStore(config);
}

void RdbDeleteTest::SetUp(void)
{
    store_ = *GetParam();
    ASSERT_NE(store_, nullptr);
    store_->ExecuteSql("DELETE FROM test");
}

void RdbDeleteTest::TearDown(void)
{
}

/**
 * @tc.name: RdbStore_Delete_001
 * @tc.desc: test RdbStore update, select id and update one row
 * @tc.type: FUNC
 */
HWTEST_P(RdbDeleteTest, RdbStore_Delete_001, TestSize.Level1)
{
    int64_t id;
    int deletedRows;

    int ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    ret = store_->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[2]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    ret = store_->Delete(deletedRows, "test", "id = 1");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, deletedRows);

    std::shared_ptr<ResultSet> resultSet =
        store_->QuerySql("SELECT * FROM test WHERE id = ?", std::vector<std::string>{ "1" });
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);

    resultSet = store_->QuerySql("SELECT * FROM test WHERE id = ?", std::vector<std::string>{ "2" });
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);

    resultSet = store_->QuerySql("SELECT * FROM test WHERE id = 3", std::vector<std::string>());
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Delete_002
 * @tc.desc: test RdbStore update, select id and update one row
 * @tc.type: FUNC
 */
HWTEST_P(RdbDeleteTest, RdbStore_Delete_002, TestSize.Level1)
{
    int64_t id;
    ValuesBucket values;
    int deletedRows;

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
    values.PutInt("age", 19);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store_->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    values.Clear();
    values.PutInt("id", 3);
    values.PutString("name", std::string("wangyjing"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store_->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    ret = store_->Delete(deletedRows, "test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, deletedRows);

    std::shared_ptr<ResultSet> resultSet = store_->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Delete_003
 * @tc.desc: test RdbStore update, select id and update one row
 * @tc.type: FUNC
 */
HWTEST_P(RdbDeleteTest, RdbStore_Delete_003, TestSize.Level1)
{
    int64_t id;
    ValuesBucket values;
    int deletedRows;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store_->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store_->Delete(deletedRows, "", "id = ?", std::vector<std::string>{ "1" });
    EXPECT_EQ(ret, E_EMPTY_TABLE_NAME);

    ret = store_->Delete(deletedRows, "wrongTable", "id = ?", std::vector<std::string>{ "1" });
    EXPECT_EQ(ret, E_SQLITE_ERROR);

    ret = store_->Delete(deletedRows, "test", "wrong sql id = ?", std::vector<std::string>{ "1" });
    EXPECT_EQ(ret, E_SQLITE_ERROR);

    ret = store_->Delete(deletedRows, "test", "id = 1", std::vector<std::string>());
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(deletedRows, 1);
}

/**
 * @tc.name: RdbStore_Delete_With_Returning_001
 * @tc.desc: normal test
 * @tc.type: FUNC
 */
HWTEST_P(RdbDeleteTest, RdbStore_Delete_With_Returning_001, TestSize.Level1)
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

    AbsRdbPredicates predicates("test");
    auto res = store_->Delete(predicates, "id");
    EXPECT_EQ(res.status, E_OK);
    EXPECT_EQ(res.count, 1);
    ASSERT_EQ(res.results.size(), 1);
    EXPECT_EQ(int(res.results[0]), 1);
}

/**
 * @tc.name: RdbStore_Delete_With_Returning_002
 * @tc.desc: abnormal test, delete over returning limit
 * @tc.type: FUNC
 */
HWTEST_P(RdbDeleteTest, RdbStore_Delete_With_Returning_002, TestSize.Level1)
{
    ValuesBuckets rows;
    for (int i = 0; i < 1124; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(row);
    }
    auto ret = store_->BatchInsert("test", rows);
    EXPECT_EQ(ret.first, E_OK);
    EXPECT_EQ(ret.second, 1124);

    AbsRdbPredicates predicates("test");
    auto res = store_->Delete(predicates, "id");
    EXPECT_EQ(res.status, E_OK);
    EXPECT_EQ(res.count, 1124);
    EXPECT_EQ(res.results.size(), 1024);
}

/**
 * @tc.name: RdbStore_Delete_With_Returning_003
 * @tc.desc: abnormal test, delete with returning field is string
 * @tc.type: FUNC
 */
HWTEST_P(RdbDeleteTest, RdbStore_Delete_With_Returning_003, TestSize.Level1)
{
    ValuesBuckets rows;
    for (int i = 0; i < 15; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim" + std::to_string(i));
        rows.Put(row);
    }
    auto ret = store_->BatchInsert("test", rows);
    EXPECT_EQ(ret.first, E_OK);
    EXPECT_EQ(ret.second, 15);

    AbsRdbPredicates predicates("test");
    auto res = store_->Delete(predicates, "name");
    EXPECT_EQ(res.status, E_OK);
    EXPECT_EQ(res.count, 15);
    EXPECT_EQ(res.results.size(), 15);
    for (int i = 0; i < 15; i++) {
        EXPECT_EQ(std::string(res.results[i]), "Jim" + std::to_string(i));
    }
}

/**
 * @tc.name: RdbStore_Delete_With_Returning_004
 * @tc.desc: abnormal test, delete with returning field is blob
 * @tc.type: FUNC
 */
HWTEST_P(RdbDeleteTest, RdbStore_Delete_With_Returning_004, TestSize.Level1)
{
    ValuesBuckets rows;
    for (int i = 0; i < 15; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim" + std::to_string(i));
        std::vector<uint8_t> blob(i);
        std::iota(blob.begin(), blob.end(), 1);
        row.PutBlob("blobType", blob);
        rows.Put(row);
    }
    auto ret = store_->BatchInsert("test", rows);
    EXPECT_EQ(ret.first, E_OK);
    EXPECT_EQ(ret.second, 15);

    AbsRdbPredicates predicates("test");
    auto res = store_->Delete(predicates, "blobType");
    EXPECT_EQ(res.status, E_OK);
    EXPECT_EQ(res.count, 15);
    EXPECT_EQ(res.results.size(), 15);
    for (int i = 0; i < 15; i++) {
        std::vector<uint8_t> blob(i);
        std::iota(blob.begin(), blob.end(), 1);
        EXPECT_EQ(std::vector<uint8_t>(res.results[i]), blob);
    }
}

/**
 * @tc.name: RdbStore_Delete_With_Returning_005
 * @tc.desc: abnormal test, delete with returning field is not exist
 * @tc.type: FUNC
 */
HWTEST_P(RdbDeleteTest, RdbStore_Delete_With_Returning_005, TestSize.Level1)
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

    AbsRdbPredicates predicates("test");
    auto res = store_->Delete(predicates, "notExist");
    EXPECT_EQ(res.status, E_SQLITE_ERROR);
    EXPECT_EQ(res.count, -1);
    ASSERT_EQ(res.results.size(), 0);
}

/**
 * @tc.name: RdbStore_Delete_With_Returning_006
 * @tc.desc: abnormal test, delete with returning field is not exist
 * @tc.type: FUNC
 */
HWTEST_P(RdbDeleteTest, RdbStore_Delete_With_Returning_006, TestSize.Level1)
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

    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", 100);
    auto res = store_->Delete(predicates, "notExist");
    EXPECT_EQ(res.status, E_SQLITE_ERROR);
    EXPECT_EQ(res.count, -1);
    ASSERT_EQ(res.results.size(), 0);
}

INSTANTIATE_TEST_SUITE_P(DeleteTest, RdbDeleteTest, testing::Values(&g_store, &g_memDb));
} // namespace OHOS::RdbDeleteTest

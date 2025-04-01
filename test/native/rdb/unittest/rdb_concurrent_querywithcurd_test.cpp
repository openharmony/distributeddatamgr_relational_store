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

#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "values_bucket.h"
using namespace testing::ext;
using namespace OHOS::NativeRdb;
namespace Test {
class QueryWithCrudTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
    void InsertData(int rowCount, int size);
    static std::shared_ptr<RdbStore> rdbStore_;
    static constexpr const char *DATABASE_PATH = "/data/test/queryWithCrud_test.db";
    static constexpr const char *CREATE_TABLE = "CREATE TABLE IF NOT EXISTS test(id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB)";
    static constexpr const char *DROP_TABLE = "DROP TABLE IF EXISTS test";
    const double SALARY = 100.5;

    class RdbCallback : public RdbOpenCallback {
    public:
        int OnCreate(RdbStore &store) override
        {
            return E_OK;
        }
        int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override
        {
            return E_OK;
        }
    };
};
std::shared_ptr<RdbStore> QueryWithCrudTest::rdbStore_;
void QueryWithCrudTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    RdbCallback callback;
    RdbStoreConfig config(DATABASE_PATH);
    RdbHelper::DeleteRdbStore(DATABASE_PATH);
    rdbStore_ = RdbHelper::GetRdbStore(config, 1, callback, errCode);
    ASSERT_NE(rdbStore_, nullptr);
}

void QueryWithCrudTest::TearDownTestCase(void)
{
    rdbStore_ = nullptr;
    RdbHelper::DeleteRdbStore(DATABASE_PATH);
}
void QueryWithCrudTest::SetUp(void)
{
    rdbStore_->ExecuteSql(DROP_TABLE);
    rdbStore_->ExecuteSql(CREATE_TABLE);
}

void QueryWithCrudTest::TearDown(void)
{
    rdbStore_->ExecuteSql(DROP_TABLE);
}
void QueryWithCrudTest::InsertData(int rowCount, int size)
{
    EXPECT_GT(rowCount, 0);
    EXPECT_GT(size, 0);
    int64_t id;
    ValuesBucket values;
    std::vector<uint8_t> u8(size, 1);
    std::vector<ValuesBucket> valuesBuckets;
    for (int i = 0; i < rowCount; i++) {
        values.Put("name", "zhangsan" + std::to_string(i));
        values.Put("age", i);
        values.Put("salary", SALARY);
        values.Put("blobType", u8);
        valuesBuckets.push_back(values);
    }
    auto ret = rdbStore_->BatchInsert(id, "test", valuesBuckets);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(id, rowCount);
}
/**
  * @tc.name: QueryWithDelete_001
  * @tc.desc: 10 records with a total of less than 2M data,
  * delete 3 records, rowCount equals 7 records.
  * @tc.type: FUNC
  */
HWTEST_F(QueryWithCrudTest, QueryWithDelete_001, TestSize.Level1)
{
    InsertData(10, 1);
    AbsRdbPredicates predicates("test");
    auto resultSet = rdbStore_->Query(predicates);
    ASSERT_NE(resultSet, nullptr);
    predicates.Between("age", 5, 7);
    int deletedRows;
    auto res = rdbStore_->Delete(deletedRows, predicates);
    EXPECT_EQ(deletedRows, 3);
    EXPECT_EQ(res, E_OK);
    int errCode = E_OK;
    while ((errCode = resultSet->GoToNextRow()) == E_OK) {
    }
    EXPECT_EQ(errCode, E_ROW_OUT_RANGE);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_EQ(count, 7);
}

/**
  * @tc.name: QueryWithDelete_002
  * @tc.desc: 10 pieces of 1M data, delete 3 pieces, rowCount equals 7 pieces.
  * @tc.type: FUNC
  */
HWTEST_F(QueryWithCrudTest, QueryWithDelete_002, TestSize.Level1)
{
    InsertData(10, 1024 * 1024);
    AbsRdbPredicates predicates("test");
    auto resultSet = rdbStore_->Query(predicates);
    ASSERT_NE(resultSet, nullptr);
    predicates.Between("age", 5, 7);
    int deletedRows;
    auto res = rdbStore_->Delete(deletedRows, predicates);
    EXPECT_EQ(deletedRows, 3);
    EXPECT_EQ(res, E_OK);
    int errCode = E_OK;
    while ((errCode = resultSet->GoToNextRow()) == E_OK) {
    }
    EXPECT_EQ(errCode, E_ROW_OUT_RANGE);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_EQ(count, 7);
}

/**
  * @tc.name: QueryWithDelete_003
  * @tc.desc: Single data exceeding 2M can return an error normally
  * @tc.type: FUNC
  */
HWTEST_F(QueryWithCrudTest, QueryWithDelete_003, TestSize.Level1)
{
    InsertData(2, 1024 * 1024 * 2);
    AbsRdbPredicates predicates("test");
    auto resultSet = rdbStore_->Query(predicates);
    ASSERT_NE(resultSet, nullptr);
    predicates.EqualTo("age", 1);
    int deletedRows;
    auto res = rdbStore_->Delete(deletedRows, predicates);
    EXPECT_EQ(deletedRows, 1);
    EXPECT_EQ(res, E_OK);
    int errCode = E_OK;
    while ((errCode = resultSet->GoToNextRow()) == E_OK) {
    }
    EXPECT_EQ(errCode, E_ERROR);
}

/**
  * @tc.name: QueryWithDelete_004
  * @tc.desc: 2 pieces of single 2M data, delete 2 pieces, rowCount equals 0.
  * @tc.type: FUNC
  */
HWTEST_F(QueryWithCrudTest, QueryWithDelete_004, TestSize.Level1)
{
    InsertData(2, 1024 * 1024 * 2);
    AbsRdbPredicates predicates("test");
    auto resultSet = rdbStore_->Query(predicates);
    ASSERT_NE(resultSet, nullptr);
    predicates.Between("age", 0, 1);
    int deletedRows;
    auto res = rdbStore_->Delete(deletedRows, predicates);
    EXPECT_EQ(deletedRows, 2);
    EXPECT_EQ(res, E_OK);
    int errCode = E_OK;
    while ((errCode = resultSet->GoToNextRow()) == E_OK) {
    }
    EXPECT_EQ(errCode, E_ROW_OUT_RANGE);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_EQ(count, 0);
}

/**
  * @tc.name: QueryWithDelete_005
  * @tc.desc: 10 pieces of data, one of which is greater than 2M, the other 1M,
  * delete 9 pieces of data less than 1M, expect an error.
  * @tc.type: FUNC
  */
HWTEST_F(QueryWithCrudTest, QueryWithDelete_005, TestSize.Level1)
{
    InsertData(9, 2);
    InsertData(1, 1024 * 1024 * 2);
    AbsRdbPredicates predicates("test");
    auto resultSet = rdbStore_->Query(predicates);
    ASSERT_NE(resultSet, nullptr);
    predicates.Between("id", 1, 9);
    int deletedRows;
    auto res = rdbStore_->Delete(deletedRows, predicates);
    EXPECT_EQ(deletedRows, 9);
    EXPECT_EQ(res, E_OK);
    int errCode = E_OK;
    while ((errCode = resultSet->GoToNextRow()) == E_OK) {
    }
    EXPECT_EQ(errCode, E_ERROR);
}

/**
  * @tc.name: QueryWithDelete_006
  * @tc.desc: 10 pieces of data, one of which is greater than 2M, the other 1M,
  * delete data greater than 2M, rowCount is 9.
  * @tc.type: FUNC
  */
HWTEST_F(QueryWithCrudTest, QueryWithDelete_006, TestSize.Level1)
{
    InsertData(9, 2);
    InsertData(1, 1024 * 1024 * 2);
    AbsRdbPredicates predicates("test");
    auto resultSet = rdbStore_->Query(predicates);
    ASSERT_NE(resultSet, nullptr);
    predicates.EqualTo("id", 10);
    int deletedRows;
    auto res = rdbStore_->Delete(deletedRows, predicates);
    EXPECT_EQ(deletedRows, 1);
    EXPECT_EQ(res, E_OK);
    int errCode = E_OK;
    while ((errCode = resultSet->GoToNextRow()) == E_OK) {
    }
    EXPECT_EQ(errCode, E_ROW_OUT_RANGE);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_EQ(count, 9);
}

/**
  * @tc.name: QueryWithDelete_007
  * @tc.desc: 10 records with a total of less than 2M data,
  * delete 10 records, rowCount equals 0 records.
  * @tc.type: FUNC
  */
HWTEST_F(QueryWithCrudTest, QueryWithDelete_007, TestSize.Level1)
{
    InsertData(10, 2);
    AbsRdbPredicates predicates("test");
    auto resultSet = rdbStore_->Query(predicates);
    ASSERT_NE(resultSet, nullptr);
    int deletedRows;
    auto res = rdbStore_->Delete(deletedRows, predicates);
    EXPECT_EQ(deletedRows, 10);
    EXPECT_EQ(res, E_OK);
    int errCode = E_OK;
    while ((errCode = resultSet->GoToNextRow()) == E_OK) {
    }
    EXPECT_EQ(errCode, E_ROW_OUT_RANGE);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_EQ(count, 0);
}

/**
  * @tc.name: QueryWithInsert_001
  * @tc.desc: 10 pieces of data with a total size less than 2M, delete 3 pieces,
  * insert 1 piece of data with a single size less than 1M, rowCount is equal to 8.
  * @tc.type: FUNC
  */
HWTEST_F(QueryWithCrudTest, QueryWithInsert_001, TestSize.Level1)
{
    InsertData(10, 2);
    AbsRdbPredicates predicates("test");
    auto resultSet = rdbStore_->Query(predicates);
    ASSERT_NE(resultSet, nullptr);
    predicates.Between("age", 5, 7);
    int deletedRows;
    auto res = rdbStore_->Delete(deletedRows, predicates);
    EXPECT_EQ(deletedRows, 3);
    EXPECT_EQ(res, E_OK);
    InsertData(1, 2);
    int errCode = E_OK;
    while ((errCode = resultSet->GoToNextRow()) == E_OK) {
    }
    EXPECT_EQ(errCode, E_ROW_OUT_RANGE);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_EQ(count, 8);
}

/**
  * @tc.name: QueryWithInsert_002
  * @tc.desc: 10 pieces of data with a total size less than 2M, delete 4 pieces,
  * insert 3 pieces of data with a single size less than 2M, rowCount is equal to 9.
  * @tc.type: FUNC
  */
HWTEST_F(QueryWithCrudTest, QueryWithInsert_002, TestSize.Level1)
{
    InsertData(10, 1024 * 1024);
    AbsRdbPredicates predicates("test");
    auto resultSet = rdbStore_->Query(predicates);
    ASSERT_NE(resultSet, nullptr);
    predicates.Between("age", 1, 4);
    int deletedRows;
    auto res = rdbStore_->Delete(deletedRows, predicates);
    EXPECT_EQ(deletedRows, 4);
    EXPECT_EQ(res, E_OK);
    InsertData(3, 2);
    int errCode = E_OK;
    while ((errCode = resultSet->GoToNextRow()) == E_OK) {
    }
    EXPECT_EQ(errCode, E_ROW_OUT_RANGE);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_EQ(count, 9);
}

/**
  * @tc.name: QueryWithInsert_003
  * @tc.desc: 3 pieces of data larger than 2M, delete 2 pieces,
  * insert 1 piece of data smaller than 1M, expect an error.
  * @tc.type: FUNC
  */
HWTEST_F(QueryWithCrudTest, QueryWithInsert_003, TestSize.Level1)
{
    InsertData(3, 1024 * 1024 * 2);
    AbsRdbPredicates predicates("test");
    auto resultSet = rdbStore_->Query(predicates);
    ASSERT_NE(resultSet, nullptr);
    predicates.Between("age", 0, 1);
    int deletedRows;
    auto res = rdbStore_->Delete(deletedRows, predicates);
    EXPECT_EQ(deletedRows, 2);
    EXPECT_EQ(res, E_OK);
    InsertData(1, 2);
    int errCode = E_OK;
    while ((errCode = resultSet->GoToNextRow()) == E_OK) {
    }
    EXPECT_EQ(errCode, E_ERROR);
}

/**
  * @tc.name: QueryWithInsert_004
  * @tc.desc: 2 pieces of data larger than 2M, delete 2 pieces,
  * insert 1 piece of data smaller than 1M, rowCount is equal to 1.
  * @tc.type: FUNC
  */
HWTEST_F(QueryWithCrudTest, QueryWithInsert_004, TestSize.Level1)
{
    InsertData(2, 1024 * 1024 * 2);
    AbsRdbPredicates predicates("test");
    auto resultSet = rdbStore_->Query(predicates);
    ASSERT_NE(resultSet, nullptr);
    int deletedRows;
    auto res = rdbStore_->Delete(deletedRows, predicates);
    EXPECT_EQ(deletedRows, 2);
    EXPECT_EQ(res, E_OK);
    InsertData(1, 2);
    int errCode = E_OK;
    while ((errCode = resultSet->GoToNextRow()) == E_OK) {
    }
    EXPECT_EQ(errCode, E_ROW_OUT_RANGE);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_EQ(count, 1);
}

/**
  * @tc.name: QueryWithInsert_005
  * @tc.desc: 10 pieces of data with a total of less than 2M, delete 6 pieces,
  * insert 1 pieces of data with a single value greater than 2M, expect an error.
  * @tc.type: FUNC
  */
HWTEST_F(QueryWithCrudTest, QueryWithInsert_005, TestSize.Level1)
{
    InsertData(10, 2);
    AbsRdbPredicates predicates("test");
    auto resultSet = rdbStore_->Query(predicates);
    ASSERT_NE(resultSet, nullptr);
    predicates.Between("age", 0, 5);
    int deletedRows;
    auto res = rdbStore_->Delete(deletedRows, predicates);
    EXPECT_EQ(deletedRows, 6);
    EXPECT_EQ(res, E_OK);
    InsertData(1, 1024 * 1024 * 2);
    int errCode = E_OK;
    while ((errCode = resultSet->GoToNextRow()) == E_OK) {
    }
    EXPECT_EQ(errCode, E_ERROR);
}

/**
  * @tc.name: QueryWithUpdate_001
  * @tc.desc: 10 records with a total of less than 2M data, updated 3 records, rowCount is 10.
  * @tc.type: FUNC
  */
HWTEST_F(QueryWithCrudTest, QueryWithUpdate_001, TestSize.Level1)
{
    InsertData(10, 2);
    AbsRdbPredicates predicates("test");
    auto resultSet = rdbStore_->Query(predicates);
    ASSERT_NE(resultSet, nullptr);
    int updatedRows;
    ValuesBucket values;
    std::vector<uint8_t> u8(2, 1);
    predicates.Between("age", 0, 2);
    values.Put("name", "zhangsan30");
    values.Put("age", 30);
    values.Put("salary", SALARY);
    values.Put("blobType", u8);
    auto res = rdbStore_->Update(updatedRows, values, predicates);
    EXPECT_EQ(updatedRows, 3);
    EXPECT_EQ(res, E_OK);
    int errCode = E_OK;
    while ((errCode = resultSet->GoToNextRow()) == E_OK) {
    }
    EXPECT_EQ(errCode, E_ROW_OUT_RANGE);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_EQ(count, 10);
}

/**
  * @tc.name: QueryWithUpdate_002
  * @tc.desc: 10 pieces of single data less than 1M, update 3 pieces, rowCount is 10.
  * @tc.type: FUNC
  */
HWTEST_F(QueryWithCrudTest, QueryWithUpdate_002, TestSize.Level1)
{
    InsertData(10, 2);
    AbsRdbPredicates predicates("test");
    auto resultSet = rdbStore_->Query(predicates);
    ASSERT_NE(resultSet, nullptr);
    int updatedRows;
    ValuesBucket values;
    std::vector<uint8_t> bigU8(1024 * 1024 * 2, 1);
    predicates.Between("age", 0, 2);
    values.Put("name", "zhangsan30");
    values.Put("age", 30);
    values.Put("salary", SALARY);
    values.Put("blobType", bigU8);
    auto res = rdbStore_->Update(updatedRows, values, predicates);
    EXPECT_EQ(updatedRows, 3);
    EXPECT_EQ(res, E_OK);
    int errCode = E_OK;
    while ((errCode = resultSet->GoToNextRow()) == E_OK) {
    }
    EXPECT_EQ(errCode, E_ERROR);
}

/**
  * @tc.name: QueryWithUpdate_003
  * @tc.desc: 2 pieces of data larger than 2M, update 2 pieces of data smaller than 1M,
  * rowCount is 2.
  * @tc.type: FUNC
  */
HWTEST_F(QueryWithCrudTest, QueryWithUpdate_003, TestSize.Level1)
{
    InsertData(2, 1024 * 1024 * 2);
    AbsRdbPredicates predicates("test");
    auto resultSet = rdbStore_->Query(predicates);
    ASSERT_NE(resultSet, nullptr);
    int updatedRows;
    ValuesBucket values;
    std::vector<uint8_t> u8(2, 1);
    predicates.Between("age", 0, 1);
    values.Put("name", "zhangsan30");
    values.Put("age", 30);
    values.Put("salary", SALARY);
    values.Put("blobType", u8);
    auto res = rdbStore_->Update(updatedRows, values, predicates);
    EXPECT_EQ(updatedRows, 2);
    EXPECT_EQ(res, E_OK);
    int errCode = E_OK;
    while ((errCode = resultSet->GoToNextRow()) == E_OK) {
    }
    EXPECT_EQ(errCode, E_ROW_OUT_RANGE);
    int count;
    resultSet->GetRowCount(count);
    EXPECT_EQ(count, 2);
}
} // namespace Test

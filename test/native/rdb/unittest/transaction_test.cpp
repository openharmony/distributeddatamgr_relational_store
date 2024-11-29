/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

using namespace testing::ext;
using namespace OHOS::NativeRdb;

static const std::string DATABASE_NAME = RDB_TEST_PATH + "transaction_test.db";
static const char CREATE_TABLE_SQL[] =
    "CREATE TABLE IF NOT EXISTS test "
    "(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB)";

class TransactionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    static inline std::shared_ptr<RdbStore> store_;

    class TransactionTestOpenCallback : public RdbOpenCallback {
    public:
        int OnCreate(RdbStore &store) override;
        int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    };
};

int TransactionTest::TransactionTestOpenCallback::OnCreate(RdbStore &store)
{
    auto [ret, value] = store.Execute(CREATE_TABLE_SQL);
    return ret;
}

int TransactionTest::TransactionTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void TransactionTest::SetUpTestCase()
{
    int errCode = E_OK;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
    RdbStoreConfig config(DATABASE_NAME);
    TransactionTestOpenCallback helper;
    TransactionTest::store_ = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(TransactionTest::store_, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void TransactionTest::TearDownTestCase()
{
    store_ = nullptr;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
}

void TransactionTest::SetUp()
{
    store_->Execute("DELETE FROM test");
}

void TransactionTest::TearDown()
{
}

/**
 * @tc.name: RdbStore_Transaction_001
 * @tc.desc: createTransaction and commit
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(1, result.second);

    result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(2, result.second);

    result = store->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[2]), RdbStore::NO_ACTION);
    ASSERT_EQ(result.first, E_SQLITE_BUSY);

    auto resultSet = transaction->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(rowCount, 2);

    ret = transaction->Commit();
    ASSERT_EQ(ret, E_OK);

    ValueObject value;
    ret = resultSet->Get(0, value);
    ASSERT_EQ(ret, E_ALREADY_CLOSED);

    result = store->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[2]), RdbStore::NO_ACTION);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(3, result.second);

    result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result.first, E_ALREADY_CLOSED);

    resultSet = store->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    resultSet->GetRowCount(rowCount);
    EXPECT_EQ(rowCount, 3);
}

/**
 * @tc.name: RdbStore_Transaction_002
 * @tc.desc: createTransaction and rollback
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(1, result.second);

    result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(2, result.second);

    ret = transaction->Rollback();
    ASSERT_EQ(ret, E_OK);

    auto resultSet = store->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(rowCount, 0);

    result = store->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[2]), RdbStore::NO_ACTION);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(3, result.second);

    result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result.first, E_ALREADY_CLOSED);

    resultSet = store->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowCount, 1);
}

/**
 * @tc.name: RdbStore_Transaction_003
 * @tc.desc: batchInsert
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    Transaction::Rows rows{
        UTUtils::SetRowData(UTUtils::g_rowData[0]),
        UTUtils::SetRowData(UTUtils::g_rowData[1]),
        UTUtils::SetRowData(UTUtils::g_rowData[2]),
    };
    auto result = transaction->BatchInsert("test", rows);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 3);

    ret = transaction->Commit();
    ASSERT_EQ(ret, E_OK);

    auto resultSet = store->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowCount, 3);
}

/**
 * @tc.name: RdbStore_Transaction_004
 * @tc.desc: batchInsert
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_004, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    Transaction::RefRows rows;
    rows.Put(UTUtils::SetRowData(UTUtils::g_rowData[0]));
    rows.Put(UTUtils::SetRowData(UTUtils::g_rowData[1]));
    rows.Put(UTUtils::SetRowData(UTUtils::g_rowData[2]));

    auto result = transaction->BatchInsert("test", rows);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 3);

    ret = transaction->Commit();
    ASSERT_EQ(ret, E_OK);

    auto resultSet = store->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowCount, 3);
}

/**
 * @tc.name: RdbStore_Transaction_005
 * @tc.desc: Update
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_005, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 1);

    result = transaction->Update("test", UTUtils::SetRowData(UTUtils::g_rowData[1]), "id=1");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 1);

    auto resultSet = transaction->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(rowCount, 1);
    ret = resultSet->GoToFirstRow();
    ASSERT_EQ(ret, E_OK);
    int32_t columnIndex{};
    ret = resultSet->GetColumnIndex("id", columnIndex);
    ASSERT_EQ(ret, E_OK);
    int32_t id{};
    ret = resultSet->GetInt(columnIndex, id);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(id, 2);

    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", ValueObject(2));
    result = transaction->Update(UTUtils::SetRowData(UTUtils::g_rowData[2]), predicates);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 1);

    ret = transaction->Commit();
    ASSERT_EQ(ret, E_OK);

    resultSet = store->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(rowCount, 1);
    ret = resultSet->GoToFirstRow();
    ASSERT_EQ(ret, E_OK);
    resultSet->GetColumnIndex("id", columnIndex);
    ret = resultSet->GetInt(columnIndex, id);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(id, 3);
}

/**
 * @tc.name: RdbStore_Transaction_006
 * @tc.desc: Delete
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_006, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    Transaction::RefRows rows;
    rows.Put(UTUtils::SetRowData(UTUtils::g_rowData[0]));
    rows.Put(UTUtils::SetRowData(UTUtils::g_rowData[1]));
    rows.Put(UTUtils::SetRowData(UTUtils::g_rowData[2]));

    auto result = transaction->BatchInsert("test", rows);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 3);

    result = transaction->Delete("test", "id=1");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 1);

    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", ValueObject(2));
    result = transaction->Delete(predicates);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 1);

    ret = transaction->Commit();
    ASSERT_EQ(ret, E_OK);

    auto resultSet = store->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(rowCount, 1);
    ret = resultSet->GoToFirstRow();
    ASSERT_EQ(ret, E_OK);
    int32_t columnIndex{};
    resultSet->GetColumnIndex("id", columnIndex);
    int32_t id{};
    ret = resultSet->GetInt(columnIndex, id);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(id, 3);
}

/**
 * @tc.name: RdbStore_Transaction_007
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_007, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto res = transaction->Execute(
        "CREATE TABLE IF NOT EXISTS test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
    ASSERT_EQ(res.first, E_OK);
    Transaction::Row row;
    row.Put("id", 1);
    row.Put("name", "Jim");
    auto result = transaction->Insert("test1", row);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 1);

    ret = transaction->Commit();
    ASSERT_EQ(ret, E_OK);

    auto resultSet = store->QueryByStep("SELECT * FROM test1");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowCount, 1);
}

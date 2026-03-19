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
#include <cstdlib>

#include "abs_rdb_predicates.h"
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
    ASSERT_NE(TransactionTest::store_, nullptr);
    ASSERT_EQ(errCode, E_OK);
}

void TransactionTest::TearDownTestCase()
{
    store_ = nullptr;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
}

void TransactionTest::SetUp()
{
    ASSERT_NE(store_, nullptr);
    store_->Execute("DELETE FROM test");
}

void TransactionTest::TearDown()
{
}

/**
 * @tc.name: RdbStore_Transaction_051
 * @tc.desc: abnormal testcase of trigger update with returning in trans.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_051, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [res, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(res, E_OK);
    ASSERT_NE(transaction, nullptr);
    
    auto [code, result1] = transaction->Execute(
        "CREATE TRIGGER before_delete BEFORE DELETE ON test"
        " BEGIN UPDATE test SET name = 'li' WHERE name = 'zhao'; END");
    EXPECT_EQ(code, E_OK);

    ValuesBuckets rows;
    ValuesBucket row;
    row.Put("id", 201);
    row.Put("name", "zhang");
    rows.Put(std::move(row));
    row.Put("id", 202);
    row.Put("name", "zhao");
    rows.Put(std::move(row));

    auto [status, result] =
        transaction->BatchInsert("test", rows, { "name" }, ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 2);
    ASSERT_NE(result.results, nullptr);

    AbsRdbPredicates predicates("test");
    predicates.EqualTo("name", "zhang");
    std::tie(status, result) = transaction->Delete(predicates, { "name" });

    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1);
    int rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    ASSERT_EQ(rowCount, 1);
    std::string value;
    ASSERT_EQ(result.results->GetString(0, value), E_OK);
    EXPECT_EQ(value, "zhang");

    // Check the trigger effect
    AbsRdbPredicates predicates1("test");
    predicates1.EqualTo("id", 202);
    auto [queryResult, queryStatus] = transaction->QueryByStep("select name from test where id = 202");

    rowCount = -1;
    queryResult->GetRowCount(rowCount);
    ASSERT_EQ(rowCount, 1);
    ASSERT_EQ(queryResult->GoToNextRow(), E_OK);

    value.clear();
    EXPECT_EQ(E_OK, queryResult->GetString(0, value));
    EXPECT_EQ(value, "li");

    transaction->Execute("DROP TRIGGER IF EXISTS before_update");

    int ret = transaction->Rollback();
    EXPECT_EQ(ret, E_OK);
}
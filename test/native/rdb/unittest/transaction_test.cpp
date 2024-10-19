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
    EXPECT_EQ(ret, E_OK);
    EXPECT_NE(transaction, nullptr);

    auto result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(result.first, E_OK);
    EXPECT_EQ(1, result.second);

    result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(result.first, E_OK);
    EXPECT_EQ(2, result.second);

    result = store->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[2]), RdbStore::NO_ACTION);
    EXPECT_EQ(result.first, E_SQLITE_BUSY);

    auto resultSet = transaction->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    if (resultSet != nullptr) {
        int32_t rowCount{};
        ret = resultSet->GetRowCount(rowCount);
        EXPECT_EQ(ret, E_OK);
        EXPECT_EQ(rowCount, 2);
    }

    ret = transaction->Commit();
    EXPECT_EQ(ret, E_OK);

    if (resultSet != nullptr) {
        ValueObject value;
        ret = resultSet->Get(0, value);
        EXPECT_EQ(ret, E_ALREADY_CLOSED);
    }

    result = store->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[2]), RdbStore::NO_ACTION);
    EXPECT_EQ(result.first, E_OK);
    EXPECT_EQ(3, result.second);

    result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(result.first, E_ALREADY_CLOSED);

    resultSet = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    if (resultSet != nullptr) {
        int32_t rowCount{};
        resultSet->GetRowCount(rowCount);
        EXPECT_EQ(rowCount, 3);
    }
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
    EXPECT_EQ(ret, E_OK);
    EXPECT_NE(transaction, nullptr);

    auto result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(result.first, E_OK);
    EXPECT_EQ(1, result.second);

    result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(result.first, E_OK);
    EXPECT_EQ(2, result.second);

    ret = transaction->Rollback();
    EXPECT_EQ(ret, E_OK);

    auto resultSet = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    if (resultSet != nullptr) {
        int32_t rowCount{};
        ret = resultSet->GetRowCount(rowCount);
        EXPECT_EQ(ret, E_OK);
        EXPECT_EQ(rowCount, 0);
    }

    result = store->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[2]), RdbStore::NO_ACTION);
    EXPECT_EQ(result.first, E_OK);
    EXPECT_EQ(3, result.second);

    result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(result.first, E_ALREADY_CLOSED);

    resultSet = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    if (resultSet != nullptr) {
        int32_t rowCount{};
        ret = resultSet->GetRowCount(rowCount);
        EXPECT_EQ(ret, E_OK);
        EXPECT_EQ(rowCount, 1);
    }
}

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
#include <random>

#include "common.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "sqlite_global_config.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbWalLimitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static std::vector<uint8_t> CreateRandomData(int32_t len);
    static void MakeWalReachLimit();
    static void MakeWalNoReachLimit();
    static void MakeWalIncrease();
    static void KeepReadConnection();
    static ValuesBucket MakeValueBucket();

    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;
    static std::unique_ptr<ResultSet> resultSet;
};

const std::string RdbWalLimitTest::DATABASE_NAME = RDB_TEST_PATH + "walLimit_test.db";
std::shared_ptr<RdbStore> RdbWalLimitTest::store = nullptr;
std::unique_ptr<ResultSet> RdbWalLimitTest::resultSet = nullptr;

// create 1M data
std::vector<uint8_t> blobValue = RdbWalLimitTest::CreateRandomData(1 * 1024 * 1024);
ValuesBucket values = RdbWalLimitTest::MakeValueBucket();

class RdbWalLimitCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &rdbStore) override;
    int OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

const std::string RdbWalLimitCallback::CREATE_TABLE_TEST("CREATE TABLE IF NOT EXISTS test "
    "(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB)");

int RdbWalLimitCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int RdbWalLimitCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbWalLimitTest::SetUpTestCase(void)
{
}

void RdbWalLimitTest::TearDownTestCase(void)
{
}

void RdbWalLimitTest::SetUp(void)
{
    int errCode = E_OK;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
    RdbStoreConfig config(DATABASE_NAME);
    RdbWalLimitCallback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void RdbWalLimitTest::TearDown(void)
{
    if (resultSet != nullptr) {
        EXPECT_EQ(resultSet->Close(), E_OK);
        resultSet = nullptr;
    }

    store = nullptr;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
}

std::vector<uint8_t> RdbWalLimitTest::CreateRandomData(int32_t len)
{
    std::random_device randomDevice;
    std::uniform_int_distribution<int> distribution(0, std::numeric_limits<uint8_t>::max());
    std::vector<uint8_t> value(len);
    for (int32_t i = 0; i < len; i++) {
        value[i] = static_cast<uint8_t>(distribution(randomDevice));
    }
    return value;
}

void RdbWalLimitTest::KeepReadConnection()
{
    int64_t id;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.8);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    EXPECT_EQ(store->Insert(id, "test", values), E_OK);

    resultSet = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    int count = 0;
    EXPECT_EQ(resultSet->GetRowCount(count), E_OK);
    EXPECT_EQ(count, 1);

    EXPECT_EQ(resultSet->GoToFirstRow(), E_OK);
}

void RdbWalLimitTest::MakeWalIncrease()
{
    int64_t id;
    ValuesBucket values;
    for (int i = 1; i < 199; i++) {
        values.Clear();
        values.PutInt("id", i);
        values.PutString("name", std::string("lisi"));
        values.PutInt("age", 18);
        values.PutDouble("salary", 200.8);
        values.PutBlob("blobType", blobValue);
        EXPECT_EQ(store->Insert(id, "test", values), E_OK);
    }
}

void RdbWalLimitTest::MakeWalReachLimit()
{
    int64_t id;
    int i = 1;
    int ret = E_OK;
    ValuesBucket values;
    while (ret == E_OK) {
        i++;
        values.Clear();
        values.PutInt("id", i);
        values.PutString("name", std::string("lisi"));
        values.PutInt("age", 18);
        values.PutDouble("salary", 200.8);
        values.PutBlob("blobType", blobValue);
        ret = store->Insert(id, "test", values);
    }
}

void RdbWalLimitTest::MakeWalNoReachLimit()
{
    int64_t id;
    ValuesBucket values;
    for (int i = 2; i < 20; i++) {
        values.Clear();
        values.PutInt("id", i);
        values.PutString("name", std::string("lisi"));
        values.PutInt("age", 18);
        values.PutDouble("salary", 200.8);
        values.PutBlob("blobType", blobValue);
        EXPECT_EQ(store->Insert(id, "test", values), E_OK);
    }
}

ValuesBucket RdbWalLimitTest::MakeValueBucket()
{
    ValuesBucket values;
    values.PutInt("id", 200);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.8);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    return values;
}

/**
 * @tc.name: RdbStore_WalOverLimit_001
 * @tc.desc: Without reading data, the WAL size will not over default limit if write data continuously.
 * @tc.type: FUNC
 * @tc.acquire: AR000HR0G5
 */
HWTEST_F(RdbWalLimitTest, RdbStore_WalOverLimit_001, TestSize.Level1)
{
    MakeWalIncrease();

    int64_t id;
    EXPECT_EQ(store->Insert(id, "test", values), E_OK);

    int changedRows;
    EXPECT_EQ(store->Update(changedRows, "test", values, "id = ?", std::vector<std::string>{ "200" }), E_OK);

    EXPECT_EQ(store->Replace(id, "test", values), E_OK);

    int deletedRows;
    EXPECT_EQ(store->Delete(deletedRows, "test", "id = 200"), E_OK);

    std::vector<ValuesBucket> valuesBuckets;
    for (int i = 0; i < 10; i++) {
        valuesBuckets.push_back(values);
    }

    int64_t insertNum = 0;
    EXPECT_EQ(store->BatchInsert(insertNum, "test", valuesBuckets), E_OK);

    EXPECT_EQ(store->ExecuteSql("DELETE FROM test"), E_OK);
}

/**
 * @tc.name: RdbStore_WalOverLimit_002
 * @tc.desc: While reading data and writing data continuously if the WAL size not over default limit.
 * @tc.type: FUNC
 * @tc.acquire: AR000HR0G5
 */
HWTEST_F(RdbWalLimitTest, RdbStore_WalOverLimit_002, TestSize.Level1)
{
    KeepReadConnection();
    MakeWalNoReachLimit();

    int changedRows;
    EXPECT_EQ(store->Update(changedRows, "test", values, "id = ?", std::vector<std::string>{ "21" }), E_OK);

    int64_t id;
    EXPECT_EQ(store->Replace(id, "test", values), E_OK);

    int deletedRows;
    EXPECT_EQ(store->Delete(deletedRows, "test", "id = 21"), E_OK);

    std::vector<ValuesBucket> valuesBuckets;
    for (int i = 0; i < 10; i++) {
        valuesBuckets.push_back(values);
    }

    int64_t insertNum = 0;
    EXPECT_EQ(store->BatchInsert(insertNum, "test", valuesBuckets), E_OK);

    EXPECT_EQ(store->ExecuteSql("DELETE FROM test"), E_OK);
}

/**
 * @tc.name: RdbStore_WalOverLimit_003
 * @tc.desc: While reading data, can not write data continuously if the WAL size over default limit.
 * @tc.type: FUNC
 * @tc.acquire: AR000HR0G5
 */
HWTEST_F(RdbWalLimitTest, RdbStore_WalOverLimit_003, TestSize.Level3)
{
    KeepReadConnection();
    MakeWalReachLimit();

    int64_t id;
    EXPECT_EQ(store->Insert(id, "test", values), E_WAL_SIZE_OVER_LIMIT);

    EXPECT_EQ(store->BeginTransaction(), E_WAL_SIZE_OVER_LIMIT);

    int changedRows;
    EXPECT_EQ(store->Update(changedRows, "test", values, "id = ?", std::vector<std::string>{ "200" }),
        E_WAL_SIZE_OVER_LIMIT);

    EXPECT_EQ(store->Replace(id, "test", values), E_WAL_SIZE_OVER_LIMIT);

    int deletedRows;
    EXPECT_EQ(store->Delete(deletedRows, "test", "id = 200"), E_WAL_SIZE_OVER_LIMIT);

    std::vector<ValuesBucket> valuesBuckets;
    for (int i = 0; i < 2; i++) {
        valuesBuckets.push_back(values);
    }
    int64_t insertNum = 0;
    EXPECT_EQ(store->BatchInsert(insertNum, "test", valuesBuckets), E_WAL_SIZE_OVER_LIMIT);

    EXPECT_EQ(store->ExecuteSql("DELETE FROM test"), E_WAL_SIZE_OVER_LIMIT);

    int64_t outLong;
    EXPECT_EQ(store->ExecuteAndGetLong(outLong, "DELETE FROM test"), E_WAL_SIZE_OVER_LIMIT);
}

/**
 * @tc.name: RdbStore_WalOverLimit_004
 * @tc.desc: Writing data after closing read connection.
 * @tc.type: FUNC
 * @tc.acquire: AR000HR0G5
 */
HWTEST_F(RdbWalLimitTest, RdbStore_WalOverLimit_004, TestSize.Level3)
{
    KeepReadConnection();
    MakeWalReachLimit();

    int64_t id;
    EXPECT_EQ(store->Insert(id, "test", values), E_WAL_SIZE_OVER_LIMIT);

    EXPECT_EQ(resultSet->Close(), E_OK);

    {
        store->BeginTransaction();
        EXPECT_EQ(store->Insert(id, "test", values), E_OK);
        store->Commit();
    }

    int changedRows;
    EXPECT_EQ(store->Update(changedRows, "test", values, "id = ?", std::vector<std::string>{ "200" }), E_OK);

    EXPECT_EQ(store->Replace(id, "test", values), E_OK);

    int deletedRows;
    EXPECT_EQ(store->Delete(deletedRows, "test", "id = 200"), E_OK);

    std::vector<ValuesBucket> valuesBuckets;
    for (int i = 0; i < 2; i++) {
        valuesBuckets.push_back(values);
    }
    int64_t insertNum = 0;
    EXPECT_EQ(store->BatchInsert(insertNum, "test", valuesBuckets), E_OK);

    EXPECT_EQ(store->ExecuteSql("DELETE FROM test"), E_OK);
}

/**
 * @tc.name: RdbStore_WalOverLimit_005
 * @tc.desc: While reading data and transaction will fail if the WAL file size over default size.
 * @tc.type: FUNC
 * @tc.acquire: AR000HR0G5
 */
HWTEST_F(RdbWalLimitTest, RdbStore_WalOverLimit_005, TestSize.Level3)
{
    KeepReadConnection();

    int64_t id;
    {
        store->BeginTransaction();
        MakeWalReachLimit();
        EXPECT_EQ(store->Insert(id, "test", values), E_WAL_SIZE_OVER_LIMIT);
        store->Commit();
    }

    int changedRows;
    EXPECT_EQ(store->Update(changedRows, "test", values, "id = ?", std::vector<std::string>{ "200" }),
        E_WAL_SIZE_OVER_LIMIT);

    EXPECT_EQ(store->Replace(id, "test", values), E_WAL_SIZE_OVER_LIMIT);

    int deletedRows;
    EXPECT_EQ(store->Delete(deletedRows, "test", "id = 200"),
    E_WAL_SIZE_OVER_LIMIT);

    std::vector<ValuesBucket> valuesBuckets;
    for (int i = 0; i < 2; i++) {
        valuesBuckets.push_back(values);
    }
    int64_t insertNum = 0;
    EXPECT_EQ(store->BatchInsert(insertNum, "test", valuesBuckets), E_WAL_SIZE_OVER_LIMIT);

    EXPECT_EQ(store->ExecuteSql("DELETE FROM test"), E_WAL_SIZE_OVER_LIMIT);
}

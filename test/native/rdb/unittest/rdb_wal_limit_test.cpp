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

#include <random>
#include <string>

#include "common.h"
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
    static ValuesBucket MakeValueBucket(const int &id);

    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;
    static std::shared_ptr<ResultSet> resultSet;
};

const std::string RdbWalLimitTest::DATABASE_NAME = RDB_TEST_PATH + "walLimit_test.db";
std::shared_ptr<RdbStore> RdbWalLimitTest::store = nullptr;
std::shared_ptr<ResultSet> RdbWalLimitTest::resultSet = nullptr;

// create 1M data
std::vector<uint8_t> blobValue = RdbWalLimitTest::CreateRandomData(1 * 1024 * 1024);

class RdbWalLimitCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
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

ValuesBucket RdbWalLimitTest::MakeValueBucket(const int &id)
{
    ValuesBucket values;
    values.PutInt("id", id);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 200.8);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    return values;
}

/**
 * @tc.name: RdbStore_WalOverLimit_001
 * @tc.desc: Without reading data or conducting transactions, if data is continuously written,
 * the WAL size will not exceed the default limit.
 * @tc.type: FUNC
 * @tc.acquire: AR000HR0G5
 */
HWTEST_F(RdbWalLimitTest, RdbStore_WalOverLimit_001, TestSize.Level1)
{
    MakeWalIncrease();

    int64_t id;

    ValuesBucket values = MakeValueBucket(199);
    values.PutBlob("blobType", blobValue);
    EXPECT_EQ(store->Insert(id, "test", values), E_OK);

    std::vector<ValuesBucket> valuesBuckets;
    for (int i = 200; i < 210; i++) {
        valuesBuckets.push_back(RdbWalLimitTest::MakeValueBucket(i));
    }

    int64_t insertNum = 0;
    EXPECT_EQ(store->BatchInsert(insertNum, "test", valuesBuckets), E_OK);

    EXPECT_EQ(store->ExecuteSql("DELETE FROM test"), E_OK);
}

/**
 * @tc.name: RdbStore_WalOverLimit_002
 * @tc.desc: Before the wal file exceeds the limit, both read and write can be executed normally.
 * @tc.type: FUNC
 * @tc.acquire: AR000HR0G5
 */
HWTEST_F(RdbWalLimitTest, RdbStore_WalOverLimit_002, TestSize.Level1)
{
    KeepReadConnection();
    MakeWalNoReachLimit();
    ValuesBucket values = MakeValueBucket(20);

    std::vector<ValuesBucket> valuesBuckets;
    for (int i = 21; i < 30; i++) {
        valuesBuckets.push_back(MakeValueBucket(i));
    }

    int64_t insertNum = 0;
    EXPECT_EQ(store->BatchInsert(insertNum, "test", valuesBuckets), E_OK);

    EXPECT_EQ(store->ExecuteSql("DELETE FROM test"), E_OK);
}

/**
 * @tc.name: RdbStore_WalOverLimit_003
 * @tc.desc: During transactions, the size of the wal file may exceed the limit.
 * @tc.type: FUNC
 * @tc.acquire: AR000HR0G5
 */
HWTEST_F(RdbWalLimitTest, RdbStore_WalOverLimit_003, TestSize.Level3)
{
    ValuesBucket values = MakeValueBucket(200);
    int64_t id;
    store->BeginTransaction();
    MakeWalReachLimit();
    EXPECT_EQ(store->Insert(id, "test", values), E_WAL_SIZE_OVER_LIMIT);
    store->Commit();
}
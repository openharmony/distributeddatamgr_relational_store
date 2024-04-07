/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#define LOG_TAG "RdbBigIntTest"
#include <gtest/gtest.h>
#include "rdb_helper.h"
#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
using namespace testing::ext;
using namespace OHOS::NativeRdb;
namespace Test {
class RdbBigIntTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    class RdbCallback : public RdbOpenCallback {
    public:
        int OnCreate(RdbStore& store) override
        {
            return E_OK;
        }
        int OnUpgrade(RdbStore& store, int oldVersion, int newVersion) override
        {
            return E_OK;
        }
    };
    using Floats = ValueObject::FloatVector;
    static constexpr const char* PATH_NAME = "/data/test/bigint_test.db";
    static constexpr const char* DATABASE_NAME = "bigint_test.db";
    static constexpr const char* CREATE_TABLE =
        "CREATE TABLE IF NOT EXISTS bigint_table(id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "value1 UNLIMITED INT NOT NULL, value2 UNLIMITED INT, value3 VECS)";
    static constexpr const char* DROP_TABLE = "DROP TABLE IF EXISTS bigint_table";
    static std::shared_ptr<RdbStore> rdbStore_;
};
std::shared_ptr<RdbStore> RdbBigIntTest::rdbStore_;
void RdbBigIntTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    RdbCallback callback;
    RdbStoreConfig config(PATH_NAME);
    config.SetName(DATABASE_NAME);
    RdbHelper::DeleteRdbStore(PATH_NAME);
    rdbStore_ = RdbHelper::GetRdbStore(config, 1, callback, errCode);
    EXPECT_NE(rdbStore_, nullptr);
}

void RdbBigIntTest::TearDownTestCase(void)
{
    rdbStore_ = nullptr;
    RdbHelper::DeleteRdbStore(PATH_NAME);
}

void RdbBigIntTest::SetUp(void)
{
    rdbStore_->ExecuteSql(DROP_TABLE);
    rdbStore_->ExecuteSql(CREATE_TABLE);
}

void RdbBigIntTest::TearDown(void)
{
    rdbStore_->ExecuteSql(DROP_TABLE);
}

/**
 * @tc.name: Insert_BigInt_INT64
 * @tc.desc: test insert bigint to rdb store
 * @tc.type: FUNC
 */
HWTEST_F(RdbBigIntTest, Insert_BigInt_INT64, TestSize.Level1)
{
    int64_t outRowId = -1;
    ValuesBucket bucket;
    bucket.Put("value1", BigInteger(158));
    bucket.Put("value2", BigInteger(-158));
    auto status = rdbStore_->Insert(outRowId, "bigint_table", bucket);
    EXPECT_EQ(status, E_OK);
    auto resultSet = rdbStore_->QuerySql("select value1, value2 from bigint_table");
    EXPECT_NE(resultSet, nullptr);
    while (resultSet->GoToNextRow() == E_OK) {
        RowEntity entity;
        status = resultSet->GetRow(entity);
        EXPECT_EQ(status, E_OK);
        auto value = entity.Get("value1");
        auto val = std::get_if<BigInteger>(&value.value);
        EXPECT_NE(val, nullptr);
        if (val != nullptr) {
            EXPECT_TRUE(*val == BigInteger(158));
        }
        value = entity.Get("value2");
        val = std::get_if<BigInteger>(&value.value);
        EXPECT_NE(val, nullptr);
        if (val != nullptr) {
            EXPECT_TRUE(*val == BigInteger(-158));
        }
    }
}

/**
 * @tc.name: Insert_Step_BigInt_INT64
 * @tc.desc: test insert bigint to rdb store
 * @tc.type: FUNC
 */
HWTEST_F(RdbBigIntTest, Insert_Step_BigInt_INT64, TestSize.Level1)
{
    int64_t outRowId = -1;
    ValuesBucket bucket;
    bucket.Put("value1", BigInteger(158));
    bucket.Put("value2", BigInteger(-158));
    auto status = rdbStore_->Insert(outRowId, "bigint_table", bucket);
    EXPECT_EQ(status, E_OK);
    auto resultSet = rdbStore_->QueryByStep("select value1, value2 from bigint_table");
    EXPECT_NE(resultSet, nullptr);
    while (resultSet->GoToNextRow() == E_OK) {
        RowEntity entity;
        status = resultSet->GetRow(entity);
        EXPECT_EQ(status, E_OK);
        auto value = entity.Get("value1");
        auto val = std::get_if<BigInteger>(&value.value);
        EXPECT_NE(val, nullptr);
        if (val != nullptr) {
            EXPECT_TRUE(*val == BigInteger(158));
        }
        value = entity.Get("value2");
        val = std::get_if<BigInteger>(&value.value);
        EXPECT_NE(val, nullptr);
        if (val != nullptr) {
            EXPECT_TRUE(*val == BigInteger(-158));
        }
    }
}

/**
 * @tc.name: Insert_BigInt_INT128
 * @tc.desc: test insert bigint to rdb store
 * @tc.type: FUNC
 */
HWTEST_F(RdbBigIntTest, Insert_BigInt_INT128, TestSize.Level1)
{
    int64_t outRowId = -1;
    BigInteger value1 = BigInteger(0, std::vector<uint64_t>{158, 0xDEADDEADDEADDEAD});
    BigInteger value2 = BigInteger(1, std::vector<uint64_t>{158, 0xDEADDEADDEADDEAD});
    ValuesBucket bucket;
    bucket.Put("value1", value1);
    bucket.Put("value2", value2);
    auto status = rdbStore_->Insert(outRowId, "bigint_table", bucket);
    EXPECT_EQ(status, E_OK);
    auto resultSet = rdbStore_->QuerySql("select value1, value2 from bigint_table");
    EXPECT_NE(resultSet, nullptr);
    while (resultSet->GoToNextRow() == E_OK) {
        RowEntity entity;
        status = resultSet->GetRow(entity);
        EXPECT_EQ(status, E_OK);
        auto value = entity.Get("value1");
        auto val = std::get_if<BigInteger>(&value.value);
        EXPECT_NE(val, nullptr);
        if (val != nullptr) {
            EXPECT_TRUE(*val == value1);
        }
        value = entity.Get("value2");
        val = std::get_if<BigInteger>(&value.value);
        EXPECT_NE(val, nullptr);
        if (val != nullptr) {
            EXPECT_TRUE(*val == value2);
        }
    }
}

/**
 * @tc.name: Insert_BigInt_INT128
 * @tc.desc: test insert bigint to rdb store
 * @tc.type: FUNC
 */
HWTEST_F(RdbBigIntTest, GetValue_BigInt_INT128, TestSize.Level1)
{
    int64_t outRowId = -1;
    BigInteger value1 = BigInteger(0, std::vector<uint64_t>{158, 0xDEADDEADDEADDEAD});
    BigInteger value2 = BigInteger(1, std::vector<uint64_t>{158, 0xDEADDEADDEADDEAD});
    ValuesBucket bucket;
    bucket.Put("value1", value1);
    bucket.Put("value2", value2);
    auto status = rdbStore_->Insert(outRowId, "bigint_table", bucket);
    EXPECT_EQ(status, E_OK);
    auto resultSet = rdbStore_->QuerySql("select value1, value2 from bigint_table");
    EXPECT_NE(resultSet, nullptr);
    while (resultSet->GoToNextRow() == E_OK) {
        ValueObject object;
        status = resultSet->Get(0, object);
        EXPECT_EQ(status, E_OK);
        auto val = std::get_if<BigInteger>(&object.value);
        EXPECT_NE(val, nullptr);
        if (val != nullptr) {
            EXPECT_TRUE(*val == value1);
        }
        status = resultSet->Get(1, object);
        EXPECT_EQ(status, E_OK);
        val = std::get_if<BigInteger>(&object.value);
        EXPECT_NE(val, nullptr);
        if (val != nullptr) {
            EXPECT_TRUE(*val == value2);
        }
    }
}

/**
 * @tc.name: Insert_Step_BigInt_INT128
 * @tc.desc: test insert bigint to rdb store
 * @tc.type: FUNC
 */
HWTEST_F(RdbBigIntTest, Insert_Step_BigInt_INT128, TestSize.Level1)
{
    int64_t outRowId = -1;
    BigInteger value1 = BigInteger(0, std::vector<uint64_t>{158, 0xDEADDEADDEADDEAD});
    BigInteger value2 = BigInteger(1, std::vector<uint64_t>{158, 0xDEADDEADDEADDEAD});
    ValuesBucket bucket;
    bucket.Put("value1", value1);
    bucket.Put("value2", value2);
    auto status = rdbStore_->Insert(outRowId, "bigint_table", bucket);
    EXPECT_EQ(status, E_OK);
    auto resultSet = rdbStore_->QueryByStep("select value1, value2 from bigint_table");
    EXPECT_NE(resultSet, nullptr);
    while (resultSet->GoToNextRow() == E_OK) {
        RowEntity entity;
        status = resultSet->GetRow(entity);
        EXPECT_EQ(status, E_OK);
        auto value = entity.Get("value1");
        auto val = std::get_if<BigInteger>(&value.value);
        EXPECT_NE(val, nullptr);
        if (val != nullptr) {
            EXPECT_TRUE(*val == value1);
        }
        value = entity.Get("value2");
        val = std::get_if<BigInteger>(&value.value);
        EXPECT_NE(val, nullptr);
        if (val != nullptr) {
            EXPECT_TRUE(*val == value2);
        }
    }
}

/**
 * @tc.name: Insert_BigInt_INTRand
 * @tc.desc: test insert bigint to rdb store
 * @tc.type: FUNC
 */
HWTEST_F(RdbBigIntTest, Insert_BigInt_INTRand, TestSize.Level1)
{
    int64_t outRowId = -1;
    std::vector<uint64_t> u64Val(2 + rand() % 100, 0);
    for (int i = 0; i < u64Val.size(); ++i) {
        uint64_t high = uint64_t(rand());
        uint64_t low = uint64_t(rand());
        u64Val[i] = (high << 32) |  low;
    }
    BigInteger value1 = BigInteger(0, std::vector<uint64_t>(u64Val));
    BigInteger value2 = BigInteger(1, std::vector<uint64_t>(u64Val));
    ValuesBucket bucket;
    bucket.Put("value1", value1);
    bucket.Put("value2", value2);
    auto status = rdbStore_->Insert(outRowId, "bigint_table", bucket);
    EXPECT_EQ(status, E_OK);
    auto resultSet = rdbStore_->QuerySql("select value1, value2 from bigint_table");
    EXPECT_NE(resultSet, nullptr);
    while (resultSet->GoToNextRow() == E_OK) {
        RowEntity entity;
        status = resultSet->GetRow(entity);
        EXPECT_EQ(status, E_OK);
        auto value = entity.Get("value1");
        auto val = std::get_if<BigInteger>(&value.value);
        EXPECT_NE(val, nullptr);
        if (val != nullptr) {
            EXPECT_TRUE(*val == value1);
        }
        value = entity.Get("value2");
        val = std::get_if<BigInteger>(&value.value);
        EXPECT_NE(val, nullptr);
        if (val != nullptr) {
            EXPECT_TRUE(*val == value2);
        }
    }
}

/**
 * @tc.name: Insert_Step_BigInt_INTRand
 * @tc.desc: test insert bigint to rdb store
 * @tc.type: FUNC
 */
HWTEST_F(RdbBigIntTest, Insert_Step_BigInt_INTRand, TestSize.Level1)
{
    int64_t outRowId = -1;
    std::vector<uint64_t> u64Val(2 + rand() % 100, 0);
    for (int i = 0; i < u64Val.size(); ++i) {
        uint64_t high = uint64_t(rand());
        uint64_t low = uint64_t(rand());
        u64Val[i] = (high << 32) |  low;
    }
    BigInteger value1 = BigInteger(0, std::vector<uint64_t>(u64Val));
    BigInteger value2 = BigInteger(1, std::vector<uint64_t>(u64Val));
    ValuesBucket bucket;
    bucket.Put("value1", value1);
    bucket.Put("value2", value2);
    auto status = rdbStore_->Insert(outRowId, "bigint_table", bucket);
    EXPECT_EQ(status, E_OK);
    auto resultSet = rdbStore_->QueryByStep("select value1, value2 from bigint_table");
    EXPECT_NE(resultSet, nullptr);
    while (resultSet->GoToNextRow() == E_OK) {
        RowEntity entity;
        status = resultSet->GetRow(entity);
        EXPECT_EQ(status, E_OK);
        auto value = entity.Get("value1");
        auto val = std::get_if<BigInteger>(&value.value);
        EXPECT_NE(val, nullptr);
        if (val != nullptr) {
            EXPECT_TRUE(*val == value1);
        }
        value = entity.Get("value2");
        val = std::get_if<BigInteger>(&value.value);
        EXPECT_NE(val, nullptr);
        if (val != nullptr) {
            EXPECT_TRUE(*val == value2);
        }
    }
}

/**
 * @tc.name: Insert_Floats
 * @tc.desc: test insert bigint to rdb store
 * @tc.type: FUNC
 */
HWTEST_F(RdbBigIntTest, Insert_Floats, TestSize.Level1)
{
    int64_t outRowId = -1;
    std::vector<uint64_t> u64Val(2 + rand() % 100, 0);
    for (int i = 0; i < u64Val.size(); ++i) {
        uint64_t high = uint64_t(rand());
        uint64_t low = uint64_t(rand());
        u64Val[i] = (high << 32) |  low;
    }
    BigInteger value1 = BigInteger(0, std::vector<uint64_t>(u64Val));
    BigInteger value2 = BigInteger(1, std::vector<uint64_t>(u64Val));
    Floats value3 = { 0.1, 2.2, 3.3, 0.5 };
    ValuesBucket bucket;
    bucket.Put("value1", value1);
    bucket.Put("value2", value2);
    bucket.Put("value3", value3);
    auto status = rdbStore_->Insert(outRowId, "bigint_table", bucket);
    EXPECT_EQ(status, E_OK);
    auto resultSet = rdbStore_->QuerySql("select * from bigint_table");
    EXPECT_NE(resultSet, nullptr);
    while (resultSet->GoToNextRow() == E_OK) {
        RowEntity entity;
        status = resultSet->GetRow(entity);
        EXPECT_EQ(status, E_OK);
        auto value = entity.Get("value3");
        auto val = std::get_if<Floats>(&value.value);
        EXPECT_NE(val, nullptr);
        if (val != nullptr) {
            EXPECT_EQ(*val, value3);
        }
    }
}

/**
 * @tc.name: Insert_Step_Floats
 * @tc.desc: test insert bigint to rdb store
 * @tc.type: FUNC
 */
HWTEST_F(RdbBigIntTest, Insert_Step_Floats, TestSize.Level1)
{
    int64_t outRowId = -1;
    std::vector<uint64_t> u64Val(2 + rand() % 100, 0);
    for (int i = 0; i < u64Val.size(); ++i) {
        uint64_t high = uint64_t(rand());
        uint64_t low = uint64_t(rand());
        u64Val[i] = (high << 32) |  low;
    }
    BigInteger value1 = BigInteger(0, std::vector<uint64_t>(u64Val));
    BigInteger value2 = BigInteger(1, std::vector<uint64_t>(u64Val));
    Floats value3 = { 0.1, 2.2, 3.3, 0.5 };
    ValuesBucket bucket;
    bucket.Put("value1", value1);
    bucket.Put("value2", value2);
    bucket.Put("value3", value3);
    auto status = rdbStore_->Insert(outRowId, "bigint_table", bucket);
    EXPECT_EQ(status, E_OK);
    auto resultSet = rdbStore_->QueryByStep("select * from bigint_table");
    EXPECT_NE(resultSet, nullptr);
    while (resultSet->GoToNextRow() == E_OK) {
        RowEntity entity;
        status = resultSet->GetRow(entity);
        EXPECT_EQ(status, E_OK);
        auto value = entity.Get("value3");
        auto val = std::get_if<Floats>(&value.value);
        EXPECT_NE(val, nullptr);
        if (val != nullptr) {
            EXPECT_EQ(*val, value3);
        }
    }
}
}

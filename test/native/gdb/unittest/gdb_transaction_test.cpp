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

#include "gdb_transaction.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <variant>

#include "edge.h"
#include "full_result.h"
#include "gdb_errors.h"
#include "gdb_helper.h"
#include "gdb_store.h"
#include "grd_adapter_manager.h"
#include "path.h"
#include "result.h"
#include "vertex.h"

using namespace testing::ext;
using namespace OHOS::DistributedDataAip;

using Transaction = OHOS::DistributedDataAip::Transaction;

class GdbTransactionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void InsertPerson(const std::string &name, const int32_t &age, std::shared_ptr<Transaction> trans = nullptr);
    void MatchAndVerifyPerson(const std::string &name, const int32_t &age,
        std::shared_ptr<Transaction> trans = nullptr, bool hasData = true);
    void VerifyPersonInfo(const GraphValue &person, const std::string &name, const int32_t &age);

    static const std::string databaseName;
    static const std::string databasePath;
    
    static const std::string createGraphGql;

    static std::shared_ptr<DBStore> store_;
};

const std::string GdbTransactionTest::databaseName = "transaction_test";
const std::string GdbTransactionTest::databasePath = "/data";

const std::string GdbTransactionTest::createGraphGql = "CREATE GRAPH test { "
                                                       "(person:Person {name STRING, age INT, sex BOOL DEFAULT false}),"
                                                       "(dog:Dog {name STRING, age INT}), "
                                                       "(person) -[:Friend]-> (person) "
                                                       "};";

std::shared_ptr<DBStore> GdbTransactionTest::store_;

static constexpr int32_t MAX_GQL_LEN = 1024 * 1024;

static constexpr int32_t MAX_CNT = 4;
static constexpr int32_t MAX_DATA_CNT = 200;

static constexpr int32_t BUSY_TIMEOUT = 2;
static constexpr int32_t EXECUTE_INTERVAL = 3;
static constexpr int32_t READ_INTERVAL = 100;

static constexpr int32_t UT_MAX_CONST_STRING_LEN = (64 * 1024);

void GdbTransactionTest::SetUpTestCase()
{
    if (!IsSupportArkDataDb()) {
        GTEST_SKIP() << "Current testcase is not compatible from current gdb";
        return;
    }
    int errCode = E_OK;
    auto config = StoreConfig(databaseName, databasePath);
    GDBHelper::DeleteDBStore(config);

    GdbTransactionTest::store_ = GDBHelper::GetDBStore(config, errCode);
}

void GdbTransactionTest::TearDownTestCase()
{
    GDBHelper::DeleteDBStore(StoreConfig(databaseName, databasePath));
    GdbTransactionTest::store_ = nullptr;
}

void GdbTransactionTest::SetUp()
{
    if (!IsSupportArkDataDb()) {
        GTEST_SKIP() << "Current testcase is not compatible from current gdb";
        return;
    }
    auto result = store_->ExecuteGql(createGraphGql);
}

void GdbTransactionTest::TearDown()
{
    if (store_ != nullptr) {
        auto result = store_->ExecuteGql("DROP GRAPH test");
    }
}

void GdbTransactionTest::InsertPerson(const std::string &name, const int32_t &age, std::shared_ptr<Transaction> trans)
{
    ASSERT_NE(store_, nullptr);
    int32_t errCode = E_OK;
    std::shared_ptr<Result> result = std::make_shared<FullResult>();
    std::string gql = "INSERT (:Person {name: '" + name + "', age: " + std::to_string(age) + "});";
    if (trans == nullptr) {
        std::tie(errCode, result) = store_->ExecuteGql(gql);
    } else {
        ASSERT_NE(trans, nullptr);
        std::tie(errCode, result) = trans->Execute(gql);
    }
    EXPECT_EQ(errCode, E_OK);
}

void GdbTransactionTest::MatchAndVerifyPerson(const std::string &name, const int32_t &age,
    std::shared_ptr<Transaction> trans, bool hasData)
{
    ASSERT_NE(store_, nullptr);
    int32_t errCode = E_OK;
    std::shared_ptr<Result> result = std::make_shared<FullResult>();
    std::string gql = "MATCH (person:Person {name: '" + name + "'}) RETURN person;";
    if (trans == nullptr) {
        std::tie(errCode, result) = store_->QueryGql(gql);
    } else {
        ASSERT_NE(trans, nullptr);
        std::tie(errCode, result) = trans->Query(gql);
    }
    ASSERT_EQ(errCode, E_OK);
    ASSERT_NE(result, nullptr);
    if (!hasData) {
        EXPECT_EQ(result->GetAllData().size(), 0);
        return;
    }
    EXPECT_EQ(result->GetAllData().size(), 1);
    GraphValue person = result->GetAllData()[0]["person"];
    VerifyPersonInfo(person, name, age);
}

void GdbTransactionTest::VerifyPersonInfo(const GraphValue &person, const std::string &name, const int32_t &age)
{
    auto expectSize = 3;
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Vertex>>(person));
    auto personVertex = std::get<std::shared_ptr<Vertex>>(person);
    EXPECT_EQ(personVertex->GetLabel(), "Person");
    ASSERT_EQ(personVertex->GetProperties().size(), expectSize);

    auto nameDb = personVertex->GetProperties().find("name");
    ASSERT_NE(nameDb, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<std::string>(nameDb->second));
    EXPECT_EQ(std::get<std::string>(nameDb->second), name);

    auto ageDb = personVertex->GetProperties().find("age");
    ASSERT_NE(ageDb, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<int64_t>(ageDb->second));
    EXPECT_EQ(std::get<int64_t>(ageDb->second), age);

    auto sex = personVertex->GetProperties().find("sex");
    ASSERT_NE(sex, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<int64_t>(sex->second));
    EXPECT_EQ(std::get<int64_t>(sex->second), 0);
}

/**
 * @tc.name: GdbTransactionTest001_CreateTransaction_Normal
 * @tc.desc: test CreateTransaction
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest001_CreateTransaction_Normal, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    auto [err1, trans1] = store_->CreateTransaction();
    EXPECT_EQ(err1, E_OK);
    EXPECT_NE(trans1, nullptr);

    auto [err2, trans2] = store_->CreateTransaction();
    EXPECT_EQ(err2, E_OK);
    EXPECT_NE(trans2, nullptr);

    auto [err3, trans3] = store_->CreateTransaction();
    EXPECT_EQ(err3, E_OK);
    EXPECT_NE(trans3, nullptr);

    auto [err4, trans4] = store_->CreateTransaction();
    EXPECT_EQ(err4, E_OK);
    EXPECT_NE(trans4, nullptr);

    err4 = trans4->Commit();
    EXPECT_EQ(err4, E_OK);

    auto [err5, trans5] = store_->CreateTransaction();
    EXPECT_EQ(err5, E_OK);
    EXPECT_NE(trans5, nullptr);
}

/**
 * @tc.name: GdbTransactionTest002_CreateTransaction_Abnormal
 * @tc.desc: test CreateTransaction upper bound
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest002_CreateTransaction_Abnormal, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    auto [err1, trans1] = store_->CreateTransaction();
    EXPECT_EQ(err1, E_OK);
    EXPECT_NE(trans1, nullptr);

    auto [err2, trans2] = store_->CreateTransaction();
    EXPECT_EQ(err2, E_OK);
    EXPECT_NE(trans2, nullptr);

    auto [err3, trans3] = store_->CreateTransaction();
    EXPECT_EQ(err3, E_OK);
    EXPECT_NE(trans3, nullptr);

    auto [err4, trans4] = store_->CreateTransaction();
    EXPECT_EQ(err4, E_OK);
    EXPECT_NE(trans4, nullptr);

    auto [err5, trans5] = store_->CreateTransaction();
    EXPECT_EQ(err5, E_DATABASE_BUSY);
    EXPECT_EQ(trans5, nullptr);
}

/**
 * @tc.name: GdbTransactionTest003_Query_Execute_Normal
 * @tc.desc: test Transaction::Query and Transaction::Execute
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest003_Query_Execute_Normal, TestSize.Level1)
{
    InsertPerson("name_1", 11);

    auto [err, trans] = store_->CreateTransaction();
    EXPECT_EQ(err, E_OK);
    EXPECT_NE(trans, nullptr);

    MatchAndVerifyPerson("name_1", 11, trans);

    InsertPerson("name_2", 22, trans);

    MatchAndVerifyPerson("name_2", 22, trans);
}

/**
 * @tc.name: GdbTransactionTest004_Query_Execute_Abnormal
 * @tc.desc: test Transaction::Query and Transaction::Execute with invalid gql
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest004_Query_Execute_Abnormal, TestSize.Level1)
{
    InsertPerson("name_1", 11);

    auto [err, trans] = store_->CreateTransaction();
    EXPECT_EQ(err, E_OK);
    EXPECT_NE(trans, nullptr);

    int32_t errCode = E_OK;
    std::shared_ptr<Result> result = std::make_shared<FullResult>();
    std::string gql = "";
    std::tie(errCode, result) = trans->Query(gql);
    EXPECT_EQ(errCode, E_INVALID_ARGS);

    std::tie(errCode, result) = trans->Execute(gql);
    EXPECT_EQ(errCode, E_INVALID_ARGS);

    for (int i = 0; i <= MAX_GQL_LEN; i++) {
        gql += "I";
    }
    std::tie(errCode, result) = trans->Query(gql);
    EXPECT_EQ(errCode, E_INVALID_ARGS);

    std::tie(errCode, result) = trans->Execute(gql);
    EXPECT_EQ(errCode, E_INVALID_ARGS);

    gql = "MATCH (person:Person {name: 11}) RETURN person;";
    std::tie(errCode, result) = trans->Query(gql);
    EXPECT_EQ(errCode, E_GRD_SEMANTIC_ERROR);

    std::tie(err, trans) = store_->CreateTransaction();
    EXPECT_EQ(err, E_OK);
    EXPECT_NE(trans, nullptr);
    gql = "INSERT (:Person {name: 11, age: 'name_1'});";
    std::tie(errCode, result) = trans->Execute(gql);
    EXPECT_EQ(errCode, E_GRD_SEMANTIC_ERROR);

    std::tie(err, trans) = store_->CreateTransaction();
    EXPECT_EQ(err, E_OK);
    EXPECT_NE(trans, nullptr);
    gql = "MATCH;";
    std::tie(errCode, result) = trans->Query(gql);
    EXPECT_EQ(errCode, E_GRD_SYNTAX_ERROR);

    std::tie(err, trans) = store_->CreateTransaction();
    EXPECT_EQ(err, E_OK);
    EXPECT_NE(trans, nullptr);
    gql = "INSERT;";
    std::tie(errCode, result) = trans->Execute(gql);
    EXPECT_EQ(errCode, E_GRD_SYNTAX_ERROR);
}

/**
 * @tc.name: GdbTransactionTest005_Commit_Normal
 * @tc.desc: test Transaction::Commit
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest005_Commit_Normal, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    auto [err, trans] = store_->CreateTransaction();
    EXPECT_EQ(err, E_OK);
    EXPECT_NE(trans, nullptr);

    InsertPerson("name_1", 11, trans);

    auto gql = "MATCH (person:Person {name: 'name_1'}) RETURN person;";
    auto result = store_->QueryGql(gql);
    EXPECT_EQ(result.first, E_DATABASE_BUSY);

    auto errCode = trans->Commit();
    EXPECT_EQ(errCode, E_OK);

    MatchAndVerifyPerson("name_1", 11);
}

/**
 * @tc.name: GdbTransactionTest006_Commit_Abnormal
 * @tc.desc: test Transaction::Commit
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest006_Commit_Abnormal, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    auto [err, trans] = store_->CreateTransaction();
    EXPECT_EQ(err, E_OK);
    ASSERT_NE(trans, nullptr);

    auto errCode = trans->Commit();
    EXPECT_EQ(errCode, E_OK);

    errCode = trans->Commit();
    EXPECT_EQ(errCode, E_GRD_DB_INSTANCE_ABNORMAL);
}

/**
 * @tc.name: GdbTransactionTest007_Rollback_Normal
 * @tc.desc: test Transaction::Rollback
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest007_Rollback_Normal, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    auto [err, trans] = store_->CreateTransaction();
    EXPECT_EQ(err, E_OK);
    EXPECT_NE(trans, nullptr);

    InsertPerson("name_1", 11, trans);

    auto gql = "MATCH (person:Person {name: 'name_1'}) RETURN person;";
    auto result = store_->QueryGql(gql);
    EXPECT_EQ(result.first, E_DATABASE_BUSY);

    auto errCode = trans->Rollback();
    EXPECT_EQ(errCode, E_OK);

    MatchAndVerifyPerson("name_1", 11, nullptr, false);
}

/**
 * @tc.name: GdbTransactionTest008_Rollback_Abnormal
 * @tc.desc: test Transaction::Rollback
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest008_Rollback_Abnormal, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    auto [err, trans] = store_->CreateTransaction();
    EXPECT_EQ(err, E_OK);
    ASSERT_NE(trans, nullptr);

    auto errCode = trans->Rollback();
    EXPECT_EQ(errCode, E_OK);

    errCode = trans->Rollback();
    EXPECT_EQ(errCode, E_GRD_DB_INSTANCE_ABNORMAL);
}

/**
 * @tc.name: GdbTransactionTest009_Isolation001
 * @tc.desc: test Transaction
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest009_Isolation001, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    auto [err1, trans1] = store_->CreateTransaction();
    EXPECT_EQ(err1, E_OK);
    EXPECT_NE(trans1, nullptr);

    auto [err2, trans2] = store_->CreateTransaction();
    EXPECT_EQ(err2, E_OK);
    EXPECT_NE(trans2, nullptr);

    InsertPerson("name_1", 11, trans1);

    auto gql = "MATCH (person:Person {name: 'name_1'}) RETURN person;";
    auto [errCode, result] = trans2->Query(gql);
    EXPECT_EQ(errCode, E_DATABASE_BUSY);
}

/**
 * @tc.name: GdbTransactionTest010_Isolation002
 * @tc.desc: test Transaction
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest010_Isolation002, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    auto [err1, trans1] = store_->CreateTransaction();
    EXPECT_EQ(err1, E_OK);
    EXPECT_NE(trans1, nullptr);

    auto [err2, trans2] = store_->CreateTransaction();
    EXPECT_EQ(err2, E_OK);
    EXPECT_NE(trans2, nullptr);

    InsertPerson("name_1", 11, trans1);

    ASSERT_NE(trans1, nullptr);
    auto errCode = trans1->Commit();
    EXPECT_EQ(errCode, E_OK);

    MatchAndVerifyPerson("name_1", 11, trans2);
}

/**
 * @tc.name: GdbTransactionTest011_Isolation003
 * @tc.desc: test Transaction
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest011_Isolation003, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    auto [err1, trans1] = store_->CreateTransaction();
    EXPECT_EQ(err1, E_OK);
    EXPECT_NE(trans1, nullptr);

    auto [err2, trans2] = store_->CreateTransaction();
    EXPECT_EQ(err2, E_OK);
    EXPECT_NE(trans2, nullptr);

    InsertPerson("name_1", 11, trans1);

    ASSERT_NE(trans1, nullptr);
    auto errCode = trans1->Rollback();
    EXPECT_EQ(errCode, E_OK);

    MatchAndVerifyPerson("name_1", 11, trans2, false);
}

/**
 * @tc.name: GdbTransactionTest012_Isolation004
 * @tc.desc: test Transaction
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest012_Isolation004, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    auto [err1, trans1] = store_->CreateTransaction();
    EXPECT_EQ(err1, E_OK);
    EXPECT_NE(trans1, nullptr);

    auto [err2, trans2] = store_->CreateTransaction();
    EXPECT_EQ(err2, E_OK);
    EXPECT_NE(trans2, nullptr);

    InsertPerson("name_1", 11, trans1);

    ASSERT_NE(trans2, nullptr);
    int32_t errCode = E_OK;
    std::shared_ptr<Result> result = std::make_shared<FullResult>();
    std::tie(errCode, result) = trans2->Execute("INSERT (:Person {name: 'name_2', age: 22});");
    EXPECT_EQ(errCode, E_DATABASE_BUSY);

    errCode = trans1->Commit();
    EXPECT_EQ(errCode, E_OK);

    InsertPerson("name_2", 22, trans2);
}

/**
 * @tc.name: GdbTransactionTest013_Close
 * @tc.desc: test Close
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest013_Close, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    auto [err, trans] = store_->CreateTransaction();
    EXPECT_EQ(err, E_OK);
    EXPECT_NE(trans, nullptr);

    InsertPerson("name_1", 11, trans);

    ASSERT_NE(store_, nullptr);
    int32_t errCode = store_->Close();
    EXPECT_EQ(errCode, E_OK);
    store_ = nullptr;

    auto config = StoreConfig(databaseName, databasePath);
    store_ = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(store_, nullptr);

    MatchAndVerifyPerson("name_1", 11, nullptr, false);
}

/**
 * @tc.name: GdbTransactionTest014_StartTransByExecute
 * @tc.desc: test Execute("START TRANSACTION;"), Execute("COMMIT") and Execute("ROLLBACK")
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest014_StartTransByExecute001, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    auto [err, result] = store_->ExecuteGql("START TRANSACTION;");
    EXPECT_EQ(err, E_INVALID_ARGS);

    std::tie(err, result) = store_->ExecuteGql("COMMIT;");
    EXPECT_EQ(err, E_INVALID_ARGS);

    std::tie(err, result) = store_->ExecuteGql("ROLLBACK;");
    EXPECT_EQ(err, E_INVALID_ARGS);
}

/**
 * @tc.name: GdbTransactionTest015_TransactionNestification
 * @tc.desc: test Transaction Nestification
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest015_TransactionNestification, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    auto [err1, trans1] = store_->CreateTransaction();
    EXPECT_EQ(err1, E_OK);
    EXPECT_NE(trans1, nullptr);

    auto result = trans1->Execute("START TRANSACTION;");
    EXPECT_EQ(result.first, E_INVALID_ARGS);
}

/**
 * @tc.name: GdbTransactionTest016_TransactionMultiThread
 * @tc.desc: test Transaction MultiThread
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest016_TransactionMultiThread, TestSize.Level1)
{
    std::thread th[MAX_CNT];
    for (int32_t i = 0; i < MAX_CNT; i++) {
        th[i] = std::thread([this, i] () {
            ASSERT_NE(store_, nullptr);

            auto [err, trans] = store_->CreateTransaction();
            EXPECT_EQ(err, E_OK);
            ASSERT_NE(trans, nullptr);

            InsertPerson("name_" + std::to_string(i), i, trans);

            err = trans->Commit();
            EXPECT_EQ(err, E_OK);
        });
    }

    for (int32_t i = 0; i < MAX_CNT; i++) {
        th[i].join();
    }

    for (int32_t i = 0; i < MAX_CNT; i++) {
        MatchAndVerifyPerson("name_" + std::to_string(i), i);
    }
}

/**
 * @tc.name: GdbTransactionTest017_TransactionMultiThread
 * @tc.desc: test Transaction MultiThread write busy(Unable to obtain lock in 2 seconds)
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest017_TransactionMultiThread, TestSize.Level1)
{
    std::thread th[MAX_CNT];
    std::atomic_int insertCnt = 0;
    std::atomic_int insertIndex = -1;
    for (int32_t i = 0; i < MAX_CNT; i++) {
        th[i] = std::thread([this, i, &insertCnt, &insertIndex] () {
            ASSERT_NE(store_, nullptr);

            auto [err, trans] = store_->CreateTransaction();
            EXPECT_EQ(err, E_OK);
            ASSERT_NE(trans, nullptr);

            std::shared_ptr<Result> result = std::make_shared<FullResult>();
            std::string age = std::to_string(i);
            std::string name = "name_" + age;
            std::string gql = "INSERT (:Person {name: '" + name + "', age: " + age + "});";
            std::tie(err, result) = trans->Execute(gql);
            if (err == E_OK && insertCnt.load() == 0) {
                insertCnt++;
                insertIndex.store(i);
            } else {
                EXPECT_EQ(err, E_DATABASE_BUSY);
            }

            std::this_thread::sleep_for(std::chrono::seconds(BUSY_TIMEOUT));

            err = trans->Commit();
            EXPECT_EQ(err, E_OK);
        });
    }

    for (int32_t i = 0; i < MAX_CNT; i++) {
        th[i].join();
    }

    for (int32_t i = 0; i < MAX_CNT; i++) {
        if (i == insertIndex.load()) {
            MatchAndVerifyPerson("name_" + std::to_string(i), i);
        } else {
            MatchAndVerifyPerson("name_" + std::to_string(i), i, nullptr, false);
        }
    }

    EXPECT_EQ(insertCnt, 1);
}

/**
 * @tc.name: GdbTransactionTest018_TransactionMultiThread
 * @tc.desc: test Transaction MultiThread Transaction.write and Transaction.read
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest018_TransactionMultiThread, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    std::thread writeThread([this] () {
        for (int i = 0; i < MAX_DATA_CNT; i++) {
            auto [err, trans] = store_->CreateTransaction();
            EXPECT_EQ(err, E_OK);
            ASSERT_NE(trans, nullptr);
            InsertPerson("name_" + std::to_string(i), i, trans);
            err = trans->Commit();
            EXPECT_EQ(err, E_OK);
            std::this_thread::sleep_for(std::chrono::milliseconds(EXECUTE_INTERVAL));
        }
    });

    std::thread readThread([this] () {
        std::this_thread::sleep_for(std::chrono::milliseconds(READ_INTERVAL));
        for (int i = 0; i < MAX_DATA_CNT; i++) {
            auto [err, trans] = store_->CreateTransaction();
            EXPECT_EQ(err, E_OK);
            ASSERT_NE(trans, nullptr);
            MatchAndVerifyPerson("name_" + std::to_string(i), i, trans);
            err = trans->Rollback();
            EXPECT_EQ(err, E_OK);
            std::this_thread::sleep_for(std::chrono::milliseconds(EXECUTE_INTERVAL));
        }
    });

    writeThread.join();
    readThread.join();
}

/**
 * @tc.name: GdbTransactionTest019_TransactionMultiThread
 * @tc.desc: test Transaction MultiThread GraphStore.write and Transaction.read
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest019_TransactionMultiThread, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    std::thread writeThread([this] () {
        for (int i = 0; i < MAX_DATA_CNT; i++) {
            InsertPerson("name_" + std::to_string(i), i);
            std::this_thread::sleep_for(std::chrono::milliseconds(EXECUTE_INTERVAL));
        }
    });

    std::thread readThread([this] () {
        std::this_thread::sleep_for(std::chrono::milliseconds(READ_INTERVAL));
        for (int i = 0; i < MAX_DATA_CNT; i++) {
            auto [err, trans] = store_->CreateTransaction();
            EXPECT_EQ(err, E_OK);
            ASSERT_NE(trans, nullptr);
            MatchAndVerifyPerson("name_" + std::to_string(i), i, trans);
            err = trans->Rollback();
            EXPECT_EQ(err, E_OK);
            std::this_thread::sleep_for(std::chrono::milliseconds(EXECUTE_INTERVAL));
        }
    });

    writeThread.join();
    readThread.join();
}

/**
 * @tc.name: GdbTransactionTest020_TransactionMultiThread
 * @tc.desc: test Transaction MultiThread Transaction.write and GraphStore.read
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest020_TransactionMultiThread, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    std::thread writeThread([this] () {
        for (int i = 0; i < MAX_DATA_CNT; i++) {
            auto [err, trans] = store_->CreateTransaction();
            EXPECT_EQ(err, E_OK);
            ASSERT_NE(trans, nullptr);
            InsertPerson("name_" + std::to_string(i), i, trans);
            err = trans->Commit();
            EXPECT_EQ(err, E_OK);
            std::this_thread::sleep_for(std::chrono::milliseconds(EXECUTE_INTERVAL));
        }
    });

    std::thread readThread([this] () {
        std::this_thread::sleep_for(std::chrono::milliseconds(READ_INTERVAL));
        for (int i = 0; i < MAX_DATA_CNT; i++) {
            MatchAndVerifyPerson("name_" + std::to_string(i), i);
            std::this_thread::sleep_for(std::chrono::milliseconds(EXECUTE_INTERVAL));
        }
    });

    writeThread.join();
    readThread.join();
}

/**
 * @tc.name: GdbTransactionTest021_TransactionMultiThread
 * @tc.desc: test Transaction MultiThread Transaction.write and GraphStore.write
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest021_TransactionMultiThread, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

    std::thread transWriteThread([this] () {
        for (int i = 0; i < MAX_DATA_CNT; i++) {
            auto [err, trans] = store_->CreateTransaction();
            EXPECT_EQ(err, E_OK);
            ASSERT_NE(trans, nullptr);
            InsertPerson("name_trans_" + std::to_string(i), i, trans);
            err = trans->Commit();
            EXPECT_EQ(err, E_OK);
            std::this_thread::sleep_for(std::chrono::milliseconds(EXECUTE_INTERVAL));
        }
    });

    std::thread writeThread([this] () {
        for (int i = 0; i < MAX_DATA_CNT; i++) {
            InsertPerson("name_" + std::to_string(i), i);
            std::this_thread::sleep_for(std::chrono::milliseconds(EXECUTE_INTERVAL));
        }
    });

    transWriteThread.join();
    writeThread.join();

    for (int i = 0; i < MAX_DATA_CNT; i++) {
        MatchAndVerifyPerson("name_trans_" + std::to_string(i), i);
        MatchAndVerifyPerson("name_" + std::to_string(i), i);
    }
}

/**
 * @tc.name: GdbTransactionTest022
 * @tc.desc: test subset_of through Transaction.read and GraphStore.read
 * @tc.type: FUNC
 */
HWTEST_F(GdbTransactionTest, GdbTransactionTest022, TestSize.Level1)
{
    std::string overLimitName(UT_MAX_CONST_STRING_LEN, 'a');
    ASSERT_NE(store_, nullptr);
    InsertPerson("name_1", 1);
    InsertPerson("name_2", 2);

    auto [errTrans, trans] = store_->CreateTransaction();
    ASSERT_EQ(errTrans, E_OK);
    ASSERT_NE(trans, nullptr);

    std::string gql = "MATCH (p:Person) WHERE subset_of('" + overLimitName + "', 'aa,11', ',') RETURN p.name";
    auto [err, result] = store_->QueryGql(gql);
    EXPECT_EQ(err, E_GRD_SEMANTIC_ERROR);
    std::tie(err, result) = trans->Query(gql);
    EXPECT_EQ(err, E_GRD_SEMANTIC_ERROR);

    gql = "MATCH (p:Person) WHERE subset_of('b', '" + overLimitName + "', ',') RETURN p.name";
    std::tie(err, result) = store_->QueryGql(gql);
    EXPECT_EQ(err, E_GRD_SEMANTIC_ERROR);
    std::tie(err, result) = trans->Query(gql);
    EXPECT_EQ(err, E_GRD_SEMANTIC_ERROR);

    gql = "MATCH (p:Person) WHERE subset_of('" + overLimitName + "', '" + overLimitName + "', ',') RETURN p.name";
    std::tie(err, result) = store_->QueryGql(gql);
    EXPECT_EQ(err, E_GRD_SEMANTIC_ERROR);
    std::tie(err, result) = trans->Query(gql);
    EXPECT_EQ(err, E_GRD_SEMANTIC_ERROR);
}

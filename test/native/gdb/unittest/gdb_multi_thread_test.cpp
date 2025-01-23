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

#include <atomic>
#include <iostream>
#include <random>
#include <string>
#include <thread>

#include "aip_errors.h"
#include "executor_pool.h"
#include "grd_adapter_manager.h"
#include "gdb_helper.h"
#include "gdb_store.h"
#include "path.h"

using namespace testing::ext;
using namespace OHOS::DistributedDataAip;
class GdbMultiThreadTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void VerifyPersonInfo(const GraphValue &person, const std::string &name, const int32_t &age);
    void MatchAndVerifyPerson(const std::string &name, const int32_t &age, std::shared_ptr<DBStore> store);
    void MultiThreadExecuteInsert(std::shared_ptr<DBStore> store);
    void MultiThreadExecuteDBStore();
    void MultiThreadInsertRelation(std::shared_ptr<DBStore> store);
    void MultiThreadQueryRelation(std::shared_ptr<DBStore> store);
    std::string RandomString(size_t length);

protected:
    std::atomic<int> counter;
    static const std::string databaseName;
    static const std::string databasePath;
    static const std::string createGraphGql;
    std::shared_ptr<OHOS::ExecutorPool> executors_;
};
const std::string GdbMultiThreadTest::databaseName = "execute_test";
const std::string GdbMultiThreadTest::databasePath = "/data";
const std::string GdbMultiThreadTest::createGraphGql = "CREATE GRAPH test { "
                                                       "(person:Person {name STRING, age INT, sex BOOL DEFAULT false}),"
                                                       "(dog:Dog {name STRING, age INT}), "
                                                       "(person) -[:Friend]-> (person) "
                                                       "};";

void GdbMultiThreadTest::SetUpTestCase(void)
{
    if (!IsSupportArkDataDb()) {
        GTEST_SKIP() << "Current testcase is not compatible from current gdb";
        return;
    }
}

void GdbMultiThreadTest::TearDownTestCase(void)
{
}

void GdbMultiThreadTest::SetUp()
{
    if (!IsSupportArkDataDb()) {
        GTEST_SKIP() << "Current testcase is not compatible from current gdb";
        return;
    }
    int32_t maxThread = 5;
    int32_t minThread = 0;
    executors_ = std::make_shared<OHOS::ExecutorPool>(maxThread, minThread);
}

void GdbMultiThreadTest::TearDown()
{
    executors_ = nullptr;
}

/**
 * @tc.name: MultiThread_GetDBStore_0001
 * @tc.desc: Start two threads to open the database.
 * @tc.type: FUNC
 */
HWTEST_F(GdbMultiThreadTest, MultiThread_GetDBStore_0001, TestSize.Level2)
{
    counter.store(0);
    MultiThreadExecuteDBStore();
    MultiThreadExecuteDBStore();
    while (true) {
        if (counter.load() == 100) {
            break;
        }
    }
}

/**
 * @tc.name: MultiThreadExecuteDBStore
 * @tc.desc: Start the database in the current thread for 50 times.
 * @tc.type: FUNC
 */
void GdbMultiThreadTest::MultiThreadExecuteDBStore()
{
    executors_->Execute([this]() {
        int errCode = E_OK;
        std::string dbName = RandomString(10) + RandomString(10);
        constexpr int32_t COUNT = 50;
        for (uint32_t j = 0; j < COUNT; j++) {
            auto config = StoreConfig(dbName + std::to_string(j), databasePath);
            GDBHelper::DeleteDBStore(config);
            auto store = GDBHelper::GetDBStore(config, errCode);
            auto result = store->ExecuteGql(createGraphGql);
            EXPECT_NE(store, nullptr);
            EXPECT_EQ(result.first, E_OK);
            ASSERT_NE(result.second, nullptr);

            result = store->ExecuteGql("DROP GRAPH test");
            EXPECT_NE(store, nullptr);
            EXPECT_EQ(result.first, E_OK);
            GDBHelper::DeleteDBStore(config);
            counter.fetch_add(1, std::memory_order_relaxed);
        }
    });
}

/**
 * @tc.name: MultiThread_GetDBStore_0002
 * @tc.desc: Start two threads to test the insertion Vertex and Edge.
 * @tc.type: FUNC
 */
HWTEST_F(GdbMultiThreadTest, MultiThread_GetDBStore_0002, TestSize.Level2)
{
    int errCode = E_OK;
    auto config = StoreConfig(databaseName + "test22", databasePath);
    auto store = GDBHelper::GetDBStore(config, errCode);
    auto result = store->ExecuteGql(createGraphGql);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    counter.store(0);
    MultiThreadExecuteInsert(store);
    sleep(1);
    MultiThreadExecuteInsert(store);
    while (true) {
        // counter ++ 200
        if (counter.load() == 200) {
            break;
        }
    }
    sleep(1);
    result = store->ExecuteGql("DROP GRAPH test");
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(result.first, E_OK);
    GDBHelper::DeleteDBStore(config);
}

/**
 * @tc.name: MultiThreadExecuteInsert
 * @tc.desc: Start threads to test the insertion Vertex and Edge.
 * @tc.type: FUNC
 */
void GdbMultiThreadTest::MultiThreadExecuteInsert(std::shared_ptr<DBStore> store)
{
    executors_->Execute([this, &store]() {
        std::string nameStr = RandomString(10) + RandomString(10);
        constexpr int32_t MAX_COUNT = 100;
        for (uint32_t j = 0; j < MAX_COUNT; j++) {
            std::string name = nameStr + std::to_string(j);
            auto result = store->ExecuteGql("INSERT (:Person {name: '" + name + "', age: 11});");
            EXPECT_EQ(result.first, E_OK);
            constexpr int32_t AGE_11 = 11;
            MatchAndVerifyPerson(name, AGE_11, store);

            std::string name2 = name + std::to_string(j);
            result = store->ExecuteGql("INSERT (:Person {name: '" + name2 + "', age: 22});");
            EXPECT_EQ(result.first, E_OK);
            constexpr int32_t AGE = 22;
            MatchAndVerifyPerson(name2, AGE, store);

            std::string name3 = name2 + std::to_string(j);
            result = store->ExecuteGql("INSERT (:Person {name: '" + name3 + "', age: 33});");
            EXPECT_EQ(result.first, E_OK);
            constexpr int32_t AGE_33 = 33;
            MatchAndVerifyPerson(name3, AGE_33, store);

            result = store->ExecuteGql("MATCH (p1:Person {name: '" + name + "'}), (p2:Person {name: '" + name2 +
                                       "'}) INSERT (p1)-[:Friend]->(p2);");
            EXPECT_EQ(result.first, E_OK);
            result = store->ExecuteGql("MATCH (p1:Person {name: '" + name2 + "'}), (p2:Person {name: '" + name3 +
                                       "'}) INSERT (p1)-[:Friend]->(p2);");
            EXPECT_EQ(result.first, E_OK);

            result = store->QueryGql(
                "MATCH (person:Person {name: '" + name + "'})-[relation:Friend]->() RETURN person, relation;");
            ASSERT_EQ(result.first, E_OK);

            auto result2 = store->QueryGql("MATCH path=(a:Person {name: '" + name +
                                           "'})-[]->{2, 2}(b:Person {name: '" + name3 + "'}) RETURN path;");
            ASSERT_EQ(result2.first, E_OK);
            counter.fetch_add(1, std::memory_order_relaxed);
        }
    });
}

/**
 * @tc.name: MultiThread_GetDBStore_0003
 * @tc.desc: Start two threads to insert edges of the same Vertex, and start another thread to query edges.
 * @tc.type: FUNC
 */
HWTEST_F(GdbMultiThreadTest, MultiThread_GetDBStore_0003, TestSize.Level2)
{
    int errCode = E_OK;
    auto config = StoreConfig(databaseName + "test33", databasePath);
    auto store = GDBHelper::GetDBStore(config, errCode);
    auto result = store->ExecuteGql(createGraphGql);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    counter.store(0);

    std::string name = "zhangsan";
    result = store->ExecuteGql("INSERT (:Person {name: '" + name + "', age: 11});");
    EXPECT_EQ(result.first, E_OK);
    constexpr int32_t AGE_11 = 11;
    MatchAndVerifyPerson(name, AGE_11, store);
    //insert Vertex and edge
    MultiThreadInsertRelation(store);
    MultiThreadInsertRelation(store);
    sleep(1);
    //query Vertex and edge
    MultiThreadExecuteInsert(store);
    while (true) {
        if (counter.load() == 300) {
            break;
        }
    }
    // query match count is 200
    result =
        store->QueryGql("MATCH (person:Person {name: '" + name + "'})-[relation:Friend]->() RETURN person, relation;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 200);

    result = store->ExecuteGql("DROP GRAPH test");
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(result.first, E_OK);
    GDBHelper::DeleteDBStore(config);
}

void GdbMultiThreadTest::MultiThreadInsertRelation(std::shared_ptr<DBStore> store)
{
    executors_->Execute([this, &store]() {
        std::string nameStr = RandomString(10) + RandomString(10);
        std::string name = "zhangsan";
        constexpr int32_t MAX_COUNT = 100;
        for (uint32_t j = 0; j < MAX_COUNT; j++) {
            std::string name2 = nameStr + std::to_string(j);
            auto result = store->ExecuteGql("INSERT (:Person {name: '" + name2 + "', age: 22});");
            EXPECT_EQ(result.first, E_OK);
            constexpr int32_t AGE = 22;
            MatchAndVerifyPerson(name2, AGE, store);

            result = store->ExecuteGql("MATCH (p1:Person {name: '" + name + "'}), (p2:Person {name: '" + name2 +
                                       "'}) INSERT (p1)-[:Friend]->(p2);");
            EXPECT_EQ(result.first, E_OK);
            counter.fetch_add(1, std::memory_order_relaxed);
        }
    });
}

void GdbMultiThreadTest::MultiThreadQueryRelation(std::shared_ptr<DBStore> store)
{
    executors_->Execute([this, &store]() {
        std::string name = "zhangsan";
        constexpr int32_t MAX_COUNT = 100;
        for (uint32_t j = 0; j < MAX_COUNT; j++) {
            auto result = store->QueryGql(
                "MATCH (person:Person {name: '" + name + "'})-[relation:Friend]->() RETURN person, relation;");
            ASSERT_EQ(result.first, E_OK);
            counter.fetch_add(1, std::memory_order_relaxed);
        }
    });
}

std::string GdbMultiThreadTest::RandomString(size_t length)
{
    const std::string letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, letters.size() - 1);

    std::string randomStr;
    for (size_t i = 0; i < length; ++i) {
        randomStr.push_back(letters[dis(gen)]);
    }
    return randomStr;
}

void GdbMultiThreadTest::MatchAndVerifyPerson(
    const std::string &name, const int32_t &age, std::shared_ptr<DBStore> store)
{
    EXPECT_NE(store, nullptr);
    auto gql = "MATCH (person:Person {name: '" + name + "', age: " + std::to_string(age) + "}) RETURN person;";
    auto result = store->QueryGql(gql);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    ASSERT_EQ(result.second->GetAllData().size(), 1);
    GraphValue person = result.second->GetAllData()[0]["person"];
    VerifyPersonInfo(person, name, age);
}

void GdbMultiThreadTest::VerifyPersonInfo(const GraphValue &person, const std::string &name, const int32_t &age)
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
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

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>
#include <variant>

#include "aip_errors.h"
#include "edge.h"
#include "gdb_helper.h"
#include "gdb_store.h"
#include "path.h"
#include "result.h"
#include "vertex.h"

using namespace testing::ext;
using namespace OHOS::DistributedDataAip;
class GdbExecuteTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void VerifyPersonInfo(const GraphValue &person, const std::string &name, const int32_t &age);
    void MatchAndVerifyPerson(const std::string &name, const int32_t &age);

    static const std::string databaseName;
    static const std::string databasePath;
    static std::shared_ptr<DBStore> store_;
    static const std::string createGraphGql;
    static const std::shared_ptr<StoreConfig> databaseConfig;
    static const std::string pathJsonString;
};
std::shared_ptr<DBStore> GdbExecuteTest::store_;
const std::string GdbExecuteTest::databaseName = "execute_test";
const std::string GdbExecuteTest::databasePath = "/data";
const std::string GdbExecuteTest::createGraphGql = "CREATE GRAPH test { "
                                                   "(person:Person {name STRING, age INT, sex BOOL DEFAULT false}),"
                                                   "(dog:Dog {name STRING, age INT}), "
                                                   "(person) -[:Friend]-> (person) "
                                                   "};";
const std::string GdbExecuteTest::pathJsonString = R"({
        "start": {
            "label": "PERSON",
            "identity": 1,
            "properties": {
                "AGE": 32,
                "SALARY": 75.35,
                "NAME": "Alice",
                "GENDER": "Female",
                "PHONENUMBERS": false,
                "EMAILS": null
            }
        },
        "end": {
            "label": "PERSON",
            "identity": 2,
            "properties": {
                "AGE": 28,
                "SALARY": 65000,
                "NAME": "Bob",
                "GENDER": "Male",
                "PHONENUMBERS": "123456789",
                "EMAILS": "bob@example.com"
            }
        },
        "relationship": {
            "label": "鐩寸郴浜插睘",
            "identity": 3,
            "start": 1,
            "end": 2,
            "properties": {
                "NUM": 4,
                "PINYIN": "zhixiqinshu"
            }
        }
    })";

void GdbExecuteTest::SetUpTestCase()
{
    int errCode = E_OK;
    auto config = StoreConfig(databaseName, databasePath);
    GDBHelper::DeleteDBStore(config);

    GdbExecuteTest::store_ = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(GdbExecuteTest::store_, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void GdbExecuteTest::TearDownTestCase()
{
    GDBHelper::DeleteDBStore(StoreConfig(databaseName, databasePath));
    store_ = nullptr;
}

void GdbExecuteTest::SetUp()
{
    auto result = store_->ExecuteGql(createGraphGql);
    EXPECT_NE(store_, nullptr);
    EXPECT_EQ(result.first, E_OK);
}

void GdbExecuteTest::TearDown()
{
    auto result = store_->ExecuteGql("DROP GRAPH test");
    EXPECT_NE(store_, nullptr);
    EXPECT_EQ(result.first, E_OK);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "success";
    std::string dbPath = databasePath;
    auto config = StoreConfig(dbName, dbPath);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStoreVector, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "success";
    std::string dbPath = databasePath;
    auto config = StoreConfig(dbName, dbPath, DBType::DB_VECTOR);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_EQ(errCode, E_NOT_SUPPORT);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStoreButt, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "success";
    std::string dbPath = databasePath;
    auto config = StoreConfig(dbName, dbPath, DBType::DB_BUTT);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_EQ(errCode, E_NOT_SUPPORT);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStoreReadConSize, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "success";
    std::string dbPath = databasePath;
    auto config = StoreConfig(dbName, dbPath);
    config.SetReadConSize(0);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStoreReadConSizeMax, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "success";
    std::string dbPath = databasePath;
    auto config = StoreConfig(dbName, dbPath);
    config.SetReadConSize(500);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_EQ(errCode, E_ARGS_READ_CON_OVERLOAD);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_NameHasdbSuffix, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "success.db";
    std::string dbPath = databasePath;
    auto config = StoreConfig(dbName, dbPath);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_NE(errCode, E_OK);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_NameHasDBSuffix, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "success.DB";
    std::string dbPath = databasePath;
    auto config = StoreConfig(dbName, dbPath);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_NE(errCode, E_OK);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_NameHasSpecialChar, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "suc@!#$*(cess.";
    std::string dbPath = databasePath;
    auto config = StoreConfig(dbName, dbPath);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_NE(errCode, E_OK);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_PathOkEmptyName, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "";
    std::string dbPath = databasePath;
    auto config = StoreConfig(dbName, dbPath);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_NE(errCode, E_OK);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_NotFoundPath, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "success";
    std::string dbPath = "/test/path1/";
    auto config = StoreConfig(dbName, dbPath);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_EQ(errCode, E_GRD_FAILED_FILE_OPERATION);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_PathErrorEmptyName, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "";
    std::string dbPath = "/test/path2";
    auto config = StoreConfig(dbName, dbPath);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_EQ(errCode, E_GRD_INVAILD_NAME_ERR);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_Empty_Path, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = databaseName;
    std::string dbPath = "";
    auto config = StoreConfig(dbName, dbPath);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_EQ(errCode, E_GRD_FAILED_FILE_OPERATION);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_Empty_NameAndPath, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "";
    std::string dbPath = "";
    auto config = StoreConfig(dbName, dbPath);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_EQ(errCode, E_GRD_INVAILD_NAME_ERR);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_OK, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "execute_test_ok";
    std::string dbPath = "/data";
    auto config = StoreConfig(dbName, dbPath);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_OK_PathRepeat, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "execute_test_ok_2";
    std::string dbPath = "/data";
    auto config = StoreConfig(dbName, dbPath);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_LongName, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "";
    for (int32_t i = 0; i < 1000000; i++) {
        dbName += "A";
    }
    std::string dbPath = "/test/path2";
    auto config = StoreConfig(dbName, dbPath);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_EQ(errCode, E_GRD_FAILED_FILE_OPERATION);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_LongNamePathOk, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "";
    for (int32_t i = 0; i < 1000000; i++) {
        dbName += "A";
    }
    std::string dbPath = "/data";
    auto config = StoreConfig(dbName, dbPath);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_EQ(errCode, E_GRD_SEMANTIC_ERROR);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_LongPath, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "";
    for (int32_t i = 0; i < 30; i++) {
        dbName += "A";
    }
    std::string dbPath = "/test/path2";
    for (int32_t i = 0; i < 3000000; i++) {
        dbPath += "A";
    }
    auto config = StoreConfig(dbName, dbPath);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_EQ(errCode, E_GRD_SEMANTIC_ERROR);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_InVaildSecurityLevel, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "tttt";
    std::string dbPath = "/data";

    auto config = StoreConfig(dbName, dbPath);
    config.SetSecurityLevel(-3);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_EQ(errCode, E_INVALID_ARGS);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_InVaildSecurityLevel02, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "tttt";
    std::string dbPath = "/data";

    auto config = StoreConfig(dbName, dbPath);
    config.SetSecurityLevel(0);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_EQ(errCode, E_INVALID_ARGS);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_InVaildSecurityLevel03, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "tttt";
    std::string dbPath = "/data";

    auto config = StoreConfig(dbName, dbPath);
    config.SetSecurityLevel(500);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_EQ(errCode, E_INVALID_ARGS);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_SecurityLevel, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "tttt";
    std::string dbPath = "/data";

    auto config = StoreConfig(dbName, dbPath);
    config.SetSecurityLevel(3);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_SecurityLevelLast, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "tttt";
    std::string dbPath = "/data";

    auto config = StoreConfig(dbName, dbPath);
    config.SetSecurityLevel(SecurityLevel::LAST);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_EQ(errCode, E_INVALID_ARGS);
    store = nullptr;
    GDBHelper::DeleteDBStore(config);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_GetSecurityLeve, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "tttt03";
    std::string dbPath = "/data";
    auto config = StoreConfig(dbName, dbPath);
    config.SetSecurityLevel(SecurityLevel::S2);
    auto level = config.GetSecurityLevel();
    EXPECT_EQ(level, SecurityLevel::S2);
    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);

    store = nullptr;
    GDBHelper::DeleteDBStore(config);

    config.SetSecurityLevel(SecurityLevel::LAST);
    level = config.GetSecurityLevel();
    EXPECT_EQ(level, SecurityLevel::LAST);
    store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(errCode, E_INVALID_ARGS);
    EXPECT_EQ(store, nullptr);
    store = nullptr;
    GDBHelper::DeleteDBStore(config);
}

/**
 * @tc.name: GdbStore_GetDBStore_SecurityLevel03
 * @tc.desc: test StoreConfig SetSecurityLevel S2->S1
 * @tc.type: FUNC
 */
HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_SecurityLevel02, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "tttt02";
    std::string dbPath = "/data";
    auto config = StoreConfig(dbName, dbPath);
    config.SetSecurityLevel(SecurityLevel::S2);
    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    store = nullptr;

    auto invalidConfig = config;
    invalidConfig.SetSecurityLevel(SecurityLevel::S1);
    store = GDBHelper::GetDBStore(invalidConfig, errCode);
    EXPECT_EQ(errCode, E_CONFIG_INVALID_CHANGE);
    EXPECT_EQ(store, nullptr);
    store = nullptr;
    GDBHelper::DeleteDBStore(config);
}

/**
 * @tc.name: GdbStore_GetDBStore_SecurityLevel03
 * @tc.desc: test StoreConfig SetSecurityLevel S2->S3
 * @tc.type: FUNC
 */
HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_SecurityLevel03, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "tttt02";
    std::string dbPath = "/data";
    auto config = StoreConfig(dbName, dbPath);
    config.SetSecurityLevel(SecurityLevel::S2);
    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    store = nullptr;

    auto invalidConfig = config;
    invalidConfig.SetSecurityLevel(SecurityLevel::S3);
    store = GDBHelper::GetDBStore(invalidConfig, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    store = nullptr;
    GDBHelper::DeleteDBStore(config);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_NoInsertQuery, TestSize.Level1)
{
    EXPECT_NE(store_, nullptr);
    auto result = store_->QueryGql("MATCH (person:Person {age: 11}) RETURN person;");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 0);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_AfterClose, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "ttttclose";
    std::string dbPath = "/data";

    auto config = StoreConfig(dbName, dbPath);
    config.SetSecurityLevel(SecurityLevel::S3);

    auto store = GDBHelper::GetDBStore(config, errCode);
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    auto ret = store->Close();
    EXPECT_EQ(E_OK, ret);
    EXPECT_NE(store, nullptr);
    auto result = store_->ExecuteGql("INSERT (:Person {name: 'name_1', age: 11});");
    EXPECT_EQ(result.first, E_OK);
    result = store_->QueryGql("MATCH (person:Person {age: 11}) RETURN person;");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
}

/**
 * @tc.name: GdbStore_GetDBStore_AfterDrop
 * @tc.desc: test GdbStore AfterDrop Insert
 * @tc.type: FUNC
 */
HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_AfterDrop, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "ttttdrop";
    std::string dbPath = "/data";

    auto config = StoreConfig(dbName, dbPath);
    config.SetSecurityLevel(SecurityLevel::S3);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);

    auto result = store_->ExecuteGql("DROP GRAPH test;");
    EXPECT_NE(result.second, nullptr);
    EXPECT_EQ(result.first, E_OK);

    result = store_->ExecuteGql("INSERT (:Person {name: 'name_1', age: 11});");
    EXPECT_EQ(result.first, E_GRD_UNDEFINED_TABLE);
    result = store_->ExecuteGql(createGraphGql);
    EXPECT_NE(result.second, nullptr);
    EXPECT_EQ(result.first, E_OK);
}

/**
 * @tc.name: GdbStore_Execute_001
 * @tc.desc: test GdbStore Execute
 * @tc.type: FUNC
 */
HWTEST_F(GdbExecuteTest, GdbStore_Execute_LongName, TestSize.Level1)
{
    EXPECT_NE(store_, nullptr);
    auto result = store_->ExecuteGql("INSERT (:Person {name: 'name_1', age: 11});");
    EXPECT_EQ(result.first, E_OK);
    result = store_->QueryGql("MATCH (person:Person {age: 11}) RETURN person;");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    std::string name = "name2";
    for (int32_t i = 0; i < 300; i++) {
        name += "A";
    }
    result = store_->ExecuteGql("INSERT (:Person {name: '" + name + "', age: 11});");
    ASSERT_EQ(result.first, E_OK);
    result = store_->QueryGql("MATCH (person:Person {age: 11}) RETURN person;");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 2);

    std::string name2 = "name2";
    for (int32_t i = 0; i < 3000000; i++) {
        name2 += "A";
    }
    result = store_->ExecuteGql("INSERT (:Person {name: '" + name2 + "', age: 11});");
    ASSERT_EQ(result.first, E_GQL_LENGTH_OVER_LIMIT);
    result = store_->QueryGql("MATCH (person:Person {age: 11}) RETURN person;");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 2);
}

/**
 * @tc.name: GdbStore_Execute_001
 * @tc.desc: test GdbStore Execute
 * @tc.type: FUNC
 */
HWTEST_F(GdbExecuteTest, GdbStore_Execute_001, TestSize.Level1)
{
    EXPECT_NE(store_, nullptr);
    auto result = store_->ExecuteGql("INSERT (:Person {name: 'name_1', age: 11});");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("name_1", 11);
    result = store_->ExecuteGql("INSERT (:Person {name: 'name_2', age: 22});");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("name_2", 22);
    result = store_->ExecuteGql("INSERT (:Person {name: 'name_3', age: 33});");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("name_3", 33);
    result = store_->ExecuteGql(
        "MATCH (p1:Person {name: 'name_1'}), (p2:Person {name: 'name_2'}) INSERT (p1)-[:Friend]->(p2);");
    EXPECT_EQ(result.first, E_OK);
    result = store_->ExecuteGql(
        "MATCH (p1:Person {name: 'name_2'}), (p2:Person {name: 'name_3'}) INSERT (p1)-[:Friend]->(p2);");
    EXPECT_EQ(result.first, E_OK);

    result = store_->QueryGql("MATCH (person:Person)-[relation:Friend]->() RETURN person, relation;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 2);
    auto data = result.second->GetAllData();
    GraphValue person = data[0]["person"];
    VerifyPersonInfo(person, "name_1", 11);

    auto result2 =
        store_->QueryGql("MATCH path=(a:Person {name: 'name_1'})-[]->{2, 2}(b:Person {name: 'name_3'}) RETURN path;");
    ASSERT_EQ(result2.first, E_OK);
    EXPECT_EQ(result2.second->GetAllData().size(), 1);

    GraphValue path = result2.second->GetAllData()[0]["path"];
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Path>>(path));

    auto pathPath = std::get<std::shared_ptr<Path>>(path);
    EXPECT_EQ(pathPath->GetPathLength(), 2);
}

/**
 * @tc.name: GdbStore_Execute_001
 * @tc.desc: test GdbStore Execute
 * @tc.type: FUNC
 */
HWTEST_F(GdbExecuteTest, GdbStore_Execute_002, TestSize.Level1)
{
    EXPECT_NE(store_, nullptr);
    auto result = store_->ExecuteGql("INSERT (:Person {name: 'name_1', age: 11});");
    EXPECT_EQ(result.first, E_OK);
    result = store_->ExecuteGql("INSERT (:Person {name: 'name_2', age: 22});");
    EXPECT_EQ(result.first, E_OK);
    result = store_->ExecuteGql("INSERT (:Person {name: 'name_3', age: 33});");
    EXPECT_EQ(result.first, E_OK);
    result = store_->ExecuteGql(
        "MATCH (p1:Person {name: 'name_1'}), (p2:Person {name: 'name_2'}) INSERT (p1)-[:Friend]->(p2);");
    EXPECT_EQ(result.first, E_OK);
    result = store_->ExecuteGql(
        "MATCH (p1:Person {name: 'name_2'}), (p2:Person {name: 'name_3'}) INSERT (p1)-[:Friend]->(p2);");
    EXPECT_EQ(result.first, E_OK);
    result = store_->ExecuteGql(
        "MATCH (p1:Person {name: 'name_1'}), (p2:Person {name: 'name_3'}) INSERT (p1)-[:Friend]->(p2);");
    EXPECT_EQ(result.first, E_OK);

    result = store_->QueryGql(
        "MATCH (person:Person {name: 'name_1'})-[relation:Friend]->(d) where d.age > 25 RETURN person, relation;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue person = result.second->GetAllData()[0]["person"];
    VerifyPersonInfo(person, "name_1", 11);

    GraphValue relation = result.second->GetAllData()[0]["relation"];
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Edge>>(relation));
    auto relationGraphEdge = std::get<std::shared_ptr<Edge>>(relation);
    EXPECT_EQ(relationGraphEdge->GetLabel(), "FRIEND");
}

void GdbExecuteTest::MatchAndVerifyPerson(const std::string &name, const int32_t &age)
{
    EXPECT_NE(store_, nullptr);
    auto gql = "MATCH (person:Person {name: '" + name + "'}) RETURN person;";
    auto result = store_->QueryGql(gql);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue person = result.second->GetAllData()[0]["person"];
    VerifyPersonInfo(person, name, age);
}

void GdbExecuteTest::VerifyPersonInfo(const GraphValue &person, const std::string &name, const int32_t &age)
{
    auto expectSize = 3;
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Vertex>>(person));
    auto personVertex = std::get<std::shared_ptr<Vertex>>(person);
    EXPECT_EQ(personVertex->GetLabel(), "PERSON");
    ASSERT_EQ(personVertex->GetProperties().size(), expectSize);

    auto nameDb = personVertex->GetProperties().find("NAME");
    ASSERT_NE(nameDb, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<std::string>(nameDb->second));
    EXPECT_EQ(std::get<std::string>(nameDb->second), name);

    auto ageDb = personVertex->GetProperties().find("AGE");
    ASSERT_NE(ageDb, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<int64_t>(ageDb->second));
    EXPECT_EQ(std::get<int64_t>(ageDb->second), age);

    auto sex = personVertex->GetProperties().find("SEX");
    ASSERT_NE(sex, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<int64_t>(sex->second));
    EXPECT_EQ(std::get<int64_t>(sex->second), 0);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_Updata, TestSize.Level1)
{
    EXPECT_NE(store_, nullptr);
    auto result = store_->ExecuteGql("INSERT (:Person {name: 'name_1', age: 11});");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("name_1", 11);

    result = store_->ExecuteGql("MATCH (p1:Person {name: 'name_1'}) SET p1.name = 'name_1_modify';");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("name_1_modify", 11);

    result = store_->ExecuteGql(
        "MATCH (p1:Person {name: 'name_1_modify'}) SET p1.name = 'name_1_modify2', p1.age=100 + 11;");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("name_1_modify2", 111);

    result = store_->ExecuteGql("INSERT (:Person {name: 'name_2', age: 22});");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("name_2", 22);
    result = store_->ExecuteGql("MATCH (p2:Person {name: 'name_2'}) SET p2 = {name: 'name_2_modify_all', age: 99};");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("name_2_modify_all", 99);

    result = store_->ExecuteGql("MATCH (p1:Person {name: 'name_1_modify2'}), (p2:Person {name: 'name_2_modify_all'}) "
                                "INSERT (p1)-[:Friend]->(p2);");
    EXPECT_EQ(result.first, E_OK);
    result =
        store_->ExecuteGql("MATCH (n:Person {name: 'name_1_modify2'})-[r:Friend]->(m:Person ) SET m.name = 'name_3';");
    MatchAndVerifyPerson("name_3", 99);
    EXPECT_EQ(result.first, E_OK);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_UpdataNull, TestSize.Level1)
{
    EXPECT_NE(store_, nullptr);
    auto result = store_->ExecuteGql("INSERT (:Person {name: 'hahaha', age: 987});");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("hahaha", 987);
    // update name = null
    result = store_->ExecuteGql("MATCH (p1:Person {name: 'hahaha'}) SET p1 = {age: 666};");
    EXPECT_EQ(result.first, E_OK);
    result = store_->QueryGql("MATCH (person:Person {age: 666}) RETURN person;");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue person = result.second->GetAllData()[0]["person"];
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Vertex>>(person));
    auto personVertex = std::get<std::shared_ptr<Vertex>>(person);
    EXPECT_EQ(personVertex->GetLabel(), "PERSON");
    ASSERT_EQ(personVertex->GetProperties().size(), 2);

    auto nameDb = personVertex->GetProperties().find("NAME");
    ASSERT_EQ(nameDb, personVertex->GetProperties().end());

    auto ageDb = personVertex->GetProperties().find("AGE");
    ASSERT_NE(ageDb, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<int64_t>(ageDb->second));
    EXPECT_EQ(std::get<int64_t>(ageDb->second), 666);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_UpdataNull02, TestSize.Level1)
{
    EXPECT_NE(store_, nullptr);
    auto result = store_->ExecuteGql("INSERT (:Person {name: 'hahaha', age: 987});");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("hahaha", 987);
    // update name = null
    result = store_->ExecuteGql("MATCH (p1:Person {name: 'hahaha'}) SET p1.age = 666, p1.name = null;");
    EXPECT_EQ(result.first, E_OK);
    result = store_->QueryGql("MATCH (person:Person {age: 666}) RETURN person;");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue person = result.second->GetAllData()[0]["person"];
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Vertex>>(person));
    auto personVertex = std::get<std::shared_ptr<Vertex>>(person);
    EXPECT_EQ(personVertex->GetLabel(), "PERSON");
    ASSERT_EQ(personVertex->GetProperties().size(), 2);

    auto nameDb = personVertex->GetProperties().find("NAME");
    ASSERT_EQ(nameDb, personVertex->GetProperties().end());

    auto ageDb = personVertex->GetProperties().find("AGE");
    ASSERT_NE(ageDb, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<int64_t>(ageDb->second));
    EXPECT_EQ(std::get<int64_t>(ageDb->second), 666);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_Updata_MatchFail, TestSize.Level1)
{
    EXPECT_NE(store_, nullptr);
    auto result = store_->ExecuteGql("INSERT (:Person {name: 'zhangsan001', age: 10});");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("zhangsan001", 10);

    result = store_->ExecuteGql("MATCH (p1:Person {name: 'notFound'}) SET p1.name = 'name_1_modify';");
    EXPECT_EQ(result.first, E_OK);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_Updata_AgeError, TestSize.Level1)
{
    EXPECT_NE(store_, nullptr);

    auto result = store_->ExecuteGql("INSERT (:Person {name: 'name_4', age: 44});");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("name_4", 44);

    result = store_->ExecuteGql("MATCH (p1:Person {name: 'name_4'}) SET p1.age = 'string_age';");
    EXPECT_EQ(result.first, E_GRD_SEMANTIC_ERROR);
    // update failed, no change
    MatchAndVerifyPerson("name_4", 44);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_Updata_ColumnError, TestSize.Level1)
{
    EXPECT_NE(store_, nullptr);

    auto result = store_->ExecuteGql("INSERT (:PersonErr {name: true, age: 44});");
    EXPECT_EQ(result.first, E_GRD_UNDEFINED_TABLE);

    auto gql = "MATCH (person:Person) RETURN person;";
    result = store_->QueryGql(gql);
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 0);

    result = store_->ExecuteGql("INSERT (:Person {name: true, age: 44});");
    EXPECT_EQ(result.first, E_GRD_SEMANTIC_ERROR);
    gql = "MATCH (person:Person) RETURN person;";
    result = store_->QueryGql(gql);
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 0);

    result = store_->ExecuteGql("INSERT (:Person {name: 'zhangsan', age: 'error'});");
    EXPECT_EQ(result.first, E_GRD_SEMANTIC_ERROR);
    gql = "MATCH (person:Person) RETURN person;";
    result = store_->QueryGql(gql);
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 0);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_Delete, TestSize.Level1)
{
    EXPECT_NE(store_, nullptr);

    auto result = store_->ExecuteGql("INSERT (:Person {name: 'zhangsan_delete', age: 10});");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("zhangsan_delete", 10);

    result = store_->ExecuteGql("MATCH (p:Person {name: 'zhangsan_delete'}) DETACH DELETE p;");
    EXPECT_EQ(result.first, E_OK);
    auto gql = "MATCH (person:Person {name: 'zhangsan_delete'}) RETURN person;";
    result = store_->QueryGql(gql);
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 0);
    // Double Delete
    result = store_->ExecuteGql("MATCH (p:Person {name: 'zhangsan_delete'}) DETACH DELETE p;");
    EXPECT_EQ(result.first, E_OK);
    gql = "MATCH (person:Person {name: 'zhangsan_delete'}) RETURN person;";
    result = store_->QueryGql(gql);
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 0);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_Delete_NotFound, TestSize.Level1)
{
    EXPECT_NE(store_, nullptr);
    auto result = store_->ExecuteGql("INSERT (:Person {name: 'zhangsan_delete', age: 10});");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("zhangsan_delete", 10);

    result = store_->ExecuteGql("MATCH (p:Person {name: 'notFound'}) DETACH DELETE p;");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("zhangsan_delete", 10);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_Delete_PError, TestSize.Level1)
{
    EXPECT_NE(store_, nullptr);
    auto result = store_->ExecuteGql("INSERT (:Person {name: 'delete_error', age: 11});");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("delete_error", 11);

    result = store_->ExecuteGql("MATCH (p:Person {name: 'delete_error'}) DETACH DELETE p_error;");
    EXPECT_EQ(result.first, E_GRD_UNDEFINED_OBJECT);
    MatchAndVerifyPerson("delete_error", 11);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_Delete_Related, TestSize.Level1)
{
    EXPECT_NE(store_, nullptr);

    auto result = store_->ExecuteGql("INSERT (:Person {name: 'delete_1', age: 11});");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("delete_1", 11);
    result = store_->ExecuteGql("INSERT (:Person {name: 'delete_2', age: 22});");
    MatchAndVerifyPerson("delete_2", 22);
    EXPECT_EQ(result.first, E_OK);

    result = store_->ExecuteGql(
        "MATCH (p1:Person {name: 'delete_1'}), (p2:Person {name: 'delete_2'}) INSERT (p1)-[:Friend]->(p2);");
    EXPECT_EQ(result.first, E_OK);
    result =
        store_->QueryGql("MATCH (person:Person {name: 'delete_1'})-[relation:Friend]->() RETURN person, relation;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue person = result.second->GetAllData()[0]["person"];
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Vertex>>(person));
    auto personVertex = std::get<std::shared_ptr<Vertex>>(person);
    EXPECT_EQ(personVertex->GetLabel(), "PERSON");
    ASSERT_EQ(personVertex->GetProperties().size(), 3);
    auto name = personVertex->GetProperties().find("NAME");
    ASSERT_NE(name, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<std::string>(name->second));
    EXPECT_EQ(std::get<std::string>(name->second), "delete_1");

    auto age = personVertex->GetProperties().find("AGE");
    ASSERT_NE(age, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<int64_t>(age->second));
    EXPECT_EQ(std::get<int64_t>(age->second), 11);

    result = store_->ExecuteGql("MATCH (p:Person)-[:Friend]->(relatedPerson:Person) DETACH DELETE p, relatedPerson;");
    EXPECT_EQ(result.first, E_OK);
    result =
        store_->QueryGql("MATCH (person:Person {name: 'delete_1'})-[relation:Friend]->() RETURN person, relation;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 0);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_Delete_Related_Error, TestSize.Level1)
{
    EXPECT_NE(store_, nullptr);

    auto result = store_->ExecuteGql("INSERT (:Person {name: 'delete_3', age: 11});");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("delete_3", 11);
    result = store_->ExecuteGql("INSERT (:Person {name: 'delete_4', age: 22});");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("delete_4", 22);

    result = store_->ExecuteGql(
        "MATCH (p1:Person {name: 'delete_3'}), (p2:Person {name: 'delete_4'}) INSERT (p1)-[:Friend]->(p2);");
    EXPECT_EQ(result.first, E_OK);
    result =
        store_->QueryGql("MATCH (person:Person {name: 'delete_3'})-[relation:Friend]->() RETURN person, relation;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue person = result.second->GetAllData()[0]["person"];
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Vertex>>(person));
    auto personVertex = std::get<std::shared_ptr<Vertex>>(person);
    EXPECT_EQ(personVertex->GetLabel(), "PERSON");
    ASSERT_EQ(personVertex->GetProperties().size(), 3);
    auto name = personVertex->GetProperties().find("NAME");
    ASSERT_NE(name, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<std::string>(name->second));
    EXPECT_EQ(std::get<std::string>(name->second), "delete_3");

    // No Friend_Error, delete Eror
    result =
        store_->ExecuteGql("MATCH (p:Person)-[:Friend_Error]->(relatedPerson:Person) DETACH DELETE p, relatedPerson;");
    EXPECT_EQ(result.first, E_GRD_UNDEFINED_TABLE);
    // p:Person, but delete p_error
    result =
        store_->ExecuteGql("MATCH (p:Person)-[:Friend]->(relatedPerson:Person) DETACH DELETE p_error, relatedPerson;");
    EXPECT_EQ(result.first, E_GRD_UNDEFINED_OBJECT);
    //relatedPerson:Person, but delete relatedPerson_error
    result =
        store_->ExecuteGql("MATCH (p:Person)-[:Friend]->(relatedPerson:Person) DETACH DELETE p, relatedPerson_error;");
    EXPECT_EQ(result.first, E_GRD_UNDEFINED_OBJECT);

    result = store_->ExecuteGql("MATCH (p:Person)-[:Friend]->(relatedPerson:Person) DETACH DELETE relatedPerson, p;");
    EXPECT_EQ(result.first, E_OK);
    // delete success, data.size == 0
    result =
        store_->QueryGql("MATCH (person:Person {name: 'delete_3'})-[relation:Friend]->() RETURN person, relation;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 0);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_QueryGql, TestSize.Level1)
{
    EXPECT_NE(store_, nullptr);
    auto result = store_->ExecuteGql("INSERT (:Person {name: 'zhangsan_111', age: 11, sex: true});");
    EXPECT_EQ(result.first, E_OK);

    result = store_->QueryGql("MATCH (person:Person {name: 'zhangsan_111'}) RETURN person;");
    EXPECT_EQ(result.first, E_OK);

    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue personErr = result.second->GetAllData()[0]["personErr"];
    // No personErr
    ASSERT_TRUE(std::holds_alternative<std::monostate>(personErr));

    GraphValue person = result.second->GetAllData()[0]["person"];
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Vertex>>(person));
    auto personVertex = std::get<std::shared_ptr<Vertex>>(person);
    ASSERT_NE(personVertex->GetLabel(), "error_label");
    EXPECT_EQ(personVertex->GetLabel(), "PERSON");
    // size = 4 {name, age, sex, identity}
    ASSERT_EQ(personVertex->GetProperties().size(), 3);

    auto name = personVertex->GetProperties().find("NAME");
    ASSERT_NE(name, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<std::string>(name->second));
    EXPECT_EQ(std::get<std::string>(name->second), "zhangsan_111");

    auto age = personVertex->GetProperties().find("AGE");
    ASSERT_NE(age, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<int64_t>(age->second));
    EXPECT_EQ(std::get<int64_t>(age->second), 11);

    auto sex = personVertex->GetProperties().find("SEX");
    ASSERT_NE(sex, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<int64_t>(sex->second));
    EXPECT_EQ(std::get<int64_t>(sex->second), 1);
    // No Propertie is OTHER, equal End
    auto other = personVertex->GetProperties().find("OTHER");
    EXPECT_EQ(other, personVertex->GetProperties().end());
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_QueryGql_2, TestSize.Level1)
{
    EXPECT_NE(store_, nullptr);

    auto result = store_->ExecuteGql("INSERT (:Person {name: 'lisi_1', age: 66});");
    EXPECT_EQ(result.first, E_OK);
    result = store_->ExecuteGql("INSERT (:Person {name: 'lisi_2', age: 66, sex: true});");
    EXPECT_EQ(result.first, E_OK);
    result = store_->ExecuteGql("INSERT (:Dog {name: 'xiaohuang1', age: 66});");
    EXPECT_EQ(result.first, E_OK);
    result = store_->QueryGql("MATCH (person:Person{age: 66}) RETURN person;");
    EXPECT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 2);

    GraphValue person = result.second->GetAllData()[0]["person"];
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Vertex>>(person));
    auto personVertex = std::get<std::shared_ptr<Vertex>>(person);
    EXPECT_EQ(personVertex->GetLabel(), "PERSON");
    ASSERT_EQ(personVertex->GetProperties().size(), 3);
    auto name = personVertex->GetProperties().find("NAME");
    ASSERT_NE(name, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<std::string>(name->second));
    EXPECT_EQ(std::get<std::string>(name->second), "lisi_1");
    auto age = personVertex->GetProperties().find("AGE");
    ASSERT_NE(age, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<int64_t>(age->second));
    EXPECT_EQ(std::get<int64_t>(age->second), 66);
    auto sex = personVertex->GetProperties().find("SEX");
    ASSERT_NE(sex, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<int64_t>(age->second));
    EXPECT_EQ(std::get<int64_t>(sex->second), 0);

    person = result.second->GetAllData()[1]["person"];
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Vertex>>(person));
    personVertex = std::get<std::shared_ptr<Vertex>>(person);
    EXPECT_EQ(personVertex->GetLabel(), "PERSON");
    ASSERT_EQ(personVertex->GetProperties().size(), 3);
    name = personVertex->GetProperties().find("NAME");
    ASSERT_NE(name, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<std::string>(name->second));
    EXPECT_EQ(std::get<std::string>(name->second), "lisi_2");
    age = personVertex->GetProperties().find("AGE");
    ASSERT_NE(age, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<int64_t>(age->second));
    EXPECT_EQ(std::get<int64_t>(age->second), 66);
    sex = personVertex->GetProperties().find("SEX");
    ASSERT_NE(sex, personVertex->GetProperties().end());
    ASSERT_TRUE(std::holds_alternative<int64_t>(age->second));
    EXPECT_EQ(std::get<int64_t>(sex->second), 1);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_ParseEdge, TestSize.Level1)
{
    EXPECT_NE(store_, nullptr);
    int errCode = E_ERROR;
    // no start, no end
    nlohmann::json json = nlohmann::json::parse("{\"name\" : \"zhangsan\"}", nullptr, false);
    ASSERT_FALSE(json.is_discarded());
    ASSERT_FALSE(json.is_null());
    Edge::Parse(json, errCode);
    EXPECT_EQ(errCode, E_PARSE_JSON_FAILED);
    // no identity
    std::string jsonStr = "{\"start\" : 1, \"end\" : 2}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    Edge::Parse(json, errCode);
    EXPECT_EQ(errCode, E_PARSE_JSON_FAILED);
    // ok
    jsonStr = "{\"start\" : 1, \"end\" : 2, \"label\":\"COMPANY\",\"identity\":3,"
              "\"properties\":{\"NAME\":\"myCompany3\",\"FOUNDED\":2011}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    Edge::Parse(json, errCode);
    EXPECT_EQ(errCode, E_OK);
    // start is AA
    jsonStr = "{\"start\" : \"AA\", \"end\" : 2, \"label\":\"COMPANY\",\"identity\":3,"
              "\"properties\":{\"NAME\":\"myCompany3\",\"FOUNDED\":2011}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    Edge::Parse(json, errCode);
    EXPECT_EQ(errCode, E_OK);
    // end is B
    jsonStr = "{\"start\" : 1, \"end\" : \"B\", \"label\":\"COMPANY\",\"identity\":3,"
              "\"properties\":{\"NAME\":\"myCompany3\",\"FOUNDED\":2011}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    Edge::Parse(json, errCode);
    EXPECT_EQ(errCode, E_OK);
    // identity is C
    jsonStr = "{\"start\" : 1, \"end\" : 2, \"label\":\"COMPANY\",\"identity\":\"C\","
              "\"properties\":{\"NAME\":\"myCompany3\",\"FOUNDED\":2011}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    Edge::Parse(json, errCode);
    EXPECT_EQ(errCode, E_OK);
    // label is 222
    jsonStr = "{\"start\" : 1, \"end\" : 2, \"label\":222,'identity':3,\"properties\":{\"NAME\":\"myCompany3\","
              "\"FOUNDED\":2011}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    Edge::Parse(json, errCode);
    EXPECT_EQ(errCode, E_PARSE_JSON_FAILED);
    // key4 is null
    jsonStr =
        "{\"start\" : 1, \"end\" : 2, \"label\":\"COMPANY\",\"identity\":2,"
        "\"properties\":{\"NAME\":\"myCompany3\",\"FOUNDED\":4.5,\"SEX\":true,\"key1\":true,\"key2\":[], \"key3\":{}, "
        "\"key4\": null}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    Edge::Parse(json, errCode);
    EXPECT_EQ(errCode, E_PARSE_JSON_FAILED);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_PathSegment, TestSize.Level1)
{
    EXPECT_NE(store_, nullptr);
    int errCode = E_ERROR;
    // NO start and end
    nlohmann::json json = nlohmann::json::parse("{\"name\" : \"zhangsan\"}", nullptr, false);
    ASSERT_FALSE(json.is_discarded());
    ASSERT_FALSE(json.is_null());
    PathSegment::Parse(json, errCode);
    ASSERT_EQ(errCode, E_PARSE_JSON_FAILED);
    // no relationship
    std::string jsonStr = "{\"start\" : {}, \"end\" : {}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    PathSegment::Parse(json, errCode);
    ASSERT_EQ(errCode, E_PARSE_JSON_FAILED);

    jsonStr = "{\"start\" : {}, \"end\" : {}, \"relationship\":{}, \"label\":\"COMPANY\",\"identity\":3,"
              "\"properties\":{\"NAME\":\"myCompany3\",\"FOUNDED\":2011}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    PathSegment::Parse(json, errCode);
    ASSERT_EQ(errCode, E_PARSE_JSON_FAILED);

    jsonStr = "{\"start\" : {}, \"end\" : {}, \"relationship\":{}, \"label\":\"COMPANY\",\"identity\":3,"
              "\"properties\":{\"NAME\":\"myCompany3\",\"FOUNDED\":2011}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    PathSegment::Parse(json, errCode);
    ASSERT_EQ(errCode, E_PARSE_JSON_FAILED);

    jsonStr = "{\"start\" : {}, \"end\" : {}, \"relationship\":{}, \"label\":\"COMPANY\",\"identity\":\"C\","
              "\"properties\":{\"NAME\":\"myCompany3\",\"FOUNDED\":2011}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    PathSegment::Parse(json, errCode);
    ASSERT_EQ(errCode, E_PARSE_JSON_FAILED);

    jsonStr = "{\"start\" : {}, \"end\" : {}, \"relationship\":{}, \"label\":222,\"identity\":2,"
              "\"properties\":{\"NAME\":\"myCompany3\",\"FOUNDED\":2011}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    PathSegment::Parse(json, errCode);
    ASSERT_EQ(errCode, E_PARSE_JSON_FAILED);

    jsonStr = "{\"start\" : {}, \"end\" : {}, \"relationship\":{}, \"label\":\"COMPANY\",\"identity\":2,"
              "\"properties\":{\"NAME\":\"myCompany3\",\"FOUNDED\":4.5,\"SEX\":true,\"key1\":true,\"key2\":[], "
              "\"key3\":{}, \"key4\": null}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    PathSegment::Parse(json, errCode);
    ASSERT_EQ(errCode, E_PARSE_JSON_FAILED);

    json = nlohmann::json::parse(pathJsonString, nullptr, false);
    PathSegment::Parse(json, errCode);
    ASSERT_EQ(errCode, E_OK);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_PathSegment02, TestSize.Level1)
{
    EXPECT_NE(store_, nullptr);
    int errCode = E_ERROR;
    nlohmann::json json = nlohmann::json::parse(pathJsonString, nullptr, false);
    PathSegment::Parse(json, errCode);
    EXPECT_EQ(errCode, E_OK);
    // identity:A, E_OK
    std::string jsonStr =
        "{\"start\":{\"label\":\"PERSON\",\"identity\":\"A\",\"properties\":{\"AGE\":32,\"SALARY\":75.35,"
        "\"NAME\":\"Alice\",\"GENDER\":\"Female\",\"PHONENUMBERS\":false,\"EMAILS\":null}},"
        "\"end\":{\"label\":\"PERSON\",\"identity\":2,\"properties\":{\"AGE\":28,\"SALARY\":65000,"
        "\"NAME\":\"Bob\",\"GENDER\":\"Male\",\"PHONENUMBERS\":\"123456789\",\"EMAILS\":\" bob@example.com\"}},"
        "\"relationship\":{\"label\":\"鐩寸郴浜插睘\",\"identity\":3,\"start\":1,\"end\":2,\"properties\":{\"NUM\":4,"
        "\"PINYIN\":\"zhixiqinshu\"}}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    PathSegment::Parse(json, errCode);
    EXPECT_EQ(errCode, E_OK);

    // label:2, E_PARSE_JSON_FAILED
    jsonStr =
        "{\"start\":{\"label\":2,\"identity\":1,\"properties\":{\"AGE\":32,\"SALARY\":75.35,"
        "\"NAME\":\"Alice\",\"GENDER\":\"Female\",\"PHONENUMBERS\":false,\"EMAILS\":null}},"
        "\"end\":{\"label\":\"PERSON\",\"identity\":2,\"properties\":{\"AGE\":28,\"SALARY\":65000,"
        "\"NAME\":\"Bob\",\"GENDER\":\"Male\",\"PHONENUMBERS\":\"123456789\",\"EMAILS\":\" bob@example.com\"}},"
        "\"relationship\":{\"label\":\"鐩寸郴浜插睘\",\"identity\":3,\"start\":1,\"end\":2,\"properties\":{\"NUM\":4,"
        "\"PINYIN\":\"zhixiqinshu\"}}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    PathSegment::Parse(json, errCode);
    EXPECT_EQ(errCode, E_PARSE_JSON_FAILED);

    // relationship->start:B, E_OK
    jsonStr =
        "{\"start\":{\"label\":\"PERSON\",\"identity\":1,\"properties\":{\"AGE\":32,\"SALARY\":75.35,"
        "\"NAME\":\"Alice\",\"GENDER\":\"Female\",\"PHONENUMBERS\":false,\"EMAILS\":null}},"
        "\"end\":{\"label\":\"PERSON\",\"identity\":2,\"properties\":{\"AGE\":28,\"SALARY\":65000,"
        "\"NAME\":\"Bob\",\"GENDER\":\"Male\",\"PHONENUMBERS\":\"123456789\",\"EMAILS\":\" bob@example.com\"}},"
        "\"relationship\":{\"label\":\"鐩寸郴浜插睘\",\"identity\":3,\"start\":\"B\",\"end\":2,\"properties\":{\"NUM\":4,"
        "\"PINYIN\":\"zhixiqinshu\"}}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    PathSegment::Parse(json, errCode);
    EXPECT_EQ(errCode, E_OK);

    // relationship->end:C, E_OK
    jsonStr =
        "{\"start\":{\"label\":\"PERSON\",\"identity\":1,\"properties\":{\"AGE\":32,\"SALARY\":75.35,"
        "\"NAME\":\"Alice\",\"GENDER\":\"Female\",\"PHONENUMBERS\":false,\"EMAILS\":null}},"
        "\"end\":{\"label\":\"PERSON\",\"identity\":2,\"properties\":{\"AGE\":28,\"SALARY\":65000,"
        "\"NAME\":\"Bob\",\"GENDER\":\"Male\",\"PHONENUMBERS\":\"123456789\",\"EMAILS\":\" bob@example.com\"}},"
        "\"relationship\":{\"label\":\"鐩寸郴浜插睘\",\"identity\":3,\"start\":1,\"end\":\"C\",\"properties\":{\"NUM\":4,"
        "\"PINYIN\":\"zhixiqinshu\"}}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    PathSegment::Parse(json, errCode);
    ASSERT_EQ(errCode, E_OK);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_PathSegment03, TestSize.Level1)
{
    EXPECT_NE(store_, nullptr);
    int errCode = E_ERROR;
    nlohmann::json json = nlohmann::json::parse(pathJsonString, nullptr, false);
    PathSegment::Parse(json, errCode);
    ASSERT_EQ(errCode, E_OK);
    // end no label:PERSON and identity: A
    std::string jsonStr =
        "{\"start\":{\"label\":\"PERSON\",\"identity\":1,\"properties\":{\"AGE\":32,\"SALARY\":75.35,"
        "\"NAME\":\"Alice\",\"GENDER\":\"Female\",\"PHONENUMBERS\":false,\"EMAILS\":null}},"
        "\"end\":{\"identity\":\"A\",\"properties\":{\"AGE\":28,\"SALARY\":65000,"
        "\"NAME\":\"Bob\",\"GENDER\":\"Male\",\"PHONENUMBERS\":\"123456789\",\"EMAILS\":\" bob@example.com\"}},"
        "\"relationship\":{\"label\":\"鐩寸郴浜插睘\",\"identity\":3,\"start\":1,\"end\":2,\"properties\":{\"NUM\":4,"
        "\"PINYIN\":\"zhixiqinshu\"}}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    PathSegment::Parse(json, errCode);
    ASSERT_EQ(errCode, E_PARSE_JSON_FAILED);
}
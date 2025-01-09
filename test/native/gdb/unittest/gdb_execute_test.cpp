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
#include <utility>
#include <variant>

#include "aip_errors.h"
#include "db_store_impl.h"
#include "edge.h"
#include "grd_adapter.h"
#include "grd_adapter_manager.h"
#include "gdb_helper.h"
#include "gdb_store.h"
#include "gdb_utils.h"
#include "graph_statement.h"
#include "graph_connection.h"
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
    if (!IsSupportArkDataDb()) {
        GTEST_SKIP() << "Current testcase is not compatible from current gdb";
        return;
    }
    int errCode = E_OK;
    auto config = StoreConfig(databaseName, databasePath);
    GDBHelper::DeleteDBStore(config);

    GdbExecuteTest::store_ = GDBHelper::GetDBStore(config, errCode);
}

void GdbExecuteTest::TearDownTestCase()
{
    GDBHelper::DeleteDBStore(StoreConfig(databaseName, databasePath));
    store_ = nullptr;
}

void GdbExecuteTest::SetUp()
{
    if (!IsSupportArkDataDb()) {
        GTEST_SKIP() << "Current testcase is not compatible from current gdb";
        return;
    }
    auto result = store_->ExecuteGql(createGraphGql);
}

void GdbExecuteTest::TearDown()
{
    if (store_ != nullptr) {
        auto result = store_->ExecuteGql("DROP GRAPH test");
    }
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
    GDBHelper::DeleteDBStore(config);
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
    GDBHelper::DeleteDBStore(config);
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
    GDBHelper::DeleteDBStore(config);
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
    GDBHelper::DeleteDBStore(config);
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
    GDBHelper::DeleteDBStore(config);
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
    GDBHelper::DeleteDBStore(config);
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
    GDBHelper::DeleteDBStore(config);
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
    ASSERT_NE(store_, nullptr);
    auto result = store_->QueryGql("MATCH (person:Person {age: 11}) RETURN person;");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 0);
}

HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_AfterClose, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
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
    GDBHelper::DeleteDBStore(config);
}

/**
 * @tc.name: GdbStore_GetDBStore_AfterDrop
 * @tc.desc: test GdbStore AfterDrop Insert
 * @tc.type: FUNC
 */
HWTEST_F(GdbExecuteTest, GdbStore_GetDBStore_AfterDrop, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
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
    GDBHelper::DeleteDBStore(config);
}

/**
 * @tc.name: GdbStore_Execute_001
 * @tc.desc: test GdbStore Execute
 * @tc.type: FUNC
 */
HWTEST_F(GdbExecuteTest, GdbStore_Execute_LongName, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
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
    ASSERT_NE(store_, nullptr);
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
    ASSERT_NE(store_, nullptr);
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
    ASSERT_NE(store_, nullptr);
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
    ASSERT_NE(store_, nullptr);
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
    ASSERT_NE(store_, nullptr);
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
    ASSERT_NE(store_, nullptr);
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
    ASSERT_NE(store_, nullptr);
    auto result = store_->ExecuteGql("INSERT (:Person {name: 'zhangsan001', age: 10});");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("zhangsan001", 10);

    result = store_->ExecuteGql("MATCH (p1:Person {name: 'notFound'}) SET p1.name = 'name_1_modify';");
    EXPECT_EQ(result.first, E_OK);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_Updata_AgeError, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

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
    ASSERT_NE(store_, nullptr);

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
    ASSERT_NE(store_, nullptr);

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
    ASSERT_NE(store_, nullptr);
    auto result = store_->ExecuteGql("INSERT (:Person {name: 'zhangsan_delete', age: 10});");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("zhangsan_delete", 10);

    result = store_->ExecuteGql("MATCH (p:Person {name: 'notFound'}) DETACH DELETE p;");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("zhangsan_delete", 10);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_Delete_PError, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
    auto result = store_->ExecuteGql("INSERT (:Person {name: 'delete_error', age: 11});");
    EXPECT_EQ(result.first, E_OK);
    MatchAndVerifyPerson("delete_error", 11);

    result = store_->ExecuteGql("MATCH (p:Person {name: 'delete_error'}) DETACH DELETE p_error;");
    EXPECT_EQ(result.first, E_GRD_UNDEFINED_OBJECT);
    MatchAndVerifyPerson("delete_error", 11);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_Delete_Related, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);

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
    ASSERT_NE(store_, nullptr);

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
    ASSERT_NE(store_, nullptr);
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
    ASSERT_NE(store_, nullptr);

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
    ASSERT_NE(store_, nullptr);
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
    ASSERT_NE(store_, nullptr);
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
    ASSERT_NE(store_, nullptr);
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
        "\"relationship\":{\"label\":\"tttt\",\"identity\":3,\"start\":1,\"end\":2,\"properties\":{\"NUM\":4,"
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
        "\"relationship\":{\"label\":\"tttt\",\"identity\":3,\"start\":1,\"end\":2,\"properties\":{\"NUM\":4,"
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
        "\"relationship\":{\"label\":\"tttt\",\"identity\":3,\"start\":\"B\",\"end\":2,\"properties\":{\"NUM\":4,"
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
        "\"relationship\":{\"label\":\"tttt\",\"identity\":3,\"start\":1,\"end\":\"C\",\"properties\":{\"NUM\":4,"
        "\"PINYIN\":\"zhixiqinshu\"}}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    PathSegment::Parse(json, errCode);
    ASSERT_EQ(errCode, E_OK);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_PathSegment03, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
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
        "\"relationship\":{\"label\":\"tttt\",\"identity\":3,\"start\":1,\"end\":2,\"properties\":{\"NUM\":4,"
        "\"PINYIN\":\"zhixiqinshu\"}}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    PathSegment::Parse(json, errCode);
    ASSERT_EQ(errCode, E_PARSE_JSON_FAILED);
    
    jsonStr = "{\"start\" : 1, \"end\" : {}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    PathSegment::Parse(json, errCode);
    ASSERT_EQ(errCode, E_PARSE_JSON_FAILED);

    jsonStr = "{\"start\" : {}, \"relationship\" : 1}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    PathSegment::Parse(json, errCode);
    ASSERT_EQ(errCode, E_PARSE_JSON_FAILED);

    jsonStr = "{\"start\" : {}, \"relationship\" : {}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    PathSegment::Parse(json, errCode);
    ASSERT_EQ(errCode, E_PARSE_JSON_FAILED);

    jsonStr = "{\"start\" : {}, \"relationship\" : {}, \"end\" : 1}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    PathSegment::Parse(json, errCode);
    ASSERT_EQ(errCode, E_PARSE_JSON_FAILED);

    jsonStr = "{\"start\" : {}, \"relationship\" : {}, \"end\" : {}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    PathSegment::Parse(json, errCode);
    ASSERT_EQ(errCode, E_PARSE_JSON_FAILED);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_PathSegment04, TestSize.Level1)
{
    int errCode = E_ERROR;
    nlohmann::json json = nlohmann::json::parse(pathJsonString, nullptr, false);
    PathSegment::Parse(json, errCode);
    EXPECT_EQ(errCode, E_OK);
    // identity:A, E_OK
    std::string jsonStr =
        "{\"start\":{\"label\":\"PERSON\",\"identity\":{},\"properties\":{\"AGE\":32,\"SALARY\":75.35,"
        "\"NAME\":\"Alice\",\"GENDER\":\"Female\",\"PHONENUMBERS\":false,\"EMAILS\":null}},"
        "\"end\":{\"label\":\"PERSON\",\"identity\":2,\"properties\":{\"AGE\":28,\"SALARY\":65000,"
        "\"NAME\":\"Bob\",\"GENDER\":\"Male\",\"PHONENUMBERS\":\"123456789\",\"EMAILS\":\" bob@example.com\"}},"
        "\"relationship\":{\"label\":\"tttt\",\"identity\":3,\"start\":1,\"end\":2,\"properties\":{\"NUM\":4,"
        "\"PINYIN\":\"zhixiqinshu\"}}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    PathSegment::Parse(json, errCode);
    EXPECT_EQ(errCode, E_PARSE_JSON_FAILED);
    std::shared_ptr<Vertex> sourceVertex;
    std::shared_ptr<Vertex> targetVertex;
    std::shared_ptr<Edge> edge;
    auto paths = std::make_shared<PathSegment>(sourceVertex, targetVertex, edge);
    EXPECT_NE(paths, nullptr);
    EXPECT_EQ(sourceVertex, paths->GetSourceVertex());
    EXPECT_EQ(edge, paths->GetEdge());
    EXPECT_EQ(targetVertex, paths->GetTargetVertex());
    jsonStr =
        "{\"start\":{\"label\":\"PERSON\",\"identity\":1,\"properties\":{\"AGE\":32,\"SALARY\":75.35,"
        "\"NAME\":\"Alice\",\"GENDER\":\"Female\",\"PHONENUMBERS\":false,\"EMAILS\":null}},"
        "\"end\":{\"label\":\"PERSON\",\"identity\":2,\"properties\":{\"AGE\":28,\"SALARY\":65000,"
        "\"NAME\":\"Bob\",\"GENDER\":\"Male\",\"PHONENUMBERS\":\"123456789\",\"EMAILS\":\" bob@example.com\"}},"
        "\"relationship\":{}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    PathSegment::Parse(json, errCode);
    ASSERT_EQ(errCode, E_PARSE_JSON_FAILED);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_Path01, TestSize.Level1)
{
    std::shared_ptr<Vertex> start = std::make_shared<Vertex>();
    std::shared_ptr<Vertex> end = std::make_shared<Vertex>();
    auto path = std::make_shared<Path>();
    path = std::make_shared<Path>(start, end);
    EXPECT_NE(path, nullptr);
    path->SetPathLength(1);
    EXPECT_EQ(1, path->GetPathLength());
    path->SetStart(std::make_shared<Vertex>("1", "HAHA"));
    EXPECT_EQ("1", path->GetStart()->GetId());
    EXPECT_EQ("HAHA", path->GetStart()->GetLabel());
    auto labels = path->GetStart()->GetLabels();
    EXPECT_EQ(1, labels.size());

    path->SetEnd(std::make_shared<Vertex>("2", "HAHA2"));
    EXPECT_EQ("2", path->GetEnd()->GetId());
    EXPECT_EQ("HAHA2", path->GetEnd()->GetLabel());
    auto segment = path->GetSegments();
    EXPECT_EQ(segment.size(), 0);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_Path02, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
    int errCode = E_ERROR;
    nlohmann::json json = nlohmann::json::parse(pathJsonString, nullptr, false);
    Path::Parse(json, errCode);
    // no length
    EXPECT_EQ(errCode, E_PARSE_JSON_FAILED);
    // identity:A, E_OK
    std::string jsonStr =
        "{\"length\": 1,\"start\":{\"label\":\"PERSON\",\"identity\":3,\"properties\":{\"AGE\":32,\"SALARY\":75.35,"
        "\"NAME\":\"Alice\",\"GENDER\":\"Female\"}},"
        "\"end\":{\"label\":\"PERSON\",\"identity\":2,\"properties\":{\"AGE\":28,\"SALARY\":65000,"
        "\"NAME\":\"Bob\",\"GENDER\":\"Male\",\"PHONENUMBERS\":\"123456789\",\"EMAILS\":\" bob@example.com\"}},"
        "\"relationship\":{\"label\":\"tttt\",\"identity\":3,\"start\":1,\"end\":2,\"properties\":{\"NUM\":4,"
        "\"PINYIN\":\"zhixiqinshu\"}},\"segments\":[{\"start\":{\"label\":\"PERSON\","
        "\"identity\":1,\"properties\":{\"AGE\":32,\"SALARY\":75.35,"
        "\"NAME\":\"Alice\",\"GENDER\":\"Female\",\"PHONENUMBERS\":false,\"EMAILS\":null}},"
        "\"end\":{\"label\":\"PERSON\",\"identity\":2,\"properties\":{\"AGE\":28,\"SALARY\":65000,"
        "\"NAME\":\"Bob\",\"GENDER\":\"Male\",\"PHONENUMBERS\":\"123456789\",\"EMAILS\":\" bob@example.com\"}},"
        "\"relationship\":{\"label\":\"tttt\",\"identity\":3,\"start\":1,\"end\":\"C\",\"properties\":{\"NUM\":4,"
        "\"PINYIN\":\"zhixiqinshu\"}}}]}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    Path::Parse(json, errCode);
    EXPECT_EQ(errCode, E_OK);

    // label:2, E_PARSE_JSON_FAILED
    jsonStr =
        "{\"length\": 1,\"start\":{\"label\":2,\"identity\":1,\"properties\":{\"AGE\":32,\"SALARY\":75.35,"
        "\"NAME\":\"Alice\",\"GENDER\":\"Female\",\"PHONENUMBERS\":false,\"EMAILS\":null}},"
        "\"end\":{\"label\":\"PERSON\",\"identity\":2,\"properties\":{\"AGE\":28,\"SALARY\":65000,"
        "\"NAME\":\"Bob\",\"GENDER\":\"Male\",\"PHONENUMBERS\":\"123456789\",\"EMAILS\":\" bob@example.com\"}},"
        "\"relationship\":{\"label\":\"tttt\",\"identity\":3,\"start\":1,\"end\":2,\"properties\":{\"NUM\":4,"
        "\"PINYIN\":\"zhixiqinshu\"}},\"segments\":[{}]}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    Path::Parse(json, errCode);
    EXPECT_EQ(errCode, E_PARSE_JSON_FAILED);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_Path03, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
    int errCode = E_ERROR;
    nlohmann::json json = nlohmann::json::parse(pathJsonString, nullptr, false);
    Path::Parse(json, errCode);
    // no length
    EXPECT_EQ(errCode, E_PARSE_JSON_FAILED);
    // relationship->start:B, E_OK
    auto jsonStr =
        "{\"length\": 1,\"start\":{\"label\":\"PERSON\",\"identity\":1,\"properties\":{\"AGE\":32,\"SALARY\":75.35,"
        "\"NAME\":\"Alice\",\"GENDER\":\"Female\",\"PHONENUMBERS\":false,\"EMAILS\":null}},"
        "\"end\":{\"label\":\"PERSON\",\"identity\":2,\"properties\":{\"AGE\":28,\"SALARY\":65000,"
        "\"NAME\":\"Bob\",\"GENDER\":\"Male\",\"PHONENUMBERS\":\"123456789\",\"EMAILS\":\" bob@example.com\"}},"
        "\"relationship\":{\"label\":\"tttt\",\"identity\":3,\"start\":\"B\",\"end\":2,\"properties\":{\"NUM\":4,"
        "\"PINYIN\":\"zhixiqinshu\"}},\"segments\":[{}]}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    Path::Parse(json, errCode);
    EXPECT_EQ(errCode, E_PARSE_JSON_FAILED);

    // relationship->end:C, E_OK
    jsonStr =
        "{\"length\": 1,\"start\":{\"label\":\"PERSON\",\"identity\":1,\"properties\":{\"AGE\":32,\"SALARY\":75.35,"
        "\"NAME\":\"Alice\",\"GENDER\":\"Female\",\"PHONENUMBERS\":false,\"EMAILS\":null}},"
        "\"end\":{\"label\":\"PERSON\",\"identity\":2,\"properties\":{\"AGE\":28,\"SALARY\":65000,"
        "\"NAME\":\"Bob\",\"GENDER\":\"Male\",\"PHONENUMBERS\":\"123456789\",\"EMAILS\":\" bob@example.com\"}},"
        "\"relationship\":{\"label\":\"tttt\",\"identity\":3,\"start\":1,\"end\":\"C\",\"properties\":{\"NUM\":4,"
        "\"PINYIN\":\"zhixiqinshu\"}},\"segments\":[{\"start\":{\"label\":\"PERSON\",\"identity\":1,"
        "\"properties\":{\"AGE\":32,\"SALARY\":75.35,"
        "\"NAME\":\"Alice\",\"GENDER\":\"Female\",\"PHONENUMBERS\":false,\"EMAILS\":null}},"
        "\"end\":{\"label\":\"PERSON\",\"identity\":2,\"properties\":{\"AGE\":28,\"SALARY\":65000,"
        "\"NAME\":\"Bob\",\"GENDER\":\"Male\",\"PHONENUMBERS\":\"123456789\",\"EMAILS\":\" bob@example.com\"}},"
        "\"relationship\":{\"label\":\"tttt\",\"identity\":3,\"start\":1,\"end\":\"C\",\"properties\":{\"NUM\":4,"
        "\"PINYIN\":\"zhixiqinshu\"}}}]}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    Path::Parse(json, errCode);
    ASSERT_EQ(errCode, E_OK);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_Vertex, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
    int errCode = E_ERROR;
    // no start, no end
    nlohmann::json json = nlohmann::json::parse("{\"name\" : \"zhangsan\"}", nullptr, false);
    ASSERT_FALSE(json.is_discarded());
    ASSERT_FALSE(json.is_null());
    Vertex::Parse(json, errCode);
    EXPECT_EQ(errCode, E_PARSE_JSON_FAILED);
    // no identity
    std::string jsonStr = "{\"start\" : 1, \"end\" : 2}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    Vertex::Parse(json, errCode);
    EXPECT_EQ(errCode, E_PARSE_JSON_FAILED);
    // ok
    jsonStr = "{\"start\" : 1, \"end\" : 2, \"label\":\"COMPANY\",\"identity\":3,"
              "\"properties\":{\"NAME\":\"myCompany3\",\"FOUNDED\":2011}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    Vertex::Parse(json, errCode);
    EXPECT_EQ(errCode, E_OK);
    // start is AA
    jsonStr = "{\"start\" : \"AA\", \"end\" : 2, \"label\":\"COMPANY\",\"identity\":3,"
              "\"properties\":{\"NAME\":\"myCompany3\",\"FOUNDED\":2011}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    Vertex::Parse(json, errCode);
    EXPECT_EQ(errCode, E_OK);
    // end is B
    jsonStr = "{\"start\" : 1, \"end\" : \"B\", \"label\":\"COMPANY\",\"identity\":3,"
              "\"properties\":{\"NAME\":\"myCompany3\",\"FOUNDED\":2011}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    Vertex::Parse(json, errCode);
    EXPECT_EQ(errCode, E_OK);
    // identity is C
    jsonStr = "{\"start\" : 1, \"end\" : 2, \"label\":\"COMPANY\",\"identity\":\"C\","
              "\"properties\":{\"NAME\":\"myCompany3\",\"FOUNDED\":2011}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    Vertex::Parse(json, errCode);
    EXPECT_EQ(errCode, E_OK);
    // label is 222
    jsonStr = "{\"start\" : 1, \"end\" : 2, \"label\":222,'identity':3,\"properties\":{\"NAME\":\"myCompany3\","
              "\"FOUNDED\":2011}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    Vertex::Parse(json, errCode);
    EXPECT_EQ(errCode, E_PARSE_JSON_FAILED);
    // key4 is null
    jsonStr =
        "{\"start\" : 1, \"end\" : 2, \"label\":\"COMPANY\",\"identity\":2,"
        "\"properties\":{\"NAME\":\"myCompany3\",\"FOUNDED\":4.5,\"SEX\":true,\"key1\":true,\"key2\":[], \"key3\":{}, "
        "\"key4\": null}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    Vertex::Parse(json, errCode);
    EXPECT_EQ(errCode, E_PARSE_JSON_FAILED);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_Vertex02, TestSize.Level1)
{
    Vertex vertex;
    Vertex vertex2("1", "PERSON");
    ASSERT_EQ(vertex2.GetLabel(), "PERSON");
    vertex2.SetLabel("PERSON1");
    ASSERT_EQ(vertex2.GetLabel(), "PERSON1");
    std::unordered_map<std::string, PropType> properties;
    Vertex vertex3("1", "PERSON2", properties);
    ASSERT_EQ(vertex3.GetLabel(), "PERSON2");
    vertex3.SetLabel("PERSON3");
    ASSERT_EQ(vertex3.GetLabel(), "PERSON3");
}

/**
 * @tc.name: GdbStore_Execute_PathChange
 * @tc.desc: test Path Change
 * @tc.type: FUNC
 */
HWTEST_F(GdbExecuteTest, GdbStore_Execute_PathChange, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
    auto result = store_->ExecuteGql("INSERT (:Person {name: 'name_1', age: 11});");
    MatchAndVerifyPerson("name_1", 11);
    result = store_->ExecuteGql("INSERT (:Person {name: 'name_2', age: 22});");
    MatchAndVerifyPerson("name_2", 22);
    result = store_->ExecuteGql("INSERT (:Person {name: 'name_3', age: 33});");
    MatchAndVerifyPerson("name_3", 33);
    result = store_->ExecuteGql("INSERT (:Person {name: 'name_4', age: 44});");
    MatchAndVerifyPerson("name_4", 44);
    result = store_->ExecuteGql(
        "MATCH (p1:Person {name: 'name_1'}), (p2:Person {name: 'name_2'}) INSERT (p1)-[:Friend]->(p2);");
    EXPECT_EQ(result.first, E_OK);
    result = store_->ExecuteGql(
        "MATCH (p1:Person {name: 'name_1'}), (p2:Person {name: 'name_3'}) INSERT (p1)-[:Friend]->(p2);");
    EXPECT_EQ(result.first, E_OK);
    result = store_->ExecuteGql(
        "MATCH (p1:Person {name: 'name_1'}), (p2:Person {name: 'name_4'}) INSERT (p1)-[:Friend]->(p2);");
    EXPECT_EQ(result.first, E_OK);
    result = store_->ExecuteGql(
        "MATCH (p1:Person {name: 'name_2'}), (p2:Person {name: 'name_3'}) INSERT (p1)-[:Friend]->(p2);");
    EXPECT_EQ(result.first, E_OK);
    result = store_->ExecuteGql(
        "MATCH (p1:Person {name: 'name_2'}), (p2:Person {name: 'name_4'}) INSERT (p1)-[:Friend]->(p2);");
    EXPECT_EQ(result.first, E_OK);
    result = store_->ExecuteGql(
        "MATCH (p1:Person {name: 'name_3'}), (p2:Person {name: 'name_4'}) INSERT (p1)-[:Friend]->(p2);");
    EXPECT_EQ(result.first, E_OK);

    result =
        store_->QueryGql("MATCH path=(a:Person {name: 'name_1'})-[]->{0, 3}(b:Person) RETURN path;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 8);

    GraphValue path = result.second->GetAllData()[0]["path"];
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Path>>(path));
}

/**
 * @tc.name: GdbStore_Execute_PathChangeRing
 * @tc.desc: Querying a Trail with a Ring
 * @tc.type: FUNC
 */
HWTEST_F(GdbExecuteTest, GdbStore_Execute_PathChangeRing, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
    auto result = store_->ExecuteGql("INSERT (:Person {name: 'name_1', age: 11});");
    MatchAndVerifyPerson("name_1", 11);
    result = store_->ExecuteGql("INSERT (:Person {name: 'name_2', age: 22});");
    MatchAndVerifyPerson("name_2", 22);
    result = store_->ExecuteGql("INSERT (:Person {name: 'name_3', age: 33});");
    MatchAndVerifyPerson("name_3", 33);
    result = store_->ExecuteGql(
        "MATCH (p1:Person {name: 'name_1'}), (p2:Person {name: 'name_2'}) INSERT (p1)-[:Friend]->(p2);");
    EXPECT_EQ(result.first, E_OK);
    result = store_->ExecuteGql(
        "MATCH (p1:Person {name: 'name_2'}), (p2:Person {name: 'name_3'}) INSERT (p1)-[:Friend]->(p2);");
    EXPECT_EQ(result.first, E_OK);
    result = store_->ExecuteGql(
        "MATCH (p1:Person {name: 'name_3'}), (p2:Person {name: 'name_1'}) INSERT (p1)-[:Friend]->(p2);");
    EXPECT_EQ(result.first, E_OK);

    result =
        store_->QueryGql("MATCH path=(a:Person {name: 'name_1'})-[]->{0, 3}(b:Person) RETURN path;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 4);

    GraphValue path = result.second->GetAllData()[0]["path"];
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Path>>(path));
}

/**
 * @tc.name: GdbStore_Execute_AllGraph
 * @tc.desc: test All Graph
 * @tc.type: FUNC
 */
HWTEST_F(GdbExecuteTest, GdbStore_Execute_AllGraph, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
    std::string name = "zhangsanfeng";
    for (int32_t i = 0; i < 50; i++) {
        auto nameInner = name + "_" + std::to_string(i);
        auto result = store_->ExecuteGql("INSERT (:Person {name: '" + nameInner + "', age: 11});");
        MatchAndVerifyPerson(nameInner, 11);
        for (int32_t j = 0; j < 100; j++) {
            auto nameOut = nameInner + "_" + std::to_string(j);
            result = store_->ExecuteGql("INSERT (:Person {name: '" + nameOut + "', age: 22});");
            MatchAndVerifyPerson(nameOut, 22);
            result = store_->ExecuteGql(
                "MATCH (p1:Person {name: '" + nameInner + "'}), (p2:Person {name: '" + nameOut + "'}) "
                    "INSERT (p1)-[:Friend]->(p2);");
            EXPECT_EQ(result.first, E_OK);
        }
    }
    auto result =
        store_->QueryGql("MATCH path=(a:Person)-[]->{0, 3}(b:Person) RETURN path;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 10050);
    GraphValue path = result.second->GetAllData()[0]["path"];
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Path>>(path));

    auto gql = "MATCH (person:Person) RETURN person;";
    result = store_->QueryGql(gql);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 5050);
}

/**
 * @tc.name: GdbStore_Execute_SelfPath
 * @tc.desc: test Self Path
 * @tc.type: FUNC
 */
HWTEST_F(GdbExecuteTest, GdbStore_Execute_SelfPath, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
    auto result = store_->ExecuteGql("INSERT (:Person {name: 'name_111', age: 11});");
    MatchAndVerifyPerson("name_111", 11);

    result = store_->ExecuteGql(
        "MATCH (p1:Person {name: 'name_111'}), (p2:Person {name: 'name_111'}) INSERT (p1)-[:Friend]->(p2);");
    EXPECT_EQ(result.first, E_OK);

    result = store_->QueryGql("MATCH path=(a:Person {name: 'name_111'})-[]->{0, 3}(b:Person) RETURN path;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 2);

    GraphValue path = result.second->GetAllData()[0]["path"];
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Path>>(path));
}

/**
 * @tc.name: GdbStore_Execute_SelfPath
 * @tc.desc: test Self Path
 * @tc.type: FUNC
 */
HWTEST_F(GdbExecuteTest, GdbStore_Execute_SelfPath02, TestSize.Level1)
{
    ASSERT_NE(store_, nullptr);
    auto result = store_->ExecuteGql("INSERT (:Person {name: 'name_test_001', age: 11});");
    MatchAndVerifyPerson("name_test_001", 11);

    result = store_->ExecuteGql("INSERT (:Person {name: 'name_test_001', age: 11});");

    result = store_->ExecuteGql(
        "MATCH (p1:Person {name: 'name_test_001'}), (p2:Person {name: 'name_test_001'}) INSERT (p1)-[:Friend]->(p2);");
    EXPECT_EQ(result.first, E_OK);

    result = store_->ExecuteGql(
        "MATCH (p1:Person {name: 'name_test_001'}), (p2:Person {name: 'name_test_001'}) INSERT (p1)-[:Friend]->(p2);");
    EXPECT_EQ(result.first, E_OK);

    result =
        store_->QueryGql("MATCH path=(a:Person {name: 'name_test_001'})-[]->{0, 3}(b:Person) RETURN path;");
    ASSERT_EQ(result.first, E_OK);
    EXPECT_EQ(result.second->GetAllData().size(), 126);

    GraphValue path = result.second->GetAllData()[0]["path"];
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Path>>(path));
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_StoreConfigSetName, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "success01";
    std::string dbPath = databasePath;
    auto config = StoreConfig(dbName, dbPath);
    config.SetName("success01_update");
    EXPECT_EQ("success01_update", config.GetName());

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    GDBHelper::DeleteDBStore(StoreConfig("success01_update", databasePath));
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_StoreConfigSetPath, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "success01";
    std::string dbPath = "/test/test";
    auto config = StoreConfig(dbName, dbPath);
    config.SetPath(databasePath);
    EXPECT_EQ(databasePath, config.GetPath());

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    GDBHelper::DeleteDBStore(StoreConfig(dbName, databasePath));
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_StoreConfigSetDbType, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "success01";
    std::string dbPath = databasePath;
    auto config = StoreConfig(dbName, dbPath);
    config.SetDbType(DBType::DB_GRAPH);
    EXPECT_EQ(config.GetDbType(), DBType::DB_GRAPH);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    GDBHelper::DeleteDBStore(StoreConfig(dbName, databasePath));
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_StoreConfigSetEncryptStatus, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "success01";
    std::string dbPath = databasePath;
    auto config = StoreConfig(dbName, dbPath);
    config.SetEncryptStatus(true);
    ASSERT_TRUE(config.IsEncrypt());
    config.SetEncryptStatus(false);
    ASSERT_TRUE(!config.IsEncrypt());
    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    GDBHelper::DeleteDBStore(StoreConfig(dbName, databasePath));
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_StoreConfigSetReadTime, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "success01";
    std::string dbPath = databasePath;
    std::vector<uint8_t> encryptKey = std::vector<uint8_t>();
    auto config = StoreConfig(dbName, dbPath, DBType::DB_GRAPH, true, encryptKey);
    config = StoreConfig(dbName, dbPath, DBType::DB_GRAPH, false, encryptKey);
    config.SetReadTime(3);
    EXPECT_EQ(config.GetReadTime(), 3);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    GDBHelper::DeleteDBStore(StoreConfig(dbName, databasePath));
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_UtilsTest, TestSize.Level1)
{
    int errCode = E_OK;
    errCode = GdbUtils::CreateDirectory("");
    EXPECT_EQ(errCode, E_OK);
    errCode = GdbUtils::CreateDirectory("dir1");
    EXPECT_EQ(errCode, E_CREATE_FOLDER_FAIT);
    GdbUtils::CreateDirectory("dir1/dir2");
    EXPECT_EQ(errCode, E_CREATE_FOLDER_FAIT);
    GdbUtils::CreateDirectory("dir1/dir2/dir3");
    EXPECT_EQ(errCode, E_CREATE_FOLDER_FAIT);
    GdbUtils::CreateDirectory("/dir1/dir2/dir3");
    EXPECT_EQ(errCode, E_CREATE_FOLDER_FAIT);
    GdbUtils::CreateDirectory("/data/");
    EXPECT_EQ(errCode, E_CREATE_FOLDER_FAIT);
    GdbUtils::CreateDirectory("/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2"
    "/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2"
    "/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2"
    "/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2"
    "/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2"
    "/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2"
    "/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2/data/dir1/dir2");
    EXPECT_EQ(errCode, E_CREATE_FOLDER_FAIT);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_UtilsAnonymousTest, TestSize.Level1)
{
    GdbUtils::Anonymous("fileName");
    GdbUtils::Anonymous("dir1/shortPath");
    GdbUtils::Anonymous("dir1/el1/longPath");
    GdbUtils::Anonymous("el1/l");
    GdbUtils::Anonymous(
        "dir1/el1/longPath/longPath/longPath/longPath/longPath/longPath/longPath/longPath/longPath/longPath/longPath");
    GdbUtils::Anonymous("/data/dir1/dir2/dir3");
    GdbUtils::Anonymous("/data/el1/dir2");
    GdbUtils::Anonymous("/data/app/el1/0/base/com.my.hmos.arkwebcore");
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_UtilsErrorTest, TestSize.Level1)
{
    auto errCode = GrdAdapter::TransErrno(100);
    EXPECT_EQ(errCode, 100);
    errCode = GrdAdapter::TransErrno(E_PARSE_JSON_FAILED);
    EXPECT_EQ(errCode, E_PARSE_JSON_FAILED);

    errCode = GrdAdapter::TransErrno(E_PARSE_JSON_FAILED);
    EXPECT_EQ(errCode, E_PARSE_JSON_FAILED);

    errCode = GrdAdapter::TransErrno(E_OK);
    EXPECT_EQ(errCode, E_OK);

    errCode = GrdAdapter::TransErrno(-100);
    EXPECT_EQ(errCode, E_GRD_INNER_ERR);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_StatementTest, TestSize.Level1)
{
    auto errCode = E_OK;
    std::string gql = "INSERT (:Person {name: 'name_test_001', age: 11});";
    GraphStatement statement(nullptr, "", nullptr, errCode);
    EXPECT_EQ(errCode, E_PREPARE_CHECK_FAILED);

    GRD_DB *dbHandle;
    auto ret = std::make_shared<GraphStatement>(dbHandle, gql, nullptr, errCode);
    EXPECT_NE(ret, nullptr);
    errCode = ret->Prepare();
    EXPECT_EQ(errCode, E_PREPARE_CHECK_FAILED);

    errCode = ret->Step();
    EXPECT_EQ(errCode, E_STEP_CHECK_FAILED);

    errCode = ret->Finalize();
    EXPECT_EQ(errCode, E_OK);

    errCode = ret->GetColumnCount();
    EXPECT_EQ(errCode, E_STATEMENT_EMPTY);

    auto pair = ret->GetColumnName(0);
    EXPECT_EQ(pair.first, E_STATEMENT_EMPTY);
    pair = ret->GetColumnName(0);
    EXPECT_EQ(pair.first, E_STATEMENT_EMPTY);
    pair = ret->GetColumnName(3);
    EXPECT_EQ(pair.first, E_STATEMENT_EMPTY);
    pair = ret->GetColumnName(9);
    EXPECT_EQ(pair.first, E_STATEMENT_EMPTY);

    auto pair1 = ret->GetColumnValue(0);
    EXPECT_EQ(pair1.first, E_CREATE_FOLDER_FAIT);
    pair1 = ret->GetColumnValue(3);
    EXPECT_EQ(pair1.first, E_CREATE_FOLDER_FAIT);
    pair1 = ret->GetColumnValue(100);
    EXPECT_EQ(pair1.first, E_CREATE_FOLDER_FAIT);

    errCode = ret->IsReady();
    EXPECT_EQ(errCode, E_OK);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_StatementTest02, TestSize.Level1)
{
    auto errCode = E_OK;
    std::string gql = "INSERT (:Person {name: 'name_test_001', age: 11});";

    auto ret = std::make_shared<GraphStatement>(nullptr, gql, nullptr, errCode);
    EXPECT_NE(ret, nullptr);
    errCode = ret->Prepare();
    EXPECT_EQ(errCode, E_PREPARE_CHECK_FAILED);

    errCode = ret->Step();
    EXPECT_EQ(errCode, E_STEP_CHECK_FAILED);

    errCode = ret->Finalize();
    EXPECT_EQ(errCode, E_OK);

    errCode = ret->GetColumnCount();
    EXPECT_EQ(errCode, E_STATEMENT_EMPTY);

    auto pair = ret->GetColumnName(0);
    EXPECT_EQ(pair.first, E_STATEMENT_EMPTY);

    auto pair1 = ret->GetColumnValue(0);
    EXPECT_EQ(pair1.first, E_CREATE_FOLDER_FAIT);

    errCode = ret->IsReady();
    EXPECT_EQ(errCode, E_OK);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_FullResult, TestSize.Level1)
{
    auto fullResult = std::make_shared<FullResult>();
    EXPECT_NE(fullResult, nullptr);
    auto errCode = fullResult->InitData();
    EXPECT_EQ(errCode, E_STATEMENT_EMPTY);
    auto statement = std::make_shared<GraphStatement>(nullptr, "", nullptr, errCode);
    fullResult = std::make_shared<FullResult>(statement);
    EXPECT_NE(fullResult, nullptr);
    errCode = fullResult->InitData();
    EXPECT_EQ(errCode, E_OK);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_EdgeTest, TestSize.Level1)
{
    auto errCode = E_ERROR;
    auto edge = std::make_shared<Edge>();
    EXPECT_NE(edge, nullptr);
    edge = std::make_shared<Edge>(std::make_shared<Vertex>(), "2", "3");
    EXPECT_NE(edge, nullptr);
    edge = std::make_shared<Edge>(nullptr, "2", "3");
    EXPECT_NE(edge, nullptr);
    edge = std::make_shared<Edge>("1", "PERSON", "2", "3");
    EXPECT_NE(edge, nullptr);
    edge->SetSourceId("22");
    EXPECT_EQ("22", edge->GetSourceId());
    edge->SetTargetId("33");
    EXPECT_EQ("33", edge->GetTargetId());
    
    auto jsonStr = "{\"start\" : 1, \"end\" : 2, \"label\":\"COMPANY\",\"identity\":3,"
              "\"properties\":{\"NAME\":\"myCompany3\",\"FOUNDED\":2011}}";
    nlohmann::json json = nlohmann::json::parse(jsonStr, nullptr, false);
    Edge::Parse(json, errCode);
    EXPECT_EQ(errCode, E_OK);

    jsonStr = "{\"start\" : {}, \"end\" : 2, \"label\":\"COMPANY\",\"identity\":3,"
              "\"properties\":{\"NAME\":\"myCompany3\",\"FOUNDED\":2011}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    Edge::Parse(json, errCode);
    EXPECT_EQ(errCode, E_PARSE_JSON_FAILED);

    jsonStr = "{\"start\" : 1, \"end\" : {}, \"label\":\"COMPANY\",\"identity\":3,"
              "\"properties\":{\"NAME\":\"myCompany3\",\"FOUNDED\":2011}}";
    json = nlohmann::json::parse(jsonStr, nullptr, false);
    Edge::Parse(json, errCode);
    EXPECT_EQ(errCode, E_PARSE_JSON_FAILED);
}

HWTEST_F(GdbExecuteTest, GdbStore_Execute_Connect, TestSize.Level1)
{
    auto errCode = E_ERROR;
    errCode = Connection::RegisterCreator(DBType::DB_BUTT, nullptr);
    EXPECT_EQ(errCode, E_NOT_SUPPORT);
    errCode = Connection::RegisterCreator(static_cast<DBType>(-1), nullptr);
    EXPECT_EQ(errCode, E_NOT_SUPPORT);
    auto func = [](const StoreConfig& config, bool isWriter) {
        std::pair<int32_t, std::shared_ptr<Connection>> ret = std::make_pair(
            static_cast<int32_t>(DBType::DB_GRAPH), nullptr);
        return ret;
    };
    errCode = Connection::RegisterCreator(DBType::DB_GRAPH, func);
    EXPECT_EQ(errCode, E_OK);
}

HWTEST_F(GdbExecuteTest, GdbStore_DBStore01, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "execute_test_ok_2";
    std::string dbPath = "/data";
    auto config = StoreConfig(dbName, dbPath);

    auto store = std::make_shared<DBStoreImpl>(config);
    EXPECT_NE(store, nullptr);
    errCode = store->InitConn();
    EXPECT_EQ(errCode, E_OK);
    errCode = store->InitConn();
    EXPECT_EQ(errCode, E_OK);
    const std::string gql = "INSERT (:Person {name: 'name_1', age: 11});";
    auto [err, result] = store->QueryGql(gql);
    EXPECT_EQ(err, E_GRD_UNDEFINED_TABLE);
    auto [err1, result1] = store->ExecuteGql(gql);
    EXPECT_EQ(err1, E_GRD_UNDEFINED_TABLE);
    GDBHelper::DeleteDBStore(config);
}
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

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <variant>

#include "aip_errors.h"
#include "db_store_impl.h"
#include "db_store_manager.h"
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
class GdbEncryptTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void VerifyPersonInfo(const GraphValue &person, const std::string &name, const int32_t &age);
    static const std::string createGraphGql;
    static const std::string databasePath;
};
const std::string GdbEncryptTest::databasePath = "/data";
const std::string GdbEncryptTest::createGraphGql = "CREATE GRAPH test { "
                                                   "(person:Person {name STRING, age INT, sex BOOL DEFAULT false}),"
                                                   "(dog:Dog {name STRING, age INT}), "
                                                   "(person) -[:Friend]-> (person) "
                                                   "};";

void GdbEncryptTest::SetUpTestCase()
{
    if (!IsSupportArkDataDb()) {
        GTEST_SKIP() << "Current testcase is not compatible from current gdb";
        return;
    }
}

void GdbEncryptTest::TearDownTestCase()
{
}

void GdbEncryptTest::SetUp()
{
    if (!IsSupportArkDataDb()) {
        GTEST_SKIP() << "Current testcase is not compatible from current gdb";
        return;
    }
}

void GdbEncryptTest::TearDown()
{
}

HWTEST_F(GdbEncryptTest, GdbEncrypt_DeaultIsUnencrypt, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "DeaultIsUnencrypt";
    std::string dbPath = databasePath;
    // DeaultIsUnencrypt
    auto config = StoreConfig(dbName, dbPath, DBType::DB_GRAPH);
    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    auto result = store->ExecuteGql(createGraphGql);
    EXPECT_NE(result.second, nullptr);
    EXPECT_EQ(result.first, E_OK);
    result = store->ExecuteGql("INSERT (:Person {name: 'name_1', age: 11});");
    EXPECT_EQ(result.first, E_OK);
    result = store->QueryGql("MATCH (person:Person {age: 11}) RETURN person;");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue person = result.second->GetAllData()[0]["person"];
    VerifyPersonInfo(person, "name_1", 11);
    store->Close();
    GDBHelper::DeleteDBStore(config);
}

HWTEST_F(GdbEncryptTest, GdbEncrypt_Unencrypt, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "Unencrypt";
    std::string dbPath = databasePath;
    // Unencryptdb
    auto config = StoreConfig(dbName, dbPath, DBType::DB_GRAPH, false);
    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    auto result = store->ExecuteGql(createGraphGql);
    EXPECT_NE(result.second, nullptr);
    EXPECT_EQ(result.first, E_OK);
    result = store->ExecuteGql("INSERT (:Person {name: 'name_1', age: 11});");
    EXPECT_EQ(result.first, E_OK);
    result = store->QueryGql("MATCH (person:Person {age: 11}) RETURN person;");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue person = result.second->GetAllData()[0]["person"];
    VerifyPersonInfo(person, "name_1", 11);
    store->Close();
    GDBHelper::DeleteDBStore(config);
}

HWTEST_F(GdbEncryptTest, GdbEncrypt_Encrypt, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "Encrypt";
    std::string dbPath = databasePath;
    // Unencryptdb
    auto config = StoreConfig(dbName, dbPath, DBType::DB_GRAPH, true);
    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    auto result = store->ExecuteGql(createGraphGql);
    EXPECT_NE(result.second, nullptr);
    EXPECT_EQ(result.first, E_OK);
    result = store->ExecuteGql("INSERT (:Person {name: 'name_1', age: 11});");
    EXPECT_EQ(result.first, E_OK);
    result = store->QueryGql("MATCH (person:Person {age: 11}) RETURN person;");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue person = result.second->GetAllData()[0]["person"];
    VerifyPersonInfo(person, "name_1", 11);
    store->Close();
    GDBHelper::DeleteDBStore(config);
}

HWTEST_F(GdbEncryptTest, GdbEncrypt_UnencryptToEncrypt, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "UnencryptToEncrypt";
    std::string dbPath = databasePath;
    // Unencryptdb
    auto config = StoreConfig(dbName, dbPath, DBType::DB_GRAPH, false);
    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    auto result = store->ExecuteGql(createGraphGql);
    EXPECT_NE(result.second, nullptr);
    EXPECT_EQ(result.first, E_OK);
    result = store->ExecuteGql("INSERT (:Person {name: 'name_1', age: 11});");
    EXPECT_EQ(result.first, E_OK);
    result = store->QueryGql("MATCH (person:Person {age: 11}) RETURN person;");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue person = result.second->GetAllData()[0]["person"];
    VerifyPersonInfo(person, "name_1", 11);
    result.second = nullptr;
    store->Close();
    StoreManager::GetInstance().Clear();
    // Unencryptdb to encryptdb
    config.SetEncryptStatus(true);
    store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    if (store != nullptr) {
        result = store->ExecuteGql("INSERT (:Person {name: 'name_2', age: 22});");
        EXPECT_EQ(result.first, E_OK);
        result = store->QueryGql("MATCH (person:Person {age: 22}) RETURN person;");
        ASSERT_EQ(result.first, E_OK);
        ASSERT_NE(result.second, nullptr);
        EXPECT_EQ(result.second->GetAllData().size(), 1);
        GraphValue person = result.second->GetAllData()[0]["person"];
        VerifyPersonInfo(person, "name_2", 22);
        store->Close();
    }
    GDBHelper::DeleteDBStore(config);
}

HWTEST_F(GdbEncryptTest, GdbEncrypt_EncryptToUnencrypt, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "EncryptToUnencrypt";
    std::string dbPath = databasePath;
    // encryptdb
    auto config = StoreConfig(dbName, dbPath, DBType::DB_GRAPH, true);
    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    auto result = store->ExecuteGql(createGraphGql);
    EXPECT_NE(result.second, nullptr);
    EXPECT_EQ(result.first, E_OK);
    result = store->ExecuteGql("INSERT (:Person {name: 'name_1', age: 11});");
    EXPECT_EQ(result.first, E_OK);
    result = store->QueryGql("MATCH (person:Person {age: 11}) RETURN person;");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue person = result.second->GetAllData()[0]["person"];
    VerifyPersonInfo(person, "name_1", 11);
    store->Close();
    StoreManager::GetInstance().Clear();
    // encryptdb to Unencryptdb
    config.SetEncryptStatus(false);
    store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_EQ(errCode, E_CONFIG_INVALID_CHANGE);
    GDBHelper::DeleteDBStore(config);
}

HWTEST_F(GdbEncryptTest, GdbEncrypt_DefaultToEncrypt, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "DefaultToEncrypt";
    std::string dbPath = databasePath;
    // Unencryptdb
    auto config = StoreConfig(dbName, dbPath);
    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    auto result = store->ExecuteGql(createGraphGql);
    EXPECT_NE(result.second, nullptr);
    EXPECT_EQ(result.first, E_OK);
    result = store->ExecuteGql("INSERT (:Person {name: 'name_1', age: 11});");
    EXPECT_EQ(result.first, E_OK);
    result = store->QueryGql("MATCH (person:Person {age: 11}) RETURN person;");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue person = result.second->GetAllData()[0]["person"];
    VerifyPersonInfo(person, "name_1", 11);
    result.second = nullptr;
    store->Close();
    StoreManager::GetInstance().Clear();
    // Unencryptdb to encryptdb
    config.SetEncryptStatus(true);
    store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    if (store != nullptr) {
        result = store->ExecuteGql("INSERT (:Person {name: 'name_2', age: 22});");
        EXPECT_EQ(result.first, E_OK);
        result = store->QueryGql("MATCH (person:Person {age: 22}) RETURN person;");
        ASSERT_EQ(result.first, E_OK);
        ASSERT_NE(result.second, nullptr);
        EXPECT_EQ(result.second->GetAllData().size(), 1);
        GraphValue person = result.second->GetAllData()[0]["person"];
        VerifyPersonInfo(person, "name_2", 22);
        store->Close();
    }
    GDBHelper::DeleteDBStore(config);
}

HWTEST_F(GdbEncryptTest, GdbEncrypt_EncryptToEncrypt, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "EncryptToUnencrypt";
    std::string dbPath = databasePath;
    // encryptdb
    auto config = StoreConfig(dbName, dbPath, DBType::DB_GRAPH, true);
    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    auto result = store->ExecuteGql(createGraphGql);
    EXPECT_NE(result.second, nullptr);
    EXPECT_EQ(result.first, E_OK);
    result = store->ExecuteGql("INSERT (:Person {name: 'name_1', age: 11});");
    EXPECT_EQ(result.first, E_OK);
    result = store->QueryGql("MATCH (person:Person {age: 11}) RETURN person;");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue person = result.second->GetAllData()[0]["person"];
    VerifyPersonInfo(person, "name_1", 11);
    store->Close();
    StoreManager::GetInstance().Clear();
    // encryptdb to encryptdb
    config.SetEncryptStatus(true);
    store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    result = store->ExecuteGql("INSERT (:Person {name: 'name_2', age: 22});");
    EXPECT_EQ(result.first, E_OK);
    result = store->QueryGql("MATCH (person:Person {age: 22}) RETURN person;");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    person = result.second->GetAllData()[0]["person"];
    VerifyPersonInfo(person, "name_2", 22);
    store->Close();
    GDBHelper::DeleteDBStore(config);
}

HWTEST_F(GdbEncryptTest, GdbEncrypt_UnencryptToUnencrypt, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "UnencryptToEncrypt";
    std::string dbPath = databasePath;
    // Unencryptdb
    auto config = StoreConfig(dbName, dbPath, DBType::DB_GRAPH, false);
    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    auto result = store->ExecuteGql(createGraphGql);
    EXPECT_NE(result.second, nullptr);
    EXPECT_EQ(result.first, E_OK);
    result = store->ExecuteGql("INSERT (:Person {name: 'name_1', age: 11});");
    EXPECT_EQ(result.first, E_OK);
    result = store->QueryGql("MATCH (person:Person {age: 11}) RETURN person;");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue person = result.second->GetAllData()[0]["person"];
    VerifyPersonInfo(person, "name_1", 11);
    store->Close();
    StoreManager::GetInstance().Clear();
    // Unencryptdb to Unencryptdb
    config.SetEncryptStatus(false);
    store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    result = store->ExecuteGql("INSERT (:Person {name: 'name_2', age: 22});");
    EXPECT_EQ(result.first, E_OK);
    result = store->QueryGql("MATCH (person:Person {age: 22}) RETURN person;");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    person = result.second->GetAllData()[0]["person"];
    VerifyPersonInfo(person, "name_2", 22);
    store->Close();
    GDBHelper::DeleteDBStore(config);
}

HWTEST_F(GdbEncryptTest, GdbEncrypt_DefaultToUnencrypt, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "UnencryptToEncrypt";
    std::string dbPath = databasePath;
    // Unencryptdb
    auto config = StoreConfig(dbName, dbPath, DBType::DB_GRAPH);
    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    auto result = store->ExecuteGql(createGraphGql);
    EXPECT_NE(result.second, nullptr);
    EXPECT_EQ(result.first, E_OK);
    result = store->ExecuteGql("INSERT (:Person {name: 'name_1', age: 11});");
    EXPECT_EQ(result.first, E_OK);
    result = store->QueryGql("MATCH (person:Person {age: 11}) RETURN person;");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    GraphValue person = result.second->GetAllData()[0]["person"];
    VerifyPersonInfo(person, "name_1", 11);
    store->Close();
    StoreManager::GetInstance().Clear();
    // Unencryptdb to Unencryptdb
    config.SetEncryptStatus(false);
    store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    result = store->ExecuteGql("INSERT (:Person {name: 'name_2', age: 22});");
    EXPECT_EQ(result.first, E_OK);
    result = store->QueryGql("MATCH (person:Person {age: 22}) RETURN person;");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_NE(result.second, nullptr);
    EXPECT_EQ(result.second->GetAllData().size(), 1);
    person = result.second->GetAllData()[0]["person"];
    VerifyPersonInfo(person, "name_2", 22);
    store->Close();
    GDBHelper::DeleteDBStore(config);
}

void GdbEncryptTest::VerifyPersonInfo(const GraphValue &person, const std::string &name, const int32_t &age)
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

HWTEST_F(GdbEncryptTest, GdbEncrypt_Config, TestSize.Level1)
{
    std::string dbName = "UnencryptToEncrypt";
    std::string dbPath = databasePath;
    auto config = StoreConfig(dbName, dbPath, DBType::DB_GRAPH);
    EXPECT_EQ(config.IsEncrypt(), false);
    config.GenerateEncryptedKey();
    EXPECT_EQ(config.GetEncryptKey().size(), 0);
    EXPECT_EQ(config.GetNewEncryptKey().size(), 0);

    config.SetBundleName("");
    EXPECT_EQ(config.GetBundleName(), "");
    config.SetEncryptStatus(true);
    EXPECT_EQ(config.IsEncrypt(), true);
    config.SetBundleName("test_name");
    EXPECT_EQ(config.GetBundleName(), "test_name");
    // empty return E_ERROR
    EXPECT_EQ(config.SetBundleName(""), E_ERROR);
    EXPECT_EQ(config.GetBundleName(), "test_name");

    config.GenerateEncryptedKey();
    // not exists bundleName, failed
    EXPECT_EQ(config.GetEncryptKey().size(), 0);
    EXPECT_EQ(config.GetNewEncryptKey().size(), 0);
    config.ChangeEncryptKey();
    config.GenerateEncryptedKey();
    config.ChangeEncryptKey();
}

HWTEST_F(GdbEncryptTest, GdbEncrypt_Config_Test, TestSize.Level1)
{
    std::string dbName = "ConfigTest";
    std::string dbPath = databasePath;
    auto config = StoreConfig(dbName, dbPath, DBType::DB_GRAPH, true);
    EXPECT_EQ(config.IsEncrypt(), true);
    config.GenerateEncryptedKey();
    ASSERT_TRUE(config.GetEncryptKey().size() > 0);
    EXPECT_EQ(config.GetNewEncryptKey().size(), 0);
    // newkey is empty, not change key
    config.ChangeEncryptKey();
    ASSERT_TRUE(config.GetEncryptKey().size() > 0);
    EXPECT_EQ(config.GetNewEncryptKey().size(), 0);
}
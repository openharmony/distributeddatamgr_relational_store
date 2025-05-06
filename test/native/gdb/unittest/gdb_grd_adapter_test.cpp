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
#include <thread>
#include <variant>

#include "gdb_errors.h"
#include "db_store_manager.h"
#include "edge.h"
#include "full_result.h"
#include "gdb_helper.h"
#include "gdb_store.h"
#include "gdb_transaction.h"
#include "grd_adapter_manager.h"
#include "path.h"
#include "result.h"
#include "vertex.h"
#include "../mock/grd_adapter.h"

using namespace testing::ext;
using namespace OHOS::DistributedDataAip;

using FuncName = GrdAdapter::FuncName;

class GdbGrdAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase() {}
    void SetUp();
    void TearDown() {}

    void CheckPrepareStepErrCode(int32_t grdErr, int32_t gdbErr, FuncName func);
    void CheckRekeyErrCode(int32_t grdErr, int32_t gdbErr);

    void GetStore(const std::string &name);
    void DeleteStore(const std::string &name);

    static const std::string path;
    static const std::string createGraphGql;
    static const std::string executeGql;
    static const std::string queryGql;

    static std::shared_ptr<DBStore> store_;
};

const std::string GdbGrdAdapterTest::path = "/data";

const std::string GdbGrdAdapterTest::createGraphGql = "CREATE GRAPH test { "
                                                      "(person:Person {name STRING, age INT, sex BOOL DEFAULT false}),"
                                                      "(dog:Dog {name STRING, age INT}), "
                                                      "(person) -[:Friend]-> (person) "
                                                      "};";

const std::string GdbGrdAdapterTest::executeGql = "INSERT (:Person {name: 'name_1', age: 11});";
const std::string GdbGrdAdapterTest::queryGql = "MATCH (person:Person {name: 'name_1'}) RETURN person;";

std::shared_ptr<DBStore> GdbGrdAdapterTest::store_;

static constexpr int32_t MAX_LEN = 128;
static constexpr int32_t MAX_PROP_CNT = 1024;

void GdbGrdAdapterTest::SetUpTestCase()
{
    if (!IsSupportArkDataDb()) {
        GTEST_SKIP() << "Current testcase is not compatible from current gdb";
        return;
    }
}

void GdbGrdAdapterTest::SetUp()
{
    if (!IsSupportArkDataDb()) {
        GTEST_SKIP() << "Current testcase is not compatible from current gdb";
        return;
    }
}

void GdbGrdAdapterTest::GetStore(const std::string &name)
{
    auto config = StoreConfig(name, path);
    GDBHelper::DeleteDBStore(config);

    int32_t errorCode = E_OK;
    store_ = GDBHelper::GetDBStore(config, errorCode);
    ASSERT_NE(store_, nullptr);
    ASSERT_EQ(errorCode, E_OK);

    auto [errCode, result] = store_->ExecuteGql(createGraphGql);
    ASSERT_EQ(errCode, E_OK);

    GrdAdapter::SetErrorCode(FuncName::ALL, GRD_OK);
}

void GdbGrdAdapterTest::DeleteStore(const std::string &name)
{
    auto config = StoreConfig(name, path);
    GDBHelper::DeleteDBStore(config);

    store_ = nullptr;
}

void GdbGrdAdapterTest::CheckPrepareStepErrCode(int32_t grdErr, int32_t gdbErr, FuncName func)
{
    std::string name = "prepare_step_test";
    GetStore(name);
    ASSERT_NE(store_, nullptr);

    GrdAdapter::SetErrorCode(func, grdErr);

    auto [errCode, result] = store_->ExecuteGql(executeGql);
    EXPECT_EQ(errCode, gdbErr);

    std::tie(errCode, result) = store_->QueryGql(queryGql);
    if (func == FuncName::STEP && grdErr == GRD_NO_DATA) {
        EXPECT_EQ(errCode, E_OK);
    } else {
        if (gdbErr == E_GRD_OVER_LIMIT) {
            EXPECT_EQ(errCode, E_GRD_SEMANTIC_ERROR);
        } else {
            EXPECT_EQ(errCode, gdbErr);
        }
    }

    auto [err, trans] = store_->CreateTransaction();
    EXPECT_EQ(err, gdbErr);
    EXPECT_EQ(trans, nullptr);
    
    GrdAdapter::SetErrorCode(func, GRD_OK);

    std::tie(err, trans) = store_->CreateTransaction();
    EXPECT_EQ(err, E_OK);
    EXPECT_NE(trans, nullptr);

    GrdAdapter::SetErrorCode(func, grdErr);

    std::tie(errCode, result) = trans->Execute(executeGql);
    EXPECT_EQ(errCode, gdbErr);

    std::tie(errCode, result) = trans->Query(queryGql);
    if (func == FuncName::STEP && grdErr == GRD_NO_DATA) {
        EXPECT_EQ(errCode, E_OK);
    } else {
        if (gdbErr == E_GRD_OVER_LIMIT) {
            EXPECT_EQ(errCode, E_GRD_SEMANTIC_ERROR);
        } else {
            EXPECT_EQ(errCode, gdbErr);
        }
    }

    errCode = trans->Commit();
    EXPECT_EQ(errCode, gdbErr);
    
    GrdAdapter::SetErrorCode(func, GRD_OK);

    std::tie(err, trans) = store_->CreateTransaction();
    EXPECT_EQ(err, E_OK);
    EXPECT_NE(trans, nullptr);

    GrdAdapter::SetErrorCode(func, grdErr);

    errCode = trans->Rollback();
    EXPECT_EQ(errCode, gdbErr);
    
    GrdAdapter::SetErrorCode(func, GRD_OK);

    DeleteStore(name);
}

void GdbGrdAdapterTest::CheckRekeyErrCode(int32_t grdErr, int32_t gdbErr)
{
    std::string name = "rekey_test";
    GetStore(name);
    ASSERT_NE(store_, nullptr);

    auto errCode = store_->Close();
    EXPECT_EQ(errCode, E_OK);
    StoreManager::GetInstance().Clear();

    GrdAdapter::SetErrorCode(FuncName::REKEY, grdErr);

    auto config = StoreConfig(name, path, DBType::DB_GRAPH, true);
    store_ = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(errCode, gdbErr);
    EXPECT_EQ(store_, nullptr);

    GrdAdapter::SetErrorCode(FuncName::REKEY, GRD_OK);

    DeleteStore(name);
}

/**
 * @tc.name: GdbGrdAdapterTest001
 * @tc.desc: test Prepare returned the following error code
 * @tc.type: FUNC
 */
HWTEST_F(GdbGrdAdapterTest, GdbGrdAdapterTest001, TestSize.Level1)
{
    std::map<int32_t, int32_t> errCodeMap = {
        { GRD_INVALID_ARGS, E_GRD_INVALID_ARGS },
        { GRD_SYNTAX_ERROR, E_GRD_SYNTAX_ERROR },
        { GRD_SEMANTIC_ERROR, E_GRD_SEMANTIC_ERROR },
        { GRD_OVER_LIMIT, E_GRD_OVER_LIMIT },
        { GRD_FAILED_MEMORY_ALLOCATE, E_GRD_FAILED_MEMORY_ALLOCATE },
        { GRD_MODEL_NOT_SUPPORT, E_GRD_SEMANTIC_ERROR },
        { GRD_FEATURE_NOT_SUPPORTED, E_GRD_SEMANTIC_ERROR },
        { GRD_DATATYPE_MISMATCH, E_GRD_SEMANTIC_ERROR },
        { GRD_INVALID_VALUE, E_GRD_INVALID_ARGS },
        { GRD_NAME_TOO_LONG, E_GRD_INVALID_NAME },
        { GRD_DUPLICATE_TABLE, E_GRD_DUPLICATE_PARAM },
        { GRD_DUPLICATE_OBJECT, E_GRD_DUPLICATE_PARAM },
        { GRD_INVALID_CONFIG_VALUE, E_CONFIG_INVALID_CHANGE },
        { GRD_DUPLICATE_COLUMN, E_GRD_DUPLICATE_PARAM },
        { GRD_UNDEFINE_COLUMN, E_GRD_UNDEFINED_PARAM },
        { GRD_UNDEFINED_OBJECT, E_GRD_UNDEFINED_PARAM },
        { GRD_UNDEFINED_TABLE, E_GRD_UNDEFINED_PARAM },
    };

    for (auto [grdErr, gdbErr] : errCodeMap) {
        CheckPrepareStepErrCode(grdErr, gdbErr, FuncName::PREPARE);
    }
}

/**
 * @tc.name: GdbGrdAdapterTest002
 * @tc.desc: test Step returned the following error code
 * @tc.type: FUNC
 */
HWTEST_F(GdbGrdAdapterTest, GdbGrdAdapterTest002, TestSize.Level1)
{
    std::map<int32_t, int32_t> errCodeMap = {
        { GRD_NO_DATA, E_GRD_NO_DATA },
        { GRD_INVALID_TABLE_DEFINITION, E_GRD_SEMANTIC_ERROR },
        { GRD_INVALID_ARGS, E_GRD_INVALID_ARGS },
        { GRD_INVALID_CONFIG_VALUE, E_CONFIG_INVALID_CHANGE },
        { GRD_DATATYPE_MISMATCH, E_GRD_SEMANTIC_ERROR },
        { GRD_DIVISION_BY_ZERO, E_GRD_SYNTAX_ERROR },
        { GRD_MODEL_NOT_SUPPORT, E_GRD_SEMANTIC_ERROR },
        { GRD_FEATURE_NOT_SUPPORTED, E_GRD_SEMANTIC_ERROR },
        { GRD_FIELD_OVERFLOW, E_GRD_SEMANTIC_ERROR },
        { GRD_FILE_OPERATE_FAILED, E_GRD_INNER_ERR },
        { GRD_INSUFFICIENT_RESOURCES, E_GRD_INNER_ERR },
        { GRD_RESOURCE_BUSY, E_DATABASE_BUSY },
        { GRD_OVER_LIMIT, E_GRD_OVER_LIMIT },
        { GRD_REQUEST_TIME_OUT, E_DATABASE_BUSY },
        { GRD_RESTRICT_VIOLATION, E_GRD_DATA_CONFLICT },
        { GRD_NO_ACTIVE_TRANSACTION, E_GRD_NO_ACTIVE_TRANSACTION },
        { GRD_TRANSACTION_ROLLBACK, E_GRD_TRANSACTION_ROLLBACK },
        { GRD_ACTIVE_TRANSACTION, E_GRD_ACTIVE_TRANSACTION },
        { GRD_UNIQUE_VIOLATION, E_GRD_DATA_CONFLICT },
        { GRD_PRIMARY_KEY_VIOLATION, E_GRD_DATA_CONFLICT },
        { GRD_UNDEFINED_TABLE, E_GRD_UNDEFINED_PARAM },
        { GRD_UNDEFINED_OBJECT, E_GRD_UNDEFINED_PARAM },
        { GRD_DUPLICATE_TABLE, E_GRD_DUPLICATE_PARAM },
        { GRD_DUPLICATE_OBJECT, E_GRD_DUPLICATE_PARAM },
        { GRD_DATA_CORRUPTED, E_GRD_DATA_CORRUPTED },
        { GRD_THIRD_PARTY_FUNCTION_EXECUTE_FAILED, E_GRD_INNER_ERR },
        { GRD_SCHEMA_CHANGED, E_CONFIG_INVALID_CHANGE },
    };

    for (auto [grdErr, gdbErr] : errCodeMap) {
        CheckPrepareStepErrCode(grdErr, gdbErr, FuncName::STEP);
    }
}

/**
 * @tc.name: GdbGrdAdapterTest003
 * @tc.desc: test ReKey returned the following error code
 * @tc.type: FUNC
 */
HWTEST_F(GdbGrdAdapterTest, GdbGrdAdapterTest003, TestSize.Level1)
{
    std::map<int32_t, int32_t> errCodeMap = {
        { GRD_INVALID_ARGS, E_GRD_INVALID_ARGS },
        { GRD_INNER_ERR, E_GRD_INNER_ERR },
        { GRD_NO_DATA, E_GRD_NO_DATA },
        { GRD_RESOURCE_BUSY, E_DATABASE_BUSY },
        { GRD_SYSTEM_ERR, E_GRD_INNER_ERR },
        { GRD_INVALID_FORMAT, E_GRD_SEMANTIC_ERROR },
        { GRD_INSUFFICIENT_SPACE, E_GRD_DISK_SPACE_FULL },
        { GRD_DB_INSTANCE_ABNORMAL, E_GRD_DB_INSTANCE_ABNORMAL },
        { GRD_DB_BUSY, E_DATABASE_BUSY },
        { GRD_DATA_CORRUPTED, E_GRD_DATA_CORRUPTED },
    };

    for (auto [grdErr, gdbErr] : errCodeMap) {
        CheckRekeyErrCode(grdErr, gdbErr);
    }
}

/**
 * @tc.name: GdbGrdAdapterTest004
 * @tc.desc: test whether the error code returned by Prepare when using the following gql is correct
 * @tc.type: FUNC
 */
HWTEST_F(GdbGrdAdapterTest, GdbGrdAdapterTest004, TestSize.Level1)
{
    std::string duplicateObjectGql = "CREATE GRAPH test { "
                                     "(person:Person {name STRING, age INT, age DOUBLE}),"
                                     "(person) -[:Friend]-> (person) "
                                     "};";
    std::map<std::string, int32_t> errCodeMap = {
        { "INSERT (:Person {});", E_GRD_SYNTAX_ERROR },  // GRD_SYNTAX_ERROR
        { "INSERT ();", E_GRD_SEMANTIC_ERROR },  // GRD_SEMANTIC_ERROR
        { "INSERT (:Person {name: 11, age: 'age_11'});", E_GRD_SEMANTIC_ERROR },  // GRD_DATATYPE_MISMATCH
        { "DROP GRAPH nonexistent_graph;", E_GRD_UNDEFINED_PARAM },  // GRD_UNDEFINE_COLUMN
        { "MATCH (a: Person {name: 'Alf'}) SET a.nationality='EN'", E_GRD_UNDEFINED_PARAM },  // GRD_UNDEFINED_OBJECT
        { "INSERT (:Student {name: 'name_1', age: 11});", E_GRD_UNDEFINED_PARAM },  // GRD_UNDEFINED_TABLE
        { duplicateObjectGql, E_GRD_DUPLICATE_PARAM },  // GRD_DUPLICATE_OBJECT
    };

    for (auto [gql, gdbErr] : errCodeMap) {
        std::string name = "prepare_test";
        GetStore(name);
        ASSERT_NE(store_, nullptr);

        auto [errCode, result] = store_->ExecuteGql(gql);
        EXPECT_EQ(errCode, gdbErr);

        DeleteStore(name);
    }
}

/**
 * @tc.name: GdbGrdAdapterTest005
 * @tc.desc: test whether the error code returned by Prepare when using the following gql is correct
 * @tc.type: FUNC
 */
HWTEST_F(GdbGrdAdapterTest, GdbGrdAdapterTest005, TestSize.Level1)
{
    std::string graphName = "test_";
    for (int i = 0; i < MAX_LEN; i++) {
        graphName += "a";
    }
    std::string nameTooLongGql = "CREATE GRAPH " + graphName + " { "
                                 "(person:Person {name STRING, age INT, sex BOOL DEFAULT false}),"
                                 "(person) -[:Friend]-> (person) "
                                 "};";
    std::string duplicateTableGql = "CREATE GRAPH test { "
                                    "(person:Person {name STRING, age INT, sex BOOL DEFAULT false}),"
                                    "(student:Person {name STRING, age INT}), "
                                    "(person) -[:Friend]-> (person) "
                                    "};";
    std::string duplicateColumnGql = "CREATE GRAPH test { "
                                     "(person:Person {name STRING, age INT, age DOUBLE}),"
                                     "(person) -[:Friend]-> (person) "
                                     "};";
    std::map<std::string, int32_t> errCodeMap = {
        { nameTooLongGql, E_GRD_INVALID_NAME },  // GRD_NAME_TOO_LONG
        { duplicateTableGql, E_GRD_DUPLICATE_PARAM },  // GRD_DUPLICATE_TABLE
        { duplicateColumnGql, E_GRD_DUPLICATE_PARAM },  // GRD_DUPLICATE_COLUMN
    };

    for (auto [gql, gdbErr] : errCodeMap) {
        std::string name = "prepare_test";
        auto config = StoreConfig(name, path);
        GDBHelper::DeleteDBStore(config);

        int32_t errorCode = E_OK;
        store_ = GDBHelper::GetDBStore(config, errorCode);
        ASSERT_NE(store_, nullptr);
        ASSERT_EQ(errorCode, E_OK);

        auto [errCode, result] = store_->ExecuteGql(gql);
        EXPECT_EQ(errCode, gdbErr);

        DeleteStore(name);
    }
}

/**
 * @tc.name: GdbGrdAdapterTest006
 * @tc.desc: test whether the error code returned by Step when using the following gql is correct
 * @tc.type: FUNC
 */
HWTEST_F(GdbGrdAdapterTest, GdbGrdAdapterTest006, TestSize.Level1)
{
    std::map<std::string, int32_t> errCodeMap = {
        { "MATCH (p:Person {age: 11}) RETURN p.age / 0;", E_GRD_SYNTAX_ERROR },  // GRD_DIVISION_BY_ZERO
        { "MATCH (p:Person {age: 11}) SET p.age=9223372036854775808;", E_GRD_SEMANTIC_ERROR },  // GRD_FIELD_OVERFLOW
    };

    for (auto [gql, gdbErr] : errCodeMap) {
        std::string name = "step_test";
        GetStore(name);
        ASSERT_NE(store_, nullptr);

        auto [errCode, result] = store_->ExecuteGql(executeGql);
        EXPECT_EQ(errCode, E_OK);

        std::tie(errCode, result) = store_->ExecuteGql(gql);
        EXPECT_EQ(errCode, gdbErr);

        DeleteStore(name);
    }
}

/**
 * @tc.name: GdbGrdAdapterTest007
 * @tc.desc: test whether the error code returned by Step when using the following gql is correct
 * @tc.type: FUNC
 */
HWTEST_F(GdbGrdAdapterTest, GdbGrdAdapterTest007, TestSize.Level1)
{
    std::string name = "step_test";
    auto config = StoreConfig(name, path);
    GDBHelper::DeleteDBStore(config);

    int32_t errorCode = E_OK;
    store_ = GDBHelper::GetDBStore(config, errorCode);
    ASSERT_NE(store_, nullptr);
    ASSERT_EQ(errorCode, E_OK);

    std::string overLimitGql = "CREATE GRAPH test { (person:Person {";
    for (int i = 0; i < MAX_PROP_CNT; i++) {
        overLimitGql += "name" + std::to_string(i) + " STRING, ";
    }
    overLimitGql += "age INT, sex BOOL DEFAULT false}) };";

    auto [errCode, result] = store_->ExecuteGql(overLimitGql);
    EXPECT_EQ(errCode, E_GRD_OVER_LIMIT);  // GRD_OVER_LIMIT

    DeleteStore(name);
}

/**
 * @tc.name: GdbGrdAdapterTest008
 * @tc.desc: test whether the error code returned by Step when using the following gql is correct
 * @tc.type: FUNC
 */
HWTEST_F(GdbGrdAdapterTest, GdbGrdAdapterTest008, TestSize.Level1)
{
    std::string name = "step_test";
    GetStore(name);
    ASSERT_NE(store_, nullptr);

    auto [errCode, result] = store_->ExecuteGql("CREATE UNIQUE INDEX nameIndex ON Person(name);");
    EXPECT_EQ(errCode, E_OK);

    std::tie(errCode, result) = store_->ExecuteGql("INSERT (:Person {name: 'name_1', age: 11});");
    EXPECT_EQ(errCode, E_OK);

    std::tie(errCode, result) = store_->ExecuteGql("INSERT (:Person {name: 'name_1', age: 22});");
    EXPECT_EQ(errCode, E_GRD_DATA_CONFLICT);  // GRD_UNIQUE_VIOLATION

    DeleteStore(name);
}

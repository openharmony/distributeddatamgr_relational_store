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

#define LOG_TAG "GdbFuncTest"
#include <gtest/gtest.h>

#include <variant>

#include "aip_errors.h"
#include "connection_pool.h"
#include "gdb_helper.h"
#include "logger.h"

using namespace testing::ext;
using namespace OHOS::DistributedDataAip;
class GdbFuncTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GdbFuncTest::SetUpTestCase()
{
    LOG_INFO("SetUpTestCase");
}

void GdbFuncTest::TearDownTestCase()
{
    LOG_INFO("TearDownTestCase");
}

void GdbFuncTest::SetUp()
{
    LOG_INFO("SetUp");
}

void GdbFuncTest::TearDown()
{
    LOG_INFO("TearDown");
}

HWTEST_F(GdbFuncTest, GdbStore_Func_OpenClose01, TestSize.Level1)
{
    int errCode = E_OK;
    std::string dbName = "testReopendb";
    std::string dbPath = "/data";
    auto config = StoreConfig(dbName, dbPath);

    auto store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);

    auto result = store->QueryGql("");
    EXPECT_NE(result.first, E_OK);

    store->Close();
    result = store->QueryGql("abc");
    EXPECT_NE(result.first, E_OK);

    store = GDBHelper::GetDBStore(config, errCode);
    EXPECT_EQ(errCode, E_OK);

    GDBHelper::DeleteDBStore(config);

    auto store1 = GDBHelper::GetDBStore(config, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    result = store1->ExecuteGql(
        "CREATE GRAPH test {(person: Person {name STRING, age INT, sex BOOL DEFAULT false})}");
    EXPECT_EQ(result.first, E_OK);
    GDBHelper::DeleteDBStore(config);
}

HWTEST_F(GdbFuncTest, GdbStore_Func_CreateConnPool01, TestSize.Level1)
{
    int32_t errCode = E_OK;
    auto config = StoreConfig("test", "/data", DBType::DB_VECTOR);
    auto connectionPool = ConnectionPool::Create(config, errCode);
    EXPECT_EQ(errCode, E_NOT_SUPPORT);
}

HWTEST_F(GdbFuncTest, GdbStore_Func_CreateConnPool02, TestSize.Level1)
{
    int32_t errCode = E_OK;
    auto config = StoreConfig("test", "/data", DBType::DB_GRAPH);
    config.SetIter(0);
    EXPECT_EQ(config.GetIter(), 0);
    auto connectionPool = ConnectionPool::Create(config, errCode);
    EXPECT_EQ(errCode, E_OK);
}

HWTEST_F(GdbFuncTest, GdbStore_Func_CreateConnPool03, TestSize.Level1)
{
    int32_t errCode = E_OK;
    auto config = StoreConfig("test", "/data", DBType::DB_GRAPH);
    config.SetReadConSize(0);
    auto connectionPool = ConnectionPool::Create(config, errCode);
    EXPECT_EQ(errCode, E_OK);

    auto connRead1 = connectionPool->AcquireRef(true);
    EXPECT_NE(connRead1, nullptr);
    EXPECT_EQ(connRead1->GetDBType(), DBType::DB_GRAPH);
    auto connRead2 = connectionPool->AcquireRef(true);
    EXPECT_NE(connRead2, nullptr);
    auto connRead3 = connectionPool->AcquireRef(true);
    EXPECT_NE(connRead3, nullptr);

    auto connWrite1 = connectionPool->AcquireRef(false);
    EXPECT_NE(connWrite1, nullptr);
    auto connWrite2 = connectionPool->AcquireRef(false);
    EXPECT_NE(connWrite2, nullptr);
    auto connWrite3 = connectionPool->AcquireRef(false);
    EXPECT_NE(connWrite3, nullptr);

    connWrite1 = nullptr;
    connWrite2 = nullptr;
    connWrite3 = nullptr;
    auto connWrite4 = connectionPool->AcquireRef(false);
    EXPECT_NE(connWrite4, nullptr);

    connectionPool->CloseAllConnections();

    connRead1 = connectionPool->AcquireRef(true);
    EXPECT_EQ(connRead1, nullptr);

    connWrite1 = connectionPool->AcquireRef(false);
    EXPECT_EQ(connWrite1, nullptr);
}

HWTEST_F(GdbFuncTest, GdbStore_Func_CreateConnPool04, TestSize.Level1)
{
    int32_t errCode = E_OK;
    auto config = StoreConfig("test", "/data", DBType::DB_GRAPH);
    config.SetReadConSize(65);
    auto connectionPool = ConnectionPool::Create(config, errCode);
    EXPECT_EQ(errCode, E_ARGS_READ_CON_OVERLOAD);
}

HWTEST_F(GdbFuncTest, GdbStore_Func_CreateConnPool05, TestSize.Level1)
{
    int32_t errCode = E_OK;
    auto config = StoreConfig("test", "/data", DBType::DB_GRAPH);
    auto connectionPool = ConnectionPool::Create(config, errCode);
    EXPECT_EQ(errCode, E_OK);

    errCode = connectionPool->Dump(true, "header");
    EXPECT_EQ(errCode, E_OK);

    errCode = connectionPool->RestartReaders();
    EXPECT_EQ(errCode, E_OK);

    auto connRead1 = connectionPool->AcquireRef(true);
    EXPECT_NE(connRead1, nullptr);
    EXPECT_NE(connRead1->GetId(), -1);
    auto connRead2 = connectionPool->AcquireRef(true);
    EXPECT_NE(connRead2, nullptr);
    auto connRead3 = connectionPool->AcquireRef(true);
    EXPECT_NE(connRead3, nullptr);
    auto connRead4 = connectionPool->AcquireRef(true);
    EXPECT_NE(connRead4, nullptr);
    auto connRead5 = connectionPool->AcquireRef(true);
    EXPECT_NE(connRead5, nullptr);
    auto connRead6 = connectionPool->AcquireRef(true);
    EXPECT_NE(connRead6, nullptr);

    auto connWrite1 = connectionPool->AcquireRef(false);
    EXPECT_NE(connWrite1, nullptr);
    auto connWrite2 = connectionPool->AcquireRef(false);
    EXPECT_EQ(connWrite2, nullptr);
    auto connWrite3 = connectionPool->AcquireRef(false);
    EXPECT_EQ(connWrite3, nullptr);

    connWrite1 = nullptr;
    connWrite2 = nullptr;
    connWrite3 = nullptr;
    auto connWrite4 = connectionPool->AcquireRef(false);
    EXPECT_NE(connWrite4, nullptr);

    connectionPool->CloseAllConnections();

    connRead1 = connectionPool->AcquireRef(true);
    EXPECT_EQ(connRead1, nullptr);

    connWrite1 = connectionPool->AcquireRef(false);
    EXPECT_EQ(connWrite1, nullptr);
}
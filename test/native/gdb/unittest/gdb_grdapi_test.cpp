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

#define LOG_TAG "GdbGrdApiTest"
#include <dlfcn.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <variant>

#include "aip_errors.h"
#include "db_store_manager.h"
#include "grd_adapter.h"
#include "grd_adapter_manager.h"
#include "grd_error.h"
#include "logger.h"

using namespace testing::ext;
using namespace OHOS::DistributedDataAip;
class GdbGrdApiTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GdbGrdApiTest::SetUpTestCase()
{
    LOG_INFO("SetUpTestCase");
}

void GdbGrdApiTest::TearDownTestCase()
{
    LOG_INFO("TearDownTestCase");
}

void GdbGrdApiTest::SetUp()
{
    LOG_INFO("SetUp");
    if (!IsSupportArkDataDb()) {
        GTEST_SKIP() << "Current testcase is not compatible from current gdb";
    }
}

void GdbGrdApiTest::TearDown()
{
    LOG_INFO("TearDown");
}

HWTEST_F(GdbGrdApiTest, GdbStore_GrdApi_TransType01, TestSize.Level1)
{
    auto type = GrdAdapter::TransColType(GRD_DB_DATATYPE_INTEGER);
    EXPECT_EQ(type, ColumnType::TYPE_INTEGER);
    type = GrdAdapter::TransColType(GRD_DB_DATATYPE_FLOAT);
    EXPECT_EQ(type, ColumnType::TYPE_FLOAT);
    type = GrdAdapter::TransColType(GRD_DB_DATATYPE_TEXT);
    EXPECT_EQ(type, ColumnType::TYPE_TEXT);
    type = GrdAdapter::TransColType(GRD_DB_DATATYPE_BLOB);
    EXPECT_EQ(type, ColumnType::TYPE_BLOB);
    type = GrdAdapter::TransColType(GRD_DB_DATATYPE_FLOATVECTOR);
    EXPECT_EQ(type, ColumnType::TYPE_FLOATVECTOR);
    type = GrdAdapter::TransColType(GRD_DB_DATATYPE_JSONSTR);
    EXPECT_EQ(type, ColumnType::TYPE_JSONSTR);
    type = GrdAdapter::TransColType(GRD_DB_DATATYPE_NULL);
    EXPECT_EQ(type, ColumnType::TYPE_NULL);
    type = GrdAdapter::TransColType(-1);
    EXPECT_EQ(type, ColumnType::TYPE_NULL);
    type = GrdAdapter::TransColType(7);
    EXPECT_EQ(type, ColumnType::TYPE_NULL);
}

HWTEST_F(GdbGrdApiTest, GdbStore_GrdApi_NotUsed01, TestSize.Level1)
{
    std::string createGql = "CREATE GRAPH test {(person:Person {name STRING} )};";
    std::string dbPath = "/data/test.db";
    std::string backupPath = "/data/testBackup.db";
    if (g_library != nullptr) {
        dlclose(g_library);
    }
    GRD_DB *db = nullptr;
    auto ret = GrdAdapter::Open(dbPath.c_str(), "", GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(ret, E_OK);

    if (g_library != nullptr) {
        dlclose(g_library);
    }
    std::vector<uint8_t> entryKey = { 't', 'e', 's', 't' };
    ret = GrdAdapter::Backup(db, backupPath.c_str(), entryKey);
    EXPECT_EQ(ret, E_NOT_SUPPORT);

    if (g_library != nullptr) {
        dlclose(g_library);
    }
    ret = GrdAdapter::Close(db, 0);
    EXPECT_EQ(ret, E_OK);

    if (g_library != nullptr) {
        dlclose(g_library);
    }
    ret = GrdAdapter::Restore(dbPath.c_str(), backupPath.c_str(), entryKey);
    EXPECT_EQ(ret, E_NOT_SUPPORT);

    if (g_library != nullptr) {
        dlclose(g_library);
    }
    ret = GrdAdapter::Repair(dbPath.c_str(), "");
    EXPECT_EQ(ret, E_NOT_SUPPORT);

    if (g_library != nullptr) {
        dlclose(g_library);
    }
    ret = GrdAdapter::Rekey(dbPath.c_str(), "", std::vector<uint8_t>());
    EXPECT_EQ(ret, E_NOT_SUPPORT);
}

HWTEST_F(GdbGrdApiTest, GdbStore_GrdApi_NotUsed02, TestSize.Level1)
{
    std::string createGql = "CREATE GRAPH test {(person:Person {name STRING} )};";
    std::string dbPath = "/data/test.db";
    std::string backupPath = "/data/testBackup.db";
    GRD_DB *db = nullptr;
    if (g_library != nullptr) {
        dlclose(g_library);
    }
    auto ret = GrdAdapter::Open(dbPath.c_str(), "", GRD_DB_OPEN_CREATE, &db);
    EXPECT_EQ(ret, E_OK);

    if (g_library != nullptr) {
        dlclose(g_library);
    }
    GRD_Stmt *stmt = nullptr;
    ret = GrdAdapter::Prepare(db, createGql.c_str(), createGql.size(), &stmt, nullptr);
    EXPECT_EQ(ret, E_OK);

    if (g_library != nullptr) {
        dlclose(g_library);
    }
    ret = GrdAdapter::Reset(stmt);
    EXPECT_EQ(ret, E_OK);

    if (g_library != nullptr) {
        dlclose(g_library);
    }
    auto result = GrdAdapter::ColumnBytes(stmt, 0);
    EXPECT_EQ(result, 0);

    if (g_library != nullptr) {
        dlclose(g_library);
    }
    auto result2 = GrdAdapter::ColumnInt64(stmt, 0);
    EXPECT_EQ(result2, 0);

    result2 = GrdAdapter::ColumnInt(stmt, 0);
    EXPECT_EQ(result2, 0);

    auto result3 = GrdAdapter::ColumnDouble(stmt, 0);
    EXPECT_EQ(result3, 0.0);

    if (g_library != nullptr) {
        dlclose(g_library);
    }
    auto value = GrdAdapter::ColumnValue(stmt, 0);
    EXPECT_EQ(value.type, GRD_DB_DATATYPE_NULL);
    ret = StoreManager::GetInstance().Delete(dbPath);
    EXPECT_EQ(ret, 1);
    ret = StoreManager::GetInstance().Delete(backupPath);
    EXPECT_EQ(ret, 1);
}
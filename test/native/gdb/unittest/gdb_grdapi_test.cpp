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
    std::map<int32_t, int32_t> GRD_ERRNO_MAP = {
        { GRD_OK, E_OK },
        { GRD_REBUILD_DATABASE, E_OK },
        { GRD_NO_DATA, E_GRD_NO_DATA },
        { GRD_DATA_CORRUPTED, E_GRD_DATA_CORRUPTED },
        { GRD_INVALID_FILE_FORMAT, E_GRD_INVALID_FILE_FORMAT },
        { GRD_PRIMARY_KEY_VIOLATION, E_GRD_PRIMARY_KEY_VIOLATION },
        { GRD_RESTRICT_VIOLATION, E_GRD_RESTRICT_VIOLATION },
        { GRD_CONSTRAINT_CHECK_VIOLATION, E_GRD_CONSTRAINT_CHECK_VIOLATION },
        { GRD_NOT_SUPPORT, E_GRD_NOT_SUPPORT },
        { GRD_OVER_LIMIT, E_GRD_OVER_LIMIT },
        { GRD_INVALID_ARGS, E_GRD_INVALID_ARGS },
        { GRD_FAILED_FILE_OPERATION, E_GRD_FAILED_FILE_OPERATION },
        { GRD_INSUFFICIENT_SPACE, E_GRD_INSUFFICIENT_SPACE },
        { GRD_RESOURCE_BUSY, E_GRD_RESOURCE_BUSY },
        { GRD_DB_BUSY, E_GRD_DB_BUSY },
        { GRD_FAILED_MEMORY_ALLOCATE, E_GRD_FAILED_MEMORY_ALLOCATE },
        { GRD_CRC_CHECK_DISABLED, E_GRD_CRC_CHECK_DISABLED },
        { GRD_DISK_SPACE_FULL, E_GRD_DISK_SPACE_FULL },

        { GRD_PERMISSION_DENIED, E_GRD_PERMISSION_DENIED },
        { GRD_PASSWORD_UNMATCHED, E_GRD_PASSWORD_UNMATCHED },
        { GRD_PASSWORD_NEED_REKEY, E_GRD_PASSWORD_NEED_REKEY },

        { GRD_NAME_TOO_LONG, E_GRD_NAME_TOO_LONG },
        { GRD_INVALID_TABLE_DEFINITION, E_GRD_INVALID_TABLE_DEFINITION },
        { GRD_SEMANTIC_ERROR, E_GRD_SEMANTIC_ERROR },
        { GRD_SYNTAX_ERROR, E_GRD_SYNTAX_ERROR },
        { GRD_WRONG_STMT_OBJECT, E_GRD_WRONG_STMT_OBJECT },
        { GRD_DATA_CONFLICT, E_GRD_DATA_CONFLICT },

        { GRD_INNER_ERR, E_GRD_INNER_ERR },
        { GRD_FAILED_MEMORY_RELEASE, E_GRD_FAILED_MEMORY_RELEASE },
        { GRD_NOT_AVAILABLE, E_GRD_NOT_AVAILABLE },
        { GRD_INVALID_FORMAT, E_GRD_INVALID_FORMAT },
        { GRD_TIME_OUT, E_GRD_TIME_OUT },
        { GRD_DB_INSTANCE_ABNORMAL, E_GRD_DB_INSTANCE_ABNORMAL },
        { GRD_CIPHER_ERROR, E_GRD_CIPHER_ERROR },
        { GRD_DUPLICATE_TABLE, E_GRD_DUPLICATE_TABLE },
        { GRD_DUPLICATE_OBJECT, E_GRD_DUPLICATE_OBJECT },
        { GRD_DUPLICATE_COLUMN, E_GRD_DUPLICATE_COLUMN },
        { GRD_UNDEFINE_COLUMN, E_GRD_UNDEFINE_COLUMN },
        { GRD_UNDEFINED_OBJECT, E_GRD_UNDEFINED_OBJECT },
        { GRD_UNDEFINED_TABLE, E_GRD_UNDEFINED_TABLE },
        { GRD_INVALID_CONFIG_VALUE, E_GRD_INVALID_CONFIG_VALUE },
        { GRD_REQUEST_TIME_OUT, E_GRD_REQUEST_TIME_OUT },
        { GRD_DATATYPE_MISMATCH, E_GRD_SEMANTIC_ERROR },
        { GRD_UNIQUE_VIOLATION, E_GRD_SEMANTIC_ERROR },
        { GRD_INVALID_BIND_VALUE, E_GRD_INVALID_BIND_VALUE },
        { GRD_JSON_OPERATION_NOT_SUPPORT, E_GRD_NOT_SUPPORT },
        { GRD_MODEL_NOT_SUPPORT, E_GRD_NOT_SUPPORT },
        { GRD_FEATURE_NOT_SUPPORTED, E_GRD_NOT_SUPPORT },
        { GRD_JSON_LEN_LIMIT, E_GRD_EXCEEDED_LIMIT },
        { GRD_SUBSCRIPTION_EXCEEDED_LIMIT, E_GRD_EXCEEDED_LIMIT },
        { GRD_SYNC_EXCEED_TASK_QUEUE_LIMIT, E_GRD_EXCEEDED_LIMIT },
        { GRD_SHARED_OBJ_ENABLE_UNDO_EXCEED_LIMIT, E_GRD_EXCEEDED_LIMIT },
        { GRD_TABLE_LIMIT_EXCEEDED, E_GRD_EXCEEDED_LIMIT },
        { GRD_FIELD_TYPE_NOT_MATCH, E_GRD_SEMANTIC_ERROR },
        { GRD_LARGE_JSON_NEST, E_GRD_SEMANTIC_ERROR },
        { GRD_INVALID_JSON_TYPE, E_GRD_SEMANTIC_ERROR },
        { GRD_INVALID_OPERATOR, E_GRD_NOT_SUPPORT },
        { GRD_INVALID_PROJECTION_FIELD, E_GRD_SEMANTIC_ERROR },
        { GRD_INVALID_PROJECTION_VALUE, E_GRD_SEMANTIC_ERROR },
        { GRD_DB_NOT_EXIST, E_GRD_DB_NOT_EXIST },
        { GRD_INVALID_VALUE, E_GRD_INVALID_ARGS },
        { GRD_SHARED_OBJ_NOT_EXIST, E_GRD_DATA_NOT_FOUND },
        { GRD_SUBSCRIBE_NOT_EXIST, E_GRD_DATA_NOT_FOUND },
        { GRD_COLLECTION_NOT_EXIST, E_GRD_DATA_NOT_FOUND },
        { GRD_RESULTSET_BUSY, E_GRD_DB_BUSY },
        { GRD_RECORD_NOT_FOUND, E_GRD_DATA_NOT_FOUND },
        { GRD_FIELD_NOT_FOUND, E_GRD_DATA_NOT_FOUND },
        { GRD_ARRAY_INDEX_NOT_FOUND, E_GRD_DATA_NOT_FOUND },
        { GRD_RESULT_SET_NOT_AVAILABLE, E_GRD_DATA_NOT_FOUND },
        { GRD_SHARED_OBJ_UNDO_NOT_AVAILABLE, E_GRD_DATA_NOT_FOUND },
        { GRD_SHARED_OBJ_REDO_NOT_AVAILABLE, E_GRD_DATA_NOT_FOUND },
        { GRD_INVALID_JSON_FORMAT, E_GRD_SEMANTIC_ERROR },
        { GRD_INVALID_KEY_FORMAT, E_GRD_SEMANTIC_ERROR },
        { GRD_INVALID_COLLECTION_NAME, E_GRD_SEMANTIC_ERROR },
        { GRD_INVALID_EQUIP_ID, E_GRD_SEMANTIC_ERROR },
        { GRD_KEY_CONFLICT, E_GRD_DATA_CONFLICT },
        { GRD_FIELD_TYPE_CONFLICT, E_GRD_DATA_CONFLICT },
        { GRD_SHARED_OBJ_CONFLICT, E_GRD_DATA_CONFLICT },
        { GRD_SUBSCRIBE_CONFLICT, E_GRD_DATA_CONFLICT },
        { GRD_EQUIP_ID_CONFLICT, E_GRD_DATA_CONFLICT },
        { GRD_SHARED_OBJ_ENABLE_UNDO_CONFLICT, E_GRD_DATA_CONFLICT },
        { GRD_SCHEMA_CHANGED, E_GRD_SCHEMA_CHANGED },
        { GRD_DATA_EXCEPTION, E_GRD_DATA_EXCEPTION },
        { GRD_FIELD_OVERFLOW, E_GRD_FIELD_OVERFLOW },
        { GRD_DIVISION_BY_ZERO, E_GRD_DIVISION_BY_ZERO },
        { GRD_TRANSACTION_ROLLBACK, E_GRD_TRANSACTION_ROLLBACK },
        { GRD_NO_ACTIVE_TRANSACTION, E_GRD_NO_ACTIVE_TRANSACTION },
        { GRD_ACTIVE_TRANSACTION, E_GRD_ACTIVE_TRANSACTION },
    };
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

HWTEST_F(GdbGrdApiTest, GdbStore_GrdApi_TransErr01, TestSize.Level1)
{
    for (const auto &item : GRD_ERRNO_MAP) {
        auto errCode = GrdAdapter::TransErrno(item.first);
        EXPECT_EQ(errCode, item.second);
    }
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
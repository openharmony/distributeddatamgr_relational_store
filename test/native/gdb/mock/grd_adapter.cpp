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

#include "grd_adapter.h"

#include <cinttypes>
#include <map>

#include "gdb_errors.h"
#include "gdb_utils.h"
#include "grd_adapter_manager.h"
#include "grd_error.h"

namespace OHOS::DistributedDataAip {

static GrdAdapterHolder g_adapterHolder;

int32_t GrdAdapter::errorCode_[FuncName::ALL] = { GRD_OK };

std::map<int32_t, int32_t> GrdAdapter::GRD_ERRNO_MAP = {
    { GRD_OK, E_OK },
    { GRD_REBUILD_DATABASE, E_OK },
    { GRD_NO_DATA, E_GRD_NO_DATA },
    { GRD_DATA_CORRUPTED, E_GRD_DATA_CORRUPTED },
    { GRD_INVALID_FILE_FORMAT, E_GRD_INVALID_FILE_FORMAT },
    { GRD_PRIMARY_KEY_VIOLATION, E_GRD_DATA_CONFLICT },
    { GRD_RESTRICT_VIOLATION, E_GRD_DATA_CONFLICT },
    { GRD_CONSTRAINT_CHECK_VIOLATION, E_GRD_DATA_CONFLICT },
    { GRD_NOT_SUPPORT, E_GRD_NOT_SUPPORT },
    { GRD_OVER_LIMIT, E_GRD_OVER_LIMIT },
    { GRD_INVALID_ARGS, E_GRD_INVALID_ARGS },
    { GRD_FAILED_FILE_OPERATION, E_GRD_FAILED_FILE_OPERATION },
    { GRD_INSUFFICIENT_SPACE, E_GRD_DISK_SPACE_FULL },
    { GRD_RESOURCE_BUSY, E_DATABASE_BUSY },
    { GRD_DB_BUSY, E_DATABASE_BUSY },
    { GRD_FAILED_MEMORY_ALLOCATE, E_GRD_FAILED_MEMORY_ALLOCATE },
    { GRD_CRC_CHECK_DISABLED, E_GRD_CRC_CHECK_DISABLED },
    { GRD_DISK_SPACE_FULL, E_GRD_DISK_SPACE_FULL },

    { GRD_PERMISSION_DENIED, E_GRD_PERMISSION_DENIED },
    { GRD_PASSWORD_UNMATCHED, E_GRD_PASSWORD_UNMATCHED },
    { GRD_PASSWORD_NEED_REKEY, E_GRD_PASSWORD_NEED_REKEY },

    { GRD_NAME_TOO_LONG, E_GRD_INVALID_NAME },
    { GRD_INVALID_TABLE_DEFINITION, E_GRD_SEMANTIC_ERROR },
    { GRD_SEMANTIC_ERROR, E_GRD_SEMANTIC_ERROR },
    { GRD_SYNTAX_ERROR, E_GRD_SYNTAX_ERROR },
    { GRD_WRONG_STMT_OBJECT, E_GRD_WRONG_STMT_OBJECT },
    { GRD_DATA_CONFLICT, E_GRD_DATA_CONFLICT },

    { GRD_INNER_ERR, E_GRD_INNER_ERR },
    { GRD_FAILED_MEMORY_RELEASE, E_GRD_FAILED_MEMORY_RELEASE },
    { GRD_NOT_AVAILABLE, E_GRD_NOT_AVAILABLE },
    { GRD_INVALID_FORMAT, E_GRD_SEMANTIC_ERROR },
    { GRD_TIME_OUT, E_DATABASE_BUSY },
    { GRD_DB_INSTANCE_ABNORMAL, E_GRD_DB_INSTANCE_ABNORMAL },
    { GRD_CIPHER_ERROR, E_GRD_CIPHER_ERROR },
    { GRD_DUPLICATE_TABLE, E_GRD_DUPLICATE_PARAM },
    { GRD_DUPLICATE_OBJECT, E_GRD_DUPLICATE_PARAM },
    { GRD_DUPLICATE_COLUMN, E_GRD_DUPLICATE_PARAM },
    { GRD_UNDEFINE_COLUMN, E_GRD_UNDEFINED_PARAM },
    { GRD_UNDEFINED_OBJECT, E_GRD_UNDEFINED_PARAM },
    { GRD_UNDEFINED_TABLE, E_GRD_UNDEFINED_PARAM },
    { GRD_INVALID_CONFIG_VALUE, E_CONFIG_INVALID_CHANGE },
    { GRD_REQUEST_TIME_OUT, E_DATABASE_BUSY },
    { GRD_DATATYPE_MISMATCH, E_GRD_SEMANTIC_ERROR },
    { GRD_UNIQUE_VIOLATION, E_GRD_DATA_CONFLICT },
    { GRD_INVALID_BIND_VALUE, E_GRD_INVALID_BIND_VALUE },
    { GRD_JSON_OPERATION_NOT_SUPPORT, E_GRD_SEMANTIC_ERROR },
    { GRD_MODEL_NOT_SUPPORT, E_GRD_SEMANTIC_ERROR },
    { GRD_FEATURE_NOT_SUPPORTED, E_GRD_SEMANTIC_ERROR },
    { GRD_JSON_LEN_LIMIT, E_GRD_DATA_CONFLICT },
    { GRD_SUBSCRIPTION_EXCEEDED_LIMIT, E_GRD_INNER_ERR },
    { GRD_SYNC_EXCEED_TASK_QUEUE_LIMIT, E_DATABASE_BUSY },
    { GRD_SHARED_OBJ_ENABLE_UNDO_EXCEED_LIMIT, E_GRD_INNER_ERR },
    { GRD_TABLE_LIMIT_EXCEEDED, E_GRD_OVER_LIMIT },
    { GRD_FIELD_TYPE_NOT_MATCH, E_GRD_SEMANTIC_ERROR },
    { GRD_LARGE_JSON_NEST, E_GRD_SEMANTIC_ERROR },
    { GRD_INVALID_JSON_TYPE, E_GRD_SEMANTIC_ERROR },
    { GRD_INVALID_OPERATOR, E_GRD_SEMANTIC_ERROR },
    { GRD_INVALID_PROJECTION_FIELD, E_GRD_SEMANTIC_ERROR },
    { GRD_INVALID_PROJECTION_VALUE, E_GRD_SEMANTIC_ERROR },
    { GRD_DB_NOT_EXIST, E_GRD_DB_NOT_EXIST },
    { GRD_INVALID_VALUE, E_GRD_INVALID_ARGS },
    { GRD_SHARED_OBJ_NOT_EXIST, E_GRD_DATA_NOT_FOUND },
    { GRD_SUBSCRIBE_NOT_EXIST, E_GRD_DATA_NOT_FOUND },
    { GRD_COLLECTION_NOT_EXIST, E_GRD_DATA_NOT_FOUND },
    { GRD_RESULTSET_BUSY, E_DATABASE_BUSY },
    { GRD_RECORD_NOT_FOUND, E_GRD_DATA_NOT_FOUND },
    { GRD_FIELD_NOT_FOUND, E_GRD_DATA_NOT_FOUND },
    { GRD_ARRAY_INDEX_NOT_FOUND, E_GRD_DATA_NOT_FOUND },
    { GRD_RESULT_SET_NOT_AVAILABLE, E_GRD_DATA_NOT_FOUND },
    { GRD_SHARED_OBJ_UNDO_NOT_AVAILABLE, E_GRD_DATA_NOT_FOUND },
    { GRD_SHARED_OBJ_REDO_NOT_AVAILABLE, E_GRD_DATA_NOT_FOUND },
    { GRD_INVALID_JSON_FORMAT, E_GRD_DATA_CONFLICT },
    { GRD_INVALID_KEY_FORMAT, E_GRD_INVALID_NAME },
    { GRD_INVALID_COLLECTION_NAME, E_GRD_INVALID_NAME },
    { GRD_INVALID_EQUIP_ID, E_GRD_SEMANTIC_ERROR },
    { GRD_KEY_CONFLICT, E_GRD_DATA_CONFLICT },
    { GRD_FIELD_TYPE_CONFLICT, E_GRD_DATA_CONFLICT },
    { GRD_SHARED_OBJ_CONFLICT, E_GRD_DATA_CONFLICT },
    { GRD_SUBSCRIBE_CONFLICT, E_GRD_DATA_CONFLICT },
    { GRD_EQUIP_ID_CONFLICT, E_GRD_DATA_CONFLICT },
    { GRD_SHARED_OBJ_ENABLE_UNDO_CONFLICT, E_GRD_DATA_CONFLICT },
    { GRD_SCHEMA_CHANGED, E_CONFIG_INVALID_CHANGE },
    { GRD_DATA_EXCEPTION, E_GRD_DATA_EXCEPTION },
    { GRD_FIELD_OVERFLOW, E_GRD_SEMANTIC_ERROR },
    { GRD_DIVISION_BY_ZERO, E_GRD_SYNTAX_ERROR },
    { GRD_TRANSACTION_ROLLBACK, E_GRD_TRANSACTION_ROLLBACK },
    { GRD_NO_ACTIVE_TRANSACTION, E_GRD_NO_ACTIVE_TRANSACTION },
    { GRD_ACTIVE_TRANSACTION, E_GRD_ACTIVE_TRANSACTION },
};

int GrdAdapter::TransErrno(int err)
{
    if (err > 0) {
        return err;
    }
    auto result = GRD_ERRNO_MAP.find(err);
    if (result != GRD_ERRNO_MAP.end()) {
        return result->second;
    }
    return E_GRD_INNER_ERR;
}

void GrdAdapter::SetErrorCode(FuncName func, int32_t err)
{
    if (func == FuncName::ALL) {
        for (int i = FuncName::PREPARE; i < FuncName::ALL; i++) {
            errorCode_[i] = err;
        }
    } else {
        errorCode_[func] = err;
    }
}

int32_t GrdAdapter::Prepare(GRD_DB *db, const char *str, uint32_t strLen, GRD_StmtT **stmt, const char **unusedStr)
{
    if (errorCode_[FuncName::PREPARE] == GRD_OK) {
        if (g_adapterHolder.Prepare == nullptr) {
            g_adapterHolder = GetAdapterHolder();
        }
        if (g_adapterHolder.Prepare == nullptr) {
            return E_NOT_SUPPORT;
        }
        int32_t ret = g_adapterHolder.Prepare(db, str, strLen, stmt, unusedStr);
        return TransErrno(ret);
    }
    return TransErrno(errorCode_[FuncName::PREPARE]);
}

int32_t GrdAdapter::Step(GRD_StmtT *stmt)
{
    if (errorCode_[FuncName::STEP] == GRD_OK) {
        if (g_adapterHolder.Step == nullptr) {
            g_adapterHolder = GetAdapterHolder();
        }
        if (g_adapterHolder.Step == nullptr) {
            return E_NOT_SUPPORT;
        }
        int32_t ret = g_adapterHolder.Step(stmt);
        return TransErrno(ret);
    }
    return TransErrno(errorCode_[FuncName::STEP]);
}

int32_t GrdAdapter::Finalize(GRD_StmtT *stmt)
{
    if (errorCode_[FuncName::FINALIZE] == GRD_OK) {
        if (g_adapterHolder.Finalize == nullptr) {
            g_adapterHolder = GetAdapterHolder();
        }
        if (g_adapterHolder.Finalize == nullptr) {
            return E_NOT_SUPPORT;
        }
        int32_t ret = g_adapterHolder.Finalize(stmt);
        return TransErrno(ret);
    }
    return TransErrno(errorCode_[FuncName::FINALIZE]);
}

int32_t GrdAdapter::Rekey(const char *dbFile, const char *configStr, const std::vector<uint8_t> &encryptedKey)
{
    if (errorCode_[FuncName::REKEY] == GRD_OK) {
        if (g_adapterHolder.Rekey == nullptr) {
            g_adapterHolder = GetAdapterHolder();
        }
        if (g_adapterHolder.Rekey == nullptr) {
            return E_NOT_SUPPORT;
        }
        if (encryptedKey.empty()) {
            return E_GRD_INVALID_ARGS;
        }
        int32_t ret = E_OK;
        GRD_CipherInfoT info = { 0 };
        const size_t keySize = encryptedKey.size() * 2 + 1;
        std::vector<char> key(keySize);
        info.hexPassword = GdbUtils::GetEncryptKey(encryptedKey, key.data(), keySize);
        ret = g_adapterHolder.Rekey(dbFile, configStr, &info);
        key.assign(keySize, 0);
        return TransErrno(ret);
    }
    return TransErrno(errorCode_[FuncName::REKEY]);
}

ColumnType GrdAdapter::TransColType(int grdColType)
{
    switch (grdColType) {
        case GRD_DB_DATATYPE_INTEGER:
            return ColumnType::TYPE_INTEGER;
        case GRD_DB_DATATYPE_FLOAT:
            return ColumnType::TYPE_FLOAT;
        case GRD_DB_DATATYPE_TEXT:
            return ColumnType::TYPE_TEXT;
        case GRD_DB_DATATYPE_BLOB:
            return ColumnType::TYPE_BLOB;
        case GRD_DB_DATATYPE_FLOATVECTOR:
            return ColumnType::TYPE_FLOATVECTOR;
        case GRD_DB_DATATYPE_JSONSTR:
            return ColumnType::TYPE_JSONSTR;
        case GRD_DB_DATATYPE_NULL:
            return ColumnType::TYPE_NULL;
        default:
            return ColumnType::TYPE_NULL;
    }
}

int GrdAdapter::Open(const char *dbPath, const char *configStr, uint32_t flags, GRD_DB **db)
{
    if (g_adapterHolder.Open == nullptr) {
        g_adapterHolder = GetAdapterHolder();
    }
    if (g_adapterHolder.Open == nullptr) {
        return E_NOT_SUPPORT;
    }
    auto ret = g_adapterHolder.Open(dbPath, configStr, flags, db);
    return TransErrno(ret);
}

int GrdAdapter::Close(GRD_DB *db, uint32_t flags)
{
    if (g_adapterHolder.Close == nullptr) {
        g_adapterHolder = GetAdapterHolder();
    }
    if (g_adapterHolder.Close == nullptr) {
        return E_NOT_SUPPORT;
    }
    auto ret = g_adapterHolder.Close(db, flags);
    return TransErrno(ret);
}

int GrdAdapter::Repair(const char *dbPath, const char *configStr)
{
    if (g_adapterHolder.Repair == nullptr) {
        g_adapterHolder = GetAdapterHolder();
    }
    if (g_adapterHolder.Repair == nullptr) {
        return E_NOT_SUPPORT;
    }
    return E_NOT_SUPPORT;
}

int GrdAdapter::Backup(GRD_DB *db, const char *backupDbFile, const std::vector<uint8_t> &encryptedKey)
{
    if (g_adapterHolder.Backup == nullptr) {
        g_adapterHolder = GetAdapterHolder();
    }
    if (g_adapterHolder.Backup == nullptr) {
        return E_NOT_SUPPORT;
    }
    return E_NOT_SUPPORT;
}

int GrdAdapter::Restore(const char *dbFile, const char *backupDbFile, const std::vector<uint8_t> &encryptedKey)
{
    if (g_adapterHolder.Restore == nullptr) {
        g_adapterHolder = GetAdapterHolder();
    }
    if (g_adapterHolder.Restore == nullptr) {
        return E_NOT_SUPPORT;
    }
    return E_NOT_SUPPORT;
}

int32_t GrdAdapter::Reset(GRD_StmtT *stmt)
{
    if (g_adapterHolder.Reset == nullptr) {
        g_adapterHolder = GetAdapterHolder();
    }
    if (g_adapterHolder.Reset == nullptr) {
        return E_NOT_SUPPORT;
    }
    return TransErrno(g_adapterHolder.Reset(stmt));
}

uint32_t GrdAdapter::ColumnCount(GRD_StmtT *stmt)
{
    if (g_adapterHolder.ColumnCount == nullptr) {
        g_adapterHolder = GetAdapterHolder();
    }
    if (g_adapterHolder.ColumnCount == nullptr) {
        return E_NOT_SUPPORT;
    }
    return g_adapterHolder.ColumnCount(stmt);
}

GRD_DbDataTypeE GrdAdapter::ColumnType(GRD_StmtT *stmt, uint32_t idx)
{
    if (g_adapterHolder.GetColumnType == nullptr) {
        g_adapterHolder = GetAdapterHolder();
    }
    if (g_adapterHolder.GetColumnType == nullptr) {
        return GRD_DB_DATATYPE_NULL;
    }
    return g_adapterHolder.GetColumnType(stmt, idx);
}

uint32_t GrdAdapter::ColumnBytes(GRD_StmtT *stmt, uint32_t idx)
{
    if (g_adapterHolder.ColumnBytes == nullptr) {
        g_adapterHolder = GetAdapterHolder();
    }
    if (g_adapterHolder.ColumnBytes == nullptr) {
        return E_NOT_SUPPORT;
    }
    return g_adapterHolder.ColumnBytes(stmt, idx);
}

char *GrdAdapter::ColumnName(GRD_StmtT *stmt, uint32_t idx)
{
    if (g_adapterHolder.ColumnName == nullptr) {
        g_adapterHolder = GetAdapterHolder();
    }
    if (g_adapterHolder.ColumnName == nullptr) {
        return nullptr;
    }
    return g_adapterHolder.ColumnName(stmt, idx);
}

GRD_DbValueT GrdAdapter::ColumnValue(GRD_StmtT *stmt, uint32_t idx)
{
    if (g_adapterHolder.ColumnValue == nullptr) {
        g_adapterHolder = GetAdapterHolder();
    }
    if (g_adapterHolder.ColumnValue == nullptr) {
        return {};
    }
    return g_adapterHolder.ColumnValue(stmt, idx);
}

int64_t GrdAdapter::ColumnInt64(GRD_StmtT *stmt, uint32_t idx)
{
    if (g_adapterHolder.ColumnInt64 == nullptr) {
        g_adapterHolder = GetAdapterHolder();
    }
    if (g_adapterHolder.ColumnInt64 == nullptr) {
        return 0;
    }
    return g_adapterHolder.ColumnInt64(stmt, idx);
}

int32_t GrdAdapter::ColumnInt(GRD_StmtT *stmt, uint32_t idx)
{
    if (g_adapterHolder.ColumnInt == nullptr) {
        g_adapterHolder = GetAdapterHolder();
    }
    if (g_adapterHolder.ColumnInt == nullptr) {
        return 0;
    }
    return g_adapterHolder.ColumnInt(stmt, idx);
}

double GrdAdapter::ColumnDouble(GRD_StmtT *stmt, uint32_t idx)
{
    if (g_adapterHolder.ColumnDouble == nullptr) {
        g_adapterHolder = GetAdapterHolder();
    }
    if (g_adapterHolder.ColumnDouble == nullptr) {
        return 0;
    }
    return g_adapterHolder.ColumnDouble(stmt, idx);
}

const char *GrdAdapter::ColumnText(GRD_StmtT *stmt, uint32_t idx)
{
    if (g_adapterHolder.ColumnText == nullptr) {
        g_adapterHolder = GetAdapterHolder();
    }
    if (g_adapterHolder.ColumnText == nullptr) {
        return nullptr;
    }
    return g_adapterHolder.ColumnText(stmt, idx);
}
}


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

#define LOG_TAG "RdUtils"
#include "rd_utils.h"

#include <securec.h>

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include "grd_api_manager.h"
#include "grd_error.h"
#include "logger.h"
#include "remote_result_set.h"
#include "task_executor.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

static GRD_APIInfo GRD_KVApiInfo;

GRD_ThreadPoolT RdUtils::threadPool_ = { 0 };

struct GrdErrnoPair {
    int32_t grdCode;
    int kvDbCode;
};

const GrdErrnoPair GRD_ERRNO_MAP[] = {
    { GRD_OK, E_OK },
    { GRD_REBUILD_DATABASE, E_OK },
    { GRD_NO_DATA, E_NO_MORE_ROWS },
    { GRD_DATA_CORRUPTED, E_SQLITE_CORRUPT },
    { GRD_INVALID_FILE_FORMAT, E_SQLITE_CORRUPT },
    { GRD_PRIMARY_KEY_VIOLATION, E_SQLITE_CONSTRAINT },
    { GRD_RESTRICT_VIOLATION, E_SQLITE_CONSTRAINT },
    { GRD_CONSTRAINT_CHECK_VIOLATION, E_SQLITE_CONSTRAINT },
    { GRD_NOT_SUPPORT, E_NOT_SUPPORT },
    { GRD_OVER_LIMIT, E_SQLITE_CONSTRAINT },
    { GRD_INVALID_ARGS, E_INVALID_ARGS },
    { GRD_FAILED_FILE_OPERATION, E_SQLITE_IOERR },
    { GRD_INSUFFICIENT_SPACE, E_SQLITE_FULL },
    { GRD_RESOURCE_BUSY, E_DATABASE_BUSY },
    { GRD_DB_BUSY, E_DATABASE_BUSY },
    { GRD_FAILED_MEMORY_ALLOCATE, E_SQLITE_NOMEM },
    { GRD_CRC_CHECK_DISABLED, E_INVALID_ARGS },
    { GRD_DISK_SPACE_FULL, E_SQLITE_FULL },

    { GRD_PERMISSION_DENIED, E_SQLITE_PERM },
    { GRD_PASSWORD_UNMATCHED, E_SQLITE_CANTOPEN },
    { GRD_PASSWORD_NEED_REKEY, E_CHANGE_UNENCRYPTED_TO_ENCRYPTED },

    { GRD_NAME_TOO_LONG, E_SQLITE_CONSTRAINT },
    { GRD_INVALID_TABLE_DEFINITION, E_SQLITE_ERROR },
    { GRD_SEMANTIC_ERROR, E_NOT_SUPPORT_THE_SQL },
    { GRD_SYNTAX_ERROR, E_NOT_SUPPORT_THE_SQL },
    { GRD_DATATYPE_MISMATCH, E_SQLITE_MISMATCH },
    { GRD_WRONG_STMT_OBJECT, E_INVALID_OBJECT_TYPE },
    { GRD_DATA_CONFLICT, E_SQLITE_CONSTRAINT },

    { GRD_ACTIVE_TRANSACTION, E_SQLITE_ERROR },
    { GRD_UNIQUE_VIOLATION, E_SQLITE_CONSTRAINT },
    { GRD_DUPLICATE_TABLE, E_SQLITE_ERROR },
    { GRD_UNDEFINED_TABLE, E_SQLITE_ERROR },
    { GRD_INVALID_BIND_VALUE, E_SQLITE_ERROR },
    { GRD_SCHEMA_CHANGED, E_SQLITE_ERROR },

    { GRD_JSON_OPERATION_NOT_SUPPORT, E_NOT_SUPPORT_THE_SQL },
    { GRD_MODEL_NOT_SUPPORT, E_NOT_SUPPORT_THE_SQL },
    { GRD_FEATURE_NOT_SUPPORTED, E_NOT_SUPPORT_THE_SQL },

    { GRD_JSON_LEN_LIMIT, E_SQLITE_TOOBIG },
    { GRD_SUBSCRIPTION_EXCEEDED_LIMIT, E_ERROR },
    { GRD_SYNC_EXCEED_TASK_QUEUE_LIMIT, E_ERROR },
    { GRD_SHARED_OBJ_ENABLE_UNDO_EXCEED_LIMIT, E_ERROR },
    { GRD_TABLE_LIMIT_EXCEEDED, E_SQLITE_CONSTRAINT },

    { GRD_FIELD_TYPE_NOT_MATCH, E_SQLITE_MISMATCH },
    { GRD_LARGE_JSON_NEST, E_NOT_SUPPORT_THE_SQL },
    { GRD_INVALID_JSON_TYPE, E_SQLITE_ERROR },
    { GRD_INVALID_CONFIG_VALUE, E_CONFIG_INVALID_CHANGE },
    { GRD_INVALID_OPERATOR, E_SQLITE_ERROR },
    { GRD_INVALID_PROJECTION_FIELD, E_SQLITE_ERROR },
    { GRD_INVALID_PROJECTION_VALUE, E_SQLITE_ERROR },
    { GRD_COLLECTION_NOT_EXIST, E_ERROR },
    { GRD_DB_NOT_EXIST, E_ERROR },
    { GRD_INVALID_VALUE, E_SQLITE_ERROR },
    { GRD_SHARED_OBJ_NOT_EXIST, E_ERROR },
    { GRD_SUBSCRIBE_NOT_EXIST, E_ERROR },
    { GRD_SHARED_OBJ_UNDO_MANAGER_NOT_EXIST, E_ERROR },
    { GRD_SHARED_OBJ_INVALID_UNDO, E_ERROR },
    { GRD_SHARED_OBJ_INVALID_REDO, E_ERROR },

    { GRD_JSON_LIB_HANDLE_FAILED, E_ERROR },
    { GRD_DIRECTORY_OPERATE_FAILED, E_SQLITE_IOERR_FULL },
    { GRD_FILE_OPERATE_FAILED, E_SQLITE_IOERR_FULL },
    { GRD_LOAD_THIRD_PARTY_LIBRARY_FAILED, E_ERROR },
    { GRD_THIRD_PARTY_FUNCTION_EXECUTE_FAILED, E_ERROR },
    { GRD_INSUFFICIENT_RESOURCES, E_ERROR },

    { GRD_RESULTSET_BUSY, E_DATABASE_BUSY },
    { GRD_RECORD_NOT_FOUND, E_SQLITE_ERROR },
    { GRD_FIELD_NOT_FOUND, E_SQLITE_ERROR },
    { GRD_ARRAY_INDEX_NOT_FOUND, E_SQLITE_ERROR },
    { GRD_KEY_CONFLICT, E_SQLITE_CONSTRAINT },
    { GRD_FIELD_TYPE_CONFLICT, E_SQLITE_MISMATCH },
    { GRD_SHARED_OBJ_CONFLICT, E_SQLITE_CONSTRAINT },
    { GRD_SUBSCRIBE_CONFLICT, E_ERROR },
    { GRD_EQUIP_ID_CONFLICT, E_SQLITE_CONSTRAINT },
    { GRD_SHARED_OBJ_ENABLE_UNDO_CONFLICT, E_ERROR },

    { GRD_DATA_EXCEPTION, E_SQLITE_CORRUPT },
    { GRD_FIELD_OVERFLOW, E_SQLITE_ERROR },
    { GRD_DIVISION_BY_ZERO, E_SQLITE_ERROR },
    { GRD_RESULT_SET_NOT_AVAILABLE, E_ERROR },
    { GRD_SHARED_OBJ_UNDO_NOT_AVAILABLE, E_ERROR },
    { GRD_SHARED_OBJ_REDO_NOT_AVAILABLE, E_ERROR },
    { GRD_TRANSACTION_ROLLBACK, E_SQLITE_ERROR },
    { GRD_NO_ACTIVE_TRANSACTION, E_SQLITE_ERROR },

    { GRD_DUPLICATE_COLUMN, E_SQLITE_ERROR },
    { GRD_DUPLICATE_OBJECT, E_SQLITE_ERROR },
    { GRD_UNDEFINE_COLUMN, E_SQLITE_ERROR },
    { GRD_UNDEFINED_OBJECT, E_SQLITE_ERROR },
    { GRD_INVALID_JSON_FORMAT, E_ERROR },
    { GRD_INVALID_KEY_FORMAT, E_ERROR },
    { GRD_INVALID_COLLECTION_NAME, E_ERROR },
    { GRD_INVALID_EQUIP_ID, E_SQLITE_CONSTRAINT },
    { GRD_REQUEST_TIME_OUT, E_DATABASE_BUSY },

    { GRD_SYNC_PREREQUISITES_ABNORMAL, E_ERROR },
    { GRD_CALC_MODE_SET_PERMISSION_DENIED, E_ERROR },
    { GRD_SYSTEM_ERR, E_ERROR },
    { GRD_INNER_ERR, E_ERROR },
    { GRD_FAILED_MEMORY_RELEASE, E_ERROR },
    { GRD_NOT_AVAILABLE, E_ERROR },
    { GRD_INVALID_FORMAT, E_ERROR },
    { GRD_TIME_OUT, E_DATABASE_BUSY },
    { GRD_DB_INSTANCE_ABNORMAL, E_ERROR },
    { GRD_CIPHER_ERROR, E_ERROR },
};

int RdUtils::TransferGrdErrno(int err)
{
    if (err > 0) {
        return err;
    }
    for (const auto &item : GRD_ERRNO_MAP) {
        if (item.grdCode == err) {
            return item.kvDbCode;
        }
    }
    return E_ERROR;
}

ColumnType RdUtils::TransferGrdTypeToColType(int grdColType)
{
    switch (grdColType) {
        case GRD_DB_DATATYPE_INTEGER:
            return ColumnType::TYPE_INTEGER;
        case GRD_DB_DATATYPE_FLOAT:
            return ColumnType::TYPE_FLOAT;
        case GRD_DB_DATATYPE_TEXT:
            return ColumnType::TYPE_STRING;
        case GRD_DB_DATATYPE_BLOB:
            return ColumnType::TYPE_BLOB;
        case GRD_DB_DATATYPE_FLOATVECTOR:
            return ColumnType::TYPE_FLOAT32_ARRAY;
        default:
            break;
    }
    return ColumnType::TYPE_NULL;
}

int RdUtils::RdDbOpen(const char *dbPath, const char *configStr, uint32_t flags, GRD_DB **db)
{
    if (GRD_KVApiInfo.DBOpenApi == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBOpenApi == nullptr) {
        return E_NOT_SUPPORT;
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBOpenApi(dbPath, configStr, flags, db));
}

int RdUtils::RdDbClose(GRD_DB *db, uint32_t flags)
{
    if (GRD_KVApiInfo.DBCloseApi == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBCloseApi == nullptr) {
        return E_NOT_SUPPORT;
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBCloseApi(db, flags));
}

int RdUtils::RdDbRepair(const char *dbPath, const char *configStr)
{
    if (GRD_KVApiInfo.DBRepairApi == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBRepairApi == nullptr) {
        return E_NOT_SUPPORT;
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBRepairApi(dbPath, configStr));
}

int RdUtils::RdSqlPrepare(GRD_DB *db, const char *str, uint32_t strLen, GRD_SqlStmt **stmt, const char **unusedStr)
{
    if (GRD_KVApiInfo.DBSqlPrepare == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlPrepare == nullptr) {
        return E_NOT_SUPPORT;
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlPrepare(db, str, strLen, stmt, unusedStr));
}

int RdUtils::RdSqlReset(GRD_SqlStmt *stmt)
{
    if (GRD_KVApiInfo.DBSqlReset == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlReset == nullptr) {
        return E_NOT_SUPPORT;
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlReset(stmt));
}

int RdUtils::RdSqlFinalize(GRD_SqlStmt *stmt)
{
    if (GRD_KVApiInfo.DBSqlFinalize == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlFinalize == nullptr) {
        return E_NOT_SUPPORT;
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlFinalize(stmt));
}

void RdSqlFreeBlob(void *blobElementSize)
{
    delete[] ((uint8_t *)blobElementSize);
}

int RdUtils::RdSqlBindBlob(GRD_SqlStmt *stmt, uint32_t idx, const void *val, int32_t len, void (*freeFunc)(void *))
{
    if (GRD_KVApiInfo.DBSqlBindBlob == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlBindBlob == nullptr) {
        return E_NOT_SUPPORT;
    }
    if (len <= 0) {
        LOG_ERROR("Invalid len %{public}d", len);
        return E_INVALID_ARGS;
    }
    uint8_t *tmpVal = new (std::nothrow)uint8_t[len]();
    if (tmpVal == nullptr) {
        return E_ERROR;
    }
    errno_t err = memcpy_s(tmpVal, len * sizeof(uint8_t), val, len * sizeof(uint8_t));
    if (err != EOK) {
        delete[] tmpVal;
        LOG_ERROR("BindBlob failed due to memcpy %{public}d, len is %{public}d", err, len);
        return TransferGrdErrno(GRD_INNER_ERR);
    }
    if (freeFunc == nullptr) {
        freeFunc = RdSqlFreeBlob;
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlBindBlob(stmt, idx, tmpVal, len, freeFunc));
}

void RdSqlFreeCharStr(void *charStr)
{
    delete[] ((char *)charStr);
}

int RdUtils::RdSqlBindText(GRD_SqlStmt *stmt, uint32_t idx, const void *val, int32_t len, void (*freeFunc)(void *))
{
    if (GRD_KVApiInfo.DBSqlBindText == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlBindText == nullptr) {
        return E_NOT_SUPPORT;
    }
    if (len < 0) {
        LOG_ERROR("Invalid len %{public}d", len);
        return E_INVALID_ARGS;
    }
    char *tmpVal = new (std::nothrow)char[len + 1]();
    if (tmpVal == nullptr) {
        return E_ERROR;
    }
    errno_t err = strcpy_s(tmpVal, len + 1, (const char *)val);
    if (err != EOK) {
        LOG_ERROR("BindText failed due to strycpy %{public}d, len is %{public}d", err, len + 1);
        delete[] tmpVal;
        return TransferGrdErrno(GRD_INNER_ERR);
    }
    if (freeFunc == nullptr) {
        freeFunc = RdSqlFreeCharStr;
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlBindText(stmt, idx, tmpVal, len, freeFunc));
}

int RdUtils::RdSqlBindInt(GRD_SqlStmt *stmt, uint32_t idx, int32_t val)
{
    if (GRD_KVApiInfo.DBSqlBindInt == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlBindInt == nullptr) {
        return E_NOT_SUPPORT;
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlBindInt(stmt, idx, val));
}

int RdUtils::RdSqlBindInt64(GRD_SqlStmt *stmt, uint32_t idx, int64_t val)
{
    if (GRD_KVApiInfo.DBSqlBindInt64 == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlBindInt64 == nullptr) {
        return E_NOT_SUPPORT;
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlBindInt64(stmt, idx, val));
}

int RdUtils::RdSqlBindDouble(GRD_SqlStmt *stmt, uint32_t idx, double val)
{
    if (GRD_KVApiInfo.DBSqlBindDouble == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlBindDouble == nullptr) {
        return E_NOT_SUPPORT;
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlBindDouble(stmt, idx, val));
}

int RdUtils::RdSqlBindNull(GRD_SqlStmt *stmt, uint32_t idx)
{
    if (GRD_KVApiInfo.DBSqlBindNull == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlBindNull == nullptr) {
        return E_NOT_SUPPORT;
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlBindNull(stmt, idx));
}

void RdSqlFreeFloatArr(void *floatElement)
{
    delete[] ((float *)floatElement);
}

int RdUtils::RdSqlBindFloatVector(GRD_SqlStmt *stmt, uint32_t idx, float *val, uint32_t dim, void (*freeFunc)(void *))
{
    if (GRD_KVApiInfo.DBSqlBindFloatVector == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlBindFloatVector == nullptr) {
        return E_NOT_SUPPORT;
    }
    if (dim <= 0) {
        LOG_ERROR("Invalid dim %{public}d", dim);
        return E_INVALID_ARGS;
    }
    float *tmpVal = new (std::nothrow)float[dim]();
    if (tmpVal == nullptr) {
        return E_ERROR;
    }
    errno_t err = memcpy_s(tmpVal, dim * sizeof(float), val, dim * sizeof(float));
    if (err != EOK) {
        delete[] tmpVal;
        LOG_ERROR("BindFloat failed due to memcpy %{public}d, dim is %{public}d", err, dim);
        return TransferGrdErrno(GRD_INNER_ERR);
    }
    if (freeFunc == nullptr) {
        freeFunc = RdSqlFreeFloatArr;
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlBindFloatVector(stmt, idx, tmpVal, dim, freeFunc));
}

int RdUtils::RdSqlStep(GRD_SqlStmt *stmt)
{
    if (GRD_KVApiInfo.DBSqlStep == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlStep == nullptr) {
        return E_NOT_SUPPORT;
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlStep(stmt));
}

int RdUtils::RdSqlColCnt(GRD_SqlStmt *stmt)
{
    if (GRD_KVApiInfo.DBSqlColCnt == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlColCnt == nullptr) {
        return E_NOT_SUPPORT;
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlColCnt(stmt));
}

ColumnType RdUtils::RdSqlColType(GRD_SqlStmt *stmt, uint32_t idx)
{
    if (GRD_KVApiInfo.DBSqlColType == nullptr) {
        GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlColType == nullptr) {
        return TransferGrdTypeToColType(0); // for invalid
    }
    return TransferGrdTypeToColType(GRD_KVApiInfo.DBSqlColType(stmt, idx));
}

int RdUtils::RdSqlColBytes(GRD_SqlStmt *stmt, uint32_t idx)
{
    if (GRD_KVApiInfo.DBSqlColBytes == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlColBytes == nullptr) {
        return E_NOT_SUPPORT;
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlColBytes(stmt, idx));
}

char *RdUtils::RdSqlColName(GRD_SqlStmt *stmt, uint32_t idx)
{
    if (GRD_KVApiInfo.DBSqlColName == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlColName == nullptr) {
        return nullptr;
    }
    return GRD_KVApiInfo.DBSqlColName(stmt, idx);
}

GRD_DbValueT RdUtils::RdSqlColValue(GRD_SqlStmt *stmt, uint32_t idx)
{
    if (GRD_KVApiInfo.DBSqlColValue == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlColValue == nullptr) {
        return {};
    }
    return GRD_KVApiInfo.DBSqlColValue(stmt, idx);
}

const void *RdUtils::RdSqlColBlob(GRD_SqlStmt *stmt, uint32_t idx)
{
    if (GRD_KVApiInfo.DBSqlColBlob == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlColBlob == nullptr) {
        return nullptr;
    }
    return GRD_KVApiInfo.DBSqlColBlob(stmt, idx);
}

const char *RdUtils::RdSqlColText(GRD_SqlStmt *stmt, uint32_t idx)
{
    if (GRD_KVApiInfo.DBSqlColText == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlColText == nullptr) {
        return nullptr;
    }
    return GRD_KVApiInfo.DBSqlColText(stmt, idx);
}

int32_t RdUtils::RdSqlColInt(GRD_SqlStmt *stmt, uint32_t idx)
{
    if (GRD_KVApiInfo.DBSqlColInt == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlColInt == nullptr) {
        return 0;
    }
    return GRD_KVApiInfo.DBSqlColInt(stmt, idx);
}

int64_t RdUtils::RdSqlColInt64(GRD_SqlStmt *stmt, uint32_t idx)
{
    if (GRD_KVApiInfo.DBSqlColInt64 == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlColInt64 == nullptr) {
        return 0;
    }
    return GRD_KVApiInfo.DBSqlColInt64(stmt, idx);
}

double RdUtils::RdSqlColDouble(GRD_SqlStmt *stmt, uint32_t idx)
{
    if (GRD_KVApiInfo.DBSqlColDouble == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlColDouble == nullptr) {
        return 0;
    }
    return GRD_KVApiInfo.DBSqlColDouble(stmt, idx);
}

const float *RdUtils::RdSqlColumnFloatVector(GRD_SqlStmt *stmt, uint32_t idx, uint32_t *dim)
{
    if (GRD_KVApiInfo.DBSqlColumnFloatVector == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlColumnFloatVector == nullptr) {
        return nullptr;
    }
    return GRD_KVApiInfo.DBSqlColumnFloatVector(stmt, idx, dim);
}

void RdUtils::ClearAndZeroString(std::string &str)
{
    std::fill(str.begin(), str.end(), char(0));
    str.clear();
}

const char *RdUtils::GetEncryptKey(const std::vector<uint8_t> &encryptedKey, char outBuff[], size_t outBufSize)
{
    char *buffer = nullptr;
    for (size_t i = 0; i < encryptedKey.size(); i++) {
        buffer = (char *)(outBuff + i * 2); // each uint8_t will convert to 2 hex char
        // each uint8_t will convert to 2 hex char
        errno_t err = snprintf_s(buffer, outBufSize - i * 2, outBufSize - i * 2, "%02x", encryptedKey[i]);
        if (err < 0) {
            return nullptr;
        }
    }
    return outBuff;
}

int RdUtils::RdDbBackup(GRD_DB *db, const char *backupDbFile, const std::vector<uint8_t> &encryptedKey)
{
    if (GRD_KVApiInfo.DBBackupApi == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBBackupApi == nullptr) {
        return E_NOT_SUPPORT;
    }
    const size_t keySize = encryptedKey.size() * 2 + 1; // 2 hex number can represent a uint8_t, 1 is for '/0'
    char key[keySize];
    GRD_CipherInfoT info = { 0 };
    info.hexPassword = (encryptedKey.size() > 0) ? GetEncryptKey(encryptedKey, key, keySize) : nullptr;
    int ret = TransferGrdErrno(GRD_KVApiInfo.DBBackupApi(db, backupDbFile, &info));
    errno_t err = memset_s(key, keySize, 0, keySize);
    if (err != E_OK) {
        LOG_ERROR("can not memset 0, size %{public}zu", keySize);
        return E_ERROR;
    }
    return ret;
}

int RdUtils::RdDbRestore(const char *dbFile, const char *backupDbFile, const std::vector<uint8_t> &encryptedKey)
{
    if (GRD_KVApiInfo.DBRestoreApi == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBRestoreApi == nullptr) {
        return E_NOT_SUPPORT;
    }
    const size_t keySize = encryptedKey.size() * 2 + 1; // 2 hex number can represent a uint8_t, 1 is for '/0'
    char key[keySize];
    GRD_CipherInfoT info = { 0 };
    info.hexPassword = (encryptedKey.size() > 0) ? GetEncryptKey(encryptedKey, key, keySize) : nullptr;
    int ret = TransferGrdErrno(GRD_KVApiInfo.DBRestoreApi(dbFile, backupDbFile, &info));
    errno_t err = memset_s(key, keySize, 0, keySize);
    if (err != E_OK) {
        LOG_ERROR("can not memset 0, size %{public}zu", keySize);
        return E_ERROR;
    }
    return ret;
}

int RdUtils::RdDbRekey(const char *dbFile, const char *configStr, const std::vector<uint8_t> &encryptedKey)
{
    if (GRD_KVApiInfo.DBReKeyApi == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBReKeyApi == nullptr) {
        return E_NOT_SUPPORT;
    }
    const size_t keySize = encryptedKey.size() * 2 + 1; // 2 hex number can represent a uint8_t, 1 is for '/0'
    char key[keySize];
    GRD_CipherInfoT info = { 0 };
    info.hexPassword = (encryptedKey.size() > 0) ? GetEncryptKey(encryptedKey, key, keySize) : nullptr;
    int ret = TransferGrdErrno(GRD_KVApiInfo.DBReKeyApi(dbFile, configStr, &info));
    errno_t err = memset_s(key, keySize, 0, keySize);
    if (err != E_OK) {
        LOG_ERROR("can not memset 0, size %{public}zu", keySize);
        return E_ERROR;
    }
    return ret;
}

int RdUtils::RdDbGetVersion(GRD_DB *db, GRD_ConfigTypeE type, int &version)
{
    if (GRD_KVApiInfo.DBGetConfigApi == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBGetConfigApi == nullptr) {
        return E_NOT_SUPPORT;
    }
    GRD_DbValueT value = GRD_KVApiInfo.DBGetConfigApi(db, type);
    version = value.value.longValue;
    return E_OK;
}

int RdUtils::RdDbSetVersion(GRD_DB *db, GRD_ConfigTypeE type, int version)
{
    if (GRD_KVApiInfo.DBSetConfigApi == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSetConfigApi == nullptr) {
        return E_NOT_SUPPORT;
    }
    GRD_DbValueT value;
    value.type = GRD_DB_DATATYPE_INTEGER;
    value.value.longValue = version;
    return TransferGrdErrno(GRD_KVApiInfo.DBSetConfigApi(db, type, value));
}

static void Schedule(void *func, void *param)
{
    auto pool = TaskExecutor::GetInstance().GetExecutor();
    if (pool == nullptr) {
        LOG_ERROR("pool is nullptr");
        return;
    }
    pool->Execute([func, param]() {
        void (*funcPtr)(void *) = reinterpret_cast<void (*)(void *)>(func);
        funcPtr(param);
    });
}

int RdUtils::RdSqlRegistryThreadPool(GRD_DB *db)
{
    if (GRD_KVApiInfo.DBSqlRegistryThreadPool == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlRegistryThreadPool == nullptr) {
        LOG_ERROR("registry threadPool ptr is nullptr");
        return E_NOT_SUPPORT;
    }
    RdUtils::threadPool_.schedule = reinterpret_cast<GRD_ScheduleFunc>(Schedule);
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlRegistryThreadPool(db, &threadPool_));
}

} // namespace NativeRdb
} // namespace OHOS

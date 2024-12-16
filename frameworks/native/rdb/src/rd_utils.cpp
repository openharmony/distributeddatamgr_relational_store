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

#include "grd_error.h"
#include "grd_api_manager.h"
#include "logger.h"
#include "remote_result_set.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

static GRD_APIInfo GRD_KVApiInfo;

struct GrdErrnoPair {
    int32_t grdCode;
    int kvDbCode;
};

const GrdErrnoPair GRD_ERRNO_MAP[] = {
    { GRD_OK, E_OK },
    { GRD_NO_DATA, E_NO_MORE_ROWS },
    { GRD_INNER_ERR, E_ERROR },
    { GRD_DATA_CORRUPTED, E_SQLITE_CORRUPT },
    { GRD_INVALID_FILE_FORMAT, E_SQLITE_CORRUPT },
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
    LOG_DEBUG("[RdUtils::RdDbClose]");
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
    uint8_t *tmpVal = new uint8_t[len]();
    if (tmpVal == nullptr) {
        return E_ERROR;
    }
    errno_t err = memcpy_s(tmpVal, len * sizeof(uint8_t), val, len * sizeof(uint8_t));
    if (err < 0) {
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
    if (len <= 0) {
        LOG_ERROR("Invalid len %{public}d", len);
        return E_INVALID_ARGS;
    }
    char *tmpVal = new char[len + 1]();
    if (tmpVal == nullptr) {
        return E_ERROR;
    }
    errno_t err = strcpy_s(tmpVal, len + 1, (const char *)val);
    if (err < 0) {
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

int RdUtils::RdSqlBindFloatVector(GRD_SqlStmt *stmt, uint32_t idx, float *val,
    uint32_t dim, void (*freeFunc)(void *))
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
    float *tmpVal = new float[dim]();
    if (tmpVal == nullptr) {
        return E_ERROR;
    }
    errno_t err = memcpy_s(tmpVal, dim * sizeof(float), val, dim * sizeof(float));
    if (err < 0) {
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

uint8_t *RdUtils::RdSqlColBlob(GRD_SqlStmt *stmt, uint32_t idx)
{
    if (GRD_KVApiInfo.DBSqlColBlob == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlColBlob == nullptr) {
        return nullptr;
    }
    return GRD_KVApiInfo.DBSqlColBlob(stmt, idx);
}

char *RdUtils::RdSqlColText(GRD_SqlStmt *stmt, uint32_t idx)
{
    if (GRD_KVApiInfo.DBSqlColText == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlColText == nullptr) {
        return nullptr;
    }
    return GRD_KVApiInfo.DBSqlColText(stmt, idx);
}

int RdUtils::RdSqlColInt(GRD_SqlStmt *stmt, uint32_t idx)
{
    if (GRD_KVApiInfo.DBSqlColInt == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlColInt == nullptr) {
        return 0;
    }
    return GRD_KVApiInfo.DBSqlColInt(stmt, idx);
}

uint64_t RdUtils::RdSqlColInt64(GRD_SqlStmt *stmt, uint32_t idx)
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

int RdUtils::RdDbBackup(GRD_DB *db, const char *backupDbFile, uint8_t *encryptedKey, uint32_t encryptedKeyLen)
{
    if (GRD_KVApiInfo.DBBackupApi == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBBackupApi == nullptr) {
        return E_NOT_SUPPORT;
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBBackupApi(db, backupDbFile, encryptedKey, encryptedKeyLen));
}

int RdUtils::RdDbRestore(GRD_DB *db, const char *backupDbFile, uint8_t *encryptedKey, uint32_t encryptedKeyLen)
{
    if (GRD_KVApiInfo.DBRestoreApi == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBRestoreApi == nullptr) {
        return E_NOT_SUPPORT;
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBRestoreApi(db, backupDbFile, encryptedKey, encryptedKeyLen));
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

} // namespace NativeRdb
} // namespace OHOS

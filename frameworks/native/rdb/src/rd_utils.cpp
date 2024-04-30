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

const std::string RdUtils::BEGIN_TRANSACTION_SQL = "begin;";
const std::string RdUtils::COMMIT_TRANSACTION_SQL = "commit;";
const std::string RdUtils::ROLLBACK_TRANSACTION_SQL = "rollback;";

struct GrdErrnoPair {
    int32_t grdCode;
    int kvDbCode;
};

const GrdErrnoPair GRD_ERRNO_MAP[] = {
    { GRD_OK, E_OK },
    { GRD_NO_DATA, E_NO_MORE_ROWS },
    { GRD_INNER_ERR, E_ERROR },
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
        case GRD_SQL_DATATYPE_INTEGER:
            return ColumnType::TYPE_INTEGER;
        case GRD_SQL_DATATYPE_FLOAT:
            return ColumnType::TYPE_FLOAT;
        case GRD_SQL_DATATYPE_TEXT:
            return ColumnType::TYPE_STRING;
        case GRD_SQL_DATATYPE_BLOB:
            return ColumnType::TYPE_BLOB;
        case GRD_SQL_DATATYPE_FLOATVECTOR:
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
        return TransferGrdErrno(GRD_INNER_ERR);
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
        return TransferGrdErrno(GRD_INNER_ERR);
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBCloseApi(db, flags));
}

int RdUtils::RdSqlPrepare(GRD_DB *db, const char *str, uint32_t strLen, GRD_SqlStmt **stmt, const char **unusedStr)
{
    LOG_DEBUG("[RdUtils::RdSqlPrepare]");
    if (GRD_KVApiInfo.DBSqlPrepare == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlPrepare == nullptr) {
        return TransferGrdErrno(GRD_INNER_ERR);
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlPrepare(db, str, strLen, stmt, unusedStr));
}

int RdUtils::RdSqlReset(GRD_SqlStmt *stmt)
{
    LOG_DEBUG("[RdUtils::RdSqlReset]");
    if (GRD_KVApiInfo.DBSqlReset == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlReset == nullptr) {
        return TransferGrdErrno(GRD_INNER_ERR);
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlReset(stmt));
}

int RdUtils::RdSqlFinalize(GRD_SqlStmt *stmt)
{
    LOG_DEBUG("[RdUtils::RdSqlFinalize]");
    if (GRD_KVApiInfo.DBSqlFinalize == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlFinalize == nullptr) {
        return TransferGrdErrno(GRD_INNER_ERR);
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlFinalize(stmt));
}


int RdUtils::RdSqlBindBlob(GRD_SqlStmt *stmt, uint32_t idx, const void *val, int32_t len, void (*freeFunc)(void *))
{
    LOG_DEBUG("[RdUtils::RdSqlBindBlob]");
    if (GRD_KVApiInfo.DBSqlBindBlob == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlBindBlob == nullptr) {
        return TransferGrdErrno(GRD_INNER_ERR);
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlBindBlob(stmt, idx, val, len, freeFunc));
}

void RdSqlFreeCharStr(void *charStr)
{
    delete[] ((char *)charStr);
}

int RdUtils::RdSqlBindText(GRD_SqlStmt *stmt, uint32_t idx, const void *val, int32_t len, void (*freeFunc)(void *))
{
    LOG_DEBUG("[RdUtils::RdSqlBindText]");
    if (GRD_KVApiInfo.DBSqlBindText == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlBindText == nullptr) {
        return TransferGrdErrno(GRD_INNER_ERR);
    }
    char *tmpVal = new char[len + 1]();
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
    LOG_DEBUG("[RdUtils::RdSqlBindInt]");
    if (GRD_KVApiInfo.DBSqlBindInt == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlBindInt == nullptr) {
        return TransferGrdErrno(GRD_INNER_ERR);
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlBindInt(stmt, idx, val));
}

int RdUtils::RdSqlBindInt64(GRD_SqlStmt *stmt, uint32_t idx, int64_t val)
{
    LOG_DEBUG("[RdUtils::RdSqlBindInt64]");
    if (GRD_KVApiInfo.DBSqlBindInt64 == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlBindInt64 == nullptr) {
        return TransferGrdErrno(GRD_INNER_ERR);
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlBindInt64(stmt, idx, val));
}

int RdUtils::RdSqlBindDouble(GRD_SqlStmt *stmt, uint32_t idx, double val)
{
    LOG_DEBUG("[RdUtils::RdSqlBindDouble]");
    if (GRD_KVApiInfo.DBSqlBindDouble == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlBindDouble == nullptr) {
        return TransferGrdErrno(GRD_INNER_ERR);
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlBindDouble(stmt, idx, val));
}

int RdUtils::RdSqlBindNull(GRD_SqlStmt *stmt, uint32_t idx)
{
    LOG_DEBUG("[RdUtils::RdSqlBindNull]");
    if (GRD_KVApiInfo.DBSqlBindNull == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlBindNull == nullptr) {
        return TransferGrdErrno(GRD_INNER_ERR);
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlBindNull(stmt, idx));
}

int RdUtils::RdSqlBindFloatVector(GRD_SqlStmt *stmt, uint32_t idx, float *val,
    uint32_t dim, void (*freeFunc)(void *))
{
    LOG_DEBUG("[RdUtils::RdSqlBindFloatVector]");
    if (GRD_KVApiInfo.DBSqlBindFloatVector == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlBindFloatVector == nullptr) {
        return TransferGrdErrno(GRD_INNER_ERR);
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlBindFloatVector(stmt, idx, val, dim, freeFunc));
}

int RdUtils::RdSqlStep(GRD_SqlStmt *stmt)
{
    LOG_DEBUG("[RdUtils::RdSqlStep]");
    if (GRD_KVApiInfo.DBSqlStep == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlStep == nullptr) {
        return TransferGrdErrno(GRD_INNER_ERR);
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlStep(stmt));
}

int RdUtils::RdSqlColCnt(GRD_SqlStmt *stmt)
{
    LOG_DEBUG("[RdUtils::RdSqlColCnt]");
    if (GRD_KVApiInfo.DBSqlColCnt == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlColCnt == nullptr) {
        return TransferGrdErrno(GRD_INNER_ERR);
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlColCnt(stmt));
}

ColumnType RdUtils::RdSqlColType(GRD_SqlStmt *stmt, uint32_t idx)
{
    LOG_DEBUG("[RdUtils::RdSqlColType]");
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
    LOG_DEBUG("[RdUtils::RdSqlColBytes]");
    if (GRD_KVApiInfo.DBSqlColBytes == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlColBytes == nullptr) {
        return TransferGrdErrno(GRD_INNER_ERR);
    }
    return TransferGrdErrno(GRD_KVApiInfo.DBSqlColBytes(stmt, idx));
}

char *RdUtils::RdSqlColName(GRD_SqlStmt *stmt, uint32_t idx)
{
    LOG_DEBUG("[RdUtils::RdSqlColName]");
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
    LOG_DEBUG("[RdUtils::RdSqlColValue]");
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
    LOG_DEBUG("[RdUtils::RdSqlColBlob]");
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
    LOG_DEBUG("[RdUtils::RdSqlColText]");
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
    LOG_DEBUG("[RdUtils::RdSqlColInt]");
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
    LOG_DEBUG("[RdUtils::RdSqlColInt64]");
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
    LOG_DEBUG("[RdUtils::RdSqlColDouble]");
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
    LOG_DEBUG("[RdUtils::RdSqlColumnFloatVector]");
    if (GRD_KVApiInfo.DBSqlColumnFloatVector == nullptr) {
        GRD_KVApiInfo = GetApiInfoInstance();
    }
    if (GRD_KVApiInfo.DBSqlColumnFloatVector == nullptr) {
        return nullptr;
    }
    return GRD_KVApiInfo.DBSqlColumnFloatVector(stmt, idx, dim);
}

} // namespace NativeRdb
} // namespace OHOS

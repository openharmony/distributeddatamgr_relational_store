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

#ifndef RD_UTILS_H
#define RD_UTILS_H

#include <stdio.h>
#include <string.h>

#include <vector>

#include "grd_type_export.h"
#include "rdb_errno.h"
#include "remote_result_set.h"

namespace OHOS {
namespace NativeRdb {

class RdUtils {
public:
    static int TransferGrdErrno(int err);
    static ColumnType TransferGrdTypeToColType(int grdColType);
    static int RdDbOpen(const char *dbPath, const char *configStr, uint32_t flags, GRD_DB **db);
    static int RdDbRepair(const char *dbPath, const char *configStr);
    static int RdDbClose(GRD_DB *db, uint32_t flags);
    static int RdSqlPrepare(GRD_DB *db, const char *str, uint32_t strLen, GRD_SqlStmt **stmt, const char **unusedStr);
    static int RdSqlReset(GRD_SqlStmt *stmt);
    static int RdSqlFinalize(GRD_SqlStmt *stmt);

    static int RdSqlBindBlob(GRD_SqlStmt *stmt, uint32_t idx, const void *val, int32_t len, void (*freeFunc)(void *));
    /**
    * @brief Binds a text buffer to a parameter in a prepared SQL statement
    *
    * This function binds a text data buffer to a parameter placeholder in a SQL prepared statement.
    * Typically used to replace "?" placeholders in SQL statements with actual values before execution.
    *
    * @param stmt      Pointer to the prepared statement object. Must be properly initialized.
    * @param idx       1-based parameter index (SQL parameter numbering starts at 1).
    * @param val       Pointer to the data buffer to bind. Can be text.
    * @param len       The actual length of the val cannot be greater than the actual length of the val.
    * @param freeFunc  Memory disposal callback
    * @return int      Operation status code:
    *                  - 0: Success
    *                  - Non-zero: Error code (see implementation-specific definitions)
    * @note The prepared statement must be in a state that accepts parameter binding.
    */
    static int RdSqlBindText(GRD_SqlStmt *stmt, uint32_t idx, const void *val, int32_t len, void (*freeFunc)(void *));
    static int RdSqlBindInt(GRD_SqlStmt *stmt, uint32_t idx, int32_t val);
    static int RdSqlBindInt64(GRD_SqlStmt *stmt, uint32_t idx, int64_t val);
    static int RdSqlBindDouble(GRD_SqlStmt *stmt, uint32_t idx, double val);
    static int RdSqlBindNull(GRD_SqlStmt *stmt, uint32_t idx);
    static int RdSqlBindFloatVector(
        GRD_SqlStmt *stmt, uint32_t idx, float *val, uint32_t dim, void (*freeFunc)(void *));

    static int RdSqlStep(GRD_SqlStmt *stmt);
    static int RdSqlColCnt(GRD_SqlStmt *stmt);
    static ColumnType RdSqlColType(GRD_SqlStmt *stmt, uint32_t idx);
    static int RdSqlColBytes(GRD_SqlStmt *stmt, uint32_t idx);
    static char *RdSqlColName(GRD_SqlStmt *stmt, uint32_t idx);
    static GRD_DbValueT RdSqlColValue(GRD_SqlStmt *stmt, uint32_t idx);

    static const void *RdSqlColBlob(GRD_SqlStmt *stmt, uint32_t idx);
    static const char *RdSqlColText(GRD_SqlStmt *stmt, uint32_t idx);
    static int32_t RdSqlColInt(GRD_SqlStmt *stmt, uint32_t idx);
    static int64_t RdSqlColInt64(GRD_SqlStmt *stmt, uint32_t idx);
    static double RdSqlColDouble(GRD_SqlStmt *stmt, uint32_t idx);
    static const float *RdSqlColumnFloatVector(GRD_SqlStmt *stmt, uint32_t idx, uint32_t *dim);

    static void ClearAndZeroString(std::string &str);
    static const char *GetEncryptKey(const std::vector<uint8_t> &encryptedKey, char outBuff[], size_t outBufSize);
    static int RdDbBackup(GRD_DB *db, const char *backupDbFile, const std::vector<uint8_t> &encryptedKey);
    static int RdDbRestore(const char *dbFile, const char *backupDbFile, const std::vector<uint8_t> &encryptedKey);
    static int RdDbRekey(const char *dbFile, const char *configStr, const std::vector<uint8_t> &encryptedKey);

    static int RdDbGetVersion(GRD_DB *db, GRD_ConfigTypeE type, int &version);
    static int RdDbSetVersion(GRD_DB *db, GRD_ConfigTypeE type, int version);

    static int RdSqlRegistryThreadPool(GRD_DB *db);
    static int RdSqlRegistryClusterAlgo(GRD_DB *db, const char *clstAlgoName, GRD_ClusterAlgoFunc func);
private:
    static GRD_ThreadPoolT threadPool_;
};

} // namespace NativeRdb
} // namespace OHOS
#endif // RD_UTILS_H
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

#ifndef OHOS_DISTRIBUTED_DATA_OHOS_DISTRIBUTED_DATA_NATIVE_GDB_GRD_ADAPTER_H
#define OHOS_DISTRIBUTED_DATA_OHOS_DISTRIBUTED_DATA_NATIVE_GDB_GRD_ADAPTER_H

#include <cstdio>
#include <cstring>
#include <map>
#include <vector>

#include "full_result.h"
#include "statement.h"
#include "grd_type_export.h"

namespace OHOS::DistributedDataAip {

class GrdAdapter {
public:
    static int TransErrno(int err);
    static ColumnType TransColType(int grdColType);
    static int Open(const char *dbPath, const char *configStr, uint32_t flags, GRD_DB **db);
    static int Repair(const char *dbPath, const char *configStr);
    static int Close(GRD_DB *db, uint32_t flags);

    /* graph */
    static int32_t Prepare(GRD_DB *db, const char *str, uint32_t strLen, GRD_StmtT **stmt, const char **unusedStr);
    static int32_t Reset(GRD_StmtT *stmt);
    static int32_t Finalize(GRD_StmtT *stmt);

    static int32_t Step(GRD_StmtT *stmt);
    static uint32_t ColumnCount(GRD_StmtT *stmt);
    static GRD_DbDataTypeE ColumnType(GRD_StmtT *stmt, uint32_t idx);
    static uint32_t ColumnBytes(GRD_StmtT *stmt, uint32_t idx);
    static char *ColumnName(GRD_StmtT *stmt, uint32_t idx);
    static GRD_DbValueT ColumnValue(GRD_StmtT *stmt, uint32_t idx);
    static int64_t ColumnInt64(GRD_StmtT *stmt, uint32_t idx);
    static int32_t ColumnInt(GRD_StmtT *stmt, uint32_t idx);
    static double ColumnDouble(GRD_StmtT *stmt, uint32_t idx);
    static const char *ColumnText(GRD_StmtT *stmt, uint32_t idx);

    static int Backup(GRD_DB *db, const char *backupDbFile, const std::vector<uint8_t> &encryptedKey);
    static int Restore(const char *dbFile, const char *backupDbFile, const std::vector<uint8_t> &encryptedKey);
    static int Rekey(const char *dbFile, const char *configStr, const std::vector<uint8_t> &encryptedKey);

private:
    static std::map<int32_t, int32_t> GRD_ERRNO_MAP;
};

} // namespace OHOS::DistributedDataAip
#endif
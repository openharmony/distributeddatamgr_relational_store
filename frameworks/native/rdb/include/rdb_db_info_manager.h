/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef RDB_DB_INFO_MANAGER_H
#define RDB_DB_INFO_MANAGER_H

#include <string>

#include "rdb_db_info_record.h"

namespace OHOS {
namespace NativeRdb {

/*
 * Provides collection utilities for per-database diagnostic records.
 * Persistence (formerly "<dbPath>.rdbdfx.json") has been migrated to the
 * unified "{auditDir}/{el}{dbName}audit.json" written by RdbAuditLoggerManager;
 * this class now only exposes best-effort collectors used by AuditLogger.
 *
 * All collection failures are best-effort: empty/partial fields are returned,
 * never throwing and never blocking the caller's open/delete/restore/backup.
 */
class RdbDbInfoManager {
public:
    static RdbDbInfoManager &GetInstance();

    // Build the last-successful-open record (audit.json block 1). Caller
    // serializes and hands it to RdbAuditLoggerManager for persistence.
    LastOpenDbInfo BuildLastOpen(const std::string &dbPath, bool created);

    // Utilities used by AuditLogger / RdbAuditLoggerManager.
    DbFileInfo CollectDbFileInfo(const std::string &dbPath);
    CallerInfo CollectCaller();

private:
    RdbDbInfoManager() = default;
    RdbDbInfoManager(const RdbDbInfoManager &) = delete;
    RdbDbInfoManager &operator=(const RdbDbInfoManager &) = delete;

    FileInfo BuildFileInfo(const std::string &path);
    BinlogInfo CollectBinlog(const std::string &dbPath);
    KeyInfo CollectKey(const std::string &dbPath);
};
} // namespace NativeRdb
} // namespace OHOS
#endif // RDB_DB_INFO_MANAGER_H

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

#ifndef RDB_DB_LOGGER_MANAGER_H
#define RDB_DB_LOGGER_MANAGER_H

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>

#include "rdb_db_info_record.h"

namespace OHOS {
namespace NativeRdb {

// Singleton owning the audit.json persistence for the four overwrite blocks:
// lastOpen / firstLoss / dbDelete / inodeChange. This object operates ONLY on
// audit.json (and its per-db lock file); events.log is handled by the separate
// RdbAuditLoggerManager. Both share the same audit root directory, which the
// RdbAuditLogger façade probes once and passes in via Init (per confirmed design).
//
// Per-database file naming (derived from dbPath):
//   audit json:  {auditDir}/{el}{dbName}_audit.json
//   audit lock:  {auditDir}/{el}{dbName}_audit.lock   (fresh fd per write)
//
// Writes are best-effort and asynchronous (TaskExecutor), never blocking the DB
// caller.
class RdbDbLoggerManager {
public:
    static RdbDbLoggerManager &GetInstance();
    ~RdbDbLoggerManager();
    RdbDbLoggerManager(const RdbDbLoggerManager &) = delete;
    RdbDbLoggerManager &operator=(const RdbDbLoggerManager &) = delete;

    // Receive the probed audit root directory from the façade. Idempotent.
    void Init(const std::string &auditDir, bool auditEnabled);

    bool IsInitialized() const { return initialized_; }

    // audit.json block 1 + 4: last successful open + inode change diff.
    void RecordOpenAsync(const std::string &dbPath, const LastOpenDbInfo &lastOpen);

    // audit.json block 2: first loss point / badfd (overwrite).
    void WriteFirstLossAsync(const std::string &dbPath, const FirstLossInfo &firstLoss);

    // audit.json block 3: delete metadata (file info, inode) (overwrite).
    void WriteDeleteAsync(const std::string &dbPath, const DeleteInfo &del);

private:
    RdbDbLoggerManager();

    void DoRecordOpen(const std::string &dbPath, const LastOpenDbInfo &lastOpen);
    void DoWriteFirstLoss(const std::string &dbPath, const FirstLossInfo &firstLoss);
    void DoWriteDelete(const std::string &dbPath, const DeleteInfo &del);

    // read-mutate-write audit.json under a per-db fresh-fd flock.
    void WithAuditRecord(const std::string &dbPath, const std::function<void(RdbDbInfoRecord &)> &mutator);

    std::string BuildAuditPath(const std::string &dbPath, const std::string &suffix) const;

    std::string auditDir_;
    bool initialized_ = false;
    mutable std::mutex mutex_;

    friend class RdbAuditE2ETest;
};

} // namespace NativeRdb
} // namespace OHOS

#endif // RDB_DB_LOGGER_MANAGER_H

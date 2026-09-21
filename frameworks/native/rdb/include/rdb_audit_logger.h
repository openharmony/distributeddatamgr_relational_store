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

#ifndef RDB_AUDIT_LOGGER_H
#define RDB_AUDIT_LOGGER_H

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

#include "rdb_audit_event.h"

namespace OHOS {
namespace NativeRdb {

class RdbStoreConfig;

// Per-store audit façade. Owned by RdbStoreImpl (or created transiently by
// RdbHelper / SqliteConnection / SqliteStatement per the confirmed design).
// All persistence is delegated to the RdbAuditLoggerManager singleton (the
// Manager's logic is only reachable through this façade). Audit is opt-in: a
// store must call RdbStoreConfig::SetAuditEnabled(true) before opening.
//
// Writes are best-effort and asynchronous: they never block the caller's
// database operations.
class RdbAuditLogger {
public:
    RdbAuditLogger() = default;
    ~RdbAuditLogger() = default;
    RdbAuditLogger(const RdbAuditLogger &) = delete;
    RdbAuditLogger &operator=(const RdbAuditLogger &) = delete;

    // Event recording interfaces (one per AuditEvt). Each lazily ensures the
    // shared audit directory + singleton managers are initialized (idempotent);
    // external callers gate on RdbStoreConfig::IsAuditEnabled before calling.
    void OnOpenOk(const std::string &dbPath, const RdbStoreConfig &config, bool created);
    void OnOpenFail(const std::string &dbPath, int rc, int osErrno);
    void OnIoError(const std::string &op, const std::string &file, int rc, int osErrno);

    // SQL audit. Caller passes the actual affected row count.
    // DELETE/DROP/TRUNCATE are always logged (no throttle).
    // INSERT/UPDATE are logged when rows > 0, with 60s per-(op,tbl) accumulation:
    // rows are accumulated within the window and flushed as a single record
    // when the next event arrives after the window expires.
    void OnSqlAudit(const std::string &dbPath, const std::string &op, const std::string &tbl, int64_t rows);

    void OnIntegrity(
        const std::string &dbPath, IntegrityTrigger trigger, IntegrityMode mode, int result, const std::string &err);

    // DB deletion audit. op = "delete_store" (business) or "vfs_xdelete" (VFS layer).
    void OnDbDelete(const std::string &dbPath, const std::string &op);

private:
    // Accumulate rows within a 60s window for INSERT/UPDATE.
    bool AccumulateOrFlush(const std::string &eventKey, int64_t rows, int64_t &flushRows);

    bool IsActive() const { return enabled_; }

    // Build jsonl lines for events.log.
    std::string BuildOpenOkJson(const std::string &dbPath);
    std::string BuildOpenFailJson(const std::string &dbPath, int rc, int osErrno);
    std::string BuildIoErrJson(const std::string &op, const std::string &file, int rc, int osErrno);
    std::string BuildSqlAuditJson(
        const std::string &dbPath, const std::string &op, const std::string &tbl, int64_t rows);
    std::string BuildIntegrityJson(
        const std::string &dbPath, IntegrityTrigger trigger, IntegrityMode mode, int result, const std::string &err);
    std::string BuildDbDeleteJson(const std::string &dbPath, const std::string &op);

    static const char *TriggerToStr(IntegrityTrigger trigger);
    static const char *ModeToStr(IntegrityMode mode);

    // Lazily probe the shared audit root and initialize both singleton
    // managers (idempotent: skips if already initialized). Sets enabled_ to
    // whether the audit directory is available.
    void EnsureInit(const std::string &dbPath);

    std::string dbPath_;
    bool enabled_ = false;
    bool enableSqlAudit_ = true;
    struct ThrottleEntry {
        int64_t timestamp = 0;
        int64_t accumulatedRows = 0;
    };
    std::unordered_map<std::string, ThrottleEntry> throttleMap_;
    std::mutex mutex_;

    friend class RdbAuditE2ETest;
};

} // namespace NativeRdb
} // namespace OHOS

#endif // RDB_AUDIT_LOGGER_H

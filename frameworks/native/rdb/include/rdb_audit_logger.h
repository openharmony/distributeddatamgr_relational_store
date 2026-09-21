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
#include <sys/stat.h>
#include <unordered_map>

#include "rdb_audit_event.h"

namespace OHOS {
namespace NativeRdb {

// Directory mode for audit subdirectories: owner+group rw, others no access.
constexpr mode_t AUDIT_DIR_MODE = 0660;

// Singleton audit logger that persists events to local audit files and
// reports fault events via HiSysEvent. All write failures are best-effort:
// they never block the caller's database operations.
//
// Audit is opt-in: a store must call RdbStoreConfig::SetAuditEnabled(true)
// before opening. Init() probes the audit directory at runtime:
//   1. /data/log/hiaudit/rdb exists -> SA scenario, per-uid sub-directory
//   2. /data/storage/el2/log exists -> app scenario, rdb sub-directory
// If neither directory exists, audit is silently disabled.
//
// Directory layout:
//   SA:  /data/log/hiaudit/rdb/{uid}/
//   App: /data/storage/el2/log/rdb/
// Files: events.log, events.1.log, last_open.bin, last_integrity.bin
class RdbAuditLogger {
public:
    static RdbAuditLogger &GetInstance();

    // Initialize the audit logger for the given store config. When the config
    // has audit enabled (IsAuditEnabled), probes the audit directory and opens
    // the persistent events.log fd + inter-process lock file. Idempotent:
    // subsequent calls after a successful init are no-ops.
    void Init();

    // Event recording interfaces (one per AuditEvt).
    void OnOpenOk(const std::string &dbPath);
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
    // Always logged (no throttle) when audit is initialized.
    void OnDbDelete(const std::string &dbPath, const std::string &op);

private:
    RdbAuditLogger() = default;
    ~RdbAuditLogger();
    RdbAuditLogger(const RdbAuditLogger &) = delete;
    RdbAuditLogger &operator=(const RdbAuditLogger &) = delete;

    // Accumulate rows within a 60s window for INSERT/UPDATE.
    // Returns true if rows were accumulated (caller should not write).
    // Returns false if the window expired; flushRows is set to the previous
    // window's accumulated total (0 if first event). Caller should write flushRows
    // and start a new window.
    bool AccumulateOrFlush(const std::string &eventKey, int64_t rows, int64_t &flushRows);

    // Append a jsonl line to events.log via persistent fd (O_APPEND).
    void AppendEvent(const std::string &jsonLine);

    // Atomic overwrite of last_open.bin (tmpfile -> rename).
    void WriteLastOpen(const std::string &snapshot);

    // Write to last_integrity.bin (tmpfile -> rename).
    void WriteLastIntegrity(const std::string &snapshot);

    // Atomic file write: tmpfile -> write -> fsync -> rename, protected by flock.
    // Used by WriteLastOpen / WriteLastIntegrity to avoid duplicated logic.
    void WriteAtomicFile(const std::string &path, const std::string &content);

    // Check writeLogSize_ and rotate events.log -> events.1.log if >= 256KB.
    void MaybeRotateLog();

    // Extract db name from path or config name (strip directory and .db suffix).
    std::string ExtractDbName(const std::string &dbPath) const;

    // Build jsonl lines for each event type.
    std::string BuildOpenOkJson(const std::string &dbPath);
    std::string BuildOpenFailJson(const std::string &dbPath, int rc, int osErrno);
    std::string BuildIoErrJson(const std::string &op, const std::string &file, int rc, int osErrno);
    std::string BuildSqlAuditJson(
        const std::string &dbPath, const std::string &op, const std::string &tbl, int64_t rows);
    std::string BuildIntegrityJson(
        const std::string &dbPath, IntegrityTrigger trigger, IntegrityMode mode, int result, const std::string &err);
    std::string BuildDbDeleteJson(const std::string &dbPath, const std::string &op);

    // Helper: IntegrityTrigger / IntegrityMode to string.
    static const char *TriggerToStr(IntegrityTrigger trigger);
    static const char *ModeToStr(IntegrityMode mode);

    std::string auditDir_;                                 // resolved audit directory
    int writeFd_ = -1;                                     // persistent fd for events.log
    int lockFd_ = -1;                                      // persistent fd for events.lock (inter-process lock)
    size_t writeLogSize_ = 0;                              // current events.log size in bytes
    bool initialized_ = false;                             // dir/fd ready
    bool enableSqlAudit_ = true;                           // SQL audit enabled flag
    // Throttle entry for accumulation mode: tracks window start time and
    // accumulated rows within the window.
    struct ThrottleEntry {
        int64_t timestamp = 0;
        int64_t accumulatedRows = 0;
    };
    std::unordered_map<std::string, ThrottleEntry> throttleMap_; // per-key throttle state
    std::mutex mutex_;               // protects all members
};

} // namespace NativeRdb
} // namespace OHOS

#endif // RDB_AUDIT_LOGGER_H

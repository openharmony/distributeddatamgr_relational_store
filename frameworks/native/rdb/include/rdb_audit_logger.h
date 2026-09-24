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
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace OHOS {
namespace NativeRdb {

// Audit logger interface. The base class is a no-op implementation: every On*
// method is an empty inline body, so callers that hold a base instance pay no
// I/O cost. RdbAuditLoggerImpl (below) overrides the methods to actually
// collect context and persist to events.log / audit.json via the singleton
// managers. RdbStoreImpl holds a pointer obtained from
// RdbAuditLogger::Create(config) and invokes On* directly — no
// IsAuditEnabled gating at the call site. When audit is disabled Create
// returns a base instance (all calls are no-ops); when enabled it returns an
// Impl instance whose constructor has already probed the audit root and
// initialized the singleton managers.
//
// Writes are best-effort and asynchronous: they never block the caller's
// database operations.
class RdbAuditLogger {
public:
    RdbAuditLogger() = default;
    virtual ~RdbAuditLogger() = default;
    RdbAuditLogger(const RdbAuditLogger &) = delete;
    RdbAuditLogger &operator=(const RdbAuditLogger &) = delete;

    // Factory: returns an RdbAuditLoggerImpl when auditEnabled is true,
    // otherwise a no-op base instance.
    static std::unique_ptr<RdbAuditLogger> Create(bool auditEnabled);

    virtual void OnOpenOk(const std::string &dbPath, bool created) {}
    virtual void OnOpenFail(const std::string &dbPath, int rc, int osErrno) {}
    virtual void OnIoError(const std::string &op, const std::string &file, int rc, int osErrno) {}
    virtual void OnSqlAudit(const std::string &dbPath, const std::string &op, const std::string &sql, int64_t rows) {}
    virtual void OnPragma(const std::string &dbPath, const std::string &sql, int rc, const std::string &result) {}
    virtual void OnCorrupt(const std::string &dbPath, int rc, int osErrno, const std::string &detail) {}
    virtual void OnDbDelete(const std::string &dbPath, const std::string &op) {}
};

// Real audit implementation. The constructor probes the shared audit root
// and initializes the singleton managers (so On* needs no lazy init).
// Delegates all persistence to the RdbAuditLoggerManager / RdbDbLoggerManager
// singletons. Created only when config.IsAuditEnabled() is true (via
// RdbAuditLogger::Create).
class RdbAuditLoggerImpl : public RdbAuditLogger {
public:
    RdbAuditLoggerImpl();
    ~RdbAuditLoggerImpl() override = default;
    RdbAuditLoggerImpl(const RdbAuditLoggerImpl &) = delete;
    RdbAuditLoggerImpl &operator=(const RdbAuditLoggerImpl &) = delete;

    void OnOpenOk(const std::string &dbPath, bool created) override;
    void OnOpenFail(const std::string &dbPath, int rc, int osErrno) override;
    void OnIoError(const std::string &op, const std::string &file, int rc, int osErrno) override;
    void OnSqlAudit(const std::string &dbPath, const std::string &op, const std::string &sql, int64_t rows) override;
    void OnPragma(const std::string &dbPath, const std::string &sql, int rc, const std::string &result) override;
    void OnCorrupt(const std::string &dbPath, int rc, int osErrno, const std::string &detail) override;
    void OnDbDelete(const std::string &dbPath, const std::string &op) override;

private:
    // Accumulate rows within a 60s window for INSERT/UPDATE.
    bool AccumulateOrFlush(const std::string &eventKey, int64_t rows, int64_t &flushRows);
    bool IsActive() const { return enabled_; }

    static std::string BuildOpenOkLine(const std::string &dbPath);
    static std::string BuildOpenFailLine(const std::string &dbPath, int rc, int osErrno);
    static std::string BuildSqlAuditLine(
        const std::string &dbPath, const std::string &op, const std::string &tbl, int64_t rows);

    bool enabled_ = false;
    struct ThrottleEntry {
        int64_t timestamp = 0;
        int64_t accumulatedRows = 0;
    };
    std::unordered_map<std::string, ThrottleEntry> throttleMap_;
    std::mutex mutex_;
};

} // namespace NativeRdb
} // namespace OHOS

#endif // RDB_AUDIT_LOGGER_H

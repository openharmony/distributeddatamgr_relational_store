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

#ifndef RDB_AUDIT_LOGGER_MANAGER_H
#define RDB_AUDIT_LOGGER_MANAGER_H

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <sys/stat.h>

namespace OHOS {
namespace NativeRdb {

// Directory mode for audit subdirectories: owner+group rwx, others no access.
// Directories require execute (x) permission to be traversable and to allow
// file creation inside; 0660 (rw-rw----) lacks x and would block file creation.
constexpr mode_t AUDIT_DIR_MODE = 0770;

// Singleton owning the events.log persistence (the append-only jsonl audit
// trail). This object operates ONLY on events.log (+ events.lock); the four
// overwrite blocks of audit.json are handled by the separate RdbDbLoggerManager.
// Both share the same audit root directory, which the RdbAuditLogger façade
// probes once and passes in via Init (per confirmed design).
//
// Writes are best-effort and asynchronous (TaskExecutor), never blocking the DB
// caller. Callers should use ExecuteAsync to dispatch the entire pipeline
// (data collection + JSON building + file write) onto the executor thread;
// AppendEventSync is the synchronous write used inside that pipeline.
//
// Directory layout (probed by the façade):
//   SA:  /data/log/hiaudit/rdb/{uid}/
//   App: /data/storage/el2/log/rdb/
// Files: events.log, events.1.log, events.lock
class RdbAuditLoggerManager {
public:
    using Task = std::function<void()>;

    static RdbAuditLoggerManager &GetInstance();
    ~RdbAuditLoggerManager();
    RdbAuditLoggerManager(const RdbAuditLoggerManager &) = delete;
    RdbAuditLoggerManager &operator=(const RdbAuditLoggerManager &) = delete;

    // Receive the probed audit root directory from the façade. Idempotent.
    void Init(const std::string &auditDir, bool auditEnabled);

    bool IsInitialized() const { return initialized_; }
    std::string GetAuditDir() const { return auditDir_; }

    // Dispatch a task (collection + JSON + write) to the executor thread.
    void ExecuteAsync(Task task);

    // Synchronous append of a jsonl line to events.log. Called from inside
    // an ExecuteAsync task — not intended for direct caller use.
    void AppendEventSync(const std::string &jsonLine);

private:
    RdbAuditLoggerManager();

    void MaybeRotateLog();

    std::string auditDir_;
    int writeFd_ = -1;  // persistent fd for events.log
    int lockFd_ = -1;  // persistent fd for events.lock (cross-process)
    bool initialized_ = false;
    mutable std::mutex mutex_;

    friend class RdbAuditE2ETest;
};

} // namespace NativeRdb
} // namespace OHOS

#endif // RDB_AUDIT_LOGGER_MANAGER_H

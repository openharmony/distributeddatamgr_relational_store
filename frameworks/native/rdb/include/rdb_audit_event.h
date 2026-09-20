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

#ifndef RDB_AUDIT_EVENT_H
#define RDB_AUDIT_EVENT_H

namespace OHOS {
namespace NativeRdb {

// Audit event types. Each maps to a specific jsonl event in events.log.
// FILE_CHANGE / CORRUPT / CHKPT are reserved for future PRs; not emitted yet.
enum class AuditEvt {
    OPEN_OK,   // Successful database open — baseline snapshot
    OPEN_FAIL, // Failed database open — error context
    IO_ERR,    // I/O error from VFS layer (EBADF / ENOSPC / EIO)
    SQL_AUDIT, // Data-change SQL: DELETE/DROP/TRUNCATE always; INSERT/UPDATE when rows >= threshold
    INTEGRITY, // Integrity check executed (auto on open or active by caller)
    DB_DELETE, // Database file deletion — delete_store (business) or vfs_xdelete (VFS layer)
};

// Who triggered the integrity check.
enum class IntegrityTrigger {
    AUTO,   // Automatically during SqliteConnection::InnerOpen()
    ACTIVE, // Business caller executed PRAGMA integrity_check / quick_check
};

// Integrity check mode.
enum class IntegrityMode {
    QUICK, // PRAGMA quick_check
    FULL,  // PRAGMA integrity_check
};

} // namespace NativeRdb
} // namespace OHOS

#endif // RDB_AUDIT_EVENT_H

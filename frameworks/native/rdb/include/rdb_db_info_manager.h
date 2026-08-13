/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <functional>
#include <string>

#include "rdb_db_info_record.h"

namespace OHOS {
namespace NativeRdb {
class RdbStoreConfig;

/*
 * Manages per-database diagnostic records persisted to "<dbPath>.rdbdfx.json"
 * (db-adjacent). Single-layer flock on "<dbPath>.rdbdfx.lock" serializes both
 * same-process threads and cross-process (fork) access; no in-process mutex is
 * needed because each lock attempt opens its own fd (distinct open file
 * descriptions) - see SecurityManager::KeyFiles for the proven pattern.
 *
 * Two hard invariants (violating either breaks mutual exclusion):
 *  1. Use BSD flock(), never fcntl(F_SETLK) POSIX record locks (per-process,
 *     do NOT exclude same-process threads).
 *  2. Always open() a fresh fd per lock attempt; never cache a long-lived fd
 *     across calls/threads (same OFD => second flock is a no-op, no blocking).
 *
 * All collection / write failures are best-effort: empty/partial fields are
 * recorded, never throwing and never blocking the caller's open/delete/restore/
 * backup/rebuild (JSON_NOEXCEPTION keeps nlohmann from throwing).
 */
class RdbDbInfoManager {
public:
    static RdbDbInfoManager &GetInstance();

    // One-shot on successful open: collects lastOpenDbInfo and, if the main
    // file changed since the prior record, writes dbInfoChange.
    void RecordOpen(const RdbStoreConfig &config, bool created);

    // RAII trace destructor commits via these:
    void CommitDelete(const std::string &dbPath, const DeleteRecord &rec);
    void CommitRestore(const std::string &dbPath, const BackupRecord &rec);
    void CommitBackup(const std::string &dbPath, const BackupRecord &rec);
    void CommitRebuild(const std::string &dbPath, const RebuildRecord &rec);

    // Utilities used by RdbDfxTrace.
    DbFileInfo CollectDbFileInfo(const std::string &dbPath);
    CallerInfo CollectCaller();

private:
    RdbDbInfoManager() = default;
    RdbDbInfoManager(const RdbDbInfoManager &) = delete;
    RdbDbInfoManager &operator=(const RdbDbInfoManager &) = delete;

    // flock(LOCK_EX) on the sidecar lock; read dfx json -> mutate -> tmp+rename.
    void WithRecord(const std::string &dbPath, const std::function<void(RdbDbInfoRecord &)> &mutator);

    FileInfo BuildFileInfo(const std::string &path);
    BinlogInfo CollectBinlog(const std::string &dbPath);
    KeyInfo CollectKey(const std::string &dbPath);
    ConfigInfo BuildConfigInfo(const RdbStoreConfig &config);
};
} // namespace NativeRdb
} // namespace OHOS
#endif // RDB_DB_INFO_MANAGER_H

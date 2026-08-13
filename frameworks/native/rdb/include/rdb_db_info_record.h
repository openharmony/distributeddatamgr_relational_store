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

#ifndef RDB_DB_INFO_RECORD_H
#define RDB_DB_INFO_RECORD_H

#include <cstdint>
#include <string>
#include <vector>

#include "serializable.h"

namespace OHOS {
namespace NativeRdb {
/*
 * Diagnostic record types for RDB open/delete/restore/backup/rebuild.
 * Each struct subclasses OHOS::Serializable and serializes to the db-adjacent
 * "<dbPath>.rdbdfx.json" file (see RdbDbInfoManager). JSON_NOEXCEPTION is
 * already defined by serializable.h, so json operations never throw.
 *
 * Declarations only here; Marshal/Unmarshal/IsEmpty/NowMs are defined in
 * rdb_db_info_record.cpp.
 */

struct PermissionInfo : public Serializable {
    uint32_t mode = 0;       // st_mode
    std::string acl;         // getfacl-style text from Acl::Dump(), "" if none
    bool Marshal(json &obj) const override;
    bool Unmarshal(const json &obj) override;
};

struct TimeInfo : public Serializable {
    int64_t ctime = 0;       // seconds
    int64_t atime = 0;
    int64_t mtime = 0;
    bool Marshal(json &obj) const override;
    bool Unmarshal(const json &obj) override;
};

struct FileInfo : public Serializable {
    int64_t node = 0;        // inode
    int64_t size = 0;        // bytes
    PermissionInfo permission;
    TimeInfo time;
    bool Marshal(json &obj) const override;
    bool Unmarshal(const json &obj) override;
};

// Group of file info for db / wal / shm. (Renamed from MainGroup.)
struct DbFileInfo : public Serializable {
    FileInfo db;
    FileInfo wal;
    FileInfo shm;
    bool Marshal(json &obj) const override;
    bool Unmarshal(const json &obj) override;
    bool IsEmpty() const;
};

struct CallerInfo : public Serializable {
    int32_t pid = 0;
    int32_t tid = 0;
    uint32_t uid = 0;
    uint32_t gid = 0;
    bool Marshal(json &obj) const override;
    bool Unmarshal(const json &obj) override;
};

struct BinlogInfo : public Serializable {
    bool exist = false;
    uint32_t fileCount = 0;
    int64_t totalSize = 0;
    bool Marshal(json &obj) const override;
    bool Unmarshal(const json &obj) override;
};

struct KeyInfo : public Serializable {
    FileInfo pubKey;
    FileInfo pubKeyNew;
    bool Marshal(json &obj) const override;
    bool Unmarshal(const json &obj) override;
};

struct ConfigInfo : public Serializable {
    std::string name;
    std::string path;
    bool isEncrypted = false;
    int32_t securityLevel = 0;
    std::string journalMode;
    std::string sync;
    int32_t walAutoCheckpoint = 0;
    bool Marshal(json &obj) const override;
    bool Unmarshal(const json &obj) override;
};

// Written only on successful open (no errCode field).
struct LastOpenDbInfo : public Serializable {
    DbFileInfo main;
    DbFileInfo replica;
    BinlogInfo binlog;
    ConfigInfo config;
    KeyInfo key;
    std::string time;        // human-readable "YYYY-MM-DD HH:MM:SS.mmm"
    CallerInfo callerInfo;
    int32_t integrityResult = 0;
    bool created = false;
    bool keyPresent = false;
    bool Marshal(json &obj) const override;
    bool Unmarshal(const json &obj) override;
};

struct DbInfoChange : public Serializable {
    DbFileInfo before;
    DbFileInfo after;
    std::vector<std::string> changedFields;
    std::string time;
    CallerInfo callerInfo;
    bool Marshal(json &obj) const override;
    bool Unmarshal(const json &obj) override;
};

struct DeleteRecord : public Serializable {
    int64_t startTime = 0;
    int64_t endTime = 0;
    DbFileInfo dbInfo;
    CallerInfo callerInfo;
    bool Marshal(json &obj) const override;
    bool Unmarshal(const json &obj) override;
};

// Used by both restore and backup records.
struct DbInfoPair : public Serializable {
    DbFileInfo backupDbInfo;
    DbFileInfo mainDbInfo;
    bool Marshal(json &obj) const override;
    bool Unmarshal(const json &obj) override;
};

struct BackupRecord : public Serializable {
    int64_t startTime = 0;
    int64_t endTime = 0;
    DbInfoPair beforeDbInfo;
    DbInfoPair afterDbInfo;
    int32_t result = 0;
    CallerInfo callerInfo;
    bool Marshal(json &obj) const override;
    bool Unmarshal(const json &obj) override;
};

struct RebuildRecord : public Serializable {
    int64_t startTime = 0;
    int64_t endTime = 0;
    DbFileInfo oldDbInfo;
    DbFileInfo newDbInfo;
    int32_t result = 0;
    CallerInfo callerInfo;
    bool Marshal(json &obj) const override;
    bool Unmarshal(const json &obj) override;
};

// Top-level record persisted to "<dbPath>.rdbdfx.json".
// lastOpenDbInfo / dbInfoChange keep only the latest one entry.
struct RdbDbInfoRecord : public Serializable {
    LastOpenDbInfo lastOpenDbInfo;
    DbInfoChange dbInfoChange;
    DeleteRecord deleteStore;
    BackupRecord restore;
    BackupRecord backup;
    RebuildRecord rebuild;
    bool Marshal(json &obj) const override;
    bool Unmarshal(const json &obj) override;
};

// Compute changed-field name list ("main.db.node", "main.wal.size", ...) between
// two DbFileInfo snapshots. Empty if identical.
std::vector<std::string> DiffDbFileInfo(const std::string &prefix, const DbFileInfo &before,
    const DbFileInfo &after);

// Epoch milliseconds (int64). RdbTimeUtils only returns human-readable strings,
// so start/end timing is computed here.
int64_t NowMs();

enum class DfxOp { DELETE, RESTORE, BACKUP, REBUILD };

/*
 * RAII guard for delete/restore/backup/rebuild start/end timing.
 * Constructor captures startTime + caller + before(main, and backup if given).
 * Destructor captures endTime + after and commits via RdbDbInfoManager.
 * resultRef points at the caller's errCode local so early returns are captured.
 * noexcept-friendly: only return-code-based APIs; never throws (JSON_NOEXCEPTION).
 */
class RdbDfxTrace {
public:
    RdbDfxTrace(DfxOp op, std::string dbPath, std::string backupPath = "", const int *resultRef = nullptr);
    ~RdbDfxTrace();
    // Set the backup/dest path once known and collect its before state.
    void SetBackupPath(const std::string &backupPath);
    RdbDfxTrace(const RdbDfxTrace &) = delete;
    RdbDfxTrace &operator=(const RdbDfxTrace &) = delete;

private:
    DfxOp op_;
    std::string dbPath_;
    std::string backupPath_;
    int64_t startTime_ = 0;
    CallerInfo caller_;
    DbFileInfo beforeMain_;
    DbFileInfo beforeBackup_;
    const int *resultRef_ = nullptr;
};
} // namespace NativeRdb
} // namespace OHOS
#endif // RDB_DB_INFO_RECORD_H

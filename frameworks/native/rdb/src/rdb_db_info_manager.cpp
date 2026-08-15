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

#define LOG_TAG "RdbDbInfoManager"
#include "rdb_db_info_manager.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>

#include "acl.h"
#include "rdb_errno.h"
#include "rdb_platform.h"
#include "rdb_security_manager.h"
#include "rdb_store_config.h"
#include "rdb_time_utils.h"
#include "sqlite_global_config.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using OHOS::DATABASE_UTILS::Acl;

namespace {
constexpr const char *DFX_SUFFIX = ".rdbdfx.json";
constexpr const char *LOCK_SUFFIX = ".rdbdfx.lock";

/*
 * RAII single-layer flock. Mirrors SecurityManager::KeyFilesAutoLock
 * (security_manager.cpp:405-413): each lock attempt opens its own fd, so the
 * open file descriptions are distinct and flock conflicts across same-process
 * threads too (no in-process mutex is needed). The fd is never cached across
 * calls - its lifetime is this critical section.
 */
class DfxFileLock {
public:
    explicit DfxFileLock(const std::string &lockPath)
    {
        fd_ = open(lockPath.c_str(), O_RDONLY | O_CREAT, S_IRUSR | S_IWUSR);
        if (fd_ < 0) {
            return;
        }
        int rc = -1;
        do {
            rc = flock(fd_, LOCK_EX);
        } while (rc < 0 && errno == EINTR);
        if (rc < 0) {
            close(fd_);
            fd_ = -1;
        }
    }
    ~DfxFileLock()
    {
        if (fd_ >= 0) {
            int rc = -1;
            do {
                rc = flock(fd_, LOCK_UN);
            } while (rc < 0 && errno == EINTR);
            close(fd_);
            fd_ = -1;
        }
    }
    bool IsLocked() const
    {
        return fd_ >= 0;
    }
    DfxFileLock(const DfxFileLock &) = delete;
    DfxFileLock &operator=(const DfxFileLock &) = delete;

private:
    int fd_ = -1;
};

// Best-effort whole-file read. Returns false on open/read failure.
bool ReadAll(const std::string &path, std::string &out)
{
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs.is_open()) {
        return false;
    }
    std::streamsize size = ifs.tellg();
    if (size < 0) {
        return false;
    }
    ifs.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    if (size > 0 && !ifs.read(&out[0], size)) {
        return false;
    }
    return true;
}

// Direct truncating write inside the flock critical section. Matches the
// SecurityManager::SaveBufferToFile convention (no tmp+rename): flock already
// serializes concurrent access, and the data is best-effort diagnostic, so a
// crash mid-write at worst loses the current update (recovered on the next open
// - JSON_NOEXCEPTION makes Unmarshall on partial json return false gracefully).
bool WriteAll(const std::string &path, const std::string &content)
{
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) {
        return false;
    }
    ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
    ofs.flush();
    return ofs.good();
}
} // namespace

RdbDbInfoManager &RdbDbInfoManager::GetInstance()
{
    static RdbDbInfoManager instance;
    return instance;
}

CallerInfo RdbDbInfoManager::CollectCaller()
{
    CallerInfo info;
    info.pid = GetPid();
    info.tid = static_cast<int32_t>(GetThreadId());
    info.uid = GetUid();
    info.gid = GetGid();
    return info;
}

FileInfo RdbDbInfoManager::BuildFileInfo(const std::string &path)
{
    FileInfo fi;
    auto [err, debug] = SqliteUtils::Stat(path);
    if (err != E_OK) {
        return fi; // file missing / stat failed => empty FileInfo (node == 0)
    }
    fi.node = static_cast<int64_t>(debug.inode_);
    fi.size = static_cast<int64_t>(debug.size_);
    fi.permission.mode = debug.mode_;
    fi.permission.acl = Acl::Dump(path, Acl::ACL_XATTR_ACCESS);
    fi.time.ctime = debug.ctime_.sec_;
    fi.time.atime = debug.atime_.sec_;
    fi.time.mtime = debug.mtime_.sec_;
    return fi;
}

DbFileInfo RdbDbInfoManager::CollectDbFileInfo(const std::string &dbPath)
{
    DbFileInfo info;
    info.db = BuildFileInfo(dbPath);
    info.wal = BuildFileInfo(dbPath + "-wal");
    info.shm = BuildFileInfo(dbPath + "-shm");
    return info;
}

BinlogInfo RdbDbInfoManager::CollectBinlog(const std::string &dbPath)
{
    BinlogInfo info;
    std::string binlogDir = dbPath + "_binlog";
    DIR *dir = opendir(binlogDir.c_str());
    if (dir == nullptr) {
        info.exist = false;
        return info;
    }
    info.exist = true;
    uint32_t count = 0;
    int64_t total = 0;
    struct dirent *ent = nullptr;
    while ((ent = readdir(dir)) != nullptr) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }
        std::string full = binlogDir + "/" + ent->d_name;
        struct stat st;
        if (stat(full.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
            count++;
            total += static_cast<int64_t>(st.st_size);
        }
    }
    closedir(dir);
    info.fileCount = count;
    info.totalSize = total;
    return info;
}

KeyInfo RdbDbInfoManager::CollectKey(const std::string &dbPath)
{
    KeyInfo info;
    // KeyFiles ctor only computes key paths; it does not open the lock fd until
    // Lock() is called, so this is side-effect-free.
    RdbSecurityManager::KeyFiles keyFiles(dbPath);
    info.pubKey = BuildFileInfo(keyFiles.GetKeyFile(RdbSecurityManager::PUB_KEY_FILE));
    info.pubKeyNew = BuildFileInfo(keyFiles.GetKeyFile(RdbSecurityManager::PUB_KEY_FILE_NEW_KEY));
    return info;
}

ConfigInfo RdbDbInfoManager::BuildConfigInfo(const RdbStoreConfig &config)
{
    ConfigInfo info;
    info.name = config.GetName();
    info.path = config.GetPath();
    info.isEncrypted = config.IsEncrypt();
    info.securityLevel = static_cast<int32_t>(config.GetSecurityLevel());
    info.journalMode = config.GetJournalMode();
    info.sync = config.GetSyncMode();
    info.walAutoCheckpoint = SqliteGlobalConfig::GetWalAutoCheckpoint();
    return info;
}

void RdbDbInfoManager::WithRecord(const std::string &dbPath, const std::function<void(RdbDbInfoRecord &)> &mutator)
{
    std::string lockPath = dbPath + LOCK_SUFFIX;
    DfxFileLock lock(lockPath);
    if (!lock.IsLocked()) {
        return; // best-effort: lock unavailable, skip to never block the caller
    }
    std::string dfxPath = dbPath + DFX_SUFFIX;
    RdbDbInfoRecord rec;
    std::string content;
    if (ReadAll(dfxPath, content) && !content.empty()) {
        // JSON_NOEXCEPTION: Unmarshall never throws on malformed/partial json.
        (void)Serializable::Unmarshall(content, rec);
    }
    mutator(rec);
    std::string out = Serializable::Marshall(rec);
    (void)WriteAll(dfxPath, out);
}

void RdbDbInfoManager::RecordOpen(const RdbStoreConfig &config, bool created)
{
    std::string dbPath = config.GetPath();
    LastOpenDbInfo info;
    info.main = CollectDbFileInfo(dbPath);
    info.replica = CollectDbFileInfo(SqliteUtils::GetSlavePath(dbPath));
    info.binlog = CollectBinlog(dbPath);
    info.config = BuildConfigInfo(config);
    info.key = CollectKey(dbPath);
    info.time = RdbTimeUtils::GetCurSysTimeWithMs();
    info.callerInfo = CollectCaller();
    info.integrityResult = 0; // open succeeded => integrity acceptable
    info.created = created;
    info.keyPresent = RdbSecurityManager::GetInstance().IsKeyFileExists(dbPath, RdbSecurityManager::PUB_KEY_FILE);

    // Compare against the prior main snapshot inside the same flock critical
    // section; record dbInfoChange only when something actually changed.
    WithRecord(dbPath, [&info](RdbDbInfoRecord &r) {
        DbFileInfo prevMain = r.lastOpenDbInfo.main;
        r.lastOpenDbInfo = info;
        if (prevMain.IsEmpty()) {
            return;
        }
        auto changed = DiffDbFileInfo("main", prevMain, info.main);
        if (changed.empty()) {
            return;
        }
        r.dbInfoChange.before = prevMain;
        r.dbInfoChange.after = info.main;
        r.dbInfoChange.changedFields = changed;
        r.dbInfoChange.time = info.time;
        r.dbInfoChange.callerInfo = info.callerInfo;
    });
}
} // namespace NativeRdb
} // namespace OHOS

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
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cinttypes>
#include <cstring>
#include <sstream>

#include "acl.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_platform.h"
#include "rdb_security_manager.h"
#include "rdb_time_utils.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using OHOS::DATABASE_UTILS::Acl;

RdbDbInfoManager &RdbDbInfoManager::GetInstance()
{
    static RdbDbInfoManager instance;
    return instance;
}

CallerInfo RdbDbInfoManager::CollectCaller()
{
    CallerInfo info;
    info.pid = GetPid();
    info.tid = gettid();
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
    std::ostringstream modeOs;
    modeOs << std::oct << debug.mode_;
    fi.permission.mode = modeOs.str();
    fi.permission.acl = Acl::Dump(path, Acl::ACL_XATTR_ACCESS);
    fi.time.ctime = RdbTimeUtils::TimeToStr(debug.ctime_.sec_);
    fi.time.atime = RdbTimeUtils::TimeToStr(debug.atime_.sec_);
    fi.time.mtime = RdbTimeUtils::TimeToStr(debug.mtime_.sec_);
    return fi;
}

DbFileInfo RdbDbInfoManager::CollectDbFileInfo(const std::string &dbPath)
{
    DbFileInfo info;
    info.db = BuildFileInfo(dbPath);
    info.wal = BuildFileInfo(dbPath + "-wal");
    info.shm = BuildFileInfo(dbPath + "-shm");
    size_t lastSlash = dbPath.rfind('/');
    if (lastSlash != std::string::npos) {
        info.parent = BuildFileInfo(dbPath.substr(0, lastSlash));
    }
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

LastOpenDbInfo RdbDbInfoManager::BuildLastOpen(const std::string &dbPath, bool created)
{
    LastOpenDbInfo info;
    info.main = CollectDbFileInfo(dbPath);
    info.replica = CollectDbFileInfo(SqliteUtils::GetSlavePath(dbPath));
    info.binlog = CollectBinlog(dbPath);
    info.config.name = SqliteUtils::Anonymous(SqliteUtils::GetDbName(dbPath));
    info.key = CollectKey(dbPath);
    info.time = RdbTimeUtils::GetCurSysTimeWithMs();
    info.callerInfo = CollectCaller();
    info.integrityResult = 0;
    info.created = created;
    info.keyPresent = RdbSecurityManager::GetInstance().IsKeyFileExists(dbPath, RdbSecurityManager::PUB_KEY_FILE);
    return info;
}
} // namespace NativeRdb
} // namespace OHOS

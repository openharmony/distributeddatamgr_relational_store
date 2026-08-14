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

#define LOG_TAG "RdbDbInfoRecord"
#include "rdb_db_info_record.h"

#include <chrono>
#include <utility>
#include <vector>

#include "rdb_db_info_manager.h"

namespace OHOS {
namespace NativeRdb {
int64_t NowMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

bool PermissionInfo::Marshal(json &obj) const
{
    SetValue(obj[GET_NAME(mode)], mode);
    SetValue(obj[GET_NAME(acl)], acl);
    return true;
}

bool PermissionInfo::Unmarshal(const json &obj)
{
    GetValue(obj, GET_NAME(mode), mode);
    GetValue(obj, GET_NAME(acl), acl);
    return true;
}

bool TimeInfo::Marshal(json &obj) const
{
    SetValue(obj[GET_NAME(ctime)], ctime);
    SetValue(obj[GET_NAME(atime)], atime);
    SetValue(obj[GET_NAME(mtime)], mtime);
    return true;
}

bool TimeInfo::Unmarshal(const json &obj)
{
    GetValue(obj, GET_NAME(ctime), ctime);
    GetValue(obj, GET_NAME(atime), atime);
    GetValue(obj, GET_NAME(mtime), mtime);
    return true;
}

bool FileInfo::Marshal(json &obj) const
{
    SetValue(obj[GET_NAME(node)], node);
    SetValue(obj[GET_NAME(size)], size);
    SetValue(obj[GET_NAME(permission)], permission);
    SetValue(obj[GET_NAME(time)], time);
    return true;
}

bool FileInfo::Unmarshal(const json &obj)
{
    GetValue(obj, GET_NAME(node), node);
    GetValue(obj, GET_NAME(size), size);
    GetValue(obj, GET_NAME(permission), permission);
    GetValue(obj, GET_NAME(time), time);
    return true;
}

bool DbFileInfo::Marshal(json &obj) const
{
    SetValue(obj[GET_NAME(db)], db);
    SetValue(obj[GET_NAME(wal)], wal);
    SetValue(obj[GET_NAME(shm)], shm);
    return true;
}

bool DbFileInfo::Unmarshal(const json &obj)
{
    GetValue(obj, GET_NAME(db), db);
    GetValue(obj, GET_NAME(wal), wal);
    GetValue(obj, GET_NAME(shm), shm);
    return true;
}

bool DbFileInfo::IsEmpty() const
{
    return db.node == 0 && wal.node == 0 && shm.node == 0;
}

bool CallerInfo::Marshal(json &obj) const
{
    SetValue(obj[GET_NAME(pid)], pid);
    SetValue(obj[GET_NAME(tid)], tid);
    SetValue(obj[GET_NAME(uid)], uid);
    SetValue(obj[GET_NAME(gid)], gid);
    return true;
}

bool CallerInfo::Unmarshal(const json &obj)
{
    GetValue(obj, GET_NAME(pid), pid);
    GetValue(obj, GET_NAME(tid), tid);
    GetValue(obj, GET_NAME(uid), uid);
    GetValue(obj, GET_NAME(gid), gid);
    return true;
}

bool BinlogInfo::Marshal(json &obj) const
{
    SetValue(obj[GET_NAME(exist)], exist);
    SetValue(obj[GET_NAME(fileCount)], fileCount);
    SetValue(obj[GET_NAME(totalSize)], totalSize);
    return true;
}

bool BinlogInfo::Unmarshal(const json &obj)
{
    GetValue(obj, GET_NAME(exist), exist);
    GetValue(obj, GET_NAME(fileCount), fileCount);
    GetValue(obj, GET_NAME(totalSize), totalSize);
    return true;
}

bool KeyInfo::Marshal(json &obj) const
{
    SetValue(obj[GET_NAME(pubKey)], pubKey);
    SetValue(obj[GET_NAME(pubKeyNew)], pubKeyNew);
    return true;
}

bool KeyInfo::Unmarshal(const json &obj)
{
    GetValue(obj, GET_NAME(pubKey), pubKey);
    GetValue(obj, GET_NAME(pubKeyNew), pubKeyNew);
    return true;
}

bool ConfigInfo::Marshal(json &obj) const
{
    SetValue(obj[GET_NAME(name)], name);
    SetValue(obj[GET_NAME(path)], path);
    SetValue(obj[GET_NAME(isEncrypted)], isEncrypted);
    SetValue(obj[GET_NAME(securityLevel)], securityLevel);
    SetValue(obj[GET_NAME(journalMode)], journalMode);
    SetValue(obj[GET_NAME(sync)], sync);
    SetValue(obj[GET_NAME(walAutoCheckpoint)], walAutoCheckpoint);
    return true;
}

bool ConfigInfo::Unmarshal(const json &obj)
{
    GetValue(obj, GET_NAME(name), name);
    GetValue(obj, GET_NAME(path), path);
    GetValue(obj, GET_NAME(isEncrypted), isEncrypted);
    GetValue(obj, GET_NAME(securityLevel), securityLevel);
    GetValue(obj, GET_NAME(journalMode), journalMode);
    GetValue(obj, GET_NAME(sync), sync);
    GetValue(obj, GET_NAME(walAutoCheckpoint), walAutoCheckpoint);
    return true;
}

bool LastOpenDbInfo::Marshal(json &obj) const
{
    SetValue(obj[GET_NAME(main)], main);
    SetValue(obj[GET_NAME(replica)], replica);
    SetValue(obj[GET_NAME(binlog)], binlog);
    SetValue(obj[GET_NAME(config)], config);
    SetValue(obj[GET_NAME(key)], key);
    SetValue(obj[GET_NAME(time)], time);
    SetValue(obj[GET_NAME(callerInfo)], callerInfo);
    SetValue(obj[GET_NAME(integrityResult)], integrityResult);
    SetValue(obj[GET_NAME(created)], created);
    SetValue(obj[GET_NAME(keyPresent)], keyPresent);
    return true;
}

bool LastOpenDbInfo::Unmarshal(const json &obj)
{
    GetValue(obj, GET_NAME(main), main);
    GetValue(obj, GET_NAME(replica), replica);
    GetValue(obj, GET_NAME(binlog), binlog);
    GetValue(obj, GET_NAME(config), config);
    GetValue(obj, GET_NAME(key), key);
    GetValue(obj, GET_NAME(time), time);
    GetValue(obj, GET_NAME(callerInfo), callerInfo);
    GetValue(obj, GET_NAME(integrityResult), integrityResult);
    GetValue(obj, GET_NAME(created), created);
    GetValue(obj, GET_NAME(keyPresent), keyPresent);
    return true;
}

bool DbInfoChange::Marshal(json &obj) const
{
    SetValue(obj[GET_NAME(before)], before);
    SetValue(obj[GET_NAME(after)], after);
    SetValue(obj[GET_NAME(changedFields)], changedFields);
    SetValue(obj[GET_NAME(time)], time);
    SetValue(obj[GET_NAME(callerInfo)], callerInfo);
    return true;
}

bool DbInfoChange::Unmarshal(const json &obj)
{
    GetValue(obj, GET_NAME(before), before);
    GetValue(obj, GET_NAME(after), after);
    GetValue(obj, GET_NAME(changedFields), changedFields);
    GetValue(obj, GET_NAME(time), time);
    GetValue(obj, GET_NAME(callerInfo), callerInfo);
    return true;
}

bool DeleteRecord::Marshal(json &obj) const
{
    SetValue(obj[GET_NAME(startTime)], startTime);
    SetValue(obj[GET_NAME(endTime)], endTime);
    SetValue(obj[GET_NAME(dbInfo)], dbInfo);
    SetValue(obj[GET_NAME(callerInfo)], callerInfo);
    return true;
}

bool DeleteRecord::Unmarshal(const json &obj)
{
    GetValue(obj, GET_NAME(startTime), startTime);
    GetValue(obj, GET_NAME(endTime), endTime);
    GetValue(obj, GET_NAME(dbInfo), dbInfo);
    GetValue(obj, GET_NAME(callerInfo), callerInfo);
    return true;
}

bool DbInfoPair::Marshal(json &obj) const
{
    SetValue(obj[GET_NAME(backupDbInfo)], backupDbInfo);
    SetValue(obj[GET_NAME(mainDbInfo)], mainDbInfo);
    return true;
}

bool DbInfoPair::Unmarshal(const json &obj)
{
    GetValue(obj, GET_NAME(backupDbInfo), backupDbInfo);
    GetValue(obj, GET_NAME(mainDbInfo), mainDbInfo);
    return true;
}

bool BackupRecord::Marshal(json &obj) const
{
    SetValue(obj[GET_NAME(startTime)], startTime);
    SetValue(obj[GET_NAME(endTime)], endTime);
    SetValue(obj[GET_NAME(beforeDbInfo)], beforeDbInfo);
    SetValue(obj[GET_NAME(afterDbInfo)], afterDbInfo);
    SetValue(obj[GET_NAME(result)], result);
    SetValue(obj[GET_NAME(callerInfo)], callerInfo);
    return true;
}

bool BackupRecord::Unmarshal(const json &obj)
{
    GetValue(obj, GET_NAME(startTime), startTime);
    GetValue(obj, GET_NAME(endTime), endTime);
    GetValue(obj, GET_NAME(beforeDbInfo), beforeDbInfo);
    GetValue(obj, GET_NAME(afterDbInfo), afterDbInfo);
    GetValue(obj, GET_NAME(result), result);
    GetValue(obj, GET_NAME(callerInfo), callerInfo);
    return true;
}

bool RebuildRecord::Marshal(json &obj) const
{
    SetValue(obj[GET_NAME(startTime)], startTime);
    SetValue(obj[GET_NAME(endTime)], endTime);
    SetValue(obj[GET_NAME(oldDbInfo)], oldDbInfo);
    SetValue(obj[GET_NAME(newDbInfo)], newDbInfo);
    SetValue(obj[GET_NAME(result)], result);
    SetValue(obj[GET_NAME(callerInfo)], callerInfo);
    return true;
}

bool RebuildRecord::Unmarshal(const json &obj)
{
    GetValue(obj, GET_NAME(startTime), startTime);
    GetValue(obj, GET_NAME(endTime), endTime);
    GetValue(obj, GET_NAME(oldDbInfo), oldDbInfo);
    GetValue(obj, GET_NAME(newDbInfo), newDbInfo);
    GetValue(obj, GET_NAME(result), result);
    GetValue(obj, GET_NAME(callerInfo), callerInfo);
    return true;
}

bool RdbDbInfoRecord::Marshal(json &obj) const
{
    SetValue(obj[GET_NAME(lastOpenDbInfo)], lastOpenDbInfo);
    SetValue(obj[GET_NAME(dbInfoChange)], dbInfoChange);
    SetValue(obj[GET_NAME(deleteStore)], deleteStore);
    SetValue(obj[GET_NAME(restore)], restore);
    SetValue(obj[GET_NAME(backup)], backup);
    SetValue(obj[GET_NAME(rebuild)], rebuild);
    return true;
}

bool RdbDbInfoRecord::Unmarshal(const json &obj)
{
    GetValue(obj, GET_NAME(lastOpenDbInfo), lastOpenDbInfo);
    GetValue(obj, GET_NAME(dbInfoChange), dbInfoChange);
    GetValue(obj, GET_NAME(deleteStore), deleteStore);
    GetValue(obj, GET_NAME(restore), restore);
    GetValue(obj, GET_NAME(backup), backup);
    GetValue(obj, GET_NAME(rebuild), rebuild);
    return true;
}

static void DiffFileInfo(const std::string &prefix, const FileInfo &a, const FileInfo &b, std::vector<std::string> &out)
{
    if (a.node != b.node) {
        out.push_back(prefix + ".node");
    }
    if (a.size != b.size) {
        out.push_back(prefix + ".size");
    }
    if (a.permission.mode != b.permission.mode) {
        out.push_back(prefix + ".mode");
    }
    if (a.permission.acl != b.permission.acl) {
        out.push_back(prefix + ".acl");
    }
    if (a.time.ctime != b.time.ctime) {
        out.push_back(prefix + ".ctime");
    }
    if (a.time.atime != b.time.atime) {
        out.push_back(prefix + ".atime");
    }
    if (a.time.mtime != b.time.mtime) {
        out.push_back(prefix + ".mtime");
    }
}

std::vector<std::string> DiffDbFileInfo(const std::string &prefix, const DbFileInfo &before, const DbFileInfo &after)
{
    std::vector<std::string> out;
    DiffFileInfo(prefix + ".db", before.db, after.db, out);
    DiffFileInfo(prefix + ".wal", before.wal, after.wal, out);
    DiffFileInfo(prefix + ".shm", before.shm, after.shm, out);
    return out;
}

RdbDfxTrace::RdbDfxTrace(DfxOp op, std::string dbPath, std::string backupPath, const int *resultRef)
    : op_(op), dbPath_(dbPath), backupPath_(backupPath), startTime_(NowMs()),
      caller_(RdbDbInfoManager::GetInstance().CollectCaller()),
      beforeMain_(RdbDbInfoManager::GetInstance().CollectDbFileInfo(dbPath)),
      beforeBackup_(!backupPath.empty() ? RdbDbInfoManager::GetInstance().CollectDbFileInfo(backupPath) : DbFileInfo()),
      resultRef_(resultRef)
{
}

void RdbDfxTrace::SetBackupPath(const std::string &backupPath)
{
    backupPath_ = backupPath;
    if (!backupPath_.empty()) {
        beforeBackup_ = RdbDbInfoManager::GetInstance().CollectDbFileInfo(backupPath_);
    }
}

RdbDfxTrace::~RdbDfxTrace()
{
    // noexcept-friendly: every call below uses return codes / no-throw json.
    int32_t result = (resultRef_ != nullptr) ? *resultRef_ : 0;
    int64_t endTime = NowMs();
    auto &mgr = RdbDbInfoManager::GetInstance();
    switch (op_) {
        case DfxOp::DELETE: {
            DeleteRecord rec;
            rec.startTime = startTime_;
            rec.endTime = endTime;
            rec.dbInfo = beforeMain_;
            rec.callerInfo = caller_;
            mgr.CommitDelete(dbPath_, rec);
            break;
        }
        case DfxOp::REBUILD: {
            DbFileInfo afterMain = mgr.CollectDbFileInfo(dbPath_);
            RebuildRecord rec;
            rec.startTime = startTime_;
            rec.endTime = endTime;
            rec.oldDbInfo = beforeMain_;
            rec.newDbInfo = afterMain;
            rec.result = result;
            rec.callerInfo = caller_;
            mgr.CommitRebuild(dbPath_, rec);
            break;
        }
        case DfxOp::RESTORE:
        case DfxOp::BACKUP: {
            DbFileInfo afterMain = mgr.CollectDbFileInfo(dbPath_);
            DbFileInfo afterBackup;
            if (!backupPath_.empty()) {
                afterBackup = mgr.CollectDbFileInfo(backupPath_);
            }
            BackupRecord rec;
            rec.startTime = startTime_;
            rec.endTime = endTime;
            rec.beforeDbInfo.backupDbInfo = beforeBackup_;
            rec.beforeDbInfo.mainDbInfo = beforeMain_;
            rec.afterDbInfo.backupDbInfo = afterBackup;
            rec.afterDbInfo.mainDbInfo = afterMain;
            rec.result = result;
            rec.callerInfo = caller_;
            if (op_ == DfxOp::RESTORE) {
                mgr.CommitRestore(dbPath_, rec);
            } else {
                mgr.CommitBackup(dbPath_, rec);
            }
            break;
        }
    }
}
} // namespace NativeRdb
} // namespace OHOS

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

#define LOG_TAG "RdbDbLoggerManager"
#include "rdb_db_logger_manager.h"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cctype>
#include <cstring>
#include <fstream>
#include <sstream>

#include "logger.h"
#include "rdb_db_info_manager.h"
#include "rdb_time_utils.h"
#include "serializable.h"
#include "sqlite_utils.h"
#include "string_utils.h"
#include "task_executor.h"

namespace OHOS {
namespace NativeRdb {

namespace {
constexpr const char *AUDIT_JSON_SUFFIX = "_audit.json";
constexpr const char *AUDIT_LOCK_SUFFIX = "_audit.lock";

// RAII single-layer flock: opens a fresh fd per lock attempt so open file
// descriptions are distinct — flock conflicts across same-process threads too
// (no in-process mutex needed). Mirrors the SecurityManager::KeyFiles pattern.
class AuditFileLock {
public:
    explicit AuditFileLock(const std::string &lockPath)
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
    ~AuditFileLock()
    {
        if (fd_ >= 0) {
            int rc = -1;
            do {
                rc = flock(fd_, LOCK_UN);
            } while (rc < 0 && errno == EINTR);
            close(fd_);
        }
    }
    bool IsLocked() const { return fd_ >= 0; }
    AuditFileLock(const AuditFileLock &) = delete;
    AuditFileLock &operator=(const AuditFileLock &) = delete;

private:
    int fd_ = -1;
};

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

RdbDbLoggerManager &RdbDbLoggerManager::GetInstance()
{
    static RdbDbLoggerManager instance;
    return instance;
}

RdbDbLoggerManager::RdbDbLoggerManager() {}

RdbDbLoggerManager::~RdbDbLoggerManager() {}

void RdbDbLoggerManager::Init(const std::string &auditDir)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (initialized_) {
        return;
    }
    if (auditDir.empty()) {
        return;
    }
    auditDir_ = auditDir;
    initialized_ = true;
}

void RdbDbLoggerManager::RecordOpenSync(const std::string &dbPath, const LastOpenDbInfo &lastOpen)
{
    WithAuditRecord(dbPath, [&lastOpen](RdbDbInfoRecord &rec) {
        DbFileInfo prevMain = rec.lastOpen.main;
        rec.lastOpen = lastOpen;
        if (prevMain.IsEmpty()) {
            return;
        }
        auto changed = DiffDbFileInfo("main", prevMain, lastOpen.main);
        if (changed.empty()) {
            return;
        }
        rec.inodeChange.before = prevMain;
        rec.inodeChange.after = lastOpen.main;
        rec.inodeChange.changedFields = changed;
        rec.inodeChange.time = lastOpen.time;
        rec.inodeChange.callerInfo = lastOpen.callerInfo;
    });
}

void RdbDbLoggerManager::WriteIoErrorSync(const std::string &dbPath, const IoErrorInfo &ioError)
{
    WithAuditRecord(dbPath, [&ioError](RdbDbInfoRecord &rec) { rec.ioError = ioError; });
}

void RdbDbLoggerManager::WriteDeleteSync(const std::string &dbPath, const DeleteInfo &del)
{
    WithAuditRecord(dbPath, [&del](RdbDbInfoRecord &rec) { rec.dbDelete = del; });
}

void RdbDbLoggerManager::WriteCorruptSync(const std::string &dbPath, const CorruptInfo &corrupt)
{
    WithAuditRecord(dbPath, [&corrupt](RdbDbInfoRecord &rec) { rec.corrupt = corrupt; });
}

void RdbDbLoggerManager::RecordCorrupt(const std::string &dbPath, int rc, int osErrno, const std::string &detail)
{
    auto executor = TaskExecutor::GetInstance().GetExecutor();
    if (executor == nullptr) {
        return;
    }
    executor->Execute([dbPath, rc, osErrno, detail, this]() {
        CorruptInfo corrupt;
        corrupt.rc = rc;
        corrupt.osErrno = osErrno;
        corrupt.detail = detail;
        corrupt.files = RdbDbInfoManager::GetInstance().CollectDbFileInfo(dbPath);
        corrupt.callerInfo = RdbDbInfoManager::GetInstance().CollectCaller();
        corrupt.time = RdbTimeUtils::GetCurSysTimeWithMs();
        WriteCorruptSync(dbPath, corrupt);
    });
}

void RdbDbLoggerManager::RecordIoError(
    const std::string &op, const std::string &file, int rc, int osErrno)
{
    auto executor = TaskExecutor::GetInstance().GetExecutor();
    if (executor == nullptr) {
        return;
    }
    executor->Execute([op, file, rc, osErrno, this]() {
        IoErrorInfo ioError;
        ioError.op = op;
        ioError.rc = rc;
        ioError.osErrno = osErrno;
        ioError.callerInfo = RdbDbInfoManager::GetInstance().CollectCaller();
        ioError.time = RdbTimeUtils::GetCurSysTimeWithMs();
        WriteIoErrorSync(file, ioError);
    });
}

void RdbDbLoggerManager::WithAuditRecord(
    const std::string &dbPath, const std::function<void(RdbDbInfoRecord &)> &mutator)
{
    if (!initialized_ || dbPath.empty()) {
        return;
    }
    std::string jsonPath = BuildAuditPath(dbPath, AUDIT_JSON_SUFFIX);
    if (jsonPath.empty()) {
        return;
    }
    AuditFileLock lock(BuildAuditPath(dbPath, AUDIT_LOCK_SUFFIX));
    if (!lock.IsLocked()) {
        return; // best-effort: lock unavailable, skip to never block the caller
    }
    RdbDbInfoRecord rec;
    std::string content;
    if (ReadAll(jsonPath, content) && !content.empty()) {
        (void)Serializable::Unmarshall(content, rec);
    }
    mutator(rec);
    std::string out = Serializable::Marshall(rec);
    (void)WriteAll(jsonPath, out);
}

std::string RdbDbLoggerManager::BuildAuditPath(const std::string &dbPath, const std::string &suffix) const
{
    if (auditDir_.empty()) {
        return "";
    }
    std::string el = SqliteUtils::GetArea(dbPath);
    std::string dbName = SqliteUtils::RemoveSuffix(StringUtils::ExtractFileName(dbPath));
    if (el.empty() || dbName.empty()) {
        return "";
    }
    return auditDir_ + el + dbName + suffix;
}

} // namespace NativeRdb
} // namespace OHOS

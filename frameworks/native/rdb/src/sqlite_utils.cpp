/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#define LOG_TAG "SqliteUtils"
#include "sqlite_utils.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <fstream>

#include "logger.h"
#include "rdb_errno.h"
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
#include "rdb_store_config.h"
#endif
#define HMFS_MONITOR_FL 0x00000002
#define HMFS_IOCTL_HW_GET_FLAGS _IOR(0xf5, 70, unsigned int)
#define HMFS_IOCTL_HW_SET_FLAGS _IOR(0xf5, 71, unsigned int)
namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

constexpr int32_t HEAD_SIZE = 3;
constexpr int32_t END_SIZE = 3;
constexpr int32_t MIN_SIZE = HEAD_SIZE + END_SIZE + 3;
constexpr const char *REPLACE_CHAIN = "***";
constexpr const char *DEFAULT_ANONYMOUS = "******";

constexpr SqliteUtils::SqlType SqliteUtils::SQL_TYPE_MAP[];
constexpr const char *SqliteUtils::ON_CONFLICT_CLAUSE[];

int SqliteUtils::GetSqlStatementType(const std::string &sql)
{
    /* the sql string length less than 3 can not be any type sql */
    if (sql.length() < 3) {
        return STATEMENT_ERROR;
    }
    /* analyze the sql type through first 3 character */
    std::string prefixSql = StrToUpper(sql.substr(0, 3));
    SqlType type = { prefixSql.c_str(), STATEMENT_OTHER };
    auto comp = [](const SqlType &first, const SqlType &second) {
        return strcmp(first.sql, second.sql) < 0;
    };
    auto it = std::lower_bound(SQL_TYPE_MAP, SQL_TYPE_MAP + TYPE_SIZE, type, comp);
    if (it < SQL_TYPE_MAP + TYPE_SIZE && !comp(type, *it)) {
        return it->type;
    }
    return STATEMENT_OTHER;
}

std::string SqliteUtils::StrToUpper(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::toupper(c); });
    return s;
}

void SqliteUtils::Replace(std::string &src, const std::string &rep, const std::string &dst)
{
    if (src.empty() || rep.empty()) {
        return;
    }
    size_t pos = 0;
    while ((pos = src.find(rep, pos)) != std::string::npos) {
        src.replace(pos, rep.length(), dst);
        pos += dst.length();
    }
}

bool SqliteUtils::IsSupportSqlForExecute(int sqlType)
{
    return (sqlType == STATEMENT_DDL || sqlType == STATEMENT_INSERT || sqlType == STATEMENT_UPDATE ||
            sqlType == STATEMENT_PRAGMA);
}

bool SqliteUtils::IsSqlReadOnly(int sqlType)
{
    return (sqlType == STATEMENT_SELECT);
}

bool SqliteUtils::IsSpecial(int sqlType)
{
    if (sqlType == STATEMENT_BEGIN || sqlType == STATEMENT_COMMIT || sqlType == STATEMENT_ROLLBACK) {
        return true;
    }
    return false;
}

const char *SqliteUtils::GetConflictClause(int conflictResolution)
{
    if (conflictResolution < 0 || conflictResolution >= CONFLICT_CLAUSE_COUNT) {
        return nullptr;
    }
    return ON_CONFLICT_CLAUSE[conflictResolution];
}

bool SqliteUtils::DeleteFile(const std::string &filePath)
{
    SqliteUtils::ControlDeleteFlag(filePath, CLEAR_FLAG);
    auto ret = remove(filePath.c_str());
    if (ret != 0) {
        LOG_WARN("remove file failed errno %{public}d ret %{public}d %{public}s", errno, ret, filePath.c_str());
        return false;
    }
    return true;
}

bool SqliteUtils::RenameFile(const std::string &srcFile, const std::string &destFile)
{
    auto ret = rename(srcFile.c_str(), destFile.c_str());
    if (ret != 0) {
        LOG_WARN("rename failed errno %{public}d ret %{public}d %{public}s -> %{public}s", errno, ret,
            destFile.c_str(), srcFile.c_str());
        return false;
    }
    return true;
}

bool SqliteUtils::CopyFile(const std::string &srcFile, const std::string &destFile)
{
    std::ifstream src(srcFile.c_str(), std::ios::binary);
    if (!src.is_open()) {
        LOG_WARN("open srcFile failed errno %{public}d %{public}s", errno, srcFile.c_str());
        return false;
    }
    std::ofstream dst(destFile.c_str(), std::ios::binary);
    if (!dst.is_open()) {
        src.close();
        LOG_WARN("open destFile failed errno %{public}d %{public}s", errno, destFile.c_str());
        return false;
    }
    dst << src.rdbuf();
    src.close();
    dst.close();
    return true;
}

std::string SqliteUtils::Anonymous(const std::string &srcFile)
{
    if (srcFile.length() <= HEAD_SIZE) {
        return DEFAULT_ANONYMOUS;
    }

    if (srcFile.length() < MIN_SIZE) {
        return (srcFile.substr(0, HEAD_SIZE) + REPLACE_CHAIN);
    }

    return (srcFile.substr(0, HEAD_SIZE) + REPLACE_CHAIN + srcFile.substr(srcFile.length() - END_SIZE, END_SIZE));
}

int SqliteUtils::GetFileSize(const std::string &fileName)
{
    struct stat fileStat;
    if (fileName.empty() || stat(fileName.c_str(), &fileStat) < 0) {
        LOG_ERROR("Failed to get file infos, errno: %{public}d, fileName:%{public}s",
                  errno, Anonymous(fileName).c_str());
        return 0;
    }

    return static_cast<int>(fileStat.st_size);
}

void SqliteUtils::ControlDeleteFlag(const std::string fileName, FlagControlType flagControlType)
{
    int fd = open(fileName.c_str(), O_RDONLY, S_IRWXU | S_IRWXG);
    if (fd < 0) {
        LOG_ERROR("Open failed, errno=%{public}d.", errno);
        return;
    }
    unsigned int flags = 0;
    int ret = ioctl(fd, HMFS_IOCTL_HW_GET_FLAGS, &flags);
    if (ret < 0) {
        LOG_ERROR("Failed to get flags, errno: %{public}d, %{public}s", errno, fileName.c_str());
        close(fd);
        return;
    }

    if ((flagControlType == SET_FLAG && (flags & HMFS_MONITOR_FL)) ||
        (flagControlType == CLEAR_FLAG && !(flags & HMFS_MONITOR_FL))) {
        LOG_DEBUG("Delete control flag is already set");
        close(fd);
        return;
    }

    if (flagControlType == SET_FLAG) {
        flags |= HMFS_MONITOR_FL;
    } else if (flagControlType == CLEAR_FLAG) {
        flags &= ~HMFS_MONITOR_FL;
    }

    ret = ioctl(fd, HMFS_IOCTL_HW_SET_FLAGS, &flags);
    if (ret < 0) {
        LOG_ERROR("Failed to set flags, errno: %{public}d, %{public}s", errno, fileName.c_str());
        close(fd);
        return;
    }

    LOG_DEBUG("Flag control operation success type: %{public}d file: %{public}s", flagControlType, fileName.c_str());
    close(fd);
}

bool SqliteUtils::IsSlaveDbName(const std::string &fileName)
{
    std::string slaveSuffix("_slave.db");
    if (fileName.size() < slaveSuffix.size()) {
        return false;
    }
    size_t pos = fileName.rfind(slaveSuffix);
    return (pos != std::string::npos) && (pos == fileName.size() - slaveSuffix.size());
}

std::string SqliteUtils::GetDbFileName(sqlite3 *db)
{
    if (db == nullptr) {
        return {};
    }
    auto fileName = sqlite3_db_filename(db, nullptr);
    if (fileName == nullptr) {
        return {};
    }
    return std::string(fileName);
}

bool SqliteUtils::TryAccessSlaveLock(sqlite3 *db, bool isDelete, bool needCreate)
{
    if (db == nullptr) {
        return false;
    }
    std::string lockFile = GetDbFileName(db) + "-locker";
    if (isDelete) {
        if (std::remove(lockFile.c_str()) != 0) {
            LOG_WARN("remove slave lock failed errno %{public}d %{public}s", errno, Anonymous(lockFile).c_str());
            return false;
        } else {
            LOG_INFO("remove slave lock %{public}s", Anonymous(lockFile).c_str());
            return true;
        }
    } else {
        if (access(lockFile.c_str(), F_OK) == 0) {
            return true;
        }
        if (needCreate) {
            std::ofstream src(lockFile.c_str(), std::ios::binary);
            if (src.is_open()) {
                LOG_INFO("create slave lock %{public}s", Anonymous(lockFile).c_str());
                src.close();
                return true;
            } else {
                LOG_WARN("open slave lock failed errno %{public}d %{public}s", errno, Anonymous(lockFile).c_str());
                return false;
            }
        }
        return false;
    }
}

std::string SqliteUtils::GetSlavePath(const std::string& name)
{
    std::string suffix(".db");
    std::string slaveSuffix("_slave.db");
    auto pos = name.rfind(suffix);
    if (pos == std::string::npos || pos < name.length() - suffix.length()) {
        return name + slaveSuffix;
    }
    return name.substr(0, pos) + slaveSuffix;
}
} // namespace NativeRdb
} // namespace OHOS

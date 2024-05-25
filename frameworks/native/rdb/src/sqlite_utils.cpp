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

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "logger.h"
#include "rdb_errno.h"

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
#include "rdb_store_config.h"
#endif

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
    SqlType type = { prefixSql.c_str(), STATEMENT_OTHER};
    auto it = std::lower_bound(SQL_TYPE_MAP, SQL_TYPE_MAP + TYPE_SIZE, type,
        [](const SqlType& first, const SqlType& second) {
            return strcmp(first.sql, second.sql) < 0;
        });
    if (it < SQL_TYPE_MAP + TYPE_SIZE) {
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
    return remove(filePath.c_str()) == 0;
}

int SqliteUtils::RenameFile(const std::string &srcFile, const std::string &destFile)
{
    return rename(srcFile.c_str(), destFile.c_str());
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
    if (fileName.empty() || access(fileName.c_str(), F_OK) != 0) {
        return 0;
    }

    struct stat fileStat;
    if (stat(fileName.c_str(), &fileStat) < 0) {
        LOG_ERROR("Failed to get file information, errno: %{public}d", errno);
        return INT_MAX;
    }

    return static_cast<int>(fileStat.st_size);
}
} // namespace NativeRdb
} // namespace OHOS

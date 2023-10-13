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

#include "sqlite_utils.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdio>

#include "logger.h"
#include "rdb_errno.h"

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
#include "rdb_store_config.h"
#endif

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

const int SqliteUtils::STATEMENT_SELECT = 1;
const int SqliteUtils::STATEMENT_UPDATE = 2;
const int SqliteUtils::STATEMENT_ATTACH = 3;
const int SqliteUtils::STATEMENT_DETACH = 4;
const int SqliteUtils::STATEMENT_BEGIN = 5;
const int SqliteUtils::STATEMENT_COMMIT = 6;
const int SqliteUtils::STATEMENT_ROLLBACK = 7;
const int SqliteUtils::STATEMENT_PRAGMA = 8;
const int SqliteUtils::STATEMENT_DDL = 9;
const int SqliteUtils::STATEMENT_OTHER = 99;

constexpr int32_t HEAD_SIZE = 3;
constexpr int32_t END_SIZE = 3;
constexpr int32_t MIN_SIZE = HEAD_SIZE + END_SIZE + 3;
constexpr const char *REPLACE_CHAIN = "***";
constexpr const char *DEFAULT_ANONYMOUS = "******";

const std::map<std::string, int> SqliteUtils::SQL_TYPE_MAP = {
    { "SEL", SqliteUtils::STATEMENT_SELECT },
    { "INS", SqliteUtils::STATEMENT_UPDATE },
    { "UPD", SqliteUtils::STATEMENT_UPDATE },
    { "REP", SqliteUtils::STATEMENT_UPDATE },
    { "DEL", SqliteUtils::STATEMENT_UPDATE },
    { "ATT", SqliteUtils::STATEMENT_ATTACH },
    { "DET", SqliteUtils::STATEMENT_DETACH },
    { "COM", SqliteUtils::STATEMENT_COMMIT },
    { "END", SqliteUtils::STATEMENT_COMMIT },
    { "ROL", SqliteUtils::STATEMENT_ROLLBACK },
    { "BEG", SqliteUtils::STATEMENT_BEGIN },
    { "PRA", SqliteUtils::STATEMENT_PRAGMA },
    { "CRE", SqliteUtils::STATEMENT_DDL },
    { "DRO", SqliteUtils::STATEMENT_DDL },
    { "ALT", SqliteUtils::STATEMENT_DDL },
};

int SqliteUtils::GetSqlStatementType(const std::string &sql)
{
    std::string sqlStr = sql;
    /* the sql string length less than 3 can not be any type sql */
    if (sqlStr.length() < 3) {
        return STATEMENT_OTHER;
    }
    /* analyze the sql type through first 3 character */
    std::string prefixSql = StrToUpper(sqlStr.substr(0, 3));
    auto iter = SQL_TYPE_MAP.find(prefixSql);
    if (iter != SQL_TYPE_MAP.end()) {
        return iter->second;
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
        pos += rep.length();
    }
}

bool SqliteUtils::IsSqlReadOnly(int sqlType)
{
    return (sqlType == STATEMENT_SELECT) ? true : false;
}

bool SqliteUtils::IsSpecial(int sqlType)
{
    if (sqlType == STATEMENT_BEGIN || sqlType == STATEMENT_COMMIT || sqlType == STATEMENT_ROLLBACK) {
        return true;
    }
    return false;
}

const std::string SqliteUtils::ON_CONFLICT_CLAUSE[] = { "", " OR ROLLBACK", " OR ABORT", " OR FAIL", " OR IGNORE",
    " OR REPLACE" };
int SqliteUtils::GetConflictClause(int conflictResolution, std::string &conflictClause)
{
    if (conflictResolution < 0 || conflictResolution >= CONFLICT_CLAUSE_COUNT) {
        return E_INVALID_CONFLICT_FLAG;
    }
    conflictClause = ON_CONFLICT_CLAUSE[conflictResolution];
    return E_OK;
}

bool SqliteUtils::DeleteFile(const std::string filePath)
{
    return remove(filePath.c_str()) == 0;
}

int SqliteUtils::RenameFile(const std::string srcFile, const std::string destFile)
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

int SqliteUtils::GetFileSize(const std::string fileName)
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

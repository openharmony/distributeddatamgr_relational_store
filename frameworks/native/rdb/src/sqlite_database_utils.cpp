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

#define LOG_TAG "SqliteDatabaseUtils"

#include "sqlite_database_utils.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#ifdef WINDOWS_PLATFORM
#include <dir.h>
#endif
#include <climits>
#include <fstream>

#include "logger.h"
#include "rdb_errno.h"
#include "sqlite_utils.h"

#ifdef WINDOWS_PLATFORM
#define REALPATH(relPath, absPath, ...) (_fullpath(absPath, relPath, ##__VA_ARGS__))
#define MKDIR(filePath) (mkdir(filePath))
#else
#define REALPATH(absPath, relPath, ...) (realpath(absPath, relPath))
#define MKDIR(filePath) (mkdir(filePath, g_mkdirMode))
#endif

namespace OHOS {
namespace NativeRdb {
std::map<std::string, int> SqliteDatabaseUtils::g_statementType = SqliteDatabaseUtils::MapInit();
std::mutex SqliteDatabaseUtils::g_locker;
// Set the file access permissions is 777
int SqliteDatabaseUtils::g_mkdirMode = 0771;
std::map<std::string, int> SqliteDatabaseUtils::MapInit()
{
    std::map<std::string, int> temp;
    temp["SEL"] = STATEMENT_SELECT;
    temp["INS"] = STATEMENT_UPDATE;
    temp["UPD"] = STATEMENT_UPDATE;
    temp["REP"] = STATEMENT_UPDATE;
    temp["DEL"] = STATEMENT_UPDATE;
    temp["ATT"] = STATEMENT_ATTACH;
    temp["DET"] = STATEMENT_DETACH;
    temp["COM"] = STATEMENT_COMMIT;
    temp["END"] = STATEMENT_COMMIT;
    temp["ROL"] = STATEMENT_ROLLBACK;
    temp["BEG"] = STATEMENT_BEGIN;
    temp["PRA"] = STATEMENT_PRAGMA;
    temp["CRE"] = STATEMENT_DDL;
    temp["DRO"] = STATEMENT_DDL;
    temp["ALT"] = STATEMENT_DDL;

    return temp;
}

/**
 * Obtains the type of SQL statement.
 */
int SqliteDatabaseUtils::GetSqlStatementType(std::string sql)
{
    if (sql.empty()) {
        return STATEMENT_OTHER;
    }
    sql.erase(0, sql.find_first_not_of(" "));
    sql.erase(sql.find_last_not_of(" ") + 1);

    if (sql.length() < SQL_FIRST_CHARACTER) {
        return STATEMENT_OTHER;
    }
    sql = StrToUpper(sql.substr(0, SQL_FIRST_CHARACTER));
    auto iter = g_statementType.find(sql);
    if (iter != g_statementType.end()) {
        return iter->second;
    }
    return STATEMENT_OTHER;
}

std::string SqliteDatabaseUtils::StrToUpper(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::toupper(c); });
    return s;
}

/**
 * Delete the specified file.
 */
void SqliteDatabaseUtils::DeleteFile(std::string &fileName)
{
    if (access(fileName.c_str(), F_OK) != 0) {
        LOG_ERROR("access %{public}s errno is %{public}d", SqliteUtils::Anonymous(fileName).c_str(), errno);
        return;
    }

    if (remove(fileName.c_str()) != 0) {
        LOG_ERROR("remove %{public}s errno is %{public}d", SqliteUtils::Anonymous(fileName).c_str(), errno);
        return;
    }
    LOG_INFO("remove %{public}s", SqliteUtils::Anonymous(fileName).c_str());
}

/**
 * Rename file.
 */
bool SqliteDatabaseUtils::RenameFile(std::string &oldFileName, std::string &newFileName)
{
    if (access(oldFileName.c_str(), F_OK) != 0) {
        LOG_ERROR("access %{public}s errno is %{public}d", SqliteUtils::Anonymous(oldFileName).c_str(), errno);
        return false;
    }
    if (rename(oldFileName.c_str(), newFileName.c_str()) != 0) {
        LOG_ERROR("Rename %{public}s to %{public}s errno %{public}d", SqliteUtils::Anonymous(oldFileName).c_str(),
            SqliteUtils::Anonymous(newFileName).c_str(), errno);
        return false;
    }
    return true;
}

/**
 * Get and Check default path.
 */
std::string SqliteDatabaseUtils::GetDefaultDatabasePath(std::string &baseDir, std::string &name, int &errorCode)
{
    std::unique_lock<std::mutex> lock(g_locker);
    if (access(baseDir.c_str(), F_OK) != 0) {
        if (MKDIR(baseDir.c_str())) {
            errorCode = E_CREATE_FOLDER_FAIL;
        }
    }
#if defined(WINDOWS_PLATFORM)
    std::string databasePath = baseDir + "\\rdb";
#else
    std::string databasePath = baseDir + "/rdb";
#endif
    if (access(databasePath.c_str(), F_OK) != 0) {
        if (MKDIR(databasePath.c_str())) {
            errorCode = E_CREATE_FOLDER_FAIL;
        }
    }
    char canonicalPath[PATH_MAX + 1] = { 0 };
    if (REALPATH(databasePath.c_str(), canonicalPath, PATH_MAX) == nullptr) {
        LOG_ERROR("Failed to obtain real path, errno:%{public}d", errno);
        errorCode = E_INVALID_FILE_PATH;
        return "";
    }
    std::string realFilePath(canonicalPath);
#if defined(WINDOWS_PLATFORM)
    realFilePath = realFilePath.append("\\").append(name);
#else
    realFilePath = realFilePath.append("/").append(name);
#endif
    return realFilePath;
}

/**
 * Get corrupt path from database path.
 */
std::string SqliteDatabaseUtils::GetCorruptPath(std::string &path, int &errorCode)
{
    std::string databaseFile = path;
    std::string name = databaseFile.substr(databaseFile.find_last_of("/") + 1);
    std::string parentFile = databaseFile.substr(0, databaseFile.find_last_of("/"));
    std::string databaseTypeDir = parentFile.substr(parentFile.find_last_of("/") + 1);
    size_t posDatabaseType = databaseTypeDir.find("_encrypt");

    bool isEncrypt = false;
    if (posDatabaseType != databaseTypeDir.npos) {
        std::string databaseTypeDirStr = databaseTypeDir.substr(posDatabaseType);
        std::string end = "_encrypt";
        if (databaseTypeDirStr.compare(end) == 0) {
            isEncrypt = true;
        }
    }

    std::string databaseDir = parentFile.substr(0, parentFile.find_last_of("/"));
    std::string encrypt = isEncrypt ? "_encrypt" : "";
    std::string corruptTypeDir = "corrupt" + encrypt;
    std::string corruptPath = databaseDir + "/" + corruptTypeDir;

    if (access(corruptPath.c_str(), F_OK) != 0) {
        if (MKDIR(corruptPath.c_str())) {
            errorCode = E_CREATE_FOLDER_FAIL;
        }
    }
    corruptPath = corruptPath + "/" + name;
    return corruptPath;
}

/**
 * Get and Check no dbname path.
 */

bool SqliteDatabaseUtils::BeginExecuteSql(const std::string &sql)
{
    int type = SqliteDatabaseUtils::GetSqlStatementType(sql);
    if (IsSpecial(type)) {
        return E_TRANSACTION_IN_EXECUTE;
    }

    return (type == STATEMENT_SELECT) ? true : false;
}

bool SqliteDatabaseUtils::IsReadOnlySql(std::string sql)
{
    int sqlType = GetSqlStatementType(sql);
    return (sqlType == STATEMENT_SELECT) ? true : false;
}

bool SqliteDatabaseUtils::IsSpecial(int sqlType)
{
    if (sqlType == STATEMENT_BEGIN || sqlType == STATEMENT_COMMIT || sqlType == STATEMENT_ROLLBACK) {
        return true;
    }
    return false;
}
} // namespace NativeRdb
} // namespace OHOS
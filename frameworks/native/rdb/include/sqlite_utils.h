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

#ifndef NATIVE_RDB_SQLITE_UTILS_H
#define NATIVE_RDB_SQLITE_UTILS_H

#include <map>
#include <string>
#include <sys/stat.h>

#include "rdb_types.h"
#include "rdb_store_config.h"

namespace OHOS {
namespace NativeRdb {

struct ErrMsgState {
    bool isCreated = false;
    bool isDeleted = false;
    bool isRenamed = false;
};

using DebugInfo = OHOS::DistributedRdb::RdbDebugInfo;
using DfxInfo = OHOS::DistributedRdb::RdbDfxInfo;
class SqliteUtils {
public:
    static constexpr int STATEMENT_SELECT = 1;
    static constexpr int STATEMENT_UPDATE = 2;
    static constexpr int STATEMENT_ATTACH = 3;
    static constexpr int STATEMENT_DETACH = 4;
    static constexpr int STATEMENT_BEGIN = 5;
    static constexpr int STATEMENT_COMMIT = 6;
    static constexpr int STATEMENT_ROLLBACK = 7;
    static constexpr int STATEMENT_PRAGMA = 8;
    static constexpr int STATEMENT_DDL = 9;
    static constexpr int STATEMENT_INSERT = 10;
    static constexpr int STATEMENT_ERROR = 11;
    static constexpr int STATEMENT_OTHER = 99;
    static constexpr int CONFLICT_CLAUSE_COUNT = 6;
    static constexpr int DISABLE_LOAD_EXTENSION = 0;
    static constexpr int ENABLE_LOAD_EXTENSION = 1;
    static constexpr int MAX_LOAD_EXTENSION_COUNT = 16;
    static constexpr int PATH_DEPTH = 3;
    static constexpr const char *REP = "#_";
    static constexpr const char *SLAVE_FAILURE = "-slaveFailure";
    static constexpr const char *SLAVE_INTERRUPT = "-syncInterrupt";
    static constexpr const char *SLAVE_RESTORE = "-restoring";
    static constexpr ssize_t SLAVE_ASYNC_REPAIR_CHECK_LIMIT = 367001600; // 367001600 = 350 * 1024 * 1024

    static int GetSqlStatementType(const std::string &sql);
    static bool IsSupportSqlForExecute(int sqlType);
    static bool IsSqlReadOnly(int sqlType);
    static bool IsSpecial(int sqlType);
    static const char *GetConflictClause(int conflictResolution);
    static std::string StrToUpper(const std::string &s);
    static std::string Replace(const std::string &src, const std::string &rep, const std::string &dst);
    static bool DeleteFile(const std::string &filePath);
    static bool RenameFile(const std::string &srcFile, const std::string &destFile);
    static bool CopyFile(const std::string &srcFile, const std::string &destFile);
    static size_t DeleteFolder(const std::string &folderPath);
    static size_t GetFileCount(const std::string &folderPath);
    API_EXPORT static std::string Anonymous(const std::string &srcFile);
    static std::string RemoveSuffix(const std::string &name);
    static std::string SqlAnonymous(const std::string &sql);
    static std::string GetArea(const std::string &srcFile);
    static ssize_t GetFileSize(const std::string &fileName);
    static bool IsSlaveDbName(const std::string &fileName);
    static bool DeleteFiles(const std::vector<std::string> &filePaths);
    static std::string GetSlavePath(const std::string &name);
    static int SetSlaveInvalid(const std::string &dbPath);
    static int SetSlaveInterrupted(const std::string &dbPath);
    static int SetSlaveRestoring(const std::string &dbPath, bool isRestore = true);
    static bool IsSlaveRestoring(const std::string &dbPath);
    static ssize_t GetDecompressedSize(const std::string &dbPath);
    static bool IsSlaveLarge(const std::string &dbPath);
    static bool IsSlaveInvalid(const std::string &dbPath);
    static bool IsSlaveInterrupted(const std::string &dbPath);
    static void SetSlaveValid(const std::string &dbPath);
    static const char *HmacAlgoDescription(int32_t hmacAlgo);
    static const char *KdfAlgoDescription(int32_t kdfAlgo);
    static const char *EncryptAlgoDescription(int32_t encryptAlgo);
    static bool DeleteDirtyFiles(const std::string &backupFilePath);
    static std::pair<int32_t, DistributedRdb::RdbDebugInfo> Stat(const std::string &path);
    static bool IsFileEmpty(const std::string &filePath);
    static bool IsFilesEmpty(const std::vector<std::string> &filePaths);
    static void WriteSqlToFile(const std::string &comparePath, const std::string &sql);
    static bool CleanFileContent(const std::string &filePath);
    static std::string GetErrInfoFromMsg(const std::string &message, const std::string &errStr);
    static ErrMsgState CompareTableFileContent(const std::string &dbPath, const std::string &bundleName,
        const std::string &tableName);
    static ErrMsgState CompareColumnFileContent(const std::string &dbPath, const std::string &bundleName,
        const std::string &columnName);
    static std::string ReadFileHeader(const std::string &filePath);
    static std::string FormatDebugInfo(const std::map<std::string, DebugInfo> &debugs, const std::string &header);
    static std::string FormatDebugInfoBrief(const std::map<std::string, DebugInfo> &debugs, const std::string &header);
    static std::string FormatDfxInfo(const DfxInfo &dfxInfo);
    static std::string GetParentModes(const std::string &path, int pathDepth = PATH_DEPTH);
    static std::string GetFileStatInfo(const DebugInfo &debugInfo);
    static bool HasDefaultAcl(const std::string &path, int32_t gid);
    static bool HasAccessAcl(const std::string &path, int32_t gid);
    static bool SetDbFileGid(const std::string &path, const std::vector<std::string> &files, int32_t gid);
    static bool SetDbDirGid(const std::string &path, int32_t gid, bool isDefault = false);

private:
    struct SqlType {
        const char *sql;
        int32_t type;
    };
    static constexpr SqlType SQL_TYPE_MAP[] = {
        { "ALT", SqliteUtils::STATEMENT_DDL },
        { "ATT", SqliteUtils::STATEMENT_ATTACH },
        { "BEG", SqliteUtils::STATEMENT_BEGIN },
        { "COM", SqliteUtils::STATEMENT_COMMIT },
        { "CRE", SqliteUtils::STATEMENT_DDL },
        { "DEL", SqliteUtils::STATEMENT_UPDATE },
        { "DET", SqliteUtils::STATEMENT_DETACH },
        { "DRO", SqliteUtils::STATEMENT_DDL },
        { "END", SqliteUtils::STATEMENT_COMMIT },
        { "INS", SqliteUtils::STATEMENT_INSERT },
        { "PRA", SqliteUtils::STATEMENT_PRAGMA },
        { "REP", SqliteUtils::STATEMENT_UPDATE },
        { "ROL", SqliteUtils::STATEMENT_ROLLBACK },
        { "SAV", SqliteUtils::STATEMENT_BEGIN },
        { "SEL", SqliteUtils::STATEMENT_SELECT },
        { "UPD", SqliteUtils::STATEMENT_UPDATE }
    };
    static constexpr size_t TYPE_SIZE = sizeof(SQL_TYPE_MAP) / sizeof(SqlType);
    static constexpr const char *ON_CONFLICT_CLAUSE[CONFLICT_CLAUSE_COUNT] = { "", " OR ROLLBACK", " OR ABORT",
        " OR FAIL", " OR IGNORE", " OR REPLACE" };

    static std::string GetAnonymousName(const std::string &fileName);
    static std::string AnonymousDigits(const std::string &digits);
    static bool IsKeyword(const std::string& word);
    static std::string GetModeInfo(uint32_t st_mode);
    static int GetPageCountCallback(void *data, int argc, char **argv, char **azColName);
    static bool HasPermit(const std::string &path, mode_t mode);
    static bool SetDefaultGid(const std::string &path, int32_t gid);
};

} // namespace NativeRdb
} // namespace OHOS
#endif
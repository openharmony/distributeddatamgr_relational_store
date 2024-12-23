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

#include "sqlite3sym.h"

namespace OHOS {
namespace NativeRdb {

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
    static constexpr const char *REP = "#_";
    static constexpr const char *SLAVE_FAILURE = "-slaveFailure";
    static constexpr const char *SLAVE_INTERRUPT = "-syncInterrupt";

    static int GetSqlStatementType(const std::string &sql);
    static bool IsSupportSqlForExecute(int sqlType);
    static bool IsSqlReadOnly(int sqlType);
    static bool IsSpecial(int sqlType);
    static const char *GetConflictClause(int conflictResolution);
    static std::string StrToUpper(std::string s);
    static void Replace(std::string &src, const std::string &rep, const std::string &dst);
    static bool DeleteFile(const std::string &filePath);
    static bool RenameFile(const std::string &srcFile, const std::string &destFile);
    static bool CopyFile(const std::string &srcFile, const std::string &destFile);
    static std::string Anonymous(const std::string &srcFile);
    static std::string AnonySql(const std::string &sql);
    static ssize_t GetFileSize(const std::string &fileName);
    static bool IsSlaveDbName(const std::string &fileName);
    static std::string GetSlavePath(const std::string &name);
    static int SetSlaveInvalid(const std::string &dbPath);
    static int SetSlaveInterrupted(const std::string &dbPath);
    static bool IsSlaveInvalid(const std::string &dbPath);
    static bool IsSlaveInterrupted(const std::string &dbPath);
    static void SetSlaveValid(const std::string &dbPath);
    static const char *HmacAlgoDescription(int32_t hmacAlgo);
    static const char *KdfAlgoDescription(int32_t kdfAlgo);
    static const char *EncryptAlgoDescription(int32_t encryptAlgo);

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

    static std::string GetAnonymousName(const std::string& fileName);
    static std::string AnonyDigits(const std::string& fileName);
    static bool IsSpecialChar(char c);
    static std::vector<std::string> SplitString(const std::string &input);
    static std::string ReplaceMultipleSpaces(const std::string &str);
    static std::string AnonyWord(const std::string &word);
    static bool Find(const std::string &word, const char *const array[], uint32_t length);
    static std::string AnonySqlString(const std::string &input, const char *const array[], uint32_t length);
};

} // namespace NativeRdb
} // namespace OHOS
#endif
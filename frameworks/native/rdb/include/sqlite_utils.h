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
    static constexpr const char* REP = "#_";

    static int GetSqlStatementType(const std::string &sql);
    static bool IsSupportSqlForExecute(int sqlType);
    static bool IsSqlReadOnly(int sqlType);
    static bool IsSpecial(int sqlType);
    static const char *GetConflictClause(int conflictResolution);
    static std::string StrToUpper(std::string s);
    static void Replace(std::string &src, const std::string &rep, const std::string &dst);
    static bool DeleteFile(const std::string &filePath);
    static int RenameFile(const std::string &srcFile, const std::string &destFile);
    static std::string Anonymous(const std::string &srcFile);
    static int GetFileSize(const std::string &fileName);

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
        { "SEL", SqliteUtils::STATEMENT_SELECT },
        { "UPD", SqliteUtils::STATEMENT_UPDATE }
    };
    static constexpr size_t TYPE_SIZE = sizeof(SQL_TYPE_MAP) / sizeof(SqlType);
    static constexpr const char* ON_CONFLICT_CLAUSE[CONFLICT_CLAUSE_COUNT] = { "", " OR ROLLBACK", " OR ABORT",
        " OR FAIL", " OR IGNORE", " OR REPLACE" };
};

} // namespace NativeRdb
} // namespace OHOS
#endif
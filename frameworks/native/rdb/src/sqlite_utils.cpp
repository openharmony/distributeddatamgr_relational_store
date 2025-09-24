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
#include <sqlite3sym.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstdio>
#include <cstring>
#if !defined(CROSS_PLATFORM)
#include <sqlite3.h>
#include "relational/relational_store_sqlite_ext.h"
#endif
#include <fstream>
#include <regex>
#include <string>
#include <sstream>
#include <iomanip>

#include "acl.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_file_system.h"
#include "rdb_platform.h"
#include "rdb_store_config.h"
#include "string_utils.h"
#include "rdb_time_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using namespace OHOS::DATABASE_UTILS;
/* A continuous number must contain at least eight digits, because the employee ID has eight digits,
    and the mobile phone number has 11 digits. The UUID is longer */
constexpr int32_t CONTINUOUS_DIGITS_MINI_SIZE = 6;
constexpr int32_t FILE_PATH_MINI_SIZE = 6;
constexpr int32_t AREA_MINI_SIZE = 4;
constexpr int32_t AREA_OFFSET_SIZE = 5;
constexpr int32_t PRE_OFFSET_SIZE = 1;
constexpr int32_t DISPLAY_BYTE = 2;
constexpr int32_t PREFIX_LENGTH = 3;
constexpr int32_t FILE_MAX_SIZE = 20 * 1024;

constexpr int32_t HEAD_SIZE = 3;
constexpr int32_t END_SIZE = 3;
constexpr int32_t MIN_SIZE = HEAD_SIZE + END_SIZE + 3;
constexpr const char *REPLACE_CHAIN = "***";
constexpr const unsigned char MAX_PRINTABLE_BYTE = 0x7F;

constexpr SqliteUtils::SqlType SqliteUtils::SQL_TYPE_MAP[];
constexpr const char *SqliteUtils::ON_CONFLICT_CLAUSE[];
constexpr char const *DATABASE = "database";

bool SqliteUtils::HasPermit(const std::string &path, mode_t mode)
{
    struct stat fileStat;
    if (stat(path.c_str(), &fileStat) == 0) {
        if (S_ISDIR(fileStat.st_mode) && ((fileStat.st_mode & mode) == mode)) {
            return true;
        }
    }
    return false;
}

bool SqliteUtils::HasAccessAcl(const std::string &path, int32_t gid)
{
    struct stat fileStat;
    if (stat(path.c_str(), &fileStat) != 0) {
        return false;
    }
    Acl aclAccess(path, Acl::ACL_XATTR_ACCESS);
    if (aclAccess.HasAccessGroup(gid, Acl::R_RIGHT | Acl::W_RIGHT | Acl::E_RIGHT)) {
        return true;
    }
    return false;
}

bool SqliteUtils::HasDefaultAcl(const std::string &path, int32_t gid)
{
    struct stat fileStat;
    if (stat(path.c_str(), &fileStat) != 0) {
        return false;
    }
    Acl aclAccess(path, Acl::ACL_XATTR_DEFAULT);
    if (aclAccess.HasDefaultGroup(gid, Acl::R_RIGHT | Acl::W_RIGHT | Acl::E_RIGHT)) {
        return true;
    }
    return false;
}

bool SqliteUtils::SetDefaultGid(const std::string &path, int32_t gid)
{
    uint16_t mode = Acl::R_RIGHT | Acl::W_RIGHT | Acl::E_RIGHT;
    struct stat fileStat;
    if (stat(path.c_str(), &fileStat) != 0) {
        return false;
    }
    Acl aclAccess(path, Acl::ACL_XATTR_ACCESS);
    Acl aclDefault(path, Acl::ACL_XATTR_DEFAULT);
    if (aclAccess.HasAccessGroup(gid, mode) && aclDefault.HasDefaultGroup(gid, mode)) {
        return true;
    }
    if ((aclAccess.SetAccessGroup(gid, mode) != E_OK) || (aclDefault.SetDefaultGroup(gid, mode) != E_OK)) {
        return false;
    }
    auto entries = RdbFileSystem::GetEntries(path);
    for (const auto &entry : entries) {
        Acl aclAccess(entry, Acl::ACL_XATTR_ACCESS);
        if ((aclAccess.SetAccessGroup(gid, mode) != E_OK)) {
            return false;
        }
    }
    return true;
}

bool SqliteUtils::SetDbFileGid(const std::string &path, const std::vector<std::string> &files, int32_t gid)
{
    if (files.empty()) {
        return false;
    }
    bool ret = true;
    uint16_t mode = Acl::R_RIGHT | Acl::W_RIGHT | Acl::E_RIGHT;
    std::string dbDir = StringUtils::ExtractFilePath(path);
    for (const auto &file : files) {
        std::string dbPath = dbDir + file;
        struct stat fileStat;
        if (stat((dbPath).c_str(), &fileStat) != 0) {
            continue;
        }
        Acl aclAccess(dbPath, Acl::ACL_XATTR_ACCESS);
        
        if (aclAccess.HasAccessGroup(gid, mode)) {
            continue;
        }
        if ((aclAccess.SetAccessGroup(gid, mode) != E_OK)) {
            ret = false;
        }
    }
    return ret;
}

bool SqliteUtils::SetDbDirGid(const std::string &path, int32_t gid, bool isDefault)
{
    if (path.empty()) {
        return false;
    }
    if (isDefault) {
        return SetDefaultGid(path, gid);
    }
    bool ret = true;
    uint16_t mode = Acl::R_RIGHT | Acl::W_RIGHT | Acl::E_RIGHT;
    std::string tempDirectory = path;
    std::string dbDir = "";
    bool isSetAcl = false;
    size_t pos = tempDirectory.find('/');
    while (pos != std::string::npos) {
        std::string directory = tempDirectory.substr(0, pos);
        tempDirectory = tempDirectory.substr(pos + 1);
        pos = tempDirectory.find('/');
        if (directory.empty()) {
            continue;
        }
        if (directory == DATABASE) {
            isSetAcl = true;
        }
        dbDir = dbDir + "/" + directory;
        if (!isSetAcl) {
            continue;
        }
        if (HasPermit(dbDir, S_IXOTH)) {
            continue;
        }
        Acl aclAccess(dbDir, Acl::ACL_XATTR_ACCESS);
        if (aclAccess.HasAccessGroup(gid, mode)) {
            continue;
        }
        if ((aclAccess.SetAccessGroup(gid, mode) != E_OK)) {
            ret = false;
        }
    }
    return ret;
}

constexpr const char *SQL_KEYWORD[] = { "ABORT", "ABS", "ACTION", "ADD", "AFTER", "ALIAS", "ALL", "ALTER", "ALWAYS",
    "AMBIGUOUS", "ANALYZE", "AND", "AS", "ASC", "ATTACH", "AUTOINCREMENT", "AVG", "BEFORE", "BEGIN", "BETWEEN", "BIG",
    "BIGINT", "BLOB", "BOOLEAN", "BY", "CASCADE", "CASE", "CAST", "CEIL", "CEILING", "CHARACTER", "CHECK", "CLOB",
    "COALESCE", "COLLATE", "COLUMN", "COMMIT", "CONCAT", "CONFLICT", "CONSTRAINT", "COUNT", "CREATE", "CROSS",
    "CURRENT", "CURRENT_DATE", "CURRENT_TIME", "CURRENT_TIMESTAMP", "DATABASE", "DATE", "DATETIME", "DECIMAL",
    "DEFAULT", "DEFERRABLE", "DEFERRED", "DELETE", "DESC", "DETACH", "DIGIT", "DISTINCT", "DO", "DOUBLE", "DROP", "E",
    "EACH", "ELSE", "END", "ESCAPE", "EXCEPT", "EXCLUDE", "EXCLUSIVE", "EXISTS", "EXP", "EXPLAIN", "EXPR", "FAIL",
    "FALSE", "FILENAME", "FILTER", "FIRST", "FLOAT", "FLOOR", "FOLLOWING", "FOR", "FOREIGN", "FROM", "FULL",
    "GENERATED", "GLOB", "GROUP", "GROUPS", "GROUP_CONCAT", "HAVING", "HEXDIGIT", "IF", "IFNULL", "IGNORE", "IMMEDIATE",
    "IN", "INDEX", "INDEXED", "INITIALLY", "INNER", "INSERT", "INSTEAD", "INSTR", "INT", "INT2", "INT8", "INTEGER",
    "INTERSECT", "INTO", "IS", "ISNULL", "JOIN", "JULIANDAY", "KEY", "LAST", "LEFT", "LENGTH", "LIKE", "LIMIT", "LN",
    "LOG", "LOWER", "LTRIM", "MATCH", "MATERIALIZED", "MAX", "MEDIUMINT", "MIN", "NAME", "NATIVE", "NATURAL", "NCHAR",
    "NEWLINE", "NO", "NOT", "NOTHING", "NOTNULL", "NULL", "NULLIF", "NULLS", "NUMERIC", "NVARCHAR", "OF", "OFFSET",
    "ON", "OR", "ORDER", "OTHERS", "OUTER", "OVER", "PARTITION", "PLAN", "POWER", "PRAGMA", "PRECEDING", "PRECISION",
    "PRIMARY", "QUERY", "RAISE", "RANDOM", "RANGE", "REAL", "RECURSIVE", "REFERENCES", "REGEXP", "REINDEX", "RELEASE",
    "RENAME", "REPLACE", "RESTRICT", "RETURNING", "RIGHT", "ROLLBACK", "ROUND", "ROW", "ROWID", "ROWS", "RTRIM",
    "SAVEPOINT", "SELECT", "SET", "SMALLINT", "SQRT", "STORED", "STRFTIME", "STRICT", "SUBSTR", "SUM", "TABLE", "TEMP",
    "TEMPORARY", "TEXT", "THEN", "TIES", "TIME", "TINYINT", "TO", "TOTAL", "TRANSACTION", "TRIGGER", "TRIM", "TRUE",
    "TYPEOF", "UNBOUNDED", "UNION", "UNIQUE", "UNSIGNED", "UPDATE", "UPPER", "USING", "VACUUM", "VALUES", "VARCHAR",
    "VARYING", "VIEW", "VIRTUAL", "WHEN", "WHERE", "WINDOW", "WITH", "WITHOUT" };

constexpr const char *WHILE_KEYWORDS[] = { "ABORTS", "ACQLOCK", "ALREADY", "AT", "BUSYLINE", "CHANGED", "CURLOCK",
    "DBREF", "DEL", "DUPLICATE", "ENABLE", "ERRNO", "ERROR", "FAILED", "FD", "FILE", "FILELOCK", "FRAMES", "F_RDLCK",
    "F_WRLCK", "GO", "HANDLELOCKS", "HAS", "IDX", "INCOMPLETE", "INPUT", "LEN", "LINE", "LITERAL", "LOCKCNT", "LOCKS",
    "MISUSE", "MONITOR", "NEAR", "NONE", "PID", "PROCESSLOCK", "QUOTED", "READ", "RECOVERED", "SCHEMA", "SHARED_FIRST",
    "SQLITE", "STATEMENT", "STRING", "SUCH", "SYNTAX", "TID", "TRX", "TYPE", "WAL", "WAL_DMS", "WARNING", "WRITE",
    "WRONG" };

constexpr int32_t WordCompare(const char *a, const char *b)
{
    while (*a && *b && (*a == *b)) {
        ++a;
        ++b;
    }
    return static_cast<unsigned char>(*a) - static_cast<unsigned char>(*b);
}

constexpr bool IsLexSorted(const char *const *keyword, size_t size)
{
    for (size_t i = 1; i < size; ++i) {
        if (WordCompare(keyword[i - 1], keyword[i]) >= 0) {
            return false;
        }
    }
    return true;
}

bool IsMatchKeyword(const char *const *keyword, size_t size, const char *str)
{
    auto it = std::lower_bound(
        keyword, keyword + size, str, [](const char *a, const char *b) { return WordCompare(a, b) < 0; });
    if (it != keyword + size && WordCompare(*it, str) == 0) {
        return true;
    }
    return false;
}

// ensure lexicographical order
static_assert(IsLexSorted(SQL_KEYWORD, sizeof(SQL_KEYWORD) / sizeof(char*)));
static_assert(IsLexSorted(WHILE_KEYWORDS, sizeof(WHILE_KEYWORDS) / sizeof(char*)));

int SqliteUtils::GetSqlStatementType(const std::string &sql)
{
    /* the sql string length less than 3 can not be any type sql */
    auto alnum = std::find_if(sql.begin(), sql.end(), [](int ch) { return !std::isspace(ch) && !std::iscntrl(ch); });
    if (alnum == sql.end()) {
        return STATEMENT_ERROR;
    }
    auto pos = static_cast<std::string::size_type>(alnum - sql.begin());
    /* 3 represents the number of prefix characters that need to be extracted and checked */
    if (pos + 3 >= sql.length()) {
        return STATEMENT_ERROR;
    }
    /* analyze the sql type through first 3 characters */
    std::string prefixSql = StrToUpper(sql.substr(pos, 3));
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

std::string SqliteUtils::StrToUpper(const std::string &s)
{
    std::string str = s;
    std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) { return std::toupper(c); });
    return str;
}

std::string SqliteUtils::Replace(const std::string &src, const std::string &rep, const std::string &dst)
{
    if (src.empty() || rep.empty()) {
        return "";
    }
    auto res = src;
    size_t pos = 0;
    while ((pos = res.find(rep, pos)) != std::string::npos) {
        res.replace(pos, rep.length(), dst);
        pos += dst.length();
    }
    return res;
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
    if (access(filePath.c_str(), F_OK) != 0) {
        return true;
    }
    auto ret = remove(filePath.c_str());
    if (ret != 0) {
        LOG_WARN(
            "remove file failed errno %{public}d ret %{public}d %{public}s", errno, ret, Anonymous(filePath).c_str());
        return false;
    }
    return true;
}

bool SqliteUtils::RenameFile(const std::string &srcFile, const std::string &destFile)
{
    auto ret = rename(srcFile.c_str(), destFile.c_str());
    if (ret != 0) {
        LOG_WARN("rename failed errno %{public}d ret %{public}d %{public}s -> %{public}s", errno, ret,
            SqliteUtils::Anonymous(destFile).c_str(), SqliteUtils::Anonymous(srcFile).c_str());
        return false;
    }
    return true;
}

bool SqliteUtils::DeleteFiles(const std::vector<std::string> &filePaths)
{
    for (auto &filePath : filePaths) {
        if (!DeleteFile(filePath)) {
            return false;
        }
    }
    return true;
}

bool SqliteUtils::CopyFile(const std::string &srcFile, const std::string &destFile)
{
    std::ifstream src(srcFile.c_str(), std::ios::binary);
    if (!src.is_open()) {
        LOG_WARN("open srcFile failed errno %{public}d %{public}s", errno, SqliteUtils::Anonymous(srcFile).c_str());
        return false;
    }
    std::ofstream dst(destFile.c_str(), std::ios::binary);
    if (!dst.is_open()) {
        src.close();
        LOG_WARN("open destFile failed errno %{public}d %{public}s", errno, SqliteUtils::Anonymous(destFile).c_str());
        return false;
    }
    dst << src.rdbuf();
    src.close();
    dst.close();
    return true;
}

std::string SqliteUtils::RemoveSuffix(const std::string &name)
{
    std::string suffix(".db");
    auto pos = name.rfind(suffix);
    if (pos == std::string::npos || pos < name.length() - suffix.length()) {
        return name;
    }
    return { name, 0, pos };
}

size_t SqliteUtils::DeleteFolder(const std::string &folderPath)
{
    auto [count, ec] = RdbFileSystem::RemoveAll(folderPath);
    auto errorCount = static_cast<std::uintmax_t>(-1);
    if (count == errorCount) {
        LOG_WARN("remove folder, %{public}d, %{public}s", ec, Anonymous(folderPath).c_str());
        count = 0;
    }
    return count;
}

bool SqliteUtils::IsKeyword(const std::string &word)
{
    return IsMatchKeyword(SQL_KEYWORD, sizeof(SQL_KEYWORD) / sizeof(char *), StrToUpper(word).c_str()) ||
           IsMatchKeyword(WHILE_KEYWORDS, sizeof(WHILE_KEYWORDS) / sizeof(char *), StrToUpper(word).c_str());
}

std::string SqliteUtils::GetAnonymousName(const std::string &fileName)
{
    if (fileName.empty()) {
        return "";
    }

    if (fileName.length() <= HEAD_SIZE) {
        return fileName.substr(0, 1) + "**";
    }

    if (fileName.length() < MIN_SIZE) {
        return (fileName.substr(0, HEAD_SIZE) + REPLACE_CHAIN);
    }

    return (fileName.substr(0, HEAD_SIZE) + REPLACE_CHAIN + fileName.substr(fileName.length() - END_SIZE, END_SIZE));
}

std::string SqliteUtils::AnonymousDigits(const std::string &digits)
{
    std::string::size_type digitsNum = digits.size();
    if (digitsNum < CONTINUOUS_DIGITS_MINI_SIZE) {
        return digits;
    }
    std::string::size_type endDigitsNum = 4;
    std::string::size_type shortEndDigitsNum = 3;
    std::string name = digits;
    std::string last = "";
    if (digitsNum == CONTINUOUS_DIGITS_MINI_SIZE) {
        last = name.substr(name.size() - shortEndDigitsNum);
    } else {
        last = name.substr(name.size() - endDigitsNum);
    }
    return "***" + last;
}

std::string ByteAnonymous(const std::string &input)
{
    std::string output;
    bool maskCurrent = false;
    for (unsigned char byte : input) {
        if (byte > MAX_PRINTABLE_BYTE) {
            if (!maskCurrent) {
                output += "***";
                maskCurrent = true;
            }
        } else {
            output.push_back(static_cast<char>(byte));
            maskCurrent = false;
        }
    }
    return output;
}

std::string SqliteUtils::SqlAnonymous(const std::string &sql)
{
    std::ostringstream result;
    std::regex idRegex(R"(\b[a-zA-Z0-9_]+\b)");
    auto begin = std::sregex_iterator(sql.begin(), sql.end(), idRegex);
    auto end = std::sregex_iterator();

    size_t lastPos = 0;
    for (auto it = begin; it != end; ++it) {
        std::smatch match = *it;
        std::string word = match.str();
        size_t pos = static_cast<size_t>(match.position());

        result << ByteAnonymous(sql.substr(lastPos, pos - lastPos));

        lastPos = pos + word.length();
        if (std::regex_match(word, std::regex(R"(\b[0-9a-fA-F]+\b)"))) {
            result << AnonymousDigits(word);
        } else if (IsKeyword(word)) {
            result << std::move(word);
        } else {
            result << GetAnonymousName(word);
        }
    }

    result << ByteAnonymous(sql.substr(lastPos));
    return result.str();
}

std::string SqliteUtils::Anonymous(const std::string &srcFile)
{
    auto pre = srcFile.find("/");
    auto end = srcFile.rfind("/");
    if (pre == std::string::npos || end - pre < FILE_PATH_MINI_SIZE) {
        return GetAnonymousName(srcFile);
    }
    auto path = srcFile.substr(pre, end - pre);
    auto area = path.find("/el");
    if (area == std::string::npos || area + AREA_MINI_SIZE > path.size()) {
        path = "";
    } else if (area + AREA_OFFSET_SIZE < path.size()) {
        path = path.substr(area, AREA_MINI_SIZE) + "/***";
    } else {
        path = path.substr(area, AREA_MINI_SIZE);
    }
    std::string fileName = srcFile.substr(end + 1); // rdb file name
    fileName = GetAnonymousName(fileName);
    return srcFile.substr(0, pre + PRE_OFFSET_SIZE) + "***" + path + "/" + fileName;
}

std::string SqliteUtils::GetArea(const std::string &srcFile)
{
    size_t start = srcFile.find("/el");
    if (start == std::string::npos) {
        return "";
    }
    size_t end = srcFile.find("/", start + 1);
    if (end != std::string::npos) {
        return srcFile.substr(start + 1, end - start - 1);
    }
    return "";
}

ssize_t SqliteUtils::GetFileSize(const std::string &fileName)
{
    struct stat fileStat;
    if (fileName.empty() || stat(fileName.c_str(), &fileStat) < 0) {
        if (errno != ENOENT) {
            LOG_ERROR("failed, errno: %{public}d, fileName:%{public}s", errno, Anonymous(fileName).c_str());
        }
        return 0;
    }

    return fileStat.st_size;
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

std::string SqliteUtils::GetSlavePath(const std::string &name)
{
    std::string suffix(".db");
    std::string slaveSuffix("_slave.db");
    auto pos = name.rfind(suffix);
    if (pos == std::string::npos || pos < name.length() - suffix.length()) {
        return name + slaveSuffix;
    }
    return name.substr(0, pos) + slaveSuffix;
}

const char *SqliteUtils::HmacAlgoDescription(int32_t hmacAlgo)
{
    HmacAlgo hmacEnum = static_cast<HmacAlgo>(hmacAlgo);
    switch (hmacEnum) {
        case HmacAlgo::SHA1:
            return "sha1";
        case HmacAlgo::SHA256:
            return "sha256";
        case HmacAlgo::SHA512:
            return "sha512";
        default:
            return "sha256";
    }
}

const char *SqliteUtils::KdfAlgoDescription(int32_t kdfAlgo)
{
    KdfAlgo kdfEnum = static_cast<KdfAlgo>(kdfAlgo);
    switch (kdfEnum) {
        case KdfAlgo::KDF_SHA1:
            return "kdf_sha1";
        case KdfAlgo::KDF_SHA256:
            return "kdf_sha256";
        case KdfAlgo::KDF_SHA512:
            return "kdf_sha512";
        default:
            return "kdf_sha256";
    }
}

const char *SqliteUtils::EncryptAlgoDescription(int32_t encryptAlgo)
{
    EncryptAlgo encryptEnum = static_cast<EncryptAlgo>(encryptAlgo);
    switch (encryptEnum) {
        case EncryptAlgo::AES_256_CBC:
            return "aes-256-cbc";
        case EncryptAlgo::AES_256_GCM:
        default:
            return "aes-256-gcm";
    }
}

int SqliteUtils::SetSlaveInvalid(const std::string &dbPath)
{
    if (IsSlaveInvalid(dbPath)) {
        return E_OK;
    }
    std::ofstream src((dbPath + SLAVE_FAILURE).c_str(), std::ios::binary);
    if (src.is_open()) {
        src.close();
        return E_OK;
    }
    return E_ERROR;
}

int SqliteUtils::SetSlaveInterrupted(const std::string &dbPath)
{
    if (IsSlaveInterrupted(dbPath)) {
        return E_OK;
    }
    std::ofstream src((dbPath + SLAVE_INTERRUPT).c_str(), std::ios::binary);
    if (src.is_open()) {
        src.close();
        return E_OK;
    }
    return E_ERROR;
}

bool SqliteUtils::IsSlaveInvalid(const std::string &dbPath)
{
    return access((dbPath + SLAVE_FAILURE).c_str(), F_OK) == 0;
}

bool SqliteUtils::IsSlaveInterrupted(const std::string &dbPath)
{
    return access((dbPath + SLAVE_INTERRUPT).c_str(), F_OK) == 0;
}

bool SqliteUtils::IsFileEmpty(const std::string &filePath)
{
    struct stat fileInfo;
    auto errCode = stat(filePath.c_str(), &fileInfo);
    if (errCode != 0) {
        return true;
    }
    return fileInfo.st_size == 0;
}

bool SqliteUtils::IsFilesEmpty(const std::vector<std::string> &filePaths)
{
    for (auto &filePath :filePaths) {
        if (!IsFileEmpty(filePath)) {
            LOG_ERROR("keyfiles is not empty");
            return false;
        }
    }
    return true;
}

int SqliteUtils::GetPageCountCallback(void *data, int argc, char **argv, char **azColName)
{
    int64_t *count = (int64_t *)data;
    if (argc > 0 && argv[0] != NULL) {
        char *endptr = nullptr;
        *count = static_cast<int64_t>(strtoll(argv[0], &endptr, 10)); // 10 means decimal
    }
    return 0;
}

ssize_t SqliteUtils::GetDecompressedSize(const std::string &dbPath)
{
    sqlite3 *dbHandle = nullptr;
    int errCode = sqlite3_open_v2(dbPath.c_str(), &dbHandle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nullptr);
    if (errCode != SQLITE_OK) {
        LOG_WARN("failed to open %{public}s to calculate size", Anonymous(dbPath).c_str());
        sqlite3_close_v2(dbHandle);
        return 0;
    }
    int64_t pageCount = 0;
    errCode = sqlite3_exec(dbHandle, "SELECT COUNT(1) FROM vfs_pages;", GetPageCountCallback, &pageCount, nullptr);
    sqlite3_close_v2(dbHandle);
    if (errCode != SQLITE_OK) {
        LOG_WARN("failed to get page count, %{public}s", Anonymous(dbPath).c_str());
        return 0;
    }
    // 4096 is the pageSize, which is 4K
    auto size = pageCount * 4096;
    if (size > SSIZE_MAX) {
        LOG_WARN("actual size overflow:%{public}" PRId64, size);
        return SSIZE_MAX;
    }
    return (ssize_t)size;
}

bool SqliteUtils::IsSlaveLarge(const std::string &dbPath)
{
    auto slavePath = GetSlavePath(dbPath);
    if (sqlite3_is_support_binlog(StringUtils::ExtractFileName(dbPath).c_str()) == SQLITE_OK) {
        auto size = GetDecompressedSize(slavePath);
        if (size > 0) {
            return size > SLAVE_ASYNC_REPAIR_CHECK_LIMIT;
        }
    }
    std::pair<int32_t, DistributedRdb::RdbDebugInfo> fileInfo = Stat(slavePath);
    if (fileInfo.first == E_OK) {
        return fileInfo.second.size_ > SLAVE_ASYNC_REPAIR_CHECK_LIMIT;
    }
    return false;
}

int SqliteUtils::SetSlaveRestoring(const std::string &dbPath, bool isRestore)
{
    if (IsSlaveRestoring(dbPath)) {
        if (!isRestore) {
            std::remove((dbPath + SLAVE_RESTORE).c_str());
        }
        return E_OK;
    }
    std::ofstream src((dbPath + SLAVE_RESTORE).c_str(), std::ios::binary);
    if (src.is_open()) {
        src.close();
        return E_OK;
    }
    return E_ERROR;
}

bool SqliteUtils::IsSlaveRestoring(const std::string &dbPath)
{
    return access((dbPath + SLAVE_RESTORE).c_str(), F_OK) == 0;
}

void SqliteUtils::SetSlaveValid(const std::string &dbPath)
{
    std::remove((dbPath + SLAVE_INTERRUPT).c_str());
    std::remove((dbPath + SLAVE_FAILURE).c_str());
}

bool SqliteUtils::DeleteDirtyFiles(const std::string &backupFilePath)
{
    auto res = DeleteFile(backupFilePath);
    res = DeleteFile(backupFilePath + "-shm") && res;
    res = DeleteFile(backupFilePath + "-wal") && res;
    return res;
}

std::pair<int32_t, DistributedRdb::RdbDebugInfo> SqliteUtils::Stat(const std::string &path)
{
    DistributedRdb::RdbDebugInfo info;
    struct stat fileStat;
    if (stat(path.c_str(), &fileStat) != 0) {
        return std::pair{ E_ERROR, info };
    }
    info.inode_ = fileStat.st_ino;
    info.oldInode_ = 0;
    info.atime_.sec_ = fileStat.st_atime;
    info.mtime_.sec_ = fileStat.st_mtime;
    info.ctime_.sec_ = fileStat.st_ctime;
#if !defined(CROSS_PLATFORM)
    info.atime_.nsec_ = fileStat.st_atim.tv_nsec;
    info.mtime_.nsec_ = fileStat.st_mtim.tv_nsec;
    info.ctime_.nsec_ = fileStat.st_ctim.tv_nsec;
#endif
    info.size_ = fileStat.st_size;
    info.dev_ = fileStat.st_dev;
    info.mode_ = fileStat.st_mode;
    info.uid_ = fileStat.st_uid;
    info.gid_ = fileStat.st_gid;
    return std::pair{ E_OK, info };
}

std::string SqliteUtils::ReadFileHeader(const std::string &filePath)
{
    constexpr int MAX_SIZE = 98;
    std::ifstream file(filePath, std::ios::binary);
    uint8_t data[MAX_SIZE] = {0};
    if (file.is_open()) {
        file.read(reinterpret_cast<char *>(data), MAX_SIZE);
        file.close();
    }
    std::stringstream ss;
    for (int i = 0; i < MAX_SIZE; i++) {
        ss << std::hex << std::setw(DISPLAY_BYTE) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return "DB_HEAD:" + ss.str();
}

std::string SqliteUtils::GetFileStatInfo(const DebugInfo &debugInfo)
{
    std::stringstream oss;
    oss << " dev:0x" << std::hex << debugInfo.dev_ << " ino:0x" << std::hex << debugInfo.inode_;
    if (debugInfo.inode_ != debugInfo.oldInode_ && debugInfo.oldInode_ != 0) {
        oss << "<>0x" << std::hex << debugInfo.oldInode_;
    }
    oss << " " << GetModeInfo(debugInfo.mode_) << " size:" << std::dec << debugInfo.size_ << " uid:" << std::dec
        << debugInfo.uid_ << " gid:" << std::dec << debugInfo.gid_
        << " atim:" << RdbTimeUtils::GetTimeWithMs(debugInfo.atime_.sec_, debugInfo.atime_.nsec_)
        << " mtim:" << RdbTimeUtils::GetTimeWithMs(debugInfo.mtime_.sec_, debugInfo.mtime_.nsec_)
        << " ctim:" << RdbTimeUtils::GetTimeWithMs(debugInfo.ctime_.sec_, debugInfo.ctime_.nsec_);
    return oss.str();
}

bool SqliteUtils::CleanFileContent(const std::string &filePath)
{
    struct stat fileStat;
    if (stat(filePath.c_str(), &fileStat) != 0) {
        return false;
    }
    if (fileStat.st_size < FILE_MAX_SIZE) {
        return false;
    }
    return DeleteFile(filePath);
}

void SqliteUtils::WriteSqlToFile(const std::string &comparePath, const std::string &sql)
{
    int fd = open(comparePath.c_str(), O_RDWR | O_CREAT, 0660);
    if (fd == -1) {
        LOG_ERROR("open file failed errno %{public}d %{public}s", errno, Anonymous(comparePath).c_str());
        return ;
    }
    if (flock(fd, LOCK_EX) == -1) {
        LOG_ERROR("Failed to lock file errno %{public}d %{public}s", errno, Anonymous(comparePath).c_str());
        close(fd);
        return ;
    }
    std::ofstream outFile(comparePath, std::ios::app);
    if (!outFile) {
        flock(fd, LOCK_UN);
        close(fd);
        return ;
    }

    outFile << sql << "\n";
    outFile.close();
    if (flock(fd, LOCK_UN) == -1) {
        LOG_ERROR("Failed to unlock file errno %{public}d %{public}s", errno, Anonymous(comparePath).c_str());
    }
    close(fd);
}

std::string SqliteUtils::GetErrInfoFromMsg(const std::string &message, const std::string &errStr)
{
    size_t startPos = message.find(errStr);
    std::string result;
    if (startPos != std::string::npos) {
        startPos += errStr.length();
        size_t endPos = message.length();
        result = message.substr(startPos, endPos - startPos);
    }
    return result;
}

ErrMsgState SqliteUtils::CompareTableFileContent(
    const std::string &dbPath, const std::string &bundleName, const std::string &tableName)
{
    ErrMsgState state;
    std::string compareFilePath = dbPath + "-compare";
    std::ifstream file(compareFilePath.c_str());
    if (!file.is_open()) {
        LOG_ERROR("compare File open failed errno %{public}d %{public}s", errno, Anonymous(compareFilePath).c_str());
        return state;
    }

    std::string line;
    while (getline(file, line)) {
        std::string target = line;
        if (target.find(tableName) == std::string::npos) {
            continue;
        }
        std::transform(target.begin(), target.end(), target.begin(), ::toupper);
        if (target.substr(0, PREFIX_LENGTH) == "CRE") {
            state.isCreated = true;
            state.isDeleted = false;
            state.isRenamed = false;
        } else if (target.substr(0, PREFIX_LENGTH) == "DRO") {
            state.isDeleted = true;
            state.isRenamed = false;
        } else if (target.substr(0, PREFIX_LENGTH) == "ALT" && target.find("RENAME") != std::string::npos) {
            state.isDeleted = false;
            state.isRenamed = true;
        }
    }
    file.close();
    return state;
}

ErrMsgState SqliteUtils::CompareColumnFileContent(
    const std::string &dbPath, const std::string &bundleName, const std::string &columnName)
{
    ErrMsgState state;
    std::string compareFilePath = dbPath + "-compare";
    std::ifstream file(compareFilePath.c_str());
    if (!file.is_open()) {
        LOG_ERROR("compare File open failed errno %{public}d %{public}s", errno, Anonymous(compareFilePath).c_str());
        return state;
    }

    std::string line;
    while (getline(file, line)) {
        std::string target = line;
        if (target.find(columnName) == std::string::npos) {
            continue;
        }
        std::transform(target.begin(), target.end(), target.begin(), ::toupper);
        if (target.substr(0, PREFIX_LENGTH) == "CRE" || (
            target.substr(0, PREFIX_LENGTH) == "ALT" && target.find("ADD") != std::string::npos)) {
            state.isCreated = true;
            state.isDeleted = false;
            state.isRenamed = false;
        } else if (target.substr(0, PREFIX_LENGTH) == "ALT" && target.find("DROP") != std::string::npos) {
            state.isDeleted = true;
            state.isRenamed = false;
        } else if (target.substr(0, PREFIX_LENGTH) == "ALT" && target.find("RENAME") != std::string::npos) {
            state.isDeleted = false;
            state.isRenamed = true;
        }
    }
    file.close();
    return state;
}

std::string SqliteUtils::FormatDebugInfo(const std::map<std::string, DebugInfo> &debugs, const std::string &header)
{
    if (debugs.empty()) {
        return "";
    }
    std::string appendix = header;
    for (auto &[name, debugInfo] : debugs) {
        appendix += "\n" + name + " :" + GetFileStatInfo(debugInfo);
    }
    return appendix;
}

std::string SqliteUtils::FormatDebugInfoBrief(const std::map<std::string, DebugInfo> &debugs,
    const std::string &header)
{
    if (debugs.empty()) {
        return "";
    }
    std::stringstream oss;
    oss << header << ":";
    for (auto &[name, debugInfo] : debugs) {
        oss << "<" << name << ",0x" << std::hex << debugInfo.inode_ << "," << std::dec << debugInfo.size_ << ","
            << std::oct << debugInfo.mode_ << ">";
    }
    return oss.str();
}
std::string SqliteUtils::FormatDfxInfo(const DfxInfo &dfxInfo)
{
    std::stringstream oss;
    oss << "LastOpen:" << dfxInfo.lastOpenTime_ << "," << "CUR_USER:" << dfxInfo.curUserId_;
    return oss.str();
}

std::string SqliteUtils::GetModeInfo(uint32_t st_mode)
{
    std::ostringstream oss;
    const uint32_t permission = 0777;
    oss << "mode:";
    if (S_ISDIR(st_mode))
        oss << 'd';
    else
        oss << '-';

    oss << std::setw(PREFIX_LENGTH) << std::setfill('0') << std::oct << (st_mode & permission);

    return oss.str();
}

std::string SqliteUtils::GetParentModes(const std::string &path, int pathDepth)
{
    std::vector<std::pair<std::string, std::string>> dirModes;
    std::string currentPath = path;

    for (int i = 0; i < pathDepth; ++i) {
        currentPath = StringUtils::GetParentPath(currentPath);
        if (currentPath == "/" || currentPath.empty()) {
            break;
        }

        std::string dirName = StringUtils::ExtractFileName(currentPath);
        struct stat st {};
        dirModes.emplace_back(dirName, (stat(currentPath.c_str(), &st) == 0) ? GetModeInfo(st.st_mode) : "access_fail");
    }
    std::string result;
    for (auto it = dirModes.rbegin(); it != dirModes.rend(); ++it) {
        if (!result.empty()) {
            result += " <- ";
        }
        result += (it->first.size() > PREFIX_LENGTH ? it->first.substr(0, PREFIX_LENGTH) + "***" : it->first) + ":" +
                  it->second;
    }
    return result.empty() ? "no_parent" : result;
}
} // namespace NativeRdb
} // namespace OHOS

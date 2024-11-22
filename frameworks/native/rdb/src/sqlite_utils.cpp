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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <regex>
#include <string>

#include "logger.h"
#include "rdb_errno.h"
#include "rdb_store_config.h"
#include "string_utils.h"
namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

/* A continuous number must contain at least eight digits, because the employee ID has eight digits,
    and the mobile phone number has 11 digits. The UUID is longer */
constexpr int32_t CONTINUOUS_DIGITS_MINI_SIZE = 6;
constexpr int32_t FILE_PATH_MINI_SIZE = 6;
constexpr int32_t AREA_MINI_SIZE = 4;
constexpr int32_t AREA_OFFSET_SIZE = 5;
constexpr int32_t PRE_OFFSET_SIZE = 1;
constexpr int32_t CREATE_DATABASE_SIZE = 15;
constexpr int32_t SQL_TYPE_SIZE = 3;
constexpr int32_t MIN_ANONYMIZE_LENGTH = 2;
constexpr int32_t MAX_ANONYMIZE_LENGTH = 4;
constexpr int32_t OTHER_SIZE = 6;
constexpr int32_t START_SIZE = 0;
const std::vector<std::string> SELECT_ARRAY = { "AS", "GROUPBY", "GROUP", "BY", "LIMIT", "COUNT", "AVERAGE", "SELECT",
    "FROM", "WHERE", "DISTRICT" };
const std::vector<std::string> INSERT_ARRAY = { "INSERT", "INTO", "VALUES" };
const std::vector<std::string> UPDATE_ARRAY = { "UPDATE", "SET", "WHERE", "AND", "OR" };
const std::vector<std::string> DELETE_ARRAY = { "DELETE", "FROM", "WHERE" };
const std::vector<std::string> DROP_ARRAY = { "DROP", "TABLE", "IF", "EXISTS", "DATABASE" };
const std::vector<std::string> PRAGMA_ARRAY = { "PRAGMA" };

constexpr SqliteUtils::SqlType SqliteUtils::SQL_TYPE_MAP[];
constexpr const char *SqliteUtils::ON_CONFLICT_CLAUSE[];

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

std::string SqliteUtils::GetAnonymousName(const std::string &fileName)
{
    std::vector<std::string> alnum;
    std::vector<std::string> noAlnum;
    std::string alnumStr;
    std::string noAlnumStr;
    for (const auto &letter : fileName) {
        if (isxdigit(letter)) {
            if (!noAlnumStr.empty()) {
                noAlnum.push_back(noAlnumStr);
                noAlnumStr.clear();
                alnum.push_back("");
            }
            alnumStr += letter;
        } else {
            if (!alnumStr.empty()) {
                alnum.push_back(alnumStr);
                alnumStr.clear();
                noAlnum.push_back("");
            }
            noAlnumStr += letter;
        }
    }
    if (!alnumStr.empty()) {
        alnum.push_back(alnumStr);
        noAlnum.push_back("");
    }
    if (!noAlnumStr.empty()) {
        noAlnum.push_back(noAlnumStr);
        alnum.push_back("");
    }
    std::string res = "";
    for (size_t i = 0; i < alnum.size(); ++i) {
        res += (AnonyDigits(alnum[i]) + noAlnum[i]);
    }
    return res;
}

std::string SqliteUtils::AnonyDigits(const std::string &fileName)
{
    std::string::size_type digitsNum = fileName.size();
    if (digitsNum < CONTINUOUS_DIGITS_MINI_SIZE) {
        return fileName;
    }
    std::string::size_type endDigitsNum = 4;
    std::string::size_type shortEndDigitsNum = 3;
    std::string name = fileName;
    std::string last = "";
    if (digitsNum == CONTINUOUS_DIGITS_MINI_SIZE) {
        last = name.substr(name.size() - shortEndDigitsNum);
    } else {
        last = name.substr(name.size() - endDigitsNum);
    }
    return "***" + last;
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
    std::string fileName = srcFile.substr(end); // rdb file name
    fileName = GetAnonymousName(fileName);
    return srcFile.substr(0, pre + PRE_OFFSET_SIZE) + "***" + path + fileName;
}

bool IsSpecialChar(char c)
{
    return (c == ' ' || c == '.' || c == ',' || c == '!' || c == '?' || c == ':' || c == '(' || c == ')' || c == ';');
}

std::vector<std::string> SplitString(const std::string &input)
{
    std::vector<std::string> result;
    std::string word;
    for (char c : input) {
        if (!IsSpecialChar(c)) {
            word += c;
        } else {
            if (!word.empty()) {
                result.push_back(word);
                word.clear();
            }
            result.push_back(std::string(1, c));
        }
    }
    if (!word.empty()) {
        result.push_back(word);
    }
    return result;
}

std::string ReplaceMultipleSpaces(const std::string &str)
{
    std::string result = str;
    if (result.empty()) {
        return result;
    }

    result.erase(0, result.find_first_not_of(" "));
    result.erase(result.find_last_not_of(" ") + 1);
    return std::regex_replace(result, std::regex(" +"), " ");
}

std::string AnonyWord(const std::string &word)
{
    std::string anonyWord = word;
    if (word.size() == 1 && std::isdigit(word[0])) {
        anonyWord[0] = '*';
    } else if (word.size() >= MIN_ANONYMIZE_LENGTH && word.size() <= MAX_ANONYMIZE_LENGTH) {
        anonyWord[0] = '*';
    } else {
        int length = anonyWord.length() - 3;
        for (int i = 0; i < length; i++) {
            anonyWord[i] = '*';
        }
    }
    return anonyWord;
}

std::string AnonyString(const std::string &input)
{
    std::vector<std::string> words = SplitString(input);
    std::string result;
    for (const std::string &word : words) {
        std::string anonyWord = AnonyWord(word);
        result += anonyWord;
    }
    return result;
}

std::string AnonySqlString(const std::string &input, const std::vector<std::string> &array)
{
    std::vector<std::string> words = SplitString(input);
    std::string result;
    for (const std::string &word : words) {
        std::string anonyWord = word;
        std::string upperWord = SqliteUtils::StrToUpper(word);
        if (std::find(array.begin(), array.end(), upperWord) == array.end()) {
            anonyWord = AnonyWord(anonyWord);
        }
        result += anonyWord;
    }
    return result;
}

std::string AnonyCreateTable(std::string &str)
{
    size_t lastSpacePos;
    if (!str.empty() && str.back() == ' ') {
        str = str.substr(0, str.length() - 1);
    }
    lastSpacePos = str.find_last_of(' ');
    if (lastSpacePos != std::string::npos) {
        str.replace(lastSpacePos + 1, str.length() - lastSpacePos,
            AnonyString(str.substr(lastSpacePos + 1, str.length() - lastSpacePos)));
    }
    return str;
}

std::string AnonyCreateColumn(std::string &str)
{
    std::vector<std::string> tokens;
    std::string delimiter = ",";
    size_t pos = 0;

    while ((pos = str.find(delimiter)) != std::string::npos) {
        std::string token = str.substr(0, pos);
        tokens.push_back(token);
        str.erase(0, pos + delimiter.length());
    }
    tokens.push_back(str);
    std::string result;
    for (const auto &token : tokens) {
        std::string repToken = ReplaceMultipleSpaces(token);
        size_t spacePos = repToken.find(' ');
        if (spacePos != std::string::npos) {
            std::string replacedToken = AnonyString(repToken.substr(0, spacePos)) + repToken.substr(spacePos);
            if (!result.empty()) {
                result += ", ";
            }
            result += replacedToken;
        }
    }
    return result;
}

std::string MaskedCreateSql(const std::string &sql)
{
    auto pre = sql.find("(");
    auto end = sql.rfind(")");
    auto table = sql.substr(0, pre);
    auto column = sql.substr(pre, end - pre);
    table = AnonyCreateTable(table);
    column = AnonyCreateColumn(column);
    return table + " " + column + ")";
}

std::string AnonyAlterDrop(const std::smatch &match, const std::string &sql)
{
    std::string columns = match[1].str();
    std::string table = match[2].str();
    std::string maskedSql = std::regex_replace(sql,
        std::regex("ALTER\\s+TABLE\\s+(.*)\\s+DROP COLUMN\\s+([^\\s;]+)", std::regex_constants::icase),
        "ALTER TABLE " + AnonyString(columns) + " DROP COLUMN " + AnonyString(table));
    return maskedSql;
}

std::string AnonyAlterAdd(const std::smatch &match, const std::string &sql)
{
    std::string columns = match[1].str();
    std::string table = match[2].str();
    std::string maskedSql = std::regex_replace(sql,
        std::regex("ALTER\\s+TABLE\\s+(.*)\\s+ADD COLUMN\\s+([^\\s;]+)", std::regex_constants::icase),
        "ALTER TABLE " + AnonyString(columns) + " ADD COLUMN " + AnonyString(table));
    return maskedSql;
}

std::string AnonySelectSql(const std::string &sql, const std::string &array)
{
    return AnonySqlString(sql, SELECT_ARRAY);
}

std::string AnonyInsertSql(const std::string &sql, const std::string &array)
{
    return AnonySqlString(sql, INSERT_ARRAY);
}

std::string AnonyUpdateSql(const std::string &sql, const std::string &array)
{
    return AnonySqlString(sql, UPDATE_ARRAY);
}

std::string AnonyDeleteSql(const std::string &sql, const std::string &array)
{
    return AnonySqlString(sql, DELETE_ARRAY);
}

std::string AnonyCreateSql(const std::string &replaceSql)
{
    std::regex createDatabaseRegex("CREATE\\s+DATABASE\\s+([^\\s;]+)", std::regex_constants::icase);
    std::regex createTableRegex("CREATE\\s+TABLE\\s+([^\\s;]+)", std::regex_constants::icase);
    std::smatch match;
    if (std::regex_search(replaceSql, match, createDatabaseRegex)) {
        std::string maskedSql =
            replaceSql.substr(START_SIZE, CREATE_DATABASE_SIZE) + AnonyString(replaceSql.substr(CREATE_DATABASE_SIZE));
        return maskedSql;
    } else if (std::regex_search(replaceSql, match, createTableRegex)) {
        std::string maskedSql = MaskedCreateSql(replaceSql);
        return maskedSql;
    }
    return replaceSql;
}

std::string AnonyDropSql(const std::string &sql, const std::string &array)
{
    return AnonySqlString(sql, DROP_ARRAY);
}

std::string AnonyPragmaSql(const std::string &sql, const std::string &array)
{
    return AnonySqlString(sql, PRAGMA_ARRAY);
}

std::string AnonyAlterSql(const std::string &replaceSql)
{
    std::regex alterDropRegex("ALTER\\s+TABLE\\s+(.*)\\s+DROP COLUMN\\s+([^\\s;]+)", std::regex_constants::icase);
    std::regex alterAddRegex("ALTER\\s+TABLE\\s+(.*)\\s+ADD COLUMN\\s+([^\\s;]+)", std::regex_constants::icase);
    std::smatch match;
    if (std::regex_search(replaceSql, match, alterDropRegex)) {
        return AnonyAlterDrop(match, replaceSql);
    } else if (std::regex_search(replaceSql, match, alterAddRegex)) {
        return AnonyAlterAdd(match, replaceSql);
    }
    return replaceSql;
}


std::string SqliteUtils::AnonySql(const std::string &sql)
{
    std::string replaceSql = ReplaceMultipleSpaces(sql);
    std::string sqlType;
    if (replaceSql.size() > SQL_TYPE_SIZE) {
        sqlType = StrToUpper(replaceSql.substr(START_SIZE, SQL_TYPE_SIZE));
    } else {
        return replaceSql;
    }
    std::smatch match;
    if (sqlType == "SEL") {
        return AnonySqlString(replaceSql, SELECT_ARRAY);
    }
    if (sqlType == "INS") {
        return AnonySqlString(replaceSql, INSERT_ARRAY);
    }
    if (sqlType == "UPD") {
        return AnonySqlString(replaceSql, UPDATE_ARRAY);
    }
    if (sqlType == "DEL") {
        return AnonySqlString(replaceSql, DELETE_ARRAY);
    }
    if (sqlType == "CRE") {
        return AnonyCreateSql(replaceSql);
    }
    if (sqlType == "DRO") {
        return AnonySqlString(replaceSql, DROP_ARRAY);
    }
    if (sqlType == "PRA") {
        return AnonySqlString(replaceSql, PRAGMA_ARRAY);
    }
    if (sqlType == "ALT") {
        return AnonyAlterSql(replaceSql);
    }

    if (replaceSql.length() > OTHER_SIZE) {
        std::string maskedSql = replaceSql.substr(START_SIZE, OTHER_SIZE) + AnonyString(replaceSql.substr(OTHER_SIZE));
        return maskedSql;
    }

    return replaceSql;
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

void SqliteUtils::SetSlaveValid(const std::string &dbPath)
{
    std::remove((dbPath + SLAVE_INTERRUPT).c_str());
    std::remove((dbPath + SLAVE_FAILURE).c_str());
}
} // namespace NativeRdb
} // namespace OHOS

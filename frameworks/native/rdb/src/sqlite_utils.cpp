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
#include <fstream>
#include <regex>
#include <string>
#include <sstream>
#include <iomanip>

#include "logger.h"
#include "rdb_errno.h"
#include "rdb_store_config.h"
#include "string_utils.h"
#include "rdb_time_utils.h"

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
constexpr int32_t DISPLAY_BYTE = 2;
constexpr int32_t PREFIX_LENGTH = 3;
constexpr int32_t FILE_MAX_SIZE = 20 * 1024;

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
    const uint32_t permission = 0777;
    oss << " dev:0x" << std::hex << debugInfo.dev_ << " ino:0x" << std::hex << debugInfo.inode_;
    if (debugInfo.inode_ != debugInfo.oldInode_ && debugInfo.oldInode_ != 0) {
        oss << "<>0x" << std::hex << debugInfo.oldInode_;
    }
    oss << " mode:0" << std::oct << (debugInfo.mode_ & permission) << " size:" << std::dec << debugInfo.size_
        << " uid:" << std::dec << debugInfo.uid_ << " gid:" << std::dec << debugInfo.gid_
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
        oss << "<" << name << ",0x" << std::hex << debugInfo.inode_ << "," << std::dec << debugInfo.size_ << ">";
    }
    return oss.str();
}
std::string SqliteUtils::FormatDfxInfo(const DfxInfo &dfxInfo)
{
    std::stringstream oss;
    oss << "LastOpen:" << dfxInfo.lastOpenTime_ << "," << "CUR_USER:" << dfxInfo.curUserId_;
    return oss.str();
}
} // namespace NativeRdb
} // namespace OHOS

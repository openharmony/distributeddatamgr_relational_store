/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#define LOG_TAG "RdbSecurityManager"
#include "rdb_security_manager.h"

#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <securec.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>

#include "directory_ex.h"
#include "file_ex.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_platform.h"
#include "rdb_sql_utils.h"
#include "rdb_store_manager.h"
#include "sqlite_utils.h"
#include "string_utils.h"
#include "rdb_fault_hiview_reporter.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using Reportor = RdbFaultHiViewReporter;

RdbPassword::RdbPassword() = default;

RdbPassword::~RdbPassword()
{
    (void)Clear();
}

bool RdbPassword::operator==(const RdbPassword &input) const
{
    if (size_ != input.GetSize()) {
        return false;
    }
    return memcmp(data_, input.GetData(), size_) == 0;
}

bool RdbPassword::operator!=(const RdbPassword &input) const
{
    return !(*this == input);
}

size_t RdbPassword::GetSize() const
{
    return size_;
}

const uint8_t *RdbPassword::GetData() const
{
    return data_;
}

int RdbPassword::SetValue(const uint8_t *inputData, size_t inputSize)
{
    if (inputSize > MAX_PASSWORD_SIZE) {
        return E_ERROR;
    }
    if (inputSize != 0 && inputData == nullptr) {
        return E_ERROR;
    }

    if (inputSize != 0) {
        std::copy(inputData, inputData + inputSize, data_);
    }

    size_t filledSize = std::min(size_, MAX_PASSWORD_SIZE);
    if (inputSize < filledSize) {
        std::fill(data_ + inputSize, data_ + filledSize, UCHAR_MAX);
    }

    size_ = inputSize;
    return E_OK;
}

int RdbPassword::Clear()
{
    return SetValue(nullptr, 0);
}

bool RdbPassword::IsValid() const
{
    return size_ != 0;
}

std::vector<uint8_t> RdbSecurityManager::GetRootKeyAlias()
{
    std::lock_guard<std::mutex> lock(rootKeyMutex_);
    return rootKeyAlias_;
}

void RdbSecurityManager::SetRootKeyAlias(std::vector<uint8_t> rootKeyAlias)
{
    std::lock_guard<std::mutex> lock(rootKeyMutex_);
    rootKeyAlias_ = std::move(rootKeyAlias);
}

std::string RdbSecurityManager::GetBundleNameByAlias()
{
    auto rootKeyAlias = GetRootKeyAlias();
    return GetBundleNameByAlias(rootKeyAlias);
}

std::string RdbSecurityManager::GetBundleNameByAlias(const std::vector<uint8_t> &rootKeyAlias)
{
    auto prefixLen = strlen(RDB_ROOT_KEY_ALIAS_PREFIX);
    if (rootKeyAlias.size() > prefixLen) {
        return std::string(rootKeyAlias.begin() + prefixLen, rootKeyAlias.end());
    }
    return "";
}

RdbSecurityManager::RdbSecurityManager()
{
};

RdbSecurityManager::~RdbSecurityManager()
{
    if (handle_ != nullptr) {
        dlclose(handle_);
        handle_ = nullptr;
    }
}

std::vector<uint8_t> RdbSecurityManager::GenerateRandomNum(int32_t len)
{
    auto handle = GetHandle();
    if (handle == nullptr) {
        return {};
    }
    RDBCryptFault rdbFault;
    auto creatorGenerateRandomNum = reinterpret_cast<GenerateRandomNumFunc>(dlsym(handle, "GenerateRandomNum"));
    if (creatorGenerateRandomNum == nullptr) {
        LOG_ERROR("dlsym GenerateRandomNum failed(%{public}d)!", errno);
        return {};
    }
    auto rootKeyAlias = GetRootKeyAlias();
    auto ret = creatorGenerateRandomNum(len);
    ReportCryptFault(rdbFault.errorCode, rdbFault.custLog);
    return ret;
}

bool RdbSecurityManager::SaveSecretKeyToFile(const std::string &keyFile, const std::vector<uint8_t> &workey)
{
    LOG_INFO("begin keyFile%{public}s.", SqliteUtils::Anonymous(keyFile).c_str());
    if (!HasRootKey()) {
        Reportor::ReportFault(RdbFaultEvent(FT_OPEN, E_ROOT_KEY_NOT_LOAD, GetBundleNameByAlias(), "not root key"));
        LOG_ERROR("Root key not exists!");
        return false;
    }
    SecurityContent securityContent;
    std::vector<uint8_t> key = workey.empty() ? GenerateRandomNum(RDB_KEY_SIZE) : workey;
    securityContent.version = SecurityContent::CURRENT_VERSION;
    securityContent.time =std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::vector<uint8_t> keyContent;
    keyContent.push_back(char(securityContent.version));
    keyContent.insert(keyContent.end(), reinterpret_cast<uint8_t*>(&securityContent.time),
        reinterpret_cast<uint8_t*>(&securityContent.time) + sizeof(securityContent.time));
    keyContent.insert(keyContent.end(), key.begin(), key.end());
    if (!EncryptWorkKey(keyContent, securityContent)) {
        LOG_INFO("EncryptWorkKey failed, keyFile%{public}s", SqliteUtils::Anonymous(keyFile).c_str());
        return false;
    }
    if (securityContent.encryptKey.empty()) {
        LOG_INFO("secretKey is null keyFile%{public}s.", SqliteUtils::Anonymous(keyFile).c_str());
        Reportor::ReportFault(RdbFaultEvent(FT_OPEN, E_WORK_KEY_FAIL, GetBundleNameByAlias(), "key is empty"));
        LOG_ERROR("Key size is 0");
        key.assign(key.size(), 0);
        return false;
    }

    key.assign(key.size(), 0);
    auto keyTempPath = ReplaceSuffix(keyFile);
    auto ret = SaveSecretKeyToDisk(keyTempPath, securityContent);
    if (!ret) {
        LOG_ERROR("Save key to file fail, ret:%{public}d", ret);
        return false;
    }
    return SqliteUtils::RenameFile(keyTempPath, keyFile);
}

bool RdbSecurityManager::SaveSecretKeyToDisk(const std::string &keyPath, SecurityContent &securityContent)
{
    LOG_INFO("begin keyPath:%{public}s.", SqliteUtils::Anonymous(keyPath).c_str());

    std::string secretKeyInString;
    secretKeyInString.append(reinterpret_cast<const char *>(&securityContent.magicNum), sizeof(uint32_t));
    secretKeyInString.append(reinterpret_cast<const char *>(securityContent.nonceValue.data()), securityContent.nonceValue.size());
    secretKeyInString.append(reinterpret_cast<const char *>(securityContent.encryptKey.data()), securityContent.encryptKey.size());

    bool ret;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto fd = open(keyPath.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
        if (fd > 0) {
            ret = SaveStringToFd(fd, secretKeyInString);
            close(fd);
        } else {
            ret = false;
        }
    }
    if (!ret) {
        Reportor::ReportFault(RdbFaultEvent(FT_EX_FILE, E_WORK_KEY_FAIL, GetBundleNameByAlias(),
            "save fail errno=" + std::to_string(errno)));
    }
    return ret;
}

void RdbSecurityManager::ReportCryptFault(const int32_t &errorCode, const std::string &custLog)
{
    if (custLog.empty()) {
        return;
    }
    Reportor::ReportFault(RdbFaultEvent(FT_EX_HUKS, errorCode, GetBundleNameByAlias(), custLog));
}

int32_t RdbSecurityManager::Init(const std::string &bundleName)
{
    std::vector<uint8_t> rootKeyAlias = GenerateRootKeyAlias(bundleName);
    constexpr uint32_t RETRY_MAX_TIMES = 5;
    constexpr int RETRY_TIME_INTERVAL_MILLISECOND = 1 * 1000 * 1000;
    int32_t ret = HKS_FAILURE;
    uint32_t retryCount = 0;
    while (retryCount < RETRY_MAX_TIMES) {
        ret = CheckRootKeyExists(rootKeyAlias);
        if (ret == HKS_ERROR_NOT_EXIST) {
            hasRootKey_ = false;
            ret = GenerateRootKey(rootKeyAlias);
        }
        if (ret == HKS_SUCCESS) {
            if (!HasRootKey()) {
                hasRootKey_ = true;
            }
            SetRootKeyAlias(std::move(rootKeyAlias));
            break;
        }
        retryCount++;
        usleep(RETRY_TIME_INTERVAL_MILLISECOND);
    }
    LOG_INFO("bundleName:%{public}s, retry:%{public}u, error:%{public}d", bundleName.c_str(), retryCount, ret);
    return ret;
}

int32_t RdbSecurityManager::CheckRootKeyExists(std::vector<uint8_t> &rootKeyAlias)
{
    auto handle = GetHandle();
    if (handle == nullptr) {
        return E_NOT_SUPPORT;
    }
    auto creatorCheck = reinterpret_cast<CheckRootKeyExistsFunc>(dlsym(handle, "checkRootKeyExists"));
    if (creatorCheck == nullptr) {
        LOG_ERROR("CheckRootKeyExists failed(%{public}d)!", errno);
        return E_NOT_SUPPORT;
    }
    return creatorCheck(rootKeyAlias);
}

int32_t RdbSecurityManager::GenerateRootKey(const std::vector<uint8_t> &rootKeyAlias)
{
    auto handle = GetHandle();
    if (handle == nullptr) {
        return E_NOT_SUPPORT;
    }
    RDBCryptFault rdbFault;
    auto creatorGenerate = reinterpret_cast<GenerateRootKeyFunc>(dlsym(handle, "generateRootKey"));
    if (creatorGenerate == nullptr) {
        LOG_ERROR("dlsym GenerateRootKey failed(%{public}d)!", errno);
        return E_NOT_SUPPORT;
    }
    auto ret = creatorGenerate(rootKeyAlias, rdbFault);
    ReportCryptFault(rdbFault.errorCode, rdbFault.custLog);
    return ret;
}

bool RdbSecurityManager::EncryptWorkKey(std::vector<uint8_t> &key, SecurityContent &content)
{
    auto handle = GetHandle();
    if (handle == nullptr) {
        return {};
    }
    RDBCryptFault rdbFault;
    auto creatorEncrypt = reinterpret_cast<EncryptFunc>(dlsym(handle, "encrypt"));
    if (creatorEncrypt == nullptr) {
        LOG_ERROR("dlsym Encrypt failed(%{public}d)!", errno);
        return {};
    }
    auto rootKeyAlias = GetRootKeyAlias();
    auto ret = creatorEncrypt(rootKeyAlias, key, rdbFault, content);
    ReportCryptFault(rdbFault.errorCode, rdbFault.custLog);
    return ret;
}

bool RdbSecurityManager::DecryptWorkKey(SecurityContent &content, std::vector<uint8_t> &key)
{
    auto handle = GetHandle();
    if (handle == nullptr) {
        return {};
    }
    RDBCryptFault rdbFault;
    auto creatorDecrypt = reinterpret_cast<DecryptFunc>(dlsym(handle, "decrypt"));
    if (creatorDecrypt == nullptr) {
        LOG_ERROR("dlsym Decrypt failed(%{public}d)!", errno);
        return {};
    }
    auto rootKeyAlias = GetRootKeyAlias();
    auto ret = creatorDecrypt(rootKeyAlias, key, rdbFault, content);
    ReportCryptFault(rdbFault.errorCode, rdbFault.custLog);
    return ret;
}

bool RdbSecurityManager::InitPath(const std::string &fileDir)
{
    constexpr mode_t DEFAULT_UMASK = 0002;
    if (access(fileDir.c_str(), F_OK) == 0) {
        return true;
    }
    umask(DEFAULT_UMASK);
    auto ret = MkDir(fileDir, (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    if (ret != 0 && errno != EEXIST) {
        Reportor::ReportFault(RdbFaultEvent(FT_EX_FILE, E_WORK_KEY_FAIL,
            RdbSecurityManager::GetInstance().GetBundleNameByAlias(),
            "mkdir err, ret=" + std::to_string(ret) + ",errno=" + std::to_string(errno) +
            ",fileDir=" + SqliteUtils::Anonymous(fileDir)));
        LOG_ERROR("mkdir error:%{public}d, area:%{public}s", errno, SqliteUtils::GetArea(fileDir).c_str());
        return false;
    }
    return true;
}

RdbPassword RdbSecurityManager::LoadSecretKeyFromFile(const std::string &keyFile)
{
    auto tempKeyPath = ReplaceSuffix(keyFile);
    RdbPassword rdbPasswd;
    if (!FileExists(tempKeyPath) && !FileExists(keyFile)) {
        return rdbPasswd;
    }
    bool result = false;
    SecurityContent content;
    std::vector<uint8_t> fullKey;
    if (FileExists(keyFile)) {
        content = LoadSecretKeyFromDisk(keyFile);
        if (!content.encryptKey.empty() && DecryptWorkKey(content, fullKey) && !fullKey.empty()) {
            SqliteUtils::DeleteFile(tempKeyPath);
            result = true;
        }
    }
    if (!result && FileExists(tempKeyPath)) {
        content = LoadSecretKeyFromDisk(tempKeyPath);
        if (!content.encryptKey.empty() && DecryptWorkKey(content, fullKey) && !fullKey.empty()) {
            result = true;
            SqliteUtils::RenameFile(tempKeyPath, keyFile);
        }
    }

    std::vector<uint8_t> key;
    size_t offset = 0;
    if (content.isNewStyle) {
        content.version = fullKey[offset++];
        std::vector<uint8_t> times;
        times.assign(fullKey.begin() + offset, fullKey.begin() + offset + (sizeof(time_t) / sizeof(uint8_t)));
        content.time = *reinterpret_cast<time_t *>(&times[0]);
        offset += (sizeof(time_t) / sizeof(uint8_t));
    }
    if (result) {
        key.assign(fullKey.begin() + offset, fullKey.end());
    }
    // old security key file
    if (result && content.nonceValue.empty()) {
        SaveSecretKeyToFile(keyFile, key); // update result
    }

    if (!result) {
        return rdbPasswd;
    }
    rdbPasswd.SetValue(key.data(), key.size());
    rdbPasswd.isKeyExpired = IsKeyExpired(content.time);
    content.encryptKey.assign(content.encryptKey.size(), 0);
    key.assign(key.size(), 0);
    return rdbPasswd;
}

SecurityContent RdbSecurityManager::LoadSecretKeyFromDisk(const std::string &keyPath)
{
    LOG_DEBUG("begin keyPath:%{public}s.", SqliteUtils::Anonymous(keyPath).c_str());
    std::vector<char> content;
    SecurityContent securityContent;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!LoadBufferFromFile(keyPath, content) || content.empty()) {
            Reportor::ReportFault(RdbFaultEvent(FT_EX_FILE, E_WORK_KEY_DECRYPT_FAIL, GetBundleNameByAlias(),
                "LoadBufferFromFile fail, errno=" + std::to_string(errno)));
            LOG_ERROR("LoadBufferFromFile failed!");
            return securityContent;
        }
    }

    for (size_t index = 0; index < SecurityContent::MAGIC_NUM; ++index) {
        if (content[index] != char(SecurityContent::MAGIC_NUMBER)) {
            securityContent.isNewStyle = false;
        }
    }
    if (securityContent.isNewStyle) {
        LoadNewKey(content, securityContent);
    } else {
        auto size = content.size();
        std::size_t offset = 0;
        auto iter = content.begin();
        if (offset + 1 >= static_cast<std::size_t>(size)) {
            return securityContent;
        }
        securityContent.magicNum = *iter;
        iter++;
        offset++;

        std::vector<uint8_t> createTime;
        if (offset + static_cast<std::size_t>(sizeof(time_t) / sizeof(uint8_t)) >= size) {
            return securityContent;
        }
        offset += sizeof(time_t) / sizeof(uint8_t);
        for (std::size_t i = 0; i < sizeof(time_t) / sizeof(uint8_t); i++) {
            createTime.push_back(*iter);
            iter++;
        }

        if (createTime.size() == sizeof(time_t)) {
            securityContent.time = *reinterpret_cast<time_t *>(&createTime[0]);
        }

        if (offset + AEAD_LEN >= static_cast<std::size_t>(size)) {
            return securityContent;
        }
        offset = size;
        securityContent.encryptKey.insert(securityContent.encryptKey.end(), iter, content.end());
    }
    content.assign(content.size(), 0);
    return securityContent;
}
 
void RdbSecurityManager::LoadNewKey(const std::vector<char> &content, SecurityContent &securityContent)
{
    size_t offset = SecurityContent::MAGIC_NUM;
    securityContent.nonceValue.assign(content.begin() + offset, content.begin() + offset + SecurityContent::NONCE_SIZE);
    offset += SecurityContent::NONCE_SIZE;
    securityContent.encryptKey.assign(content.begin() + offset, content.end());
}

RdbPassword RdbSecurityManager::GetRdbPassword(const std::string &dbPath, KeyFileType keyFileType)
{
    RdbPassword rdbPassword;
    if (SqliteUtils::IsPathInvalid(dbPath)) {
        return rdbPassword;
    }
    KeyFiles keyFiles(dbPath);
    keyFiles.Lock();
    auto &keyFile = keyFiles.GetKeyFile(keyFileType);
    auto tempKeyPath = ReplaceSuffix(keyFile);
    if (IsKeyFileEmpty(keyFile) && IsKeyFileEmpty(tempKeyPath)) {
        keyFiles.InitKeyPath();
        if (!SaveSecretKeyToFile(keyFile)) {
            keyFiles.Unlock();
            LOG_ERROR("Failed to save key type:%{public}d err:%{public}d.", keyFileType, errno);
            return {};
        }
    }
    rdbPassword = LoadSecretKeyFromFile(keyFile);
    keyFiles.Unlock();
    return rdbPassword;
}

std::vector<uint8_t> RdbSecurityManager::GenerateRootKeyAlias(const std::string &bundlename)
{
    std::vector<uint8_t> rootKeyAlias =
        std::vector<uint8_t>(RDB_ROOT_KEY_ALIAS_PREFIX, RDB_ROOT_KEY_ALIAS_PREFIX + strlen(RDB_ROOT_KEY_ALIAS_PREFIX));
    rootKeyAlias.insert(rootKeyAlias.end(), bundlename.begin(), bundlename.end());
    return rootKeyAlias;
}

void RdbSecurityManager::DelAllKeyFiles(const std::string &dbPath)
{
    LOG_INFO("Delete all key files begin.");
    if (SqliteUtils::IsPathInvalid(dbPath)) {
        return;
    }
    const std::string dbKeyDir = StringUtils::ExtractFilePath(dbPath) + "key/";
    if (access(dbKeyDir.c_str(), F_OK) != 0) {
        return;
    }
    KeyFiles keyFiles(dbPath);
    keyFiles.Lock();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        SqliteUtils::DeleteFile(keyFiles.GetKeyFile(PUB_KEY_FILE));
        SqliteUtils::DeleteFile(keyFiles.GetKeyFile(PUB_KEY_FILE_NEW_KEY));
    }
    keyFiles.Unlock();
    keyFiles.DestroyLock();
}

void RdbSecurityManager::DelKeyFile(const std::string &dbPath, KeyFileType keyFileType)
{
    if (SqliteUtils::IsPathInvalid(dbPath)) {
        return;
    }
    KeyFiles keyFiles(dbPath);
    keyFiles.Lock();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        SqliteUtils::DeleteFile(keyFiles.GetKeyFile(keyFileType));
    }
    keyFiles.Unlock();
}

bool RdbSecurityManager::IsKeyExpired(const time_t &createTime)
{
    auto timePoint = std::chrono::system_clock::from_time_t(createTime);
    return ((timePoint + std::chrono::hours(HOURS_PER_YEAR)) < std::chrono::system_clock::now());
}

RdbSecurityManager &RdbSecurityManager::GetInstance()
{
    static RdbSecurityManager instance;
    return instance;
}

static std::string RemoveSuffix(const std::string &name)
{
    std::string suffix(".db");
    auto pos = name.rfind(suffix);
    if (pos == std::string::npos || pos < name.length() - suffix.length()) {
        return name;
    }
    return { name, 0, pos };
}

bool RdbSecurityManager::IsKeyFileExists(const std::string &dbPath, KeyFileType keyFileType)
{
    KeyFiles keyFiles(dbPath, false);
    return (access(keyFiles.GetKeyFile(keyFileType).c_str(), F_OK) == 0);
}

void RdbSecurityManager::ChangeKeyFile(const std::string &dbPath)
{
    KeyFiles keyFiles(dbPath);
    keyFiles.Lock();
    auto &reKeyFile = keyFiles.GetKeyFile(PUB_KEY_FILE_NEW_KEY);
    auto &keyFile = keyFiles.GetKeyFile(PUB_KEY_FILE);
    SqliteUtils::RenameFile(reKeyFile, keyFile);
    keyFiles.Unlock();
}

bool RdbSecurityManager::HasRootKey()
{
    return hasRootKey_;
}

void* RdbSecurityManager::GetHandle()
{
    std::lock_guard<std::mutex> lock(handleMutex_);
    if (handle_ == nullptr) {
        handle_ = dlopen("librelational_store_crypt.z.so", RTLD_LAZY);
        if (handle_ == nullptr) {
            LOG_ERROR("crypt dlopen failed errno is %{public}d", errno);
        }
    }
    return handle_;
}

bool RdbSecurityManager::IsKeyFileEmpty(const std::string &keyFile)
{
    struct stat fileInfo;
    auto errCode = stat(keyFile.c_str(), &fileInfo);
    if (errCode != 0) {
        return true;
    }
    return fileInfo.st_size == 0;
}

int32_t RdbSecurityManager::RestoreKeyFile(const std::string &dbPath, const std::vector<uint8_t> &key)
{
    KeyFiles keyFiles(dbPath);
    keyFiles.Lock();
    auto &keyFile = keyFiles.GetKeyFile(PUB_KEY_FILE);
    auto &reKeyFile = keyFiles.GetKeyFile(PUB_KEY_FILE_NEW_KEY);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        SqliteUtils::DeleteFile(keyFile);
        SqliteUtils::DeleteFile(reKeyFile);
    }
    if (!SaveSecretKeyToFile(keyFile, key)) {
        LOG_ERROR("failed, save key err:%{public}d, file:%{public}s.", errno, SqliteUtils::Anonymous(keyFile).c_str());
    }
    keyFiles.Unlock();
    return E_OK;
}

RdbSecurityManager::KeyFiles::KeyFiles(const std::string &dbPath, bool openFile)
{
    const std::string dbKeyDir = StringUtils::ExtractFilePath(dbPath) + "key/";
    const std::string lockDir = StringUtils::ExtractFilePath(dbPath) + "lock/";
    bool isDirCreate = InitPath(lockDir);
    const std::string dbName = RemoveSuffix(StringUtils::ExtractFileName(dbPath));
    lock_ = lockDir + dbName + SUFFIX_KEY_LOCK;
    keys_[PUB_KEY_FILE] = dbKeyDir + dbName + SUFFIX_PUB_KEY;
    keys_[PUB_KEY_FILE_NEW_KEY] = dbKeyDir + dbName + SUFFIX_PUB_KEY_NEW;
    if (!openFile) {
        return;
    }
    lockFd_ = open(lock_.c_str(), O_RDONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (lockFd_ < 0 && isDirCreate) {
        LOG_WARN("open failed, errno:%{public}d, file:%{public}s.", errno, SqliteUtils::Anonymous(lock_).c_str());
    }
}

RdbSecurityManager::KeyFiles::~KeyFiles()
{
    if (lockFd_ < 0) {
        return;
    }
    close(lockFd_);
    lockFd_ = -1;
}

const std::string &RdbSecurityManager::KeyFiles::GetKeyFile(KeyFileType type)
{
    if (type == PUB_KEY_FILE) {
        return keys_[PUB_KEY_FILE];
    }
    return keys_[PUB_KEY_FILE_NEW_KEY];
}

int32_t RdbSecurityManager::KeyFiles::InitKeyPath()
{
    const std::string keyDir = StringUtils::ExtractFilePath(keys_[PUB_KEY_FILE]);
    if (!InitPath(keyDir)) {
        LOG_ERROR("keyDir failed, errno:%{public}d, dir:%{public}s.", errno, SqliteUtils::Anonymous(keyDir).c_str());
    }
    return E_OK;
}

int32_t RdbSecurityManager::KeyFiles::Lock()
{
    if (lockFd_ < 0) {
        return E_INVALID_FILE_PATH;
    }
    int32_t errCode;
    do {
        errCode = flock(lockFd_, LOCK_EX);
    } while (errCode < 0 && errno == EINTR);
    if (errCode < 0) {
        LOG_WARN("lock failed, errno:%{public}d, dir:%{public}s.", errno, SqliteUtils::Anonymous(lock_).c_str());
        return E_ERROR;
    }
    return E_OK;
}

int32_t RdbSecurityManager::KeyFiles::Unlock()
{
    if (lockFd_ < 0) {
        return E_INVALID_FILE_PATH;
    }
    int32_t errCode;
    do {
        errCode = flock(lockFd_, LOCK_UN);
    } while (errCode < 0 && errno == EINTR);
    if (errCode < 0) {
        LOG_WARN("unlock failed, errno:%{public}d, dir:%{public}s.", errno, SqliteUtils::Anonymous(lock_).c_str());
        return E_ERROR;
    }
    return E_OK;
}

int32_t RdbSecurityManager::KeyFiles::DestroyLock()
{
    if (lockFd_ >= 0) {
        close(lockFd_);
        lockFd_ = -1;
    }
    SqliteUtils::DeleteFile(lock_);
    return E_OK;
}

std::string RdbSecurityManager::ReplaceSuffix(const std::string &str)
{
    std::string oldSuffix = std::string(SUFFIX_PUB_KEY);
    std::string newSuffix = std::string(SUFFIX_PUB_KEY_NEW);
    if (str.length() >= oldSuffix.length() &&
        str.compare(str.length() - oldSuffix.length(), oldSuffix.length(), oldSuffix) == 0) {
        return str.substr(0, str.length() - oldSuffix.length()) + SUFFIX_PUB_TMP_KEY;
    } else if (str.length() >= newSuffix.length() &&
        str.compare(str.length() - newSuffix.length(), newSuffix.length(), newSuffix) == 0) {
        return str.substr(0, str.length() - newSuffix.length()) + SUFFIX_PUB_TMP_NEW_KEY;
    }
    return str;
}
} // namespace NativeRdb
} // namespace OHOS

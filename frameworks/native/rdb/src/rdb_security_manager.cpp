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
#include "relational_store_crypt.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using Reporter = RdbFaultHiViewReporter;
using CheckRootKeyExistsFunc = int32_t (*)(std::vector<uint8_t> &);
using GenerateRootKeyFunc = int32_t (*)(const std::vector<uint8_t> &, RDBCryptoFault &);
using EncryptFunc = std::vector<uint8_t> (*)(const RDBCryptoParam &, RDBCryptoFault &);
using DecryptFunc = std::vector<uint8_t> (*)(const RDBCryptoParam &, RDBCryptoFault &);
using GenerateRandomNumFunc = std::vector<uint8_t> (*)(int32_t &);

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
    handle_ = nullptr;
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
    auto generateRandomNum = reinterpret_cast<GenerateRandomNumFunc>(dlsym(handle, "generateRandomNum"));
    if (generateRandomNum == nullptr) {
        LOG_ERROR("dlsym GenerateRandomNum failed(%{public}d)!", errno);
        return {};
    }
    auto rootKeyAlias = GetRootKeyAlias();
    auto ret = generateRandomNum(len);
    return ret;
}

bool RdbSecurityManager::SaveSecretKeyToFile(const std::string &keyFile, const std::vector<uint8_t> &workey)
{
    LOG_INFO("begin keyFile%{public}s.", SqliteUtils::Anonymous(keyFile).c_str());
    if (!HasRootKey()) {
        Reporter::ReportFault(RdbFaultEvent(FT_OPEN, E_ROOT_KEY_NOT_LOAD, GetBundleNameByAlias(), "not root key"));
        LOG_ERROR("Root key not exists!");
        return false;
    }

    std::vector<uint8_t> key = workey.empty() ? GenerateRandomNum(RDB_KEY_SIZE) : workey;
    if (key.empty()) {
        return false;
    }
    RdbSecretKeyData keyData;
    keyData.timeValue = std::chrono::system_clock::to_time_t(std::chrono::system_clock::system_clock::now());
    std::vector<uint8_t> keyContent;
    keyContent.push_back(char(keyData.distributed));
    keyContent.insert(keyContent.end(), reinterpret_cast<uint8_t*>(&keyData.timeValue),
        reinterpret_cast<uint8_t*>(&keyData.timeValue) + sizeof(keyData.timeValue));
    keyContent.insert(keyContent.end(), key.begin(), key.end());
    auto [res, secretContent] = EncryptWorkKey(keyContent);
    if (!res) {
        LOG_ERROR("EncryptWorkKey failed, keyFile%{public}s", SqliteUtils::Anonymous(keyFile).c_str());
        keyContent.assign(keyContent.size(), 0);
        key.assign(key.size(), 0);
        return false;
    }
    if (secretContent.encryptValue.empty()) {
        Reporter::ReportFault(RdbFaultEvent(FT_OPEN, E_WORK_KEY_FAIL, GetBundleNameByAlias(), "key is empty"));
        LOG_ERROR("Key size is 0");
        keyContent.assign(keyContent.size(), 0);
        key.assign(key.size(), 0);
        return false;
    }

    keyContent.assign(keyContent.size(), 0);
    key.assign(key.size(), 0);
    auto keyFileOld = ReplaceSuffix(keyFile);
    auto ret = SaveSecretKeyToDisk(keyFile, secretContent);
    if (!ret) {
        LOG_ERROR("Save key to file fail, ret:%{public}d", ret);
        return false;
    }
    return SqliteUtils::DeleteFile(keyFileOld);
}

bool RdbSecurityManager::SaveSecretKeyToDisk(const std::string &keyPath, const RdbSecretContent &secretContent)
{
    LOG_INFO("begin keyPath:%{public}s.", SqliteUtils::Anonymous(keyPath).c_str());

    std::string secretKeyInString;
    secretKeyInString.append(reinterpret_cast<const char *>(&secretContent.magicNum), sizeof(uint32_t));
    secretKeyInString.append(
        reinterpret_cast<const char *>(secretContent.nonceValue.data()), secretContent.nonceValue.size());
    secretKeyInString.append(
        reinterpret_cast<const char *>(secretContent.encryptValue.data()), secretContent.encryptValue.size());

    bool ret;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto fd = open(keyPath.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
        ret = SaveStringToFd(fd, secretKeyInString);
        if (fd >= 0) {
            close(fd);
        }
    }
    if (!ret) {
        Reporter::ReportFault(RdbFaultEvent(
            FT_EX_FILE, E_WORK_KEY_FAIL, GetBundleNameByAlias(), "save fail errno=" + std::to_string(errno)));
    }
    return ret;
}

void RdbSecurityManager::ReportCryptFault(int32_t code, const std::string &message)
{
    if (message.empty()) {
        return;
    }
    Reporter::ReportFault(RdbFaultEvent(FT_EX_HUKS, code, GetBundleNameByAlias(), message));
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
    RDBCryptoFault rdbFault;
    auto generateRootKey = reinterpret_cast<GenerateRootKeyFunc>(dlsym(handle, "generateRootKey"));
    if (generateRootKey == nullptr) {
        LOG_ERROR("dlsym GenerateRootKey failed(%{public}d)!", errno);
        return E_NOT_SUPPORT;
    }
    auto ret = generateRootKey(rootKeyAlias, rdbFault);
    ReportCryptFault(rdbFault.code, rdbFault.message);
    return ret;
}

std::pair<bool, RdbSecretContent> RdbSecurityManager::EncryptWorkKey(const std::vector<uint8_t> &key)
{
    RdbSecretContent rdbSecretContent;
    auto handle = GetHandle();
    if (handle == nullptr) {
        return { false, rdbSecretContent };
    }
    RDBCryptoFault rdbFault;
    auto encrypt = reinterpret_cast<EncryptFunc>(dlsym(handle, "encrypt"));
    if (encrypt == nullptr) {
        LOG_ERROR("dlsym Encrypt failed(%{public}d)!", errno);
        return { false, rdbSecretContent };
    }
    auto rootKeyAlias = GetRootKeyAlias();
    RDBCryptoParam param;
    param.KeyValue = key;
    param.rootAlias = rootKeyAlias;
    param.nonceValue = GenerateRandomNum(RdbSecretContent::NONCE_VALUE_SIZE);
    if (param.nonceValue.empty()) {
        return { false, rdbSecretContent };
    }
    auto encryptKey = encrypt(param, rdbFault);
    rdbSecretContent.nonceValue = param.nonceValue;
    rdbSecretContent.encryptValue = encryptKey;
    ReportCryptFault(rdbFault.code, rdbFault.message);
    return { true, rdbSecretContent };
}

std::vector<uint8_t> RdbSecurityManager::DecryptWorkKey(
    const std::vector<uint8_t> &key, const std::vector<uint8_t> &nonce)
{
    auto handle = GetHandle();
    if (handle == nullptr) {
        return {};
    }
    RDBCryptoFault rdbFault;
    auto decrypt = reinterpret_cast<DecryptFunc>(dlsym(handle, "decrypt"));
    if (decrypt == nullptr) {
        LOG_ERROR("dlsym Decrypt failed(%{public}d)!", errno);
        return {};
    }
    RDBCryptoParam param;
    param.KeyValue = key;
    param.nonceValue = nonce;
    param.rootAlias = GetRootKeyAlias();
    auto decryptKey = decrypt(param, rdbFault);
    ReportCryptFault(rdbFault.code, rdbFault.message);
    return decryptKey;
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
        Reporter::ReportFault(RdbFaultEvent(FT_EX_FILE, E_WORK_KEY_FAIL,
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
    auto keyFileOld = ReplaceSuffix(keyFile);
    RdbPassword rdbPasswd;
    RdbSecretKeyData keyData;
    if (access(keyFile.c_str(), F_OK) == 0) {
        if (LoadSecretKeyFromDiskV1(keyFile, keyData) && !keyData.secretKey.empty()) {
            rdbPasswd.isKeyExpired = IsKeyExpired(keyData.timeValue);
            rdbPasswd.SetValue(keyData.secretKey.data(), keyData.secretKey.size());
            return rdbPasswd;
        }
    } else {
        if (LoadSecretKeyFromDisk(keyFileOld, keyData) && !keyData.secretKey.empty()) {
            rdbPasswd.isKeyExpired = IsKeyExpired(keyData.timeValue);
            rdbPasswd.SetValue(keyData.secretKey.data(), keyData.secretKey.size());
            return rdbPasswd;
        }
    }
    return {};
}

bool RdbSecurityManager::LoadSecretKeyFromDisk(const std::string &keyPath, RdbSecretKeyData &keyData)
{
    std::vector<char> content;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!LoadBufferFromFile(keyPath, content) || content.empty()) {
            Reporter::ReportFault(RdbFaultEvent(FT_EX_FILE, E_WORK_KEY_DECRYPT_FAIL, GetBundleNameByAlias(),
                "LoadBufferFromFile fail, errno=" + std::to_string(errno)));
            LOG_ERROR("LoadBufferFromFile failed!");
            return false;
        }
    }
    auto [res, rdbSecretContent] = UnpackV1(content);
    if (!res) {
        LOG_ERROR("UnpackV1 failed:%{public}s.", SqliteUtils::Anonymous(keyPath).c_str());
        return false;
    }
    std::tie(res, keyData) = DecryptV1(rdbSecretContent);
    if (!res) {
        LOG_ERROR("DecryptV1 failed:%{public}s.", SqliteUtils::Anonymous(keyPath).c_str());
        return false;
    }
    std::string keyPathV1;
    std::string oldSuffix = std::string(SUFFIX_PUB_KEY_OLD);
    if (keyPath.length() >= oldSuffix.length() &&
        keyPath.compare(keyPath.length() - oldSuffix.length(), oldSuffix.length(), oldSuffix) == 0) {
        keyPathV1 = keyPath.substr(0, keyPath.length() - oldSuffix.length()) + SUFFIX_PUB_KEY;
    }
    SaveSecretKeyToFile(keyPathV1, keyData.secretKey);
    return true;
}

bool RdbSecurityManager::LoadSecretKeyFromDiskV1(const std::string &keyPath, RdbSecretKeyData &keyData)
{
    std::vector<char> content;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!LoadBufferFromFile(keyPath, content) || content.empty()) {
            Reporter::ReportFault(RdbFaultEvent(FT_EX_FILE, E_WORK_KEY_DECRYPT_FAIL, GetBundleNameByAlias(),
                "LoadBufferFromFile fail, errno=" + std::to_string(errno)));
            LOG_ERROR("LoadBufferFromFile failed!");
            return false;
        }
    }
    auto [res, rdbSecretContent] = UnpackV2(content);
    if (!res) {
        LOG_ERROR("UnpackV2 failed:%{public}s.", SqliteUtils::Anonymous(keyPath).c_str());
        return false;
    }
    std::tie(res, keyData) = DecryptV2(rdbSecretContent);
    if (!res) {
        LOG_ERROR("DecryptV2 failed:%{public}s.", SqliteUtils::Anonymous(keyPath).c_str());
        return false;
    }
    return true;
}

RdbPassword RdbSecurityManager::GetRdbPassword(const std::string &dbPath, KeyFileType keyFileType)
{
    KeyFiles keyFiles(dbPath);
    keyFiles.Lock();
    auto keyFile = keyFiles.GetKeyFile(keyFileType);
    auto keyFileOld = ReplaceSuffix(keyFile);
    if (IsKeyFileEmpty(keyFile) && IsKeyFileEmpty(keyFileOld)) {
        keyFiles.InitKeyPath();
        if (!SaveSecretKeyToFile(keyFile)) {
            keyFiles.Unlock();
            LOG_ERROR("Failed to save key type:%{public}d err:%{public}d.", keyFileType, errno);
            return {};
        }
    }
    auto rdbPassword = LoadSecretKeyFromFile(keyFile);
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
        SqliteUtils::DeleteFile(ReplaceSuffix(keyFiles.GetKeyFile(PUB_KEY_FILE)));
        SqliteUtils::DeleteFile(ReplaceSuffix(keyFiles.GetKeyFile(PUB_KEY_FILE_NEW_KEY)));
    }
    keyFiles.Unlock();
    keyFiles.DestroyLock();
}

void RdbSecurityManager::DelKeyFile(const std::string &dbPath, KeyFileType keyFileType)
{
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
            LOG_ERROR("crypto dlopen failed errno is %{public}d", errno);
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

std::pair<bool, RdbSecretContent> RdbSecurityManager::UnpackV1(const std::vector<char> &content)
{
    RdbSecretContent rdbSecretContent;
    rdbSecretContent.magicNum = 0;
    rdbSecretContent.nonceValue = { RDB_HKS_BLOB_TYPE_NONCE,
        RDB_HKS_BLOB_TYPE_NONCE + strlen(RDB_HKS_BLOB_TYPE_NONCE) };
    rdbSecretContent.encryptValue = { content.begin(), content.end() };
    return { true, rdbSecretContent };
}
 
std::pair<bool, RdbSecretContent> RdbSecurityManager::UnpackV2(const std::vector<char> &content)
{
    std::pair<bool, RdbSecretContent> result;
    auto &[res, rdbSecretContent] = result;
    rdbSecretContent.magicNum = RdbSecretContent::MAGIC_NUMBER_V2;
    res = false;
    auto size = content.size();
    std::size_t offset = sizeof(rdbSecretContent.magicNum);
    if (offset >= static_cast<std::size_t>(size)) {
        return result;
    }
    if (offset + RdbSecretContent::NONCE_VALUE_SIZE >= static_cast<std::size_t>(size)) {
        return result;
    }
    rdbSecretContent.nonceValue = { content.begin() + offset,
        content.begin() + offset + RdbSecretContent::NONCE_VALUE_SIZE };
    offset += RdbSecretContent::NONCE_VALUE_SIZE;
    rdbSecretContent.encryptValue = { content.begin() + offset, content.end() };
    res = true;
    return result;
}
 
std::pair<bool, RdbSecretKeyData> RdbSecurityManager::DecryptV1(const RdbSecretContent &content)
{
    RdbSecretKeyData keyData;
    auto size = content.encryptValue.size();
    std::size_t offset = 0;
    auto iter = content.encryptValue.begin();
    if (offset + 1 >= static_cast<std::size_t>(size)) {
        return { false, keyData };
    }
    keyData.distributed = *iter;
    iter++;
    offset++;
 
    std::vector<uint8_t> createTime;
    if (offset + static_cast<std::size_t>(sizeof(time_t) / sizeof(uint8_t)) >= size) {
        return { false, keyData };
    }
    offset += sizeof(time_t) / sizeof(uint8_t);
    for (std::size_t i = 0; i < sizeof(time_t) / sizeof(uint8_t); i++) {
        createTime.push_back(*iter);
        iter++;
    }
 
    if (createTime.size() == sizeof(time_t)) {
        keyData.timeValue = *reinterpret_cast<time_t *>(&createTime[0]);
    }
 
    if (offset + AEAD_LEN >= static_cast<std::size_t>(size)) {
        return { false, keyData };
    }
    std::vector<uint8_t> key = { iter, content.encryptValue.end() };
    keyData.secretKey = DecryptWorkKey(key, content.nonceValue);
    key.assign(key.size(), 0);
    return { true, keyData };
}
 
std::pair<bool, RdbSecretKeyData> RdbSecurityManager::DecryptV2(const RdbSecretContent &content)
{
    RdbSecretKeyData keyData;
    std::vector<uint8_t> value = DecryptWorkKey(content.encryptValue, content.nonceValue);
    std::shared_ptr<const char> autoClean =
        std::shared_ptr<const char>("autoClean", [&value](const char *) mutable { value.assign(value.size(), 0); });
    auto size = value.size();
    std::size_t offset = 0;
    auto iter = value.begin();
    if (offset + 1 >= static_cast<std::size_t>(size)) {
        return { false, keyData };
    }
    keyData.distributed = *iter;
    iter++;
    offset++;
 
    std::vector<uint8_t> createTime;
    if (offset + static_cast<std::size_t>(sizeof(time_t) / sizeof(uint8_t)) >= size) {
        return { false, keyData };
    }
    offset += sizeof(time_t) / sizeof(uint8_t);
    for (std::size_t i = 0; i < sizeof(time_t) / sizeof(uint8_t); i++) {
        createTime.push_back(*iter);
        iter++;
    }
 
    if (createTime.size() == sizeof(time_t)) {
        keyData.timeValue = *reinterpret_cast<time_t *>(&createTime[0]);
    }
 
    if (offset + AEAD_LEN >= static_cast<std::size_t>(size)) {
        return { false, keyData };
    }
    keyData.secretKey = { iter, value.end() };
    return { true, keyData };
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
        return str.substr(0, str.length() - oldSuffix.length()) + SUFFIX_PUB_KEY_OLD;
    } else if (str.length() >= newSuffix.length() &&
        str.compare(str.length() - newSuffix.length(), newSuffix.length(), newSuffix) == 0) {
        return str.substr(0, str.length() - newSuffix.length()) + SUFFIX_PUB_TMP_NEW_KEY;
    }
    return str;
}
} // namespace NativeRdb
} // namespace OHOS

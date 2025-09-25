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
#include <fstream>
#include <securec.h>
#include <sstream>
#include <iomanip>
#include <openssl/hmac.h>
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
#include "sqlite_utils.h"
#include "string_utils.h"
#include "rdb_fault_hiview_reporter.h"
#include "relational_store_crypt.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using Reportor = RdbFaultHiViewReporter;
using Creator = std::shared_ptr<OHOS::NativeRdb::RDBCrypto> (*)(const std::vector<uint8_t> &rootKeyAlias);
using GenerateRandomNumFunc = std::vector<uint8_t> (*)(const uint32_t, RDBCryptoFault &);

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

RdbSecurityManager::RdbSecurityManager()
    : rootAlias_(std::vector<uint8_t>(RDB_ROOT_KEY_ALIAS, RDB_ROOT_KEY_ALIAS + strlen(RDB_ROOT_KEY_ALIAS))),
      handle_(nullptr)
{
}

void RdbSecurityManager::SetBundleName(const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(bundleNameMutex_);
    bundleNames_.insert(bundleName);
}

std::set<std::string> RdbSecurityManager::GetBundleNames()
{
    std::lock_guard<std::mutex> lock(bundleNameMutex_);
    return bundleNames_;
}

std::string RdbSecurityManager::GetBundleName()
{
    std::lock_guard<std::mutex> lock(bundleNameMutex_);
    if (bundleNames_.empty()) {
        return "";
    }
    std::string result;
    for (const auto& bundleName: bundleNames_) {
        if (!result.empty()) {
            result += " ";
        }
        result += bundleName;
    }
    return result;
}

RdbSecurityManager::~RdbSecurityManager()
{
    rdbCrypto_ = nullptr;
    if (handle_ != nullptr) {
        dlclose(handle_);
        handle_ = nullptr;
    }
}

std::vector<uint8_t> RdbSecurityManager::GenerateRandomNum(uint32_t len)
{
    auto handle = GetHandle();
    if (handle == nullptr) {
        return {};
    }
    auto generateRandomNum = reinterpret_cast<GenerateRandomNumFunc>(dlsym(handle, "GenerateRdbRandomNum"));
    if (generateRandomNum == nullptr) {
        LOG_ERROR("dlsym GenerateRandomNum failed(%{public}d)!", errno);
        return {};
    }
    RDBCryptoFault rdbFault;
    auto ret = generateRandomNum(len, rdbFault);
    ReportCryptFault(rdbFault.code, rdbFault.message);
    return ret;
}

bool RdbSecurityManager::SaveSecretKeyToFile(const std::string &keyFile, const std::vector<uint8_t> &workKey)
{
    LOG_INFO("begin keyFile%{public}s.", SqliteUtils::Anonymous(keyFile).c_str());

    std::vector<uint8_t> key = workKey.empty() ? GenerateRandomNum(RDB_KEY_SIZE) : workKey;
    if (key.empty()) {
        return false;
    }
    std::shared_ptr<const char> autoClean =
        std::shared_ptr<const char>("autoClean", [&key](const char *) mutable { key.assign(key.size(), 0); });
    auto [res, secretContent] = EncryptWorkKey(key);
    if (!res || secretContent.encrypt_.empty()) {
        Reportor::ReportFault(
            RdbFaultEvent(FT_OPEN, E_WORK_KEY_FAIL, GetBundleName() + "res:" + std::to_string(res), "key is empty"));
        LOG_ERROR("EncryptWorkKey failed, keyFile%{public}s", SqliteUtils::Anonymous(keyFile).c_str());
        return false;
    }
    return SaveSecretKeyToDisk(keyFile, secretContent);
}

std::vector<char> RdbSecurityManager::GenerateHMAC(std::vector<char> &data)
{
    unsigned char hmacResult[EVP_MAX_MD_SIZE] = {0};
    unsigned int hmacLen = 0;
    std::string key = "";
    std::vector<char> result;
    result.resize(HMAC_SIZE, 0);

    HMAC(EVP_sha256(),
         key.c_str(), static_cast<int>(key.length()),
         reinterpret_cast<const unsigned char*>(data.data()), static_cast<int>(data.size()),
         hmacResult, &hmacLen);
    if (hmacLen == 0) {
        LOG_ERROR("hmac generate failed");
        Reportor::ReportFault(RdbFaultEvent(
            FT_EX_FILE, E_DFX_HMAC_KEY_FAIL, GetBundleName(), "hmac generate failed" + std::to_string(hmacLen)));
        return result;
    }
    for (unsigned int i = 0; i < HMAC_SIZE && i < hmacLen; ++i) {
        result[i] = static_cast<char>(hmacResult[i]);
    }
    return result;
}

bool RdbSecurityManager::SaveSecretKeyToDisk(const std::string &keyPath, const RdbSecretContent &secretContent)
{
    LOG_INFO("begin keyPath:%{public}s.", SqliteUtils::Anonymous(keyPath).c_str());
    std::vector<char> payload;
    payload.push_back(secretContent.version);
    payload.insert(payload.end(), secretContent.nonce_.begin(), secretContent.nonce_.end());
    payload.insert(payload.end(), secretContent.encrypt_.begin(), secretContent.encrypt_.end());
    auto hmacKey = GenerateHMAC(payload);
    payload.insert(payload.end(), hmacKey.begin(), hmacKey.end());
    bool ret = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto fd = open(keyPath.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
        if (fd >= 0) {
            close(fd);
            ret = SaveBufferToFile(keyPath, payload);
        }
    }
    if (!ret) {
        Reportor::ReportFault(
            RdbFaultEvent(FT_EX_FILE, E_WORK_KEY_FAIL, GetBundleName(), "save fail errno=" + std::to_string(errno)));
        LOG_ERROR("Save key to file fail errno:%{public}d", errno);
    }
    return ret;
}

void RdbSecurityManager::ReportCryptFault(int32_t code, const std::string &message)
{
    if (message.empty()) {
        return;
    }
    Reportor::ReportFault(RdbFaultEvent(FT_EX_HUKS, code, GetBundleName(), message));
}

std::shared_ptr<RDBCrypto> RdbSecurityManager::GetDelegate()
{
    std::lock_guard<std::mutex> lock(cryptoMutex_);
    if (rdbCrypto_ != nullptr) {
        return rdbCrypto_;
    }
    rdbCrypto_ = CreateDelegate(rootAlias_);
    RDBCryptoFault fault;
    auto ret = rdbCrypto_->Init(fault);
    if (ret != E_OK) {
        ReportCryptFault(fault.code, fault.message);
        rdbCrypto_ = nullptr;
        return nullptr;
    }
    return rdbCrypto_;
}

int32_t RdbSecurityManager::Init(const std::string &bundleName)
{
    auto rdbCrypto = GetDelegate();
    if (rdbCrypto == nullptr) {
        return E_ERROR;
    }
    if (!bundleName.empty()) {
        SetBundleName(bundleName);
    }
    LOG_INFO("bundleName:%{public}s", bundleName.c_str());
    return E_OK;
}

std::pair<bool, RdbSecretContent> RdbSecurityManager::EncryptWorkKey(const std::vector<uint8_t> &key)
{
    RdbSecretContent rdbSecretContent;
    auto rdbCrypto = GetDelegate();
    if (rdbCrypto == nullptr) {
        return { false, rdbSecretContent };
    }
    RDBCryptoParam param;
    param.KeyValue = key;
    param.nonce_ = GenerateRandomNum(RdbSecretContent::NONCE_VALUE_SIZE);
    if (param.nonce_.empty()) {
        return { false, rdbSecretContent };
    }
    RDBCryptoFault rdbFault;
    auto encryptKey = rdbCrypto->Encrypt(param, rdbFault);
    rdbSecretContent.nonce_ = std::move(param.nonce_);
    rdbSecretContent.encrypt_ = std::move(encryptKey);
    ReportCryptFault(rdbFault.code, rdbFault.message);
    return { true, rdbSecretContent };
}

std::vector<uint8_t> RdbSecurityManager::DecryptWorkKey(
    const std::vector<uint8_t> &key, const std::vector<uint8_t> &nonce)
{
    auto rdbCrypto = GetDelegate();
    if (rdbCrypto == nullptr) {
        return {};
    }
    RDBCryptoParam param;
    param.KeyValue = key;
    param.nonce_ = nonce;
    RDBCryptoFault rdbFault;
    std::vector<uint8_t> decryptKey = rdbCrypto->Decrypt(param, rdbFault);
    if (!decryptKey.empty()) {
        return decryptKey;
    }
    auto bundleNames = GetBundleNames();
    for (const auto &bundleName : bundleNames) {
        std::vector<uint8_t> rootKeyAlias =
            std::vector<uint8_t>(RDB_ROOT_KEY_ALIAS, RDB_ROOT_KEY_ALIAS + strlen(RDB_ROOT_KEY_ALIAS));
        rootKeyAlias.insert(rootKeyAlias.end(), bundleName.begin(), bundleName.end());
        auto rdbBundleCrypto = CreateDelegate(rootKeyAlias);
        if (rdbBundleCrypto == nullptr || (!rdbBundleCrypto->RootKeyExists())) {
            continue;
        }
        decryptKey = rdbBundleCrypto->Decrypt(param, rdbFault);
        if (!decryptKey.empty()) {
            return decryptKey;
        }
    }
    ReportCryptFault(rdbFault.code, rdbFault.message);
    return decryptKey;
}

bool RdbSecurityManager::CreateDir(const std::string &fileDir)
{
    constexpr mode_t DEFAULT_UMASK = 0002;
    if (access(fileDir.c_str(), F_OK) == 0) {
        return true;
    }
    umask(DEFAULT_UMASK);
    auto ret = MkDir(fileDir, (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    if (ret != 0 && errno != EEXIST) {
        Reportor::ReportFault(RdbFaultEvent(FT_EX_FILE, E_WORK_KEY_FAIL,
            RdbSecurityManager::GetInstance().GetBundleName(),
            "mkdir err, ret=" + std::to_string(ret) + ",errno=" + std::to_string(errno) +
            ",fileDir=" + SqliteUtils::Anonymous(fileDir)));
        LOG_ERROR("mkdir error:%{public}d, area:%{public}s", errno, SqliteUtils::GetArea(fileDir).c_str());
        return false;
    }
    return true;
}

std::pair<bool, RdbSecretKeyData> RdbSecurityManager::LoadSecretKeyFromDiskV0(const std::string &keyPath)
{
    LOG_INFO("load secret key path:%{public}s.", SqliteUtils::Anonymous(keyPath).c_str());
    RdbSecretKeyData keyData;
    if (SqliteUtils::IsFileEmpty(keyPath)) {
        return { false, keyData };
    }
    std::vector<char> content;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!LoadBufferFromFile(keyPath, content)) {
            Reportor::ReportFault(RdbFaultEvent(FT_EX_FILE, E_WORK_KEY_DECRYPT_FAIL, GetBundleName(),
                "LoadBufferFromFile fail, errno=" + std::to_string(errno)));
            LOG_ERROR("LoadBufferFromFile failed:%{public}s.", SqliteUtils::Anonymous(keyPath).c_str());
            return { false, keyData };
        }
    }

    auto [res, rdbSecretContent] = UnpackV0(content);
    std::tie(res, keyData) = DecryptV0(rdbSecretContent);
    if (!res) {
        LOG_ERROR("DecryptV0 %{public}s failed, size:%{public}zu.", SqliteUtils::Anonymous(keyPath).c_str(),
            rdbSecretContent.encrypt_.size());
    }
    return { res, keyData };
}

std::pair<bool, RdbSecretKeyData> RdbSecurityManager::LoadSecretKeyFromDiskV1(const std::string &keyPath)
{
    LOG_INFO("load secret key path:%{public}s.", SqliteUtils::Anonymous(keyPath).c_str());
    RdbSecretKeyData keyData;
    if (SqliteUtils::IsFileEmpty(keyPath)) {
        return { false, keyData };
    }
    std::vector<char> content;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!LoadBufferFromFile(keyPath, content)) {
            Reportor::ReportFault(RdbFaultEvent(FT_EX_FILE, E_WORK_KEY_DECRYPT_FAIL, GetBundleName(),
                "LoadBufferFromFile fail, errno=" + std::to_string(errno)));
            LOG_ERROR("LoadBufferFromFile failed:%{public}s.", SqliteUtils::Anonymous(keyPath).c_str());
            return { false, keyData };
        }
    }

    auto [res, rdbSecretContent] = UnpackV1(content);
    if (!res) {
        LOG_ERROR("UnpackV1 failed:%{public}s.", SqliteUtils::Anonymous(keyPath).c_str());
        return { false, keyData };
    }
    std::tie(res, keyData) = DecryptV1(rdbSecretContent);
    if (!res) {
        LOG_ERROR("DecryptV1 failed:%{public}s.", SqliteUtils::Anonymous(keyPath).c_str());
    }
    return { res, keyData };
}

void RdbSecurityManager::UpgradeKey(const std::string &keyPath, const std::string &dbPath, KeyFileType keyFileType)
{
    auto suffixes = (keyFileType == PUB_KEY_FILE) ? OLD_PUB_KEY_SUFFIXES : OLD_PUB_NEW_KEY_SUFFIXES;
    const std::string dbKeyDir = StringUtils::ExtractFilePath(dbPath) + "key/";
    const std::string dbName = SqliteUtils::RemoveSuffix(StringUtils::ExtractFileName(dbPath));
    std::vector<std::string> oldKeyPaths;
    for (int32_t i = 0; i < PUB_KEY_FILE_BUTT; i++) {
        std::string oldKeyPath = dbKeyDir + dbName + suffixes[i];
        oldKeyPaths.push_back(std::move(oldKeyPath));
    }
    if (SqliteUtils::IsFilesEmpty(oldKeyPaths)) {
        return;
    }
    for (int32_t type = PUB_KEY_FILE; type < PUB_KEY_FILE_BUTT; type++) {
        auto [ret, keyData] = (this->*LOAD_KEY_HANDLERS[type])(oldKeyPaths[type]);
        if (!ret || keyData.secretKey.empty()) {
            continue;
        }
        LOG_INFO("begin to upgrade key path:%{public}s", SqliteUtils::Anonymous(oldKeyPaths[type]).c_str());
        if (SaveSecretKeyToFile(keyPath, keyData.secretKey)) {
            SqliteUtils::DeleteFiles(oldKeyPaths);
            keyData.secretKey.assign(keyData.secretKey.size(), 0);
            LOG_INFO("UpgradeKey success oldversion:%{public}d, path:%{public}s", type,
                SqliteUtils::Anonymous(oldKeyPaths[type]).c_str());
            return;
        }
        LOG_WARN("upgrade key failed path:%{public}s", oldKeyPaths[type].c_str());
        Reportor::ReportFault(RdbFaultEvent(FT_EX_FILE, E_DFX_UPGRADE_KEY_FAIL, GetBundleName(),
            "version:" + std::to_string(type) + "upgrade key failed" + std::to_string(errno)));
        keyData.secretKey.assign(keyData.secretKey.size(), 0);
    }
}

RdbPassword RdbSecurityManager::LoadSecretKeyFromFile(const std::string &keyPath)
{
    RdbPassword rdbPasswd;
    auto [res, keyData] = LoadSecretKeyFromDisk(keyPath);
    if (!keyData.secretKey.empty()) {
        rdbPasswd.SetValue(keyData.secretKey.data(), keyData.secretKey.size());
        keyData.secretKey.assign(keyData.secretKey.size(), 0);
        return rdbPasswd;
    }
    return {};
}

std::pair<bool, RdbSecretKeyData> RdbSecurityManager::LoadSecretKeyFromDisk(const std::string &keyPath)
{
    LOG_INFO("LoadSecretKeyFromDisk keyPath:%{public}s", SqliteUtils::Anonymous(keyPath).c_str());
    RdbSecretKeyData keyData;
    std::vector<char> content;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!LoadBufferFromFile(keyPath, content)) {
            Reportor::ReportFault(RdbFaultEvent(FT_EX_FILE, E_WORK_KEY_DECRYPT_FAIL, GetBundleName(),
                "LoadBufferFromFile fail, errno=" + std::to_string(errno)));
            LOG_ERROR("LoadBufferFromFile failed:%{public}s.", SqliteUtils::Anonymous(keyPath).c_str());
            return { false, keyData };
        }
    }
    auto [res, rdbSecretContent] = Unpack(content);
    if (!res) {
        LOG_ERROR("Unpack failed:%{public}s.", SqliteUtils::Anonymous(keyPath).c_str());
        return { false, keyData };
    }
    std::tie(res, keyData) = Decrypt(rdbSecretContent);
    if (!res) {
        LOG_ERROR("Decrypt failed:%{public}s.", SqliteUtils::Anonymous(keyPath).c_str());
    }
    return { res, keyData };
}

RdbPassword RdbSecurityManager::GetRdbPassword(const std::string &dbPath, KeyFileType keyFileType)
{
    KeyFiles keyFiles(dbPath);
    keyFiles.Lock();
    auto &keyFile = keyFiles.GetKeyFile(keyFileType);
    UpgradeKey(keyFile, dbPath, keyFileType);
    if (SqliteUtils::IsFileEmpty(keyFile)) {
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
        for (int32_t type = PUB_KEY_FILE; type < PUB_KEY_FILE_BUTT; type++) {
            SqliteUtils::DeleteFile(keyFiles.GetKeyFile(KeyFileType(type)));
        }
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

RdbSecurityManager &RdbSecurityManager::GetInstance()
{
    static RdbSecurityManager instance;
    return instance;
}

bool RdbSecurityManager::IsKeyFileExists(const std::string &dbPath, KeyFileType keyFileType)
{
    KeyFiles keyFiles(dbPath, false);
    auto suffixes = (keyFileType == PUB_KEY_FILE) ? OLD_PUB_KEY_SUFFIXES : OLD_PUB_NEW_KEY_SUFFIXES;
    const std::string dbKeyDir = StringUtils::ExtractFilePath(dbPath) + "key/";
    const std::string dbName = SqliteUtils::RemoveSuffix(StringUtils::ExtractFileName(dbPath));
    std::vector<std::string> keyPaths;
    for (int32_t i = 0; i < PUB_KEY_FILE_BUTT; i++) {
        std::string oldKeyPath = dbKeyDir + dbName + suffixes[i];
        keyPaths.push_back(std::move(oldKeyPath));
    }
    keyPaths.push_back(keyFiles.GetKeyFile(keyFileType));
    return !SqliteUtils::IsFilesEmpty(keyPaths);
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

std::pair<bool, RdbSecretContent> RdbSecurityManager::UnpackV0(const std::vector<char> &content)
{
    RdbSecretContent rdbSecretContent;
    rdbSecretContent.version = 0;
    rdbSecretContent.nonce_ = { RDB_HKS_BLOB_TYPE_NONCE,
        RDB_HKS_BLOB_TYPE_NONCE + strlen(RDB_HKS_BLOB_TYPE_NONCE) };
    rdbSecretContent.encrypt_ = { content.begin(), content.end() };
    return { true, rdbSecretContent };
}

std::pair<bool, RdbSecretContent> RdbSecurityManager::UnpackV1(const std::vector<char> &content)
{
    RdbSecretContent rdbSecretContent;

    auto size = content.size();
    std::size_t offset = sizeof(rdbSecretContent.magicNum);
    if (offset >= static_cast<std::size_t>(size)) {
        return { false, rdbSecretContent };
    }
    rdbSecretContent.magicNum = *reinterpret_cast<const uint32_t *>(&content[0]);
    if (offset + RdbSecretContent::NONCE_VALUE_SIZE >= static_cast<std::size_t>(size)) {
        return { false, rdbSecretContent };
    }
    rdbSecretContent.nonce_ = { content.begin() + offset,
        content.begin() + offset + RdbSecretContent::NONCE_VALUE_SIZE };
    offset += RdbSecretContent::NONCE_VALUE_SIZE;
    rdbSecretContent.encrypt_ = { content.begin() + offset, content.end() };
    return { true, rdbSecretContent };
}

std::pair<bool, RdbSecretContent> RdbSecurityManager::Unpack(const std::vector<char> &content)
{
    RdbSecretContent rdbSecretContent;
    if (content.size() <= HMAC_SIZE) {
        LOG_ERROR("Content too short for HMAC verification, size: %zu", content.size());
        return { false, rdbSecretContent };
    }

    size_t dataLength = content.size() - HMAC_SIZE;
    std::vector<char> originalData(content.begin(), content.begin() + dataLength);
    std::vector<char> storedHMAC(content.begin() + dataLength, content.end());
    auto calculatedHMAC = GenerateHMAC(originalData);
    if (calculatedHMAC != storedHMAC) {
        Reportor::ReportFault(RdbFaultEvent(
            FT_EX_FILE, E_DFX_HMAC_KEY_FAIL, GetBundleName(), "hmac key file failed" + std::to_string(errno)));
        LOG_ERROR("hmac check failed, bundlename:%{public}s", GetBundleName().c_str());
    }
    if (originalData.size() <= (sizeof(rdbSecretContent.version) + RdbSecretContent::NONCE_VALUE_SIZE)) {
        return { false, rdbSecretContent };
    }
    std::size_t offset = 0;
    rdbSecretContent.version = static_cast<uint8_t>(originalData[offset]);
    offset += sizeof(rdbSecretContent.version);

    rdbSecretContent.nonce_.assign(
        originalData.begin() + offset, originalData.begin() + offset + RdbSecretContent::NONCE_VALUE_SIZE);
    offset += RdbSecretContent::NONCE_VALUE_SIZE;

    rdbSecretContent.encrypt_.assign(originalData.begin() + offset, originalData.end());
    return { true, rdbSecretContent };
}

std::pair<bool, RdbSecretKeyData> RdbSecurityManager::DecryptV0(const RdbSecretContent &content)
{
    RdbSecretKeyData keyData;
    auto size = content.encrypt_.size();
    std::size_t offset = 0;
    auto iter = content.encrypt_.begin();
    if (offset + 1 >= static_cast<std::size_t>(size)) {
        return { false, keyData };
    }
    keyData.version = *iter;
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
    std::vector<uint8_t> key = { iter, content.encrypt_.end() };
    keyData.secretKey = DecryptWorkKey(key, content.nonce_);
    key.assign(key.size(), 0);
    return { true, keyData };
}

std::pair<bool, RdbSecretKeyData> RdbSecurityManager::DecryptV1(const RdbSecretContent &content)
{
    RdbSecretKeyData keyData;
    std::vector<uint8_t> value = DecryptWorkKey(content.encrypt_, content.nonce_);
    std::shared_ptr<const char> autoClean =
        std::shared_ptr<const char>("autoClean", [&value](const char *) mutable { value.assign(value.size(), 0); });
    auto size = value.size();
    std::size_t offset = 0;
    auto iter = value.begin();
    if (offset + 1 >= static_cast<std::size_t>(size)) {
        return { false, keyData };
    }
    keyData.version = *iter;
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

std::pair<bool, RdbSecretKeyData> RdbSecurityManager::Decrypt(const RdbSecretContent &content)
{
    RdbSecretKeyData keyData;
    std::vector<uint8_t> value = DecryptWorkKey(content.encrypt_, content.nonce_);
    keyData.secretKey = { value.begin(), value.end() };
    value.assign(value.size(), 0);
    return { true, keyData };
}

std::shared_ptr<RDBCrypto> RdbSecurityManager::CreateDelegate(const std::vector<uint8_t> &rootKeyAlias)
{
    auto handle = GetHandle();
    if (handle == nullptr) {
        return nullptr;
    }
    auto creator = reinterpret_cast<Creator>(dlsym(handle, "CreateRdbCryptoDelegate"));
    if (creator == nullptr) {
        LOG_ERROR("dlsym failed!");
        return nullptr;
    }
    return creator(rootKeyAlias);
}

RdbSecurityManager::KeyFiles::KeyFiles(const std::string &dbPath, bool openFile)
{
    const std::string dbKeyDir = StringUtils::ExtractFilePath(dbPath) + "key/";
    const std::string dbName = SqliteUtils::RemoveSuffix(StringUtils::ExtractFileName(dbPath));
    for (uint32_t i = 0; i < PUB_KEY_FILE_BUTT; i++) {
        keys_[i] = dbKeyDir + dbName + PUB_KEY_SUFFIXES[i];
    }
    const std::string lockDir = StringUtils::ExtractFilePath(dbPath) + "lock/";
    lock_ = lockDir + dbName + SUFFIX_KEY_LOCK;
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
    if (!CreateDir(keyDir)) {
        LOG_ERROR("keyDir failed, errno:%{public}d, dir:%{public}s.", errno, SqliteUtils::Anonymous(keyDir).c_str());
    }
    return E_OK;
}

int32_t RdbSecurityManager::KeyFiles::Lock(bool isBlock)
{
    if (!InitLockPath() || lockFd_ < 0) {
        return E_INVALID_FILE_PATH;
    }
    int32_t errCode;
    int lockType = isBlock ? LOCK_EX : LOCK_EX | LOCK_NB;
    do {
        errCode = flock(lockFd_, lockType);
    } while (errCode < 0 && errno == EINTR);
    if (errCode < 0) {
        LOG_WARN("lock failed, type:%{public}d, errno:%{public}d, dir:%{public}s.", lockType, errno,
            SqliteUtils::Anonymous(lock_).c_str());
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

bool RdbSecurityManager::KeyFiles::InitLockPath()
{
    bool isDirCreate = CreateDir(StringUtils::ExtractFilePath(lock_));
    if (!isDirCreate) {
        return false;
    }
    if (lockFd_ < 0) {
        lockFd_ = open(lock_.c_str(), O_RDONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    }
    if (lockFd_ < 0) {
        LOG_WARN("open failed, errno:%{public}d, file:%{public}s.", errno, SqliteUtils::Anonymous(lock_).c_str());
        return false;
    }
    return true;
}
} // namespace NativeRdb
} // namespace OHOS

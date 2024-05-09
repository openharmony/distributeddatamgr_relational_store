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
#define LOG_TAG "RdbPassword"
#include "rdb_security_manager.h"

#include <securec.h>

#include <string>
#include <utility>

#include "directory_ex.h"
#include "file_ex.h"
#include "hks_param.h"
#include "logger.h"
#include "rdb_sql_utils.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

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

int32_t RdbSecurityManager::HksLoopUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    if (outData->size < inData->size * TIMES) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    struct HksBlob input = {MAX_UPDATE_SIZE, inData->data};
    uint8_t *end = inData->data + inData->size - 1;
    outData->size = 0;
    struct HksBlob output = { MAX_OUTDATA_SIZE, outData->data };
    while (input.data <= end) {
        if (input.data + MAX_UPDATE_SIZE > end) {
            input.size = end - input.data + 1;
            break;
        }

        if (HksUpdate(handle, paramSet, &input, &output) != HKS_SUCCESS) {
            LOG_ERROR("HksUpdate Failed.");
            return HKS_FAILURE;
        }

        output.data += output.size;
        outData->size += output.size;
        input.data += MAX_UPDATE_SIZE;
    }
    output.size = input.size * TIMES;
    if (HksFinish(handle, paramSet, &input, &output) != HKS_SUCCESS) {
        LOG_ERROR("HksFinish Failed.");
        return HKS_FAILURE;
    }
    outData->size += output.size;
    return HKS_SUCCESS;
}

int32_t RdbSecurityManager::HksEncryptThreeStage(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *plainText, struct HksBlob *cipherText)
{
    uint8_t handle[sizeof(uint64_t)] = { 0 };
    struct HksBlob handleBlob = { sizeof(uint64_t), handle };
    int32_t result = HksInit(keyAlias, paramSet, &handleBlob, nullptr);
    if (result != HKS_SUCCESS) {
        LOG_ERROR("HksEncrypt failed with error %{public}d", result);
        return result;
    }
    return HksLoopUpdate(&handleBlob, paramSet, plainText, cipherText);
}

int32_t RdbSecurityManager::HksDecryptThreeStage(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText)
{
    uint8_t handle[sizeof(uint64_t)] = { 0 };
    struct HksBlob handleBlob = { sizeof(uint64_t), handle };
    int32_t result = HksInit(keyAlias, paramSet, &handleBlob, nullptr);
    if (result != HKS_SUCCESS) {
        LOG_ERROR("HksEncrypt failed with error %{public}d", result);
        return result;
    }
    return HksLoopUpdate(&handleBlob, paramSet, cipherText, plainText);
}

RdbSecurityManager::RdbSecurityManager()
    : nonce_(RDB_HKS_BLOB_TYPE_NONCE, RDB_HKS_BLOB_TYPE_NONCE + strlen(RDB_HKS_BLOB_TYPE_NONCE)),
      aad_(RDB_HKS_BLOB_TYPE_AAD, RDB_HKS_BLOB_TYPE_AAD + strlen(RDB_HKS_BLOB_TYPE_AAD)){};

RdbSecurityManager::~RdbSecurityManager() = default;

std::vector<uint8_t> RdbSecurityManager::GenerateRandomNum(int32_t len)
{
    std::random_device randomDevice;
    std::uniform_int_distribution<int> distribution(0, std::numeric_limits<uint8_t>::max());
    std::vector<uint8_t> key(len);
    for (int32_t i = 0; i < len; i++) {
        key[i] = static_cast<uint8_t>(distribution(randomDevice));
    }
    return key;
}

bool RdbSecurityManager::SaveSecretKeyToFile(const std::string &dbPath, RdbSecurityManager::KeyFileType keyFileType)
{
    LOG_INFO("SaveSecretKeyToFile begin.");
    if (!HasRootKey()) {
        LOG_ERROR("Root key not exists!");
        return false;
    }
    std::vector<uint8_t> key = GenerateRandomNum(RDB_KEY_SIZE);
    RdbSecretKeyData keyData;
    keyData.timeValue = std::chrono::system_clock::to_time_t(std::chrono::system_clock::system_clock::now());
    keyData.distributed = 0;
    keyData.secretKey = EncryptWorkKey(key);

    if (keyData.secretKey.empty()) {
        LOG_ERROR("Key size is 0");
        key.assign(key.size(), 0);
        return false;
    }

    key.assign(key.size(), 0);
    if (!RdbSecurityManager::InitPath(ExtractFilePath(dbPath) + std::string("key/"))) {
        LOG_ERROR("InitPath err.");
        return false;
    }

    return SaveSecretKeyToDisk(GetKeyPath(dbPath, keyFileType), keyData);
}

bool RdbSecurityManager::SaveSecretKeyToDisk(const std::string &keyPath, RdbSecretKeyData &keyData)
{
    LOG_INFO("SaveSecretKeyToDisk begin.");
    std::vector<uint8_t> distributedInByte = { &keyData.distributed, &keyData.distributed + sizeof(uint8_t) };
    std::vector<uint8_t> timeInByte = { reinterpret_cast<uint8_t *>(&keyData.timeValue),
        reinterpret_cast<uint8_t *>(&keyData.timeValue) + sizeof(time_t) };

    std::vector<char> secretKeyInChar;
    secretKeyInChar.insert(secretKeyInChar.end(), distributedInByte.begin(), distributedInByte.end());
    secretKeyInChar.insert(secretKeyInChar.end(), timeInByte.begin(), timeInByte.end());
    secretKeyInChar.insert(secretKeyInChar.end(), keyData.secretKey.begin(), keyData.secretKey.end());

    std::lock_guard<std::mutex> lock(mutex_);
    bool ret = SaveBufferToFile(keyPath, secretKeyInChar);
    if (!ret) {
        LOG_ERROR("SaveBufferToFile failed!");
        return false;
    }

    return true;
}

int RdbSecurityManager::GenerateRootKey(const std::vector<uint8_t> &rootKeyAlias)
{
    LOG_INFO("RDB GenerateRootKey begin.");
    std::vector<uint8_t> tempRootKeyAlias = rootKeyAlias;
    struct HksBlob rootKeyName = { uint32_t(rootKeyAlias.size()), tempRootKeyAlias.data() };
    struct HksParamSet *params = nullptr;
    int32_t ret = HksInitParamSet(&params);
    if (ret != HKS_SUCCESS) {
        LOG_ERROR("HksInitParamSet()-client failed with error %{public}d", ret);
        return ret;
    }

    struct HksParam hksParam[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = 0 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    };

    ret = HksAddParams(params, hksParam, sizeof(hksParam) / sizeof(hksParam[0]));
    if (ret != HKS_SUCCESS) {
        LOG_ERROR("HksAddParams-client failed with error %{public}d", ret);
        HksFreeParamSet(&params);
        return ret;
    }

    ret = HksBuildParamSet(&params);
    if (ret != HKS_SUCCESS) {
        LOG_ERROR("HksBuildParamSet-client failed with error %{public}d", ret);
        HksFreeParamSet(&params);
        return ret;
    }

    ret = HksGenerateKey(&rootKeyName, params, nullptr);
    HksFreeParamSet(&params);
    if (ret != HKS_SUCCESS) {
        LOG_ERROR("HksGenerateKey-client failed with error %{public}d", ret);
    }
    return ret;
}

std::vector<uint8_t> RdbSecurityManager::EncryptWorkKey(std::vector<uint8_t> &key)
{
    struct HksBlob blobAad = { uint32_t(aad_.size()), aad_.data() };
    struct HksBlob blobNonce = { uint32_t(nonce_.size()), nonce_.data() };
    struct HksBlob rootKeyName = { uint32_t(rootKeyAlias_.size()), rootKeyAlias_.data() };
    struct HksBlob plainKey = { uint32_t(key.size()), key.data() };
    struct HksParamSet *params = nullptr;
    int32_t ret = HksInitParamSet(&params);
    if (ret != HKS_SUCCESS) {
        LOG_ERROR("HksInitParamSet() failed with error %{public}d", ret);
        return {};
    }
    struct HksParam hksParam[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = 0 },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_NONCE, .blob = blobNonce },
        { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = blobAad },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    };
    ret = HksAddParams(params, hksParam, sizeof(hksParam) / sizeof(hksParam[0]));
    if (ret != HKS_SUCCESS) {
        LOG_ERROR("HksAddParams failed with error %{public}d", ret);
        HksFreeParamSet(&params);
        return {};
    }

    ret = HksBuildParamSet(&params);
    if (ret != HKS_SUCCESS) {
        LOG_ERROR("HksBuildParamSet failed with error %{public}d", ret);
        HksFreeParamSet(&params);
        return {};
    }
    std::vector<uint8_t> encryptedKey(plainKey.size * TIMES + 1);
    struct HksBlob cipherText = { uint32_t(encryptedKey.size()), encryptedKey.data() };
    ret = HksEncryptThreeStage(&rootKeyName, params, &plainKey, &cipherText);
    (void)HksFreeParamSet(&params);
    if (ret != HKS_SUCCESS) {
        encryptedKey.assign(encryptedKey.size(), 0);
        LOG_ERROR("HksEncrypt failed with error %{public}d", ret);
        return {};
    }
    encryptedKey.resize(cipherText.size);
    return encryptedKey;
}

bool RdbSecurityManager::DecryptWorkKey(std::vector<uint8_t> &source, std::vector<uint8_t> &key)
{
    struct HksBlob blobAad = { uint32_t(aad_.size()), &(aad_[0]) };
    struct HksBlob blobNonce = { uint32_t(nonce_.size()), &(nonce_[0]) };
    struct HksBlob rootKeyName = { uint32_t(rootKeyAlias_.size()), &(rootKeyAlias_[0]) };
    struct HksBlob encryptedKeyBlob = { uint32_t(source.size() - AEAD_LEN), source.data() };
    struct HksBlob blobAead = { AEAD_LEN, source.data() + source.size() - AEAD_LEN };
    struct HksParamSet *params = nullptr;
    int32_t ret = HksInitParamSet(&params);
    if (ret != HKS_SUCCESS) {
        LOG_ERROR("HksInitParamSet() failed with error %{public}d", ret);
        return false;
    }
    struct HksParam hksParam[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = 0 },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_NONCE, .blob = blobNonce },
        { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = blobAad },
        { .tag = HKS_TAG_AE_TAG, .blob = blobAead },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    };
    ret = HksAddParams(params, hksParam, sizeof(hksParam) / sizeof(hksParam[0]));
    if (ret != HKS_SUCCESS) {
        LOG_ERROR("HksAddParams failed with error %{public}d", ret);
        HksFreeParamSet(&params);
        return false;
    }

    ret = HksBuildParamSet(&params);
    if (ret != HKS_SUCCESS) {
        LOG_ERROR("HksBuildParamSet failed with error %{public}d", ret);
        HksFreeParamSet(&params);
        return false;
    }
    key.resize(encryptedKeyBlob.size * TIMES + 1);
    struct HksBlob plainKeyBlob = { uint32_t(key.size()), key.data() };
    ret = HksDecryptThreeStage(&rootKeyName, params, &encryptedKeyBlob, &plainKeyBlob);
    (void)HksFreeParamSet(&params);
    if (ret != HKS_SUCCESS) {
        key.assign(key.size(), 0);
        LOG_ERROR("HksDecrypt failed with error %{public}d", ret);
        return false;
    }
    key.resize(plainKeyBlob.size);
    return true;
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
                rootKeyAlias_ = std::move(rootKeyAlias);
            }
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
    LOG_DEBUG("RDB checkRootKeyExist begin.");
    struct HksBlob rootKeyName = { uint32_t(rootKeyAlias.size()), rootKeyAlias.data() };
    struct HksParamSet *params = nullptr;
    int32_t ret = HksInitParamSet(&params);
    if (ret != HKS_SUCCESS) {
        LOG_ERROR("HksInitParamSet()-client failed with error %{public}d", ret);
        return ret;
    }

    struct HksParam hksParam[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = 0 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    };

    ret = HksAddParams(params, hksParam, sizeof(hksParam) / sizeof(hksParam[0]));
    if (ret != HKS_SUCCESS) {
        LOG_ERROR("HksAddParams failed with error %{public}d", ret);
        HksFreeParamSet(&params);
        return ret;
    }

    ret = HksBuildParamSet(&params);
    if (ret != HKS_SUCCESS) {
        LOG_ERROR("HksBuildParamSet failed with error %{public}d", ret);
        HksFreeParamSet(&params);
        return ret;
    }

    ret = HksKeyExist(&rootKeyName, params);
    HksFreeParamSet(&params);
    return ret;
}

bool RdbSecurityManager::InitPath(const std::string &dbKeyDir)
{
    constexpr mode_t DEFAULT_UMASK = 0002;
    if (access(dbKeyDir.c_str(), F_OK) == 0) {
        return true;
    }
    umask(DEFAULT_UMASK);
    if (mkdir(dbKeyDir.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) != 0 && errno != EEXIST) {
        LOG_ERROR("mkdir error:%{public}d, dbDir:%{public}s", errno, SqliteUtils::Anonymous(dbKeyDir).c_str());
        return false;
    }
    return true;
}

RdbPassword RdbSecurityManager::LoadSecretKeyFromFile(const std::string &dbPath, KeyFileType keyFileType)
{
    std::string keyPath = GetKeyPath(dbPath, keyFileType);
    if (!FileExists(keyPath)) {
        LOG_ERROR("Key file not exists.");
        return {};
    }

    RdbSecretKeyData keyData;
    if (!LoadSecretKeyFromDisk(keyPath, keyData)) {
        LOG_ERROR("Load key failed.");
        return {};
    }

    std::vector<uint8_t> key;
    if (!DecryptWorkKey(keyData.secretKey, key)) {
        LOG_ERROR("Decrypt key failed!");
        return {};
    }

    RdbPassword rdbPasswd;
    rdbPasswd.isKeyExpired = IsKeyExpired(keyData.timeValue);
    rdbPasswd.SetValue(key.data(), key.size());
    key.assign(key.size(), 0);
    return rdbPasswd;
}

bool RdbSecurityManager::LoadSecretKeyFromDisk(const std::string &keyPath, RdbSecretKeyData &keyData)
{
    LOG_DEBUG("LoadSecretKeyFromDisk begin.");
    std::vector<char> content;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!LoadBufferFromFile(keyPath, content) || content.empty()) {
            LOG_ERROR("LoadBufferFromFile failed!");
            return false;
        }
    }

    auto iter = content.begin();
    keyData.distributed = *iter;
    iter++;

    std::vector<uint8_t> createTime;
    for (int i = 0; i < static_cast<int>(sizeof(time_t) / sizeof(uint8_t)); i++) {
        createTime.push_back(*iter);
        iter++;
    }

    if (createTime.size() == sizeof(time_t)) {
        keyData.timeValue = *reinterpret_cast<time_t *>(&createTime[0]);
    }

    keyData.secretKey.insert(keyData.secretKey.end(), iter, content.end());

    return true;
}

RdbPassword RdbSecurityManager::GetRdbPassword(const std::string &dbPath, RdbSecurityManager::KeyFileType keyFileType)
{
    if (!IsKeyFileExists(dbPath, keyFileType)) {
        if (!SaveSecretKeyToFile(dbPath, keyFileType)) {
            LOG_ERROR("Failed to save key.");
            return {};
        }
    }

    return LoadSecretKeyFromFile(dbPath, keyFileType);
}

std::vector<uint8_t> RdbSecurityManager::GenerateRootKeyAlias(const std::string &bundlename)
{
    std::vector<uint8_t> rootKeyAlias =
        std::vector<uint8_t>(RDB_ROOT_KEY_ALIAS_PREFIX, RDB_ROOT_KEY_ALIAS_PREFIX + strlen(RDB_ROOT_KEY_ALIAS_PREFIX));
    rootKeyAlias.insert(rootKeyAlias.end(), bundlename.begin(), bundlename.end());
    return rootKeyAlias;
}

void RdbSecurityManager::DelRdbSecretDataFile(const std::string &dbPath)
{
    LOG_INFO("Delete all key files begin.");
    std::lock_guard<std::mutex> lock(mutex_);
    auto keyPaths = ConcatenateKeyPath(dbPath);
    SqliteUtils::DeleteFile(keyPaths.first);
    SqliteUtils::DeleteFile(keyPaths.second);
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

std::pair<std::string, std::string> RdbSecurityManager::ConcatenateKeyPath(const std::string &dbPath)
{
    const std::string dbName = RemoveSuffix(ExtractFileName(dbPath));
    const std::string dbKeyDir = ExtractFilePath(dbPath) + "key/";
    const std::string keyPath = dbKeyDir + dbName + RdbSecurityManager::SUFFIX_PUB_KEY;
    const std::string newKeyPath = dbKeyDir + dbName + RdbSecurityManager::SUFFIX_PUB_KEY_NEW;
    return std::make_pair(keyPath, newKeyPath);
}

bool RdbSecurityManager::IsKeyFileExists(const std::string &dbPath, RdbSecurityManager::KeyFileType keyFileType)
{
    return FileExists(GetKeyPath(dbPath, keyFileType));
}

std::string RdbSecurityManager::GetKeyPath(const std::string &dbPath, RdbSecurityManager::KeyFileType keyFileType)
{
    auto keyPaths = ConcatenateKeyPath(dbPath);
    if (keyFileType == KeyFileType::PUB_KEY_FILE) {
        return keyPaths.first;
    } else {
        return keyPaths.second;
    }
}

void RdbSecurityManager::DelRdbSecretDataFile(const std::string &dbPath, RdbSecurityManager::KeyFileType keyFileType)
{
    std::string keyPath = GetKeyPath(dbPath, keyFileType);
    SqliteUtils::DeleteFile(keyPath);
}

void RdbSecurityManager::UpdateKeyFile(const std::string &dbPath)
{
    auto keyPaths = ConcatenateKeyPath(dbPath);
    if (SqliteUtils::RenameFile(keyPaths.second, keyPaths.first) != E_OK) {
        LOG_ERROR("Rename key file failed.");
        return;
    }
}

bool RdbSecurityManager::HasRootKey()
{
    return hasRootKey_;
}
} // namespace NativeRdb
} // namespace OHOS

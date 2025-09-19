/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define LOG_TAG "RdbEncryptUpgradeTest"
#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <string>
#include <thread>

#include "block_data.h"
#include "common.h"
#include "file_ex.h"
#include "hks_api.h"
#include "hks_param.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_security_manager.h"
#include "rdb_store_manager.h"
#include "relational_store_crypt.h"
#include "sqlite_utils.h"
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Rdb;

static const std::string BUNDLE_NAME = "ohos.hmos.test";
static const std::string BUNDLE_NAME_1 = "ohos.hmos.test1";
static const std::string ENCRYPT_NAME = "encrypted.db";
static const std::string ENCRYPT_PATH = RDB_TEST_PATH + ENCRYPT_NAME;
static const std::string ENCRYPT_NAME_1 = "encrypted1.db";
static const std::string ENCRYPT_PATH_1 = RDB_TEST_PATH + ENCRYPT_NAME_1;
static const std::string ENCRYPT_DATABASE_KEY_DIR = RDB_TEST_PATH + "key/";
static constexpr uint32_t MAGIC_NUMBER_V2 = 0x6B6B6B6B;
struct RdbSecretKeyDataV0 {
    uint8_t distributed = 0;
    time_t timeValue{};
    std::vector<uint8_t> secretKey{};
    RdbSecretKeyDataV0() = default;
    ~RdbSecretKeyDataV0()
    {
        secretKey.assign(secretKey.size(), 0);
    }
};
struct RdbSecretContentV2 {
    uint32_t magicNum = MAGIC_NUMBER_V2;
    std::vector<uint8_t> nonce_{};
    std::vector<uint8_t> encrypt_{};
    RdbSecretContentV2() = default;
    ~RdbSecretContentV2()
    {
        nonce_.assign(nonce_.size(), 0);
        encrypt_.assign(encrypt_.size(), 0);
    }
};
class RdbEncryptUpgradeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    static std::vector<uint8_t> GetRootKeyAlias(const std::string& bundleName);
    std::vector<uint8_t> Encrypt(std::vector<uint8_t> &key, std::vector<uint8_t> rootKeyAlias);
    std::vector<uint8_t> Encryptv1(const RDBCryptoParam &param, std::vector<uint8_t> rootKeyAlias);
    bool GetRDBStore(const RdbStoreConfig &config);
    void InitRootAlias(std::vector<uint8_t> &rootKeyAlias);
    RdbStoreConfig GetConfig(const std::string &dbPath, const std::string &bundleName);
    bool SaveSecretV0KeyToFile(const std::string &keyPath, RdbSecretKeyDataV0 &keyData);
    bool SaveSecretV1KeyToFile(const std::string &keyPath, RDBCryptoParam &keyData);
    int32_t HksLoopUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
        const struct HksBlob *inData, struct HksBlob *outData);
    int32_t HksEncryptThreeStage(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
        const struct HksBlob *plainText, struct HksBlob *cipherText);
    int32_t CheckRootKeyExists(std::vector<uint8_t> &rootKeyAlias);
    int32_t GenerateRootKey(const std::vector<uint8_t> &rootKeyAlias);
    void GetKeyFileV0FromV2(const std::string &keyPathV2, const std::string &keyPathV0, const std::string& bundleName);
    void GetKeyFileV1FromV2(const std::string &keyPathV2, const std::string &keyPathV1, const std::string& bundleName);
    std::mutex mutex_;
};

static constexpr uint32_t TIMES = 4;
static constexpr uint32_t MAX_UPDATE_SIZE = 64;
static constexpr uint32_t MAX_OUTDATA_SIZE = MAX_UPDATE_SIZE * TIMES;
static constexpr const char *RDB_HKS_BLOB_TYPE_NONCE = "Z5s0Bo571Koq";
static constexpr const char *RDB_HKS_BLOB_TYPE_AAD = "RdbClientAAD";

class RdbEncryptUpgradeTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string createTableTest;
};
std::string const RdbEncryptUpgradeTestOpenCallback::createTableTest = "CREATE TABLE IF NOT EXISTS test "
                                                                       "(id INTEGER PRIMARY KEY "
                                                                       "AUTOINCREMENT, "
                                                                       "name TEXT NOT NULL, age INTEGER, "
                                                                       "salary "
                                                                       "REAL, blobType BLOB)";
int RdbEncryptUpgradeTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(createTableTest);
}

int RdbEncryptUpgradeTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbEncryptUpgradeTest::SetUpTestCase()
{
}

void RdbEncryptUpgradeTest::TearDownTestCase()
{
}

void RdbEncryptUpgradeTest::SetUp()
{
    std::vector<uint8_t> rootKeyAlias = GetRootKeyAlias(BUNDLE_NAME);
    std::vector<uint8_t> rootKeyAlias1 = GetRootKeyAlias(BUNDLE_NAME_1);
    InitRootAlias(rootKeyAlias);
    InitRootAlias(rootKeyAlias1);
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(ENCRYPT_PATH);
    RdbHelper::DeleteRdbStore(ENCRYPT_PATH_1);
}

void RdbEncryptUpgradeTest::TearDown()
{
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(ENCRYPT_PATH);
    RdbHelper::DeleteRdbStore(ENCRYPT_PATH_1);
}
void RdbEncryptUpgradeTest::InitRootAlias(std::vector<uint8_t> &rootKeyAlias)
{
    constexpr uint32_t RETRY_MAX_TIMES = 5;
    constexpr int RETRY_TIME_INTERVAL_MILLISECOND = 1 * 1000 * 1000;
    int32_t ret = HKS_FAILURE;
    uint32_t retryCount = 0;
    while (retryCount < RETRY_MAX_TIMES) {
        ret = CheckRootKeyExists(rootKeyAlias);
        if (ret == HKS_ERROR_NOT_EXIST) {
            ret = GenerateRootKey(rootKeyAlias);
        }
        if (ret == HKS_SUCCESS) {
            break;
        }
        retryCount++;
        usleep(RETRY_TIME_INTERVAL_MILLISECOND);
    }
    EXPECT_EQ(ret, HKS_SUCCESS);
}

bool RdbEncryptUpgradeTest::GetRDBStore(const RdbStoreConfig &config)
{
    RdbEncryptUpgradeTestOpenCallback helper;
    int errCode = E_OK;
    bool ret = false;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    if (store) {
        ret = true;
    }
    store = nullptr;
    return ret;
}

RdbStoreConfig RdbEncryptUpgradeTest::GetConfig(const std::string &dbPath, const std::string &bundleName)
{
    RdbStoreConfig config(dbPath);
    config.SetSecurityLevel(SecurityLevel::S1);
    config.SetBundleName(bundleName);
    config.SetEncryptStatus(true);
    return config;
}

std::vector<uint8_t> RdbEncryptUpgradeTest::GetRootKeyAlias(const std::string &bundleName)
{
    std::vector<uint8_t> rootKeyAlias = std::vector<uint8_t>(RdbSecurityManager::RDB_ROOT_KEY_ALIAS,
        RdbSecurityManager::RDB_ROOT_KEY_ALIAS + strlen(RdbSecurityManager::RDB_ROOT_KEY_ALIAS));
    rootKeyAlias.insert(rootKeyAlias.end(), bundleName.begin(), bundleName.end());
    return rootKeyAlias;
}

int32_t RdbEncryptUpgradeTest::HksLoopUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    if (outData->size < inData->size * TIMES) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    struct HksBlob input = { MAX_UPDATE_SIZE, inData->data };
    uint8_t *end = inData->data + inData->size - 1;
    outData->size = 0;
    struct HksBlob output = { MAX_OUTDATA_SIZE, outData->data };
    while (input.data <= end) {
        if (input.data + MAX_UPDATE_SIZE > end) {
            input.size = end - input.data + 1;
            break;
        }
        auto result = HksUpdate(handle, paramSet, &input, &output);
        if (result != HKS_SUCCESS) {
            LOG_ERROR("HksUpdate Failed.");
            return HKS_FAILURE;
        }
        output.data += output.size;
        outData->size += output.size;
        input.data += MAX_UPDATE_SIZE;
    }
    output.size = input.size * TIMES;
    auto result = HksFinish(handle, paramSet, &input, &output);
    if (result != HKS_SUCCESS) {
        LOG_ERROR("HksFinish Failed.");
        return HKS_FAILURE;
    }
    outData->size += output.size;
    return HKS_SUCCESS;
}

int32_t RdbEncryptUpgradeTest::HksEncryptThreeStage(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *plainText, struct HksBlob *cipherText)
{
    uint8_t handle[sizeof(uint64_t)] = { 0 };
    struct HksBlob handleBlob = { sizeof(uint64_t), handle };
    int32_t result = HksInit(keyAlias, paramSet, &handleBlob, nullptr);
    if (result != HKS_SUCCESS) {
        LOG_ERROR("bai: HksEncrypt failed with error %{public}d", result);
        return result;
    }
    return HksLoopUpdate(&handleBlob, paramSet, plainText, cipherText);
}

std::vector<uint8_t> RdbEncryptUpgradeTest::Encrypt(std::vector<uint8_t> &key, std::vector<uint8_t> rootKeyAlias)
{
    std::vector<uint8_t> nonce_(RDB_HKS_BLOB_TYPE_NONCE, RDB_HKS_BLOB_TYPE_NONCE + strlen(RDB_HKS_BLOB_TYPE_NONCE));
    std::vector<uint8_t> aad_(RDB_HKS_BLOB_TYPE_AAD, RDB_HKS_BLOB_TYPE_AAD + strlen(RDB_HKS_BLOB_TYPE_AAD));
    struct HksBlob blobAad = { uint32_t(aad_.size()), aad_.data() };
    struct HksBlob blobNonce = { uint32_t(nonce_.size()), nonce_.data() };
    struct HksBlob rootKeyName = { uint32_t(rootKeyAlias.size()), rootKeyAlias.data() };
    struct HksBlob plainKey = { uint32_t(key.size()), key.data() };
    struct HksParamSet *params = nullptr;
    int32_t ret = HksInitParamSet(&params);
    if (ret != HKS_SUCCESS) {
        LOG_ERROR("HksInitParamSet() failed with error %{public}d", ret);
        return {};
    }
    struct HksParam hksParam[] = { { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = 0 }, { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE }, { .tag = HKS_TAG_NONCE, .blob = blobNonce },
        { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = blobAad },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE } };
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
        LOG_ERROR("bai: HksEncrypt failed with error %{public}d", ret);
        return {};
    }
    encryptedKey.resize(cipherText.size);
    return encryptedKey;
}

std::vector<uint8_t> RdbEncryptUpgradeTest::Encryptv1(const RDBCryptoParam &param, std::vector<uint8_t> rootKeyAlias)
{
    std::vector<uint8_t> tempRootKeyAlias(rootKeyAlias);
    std::vector<uint8_t> tempKey(param.KeyValue);
    std::vector<uint8_t> hksAdd(RDB_HKS_BLOB_TYPE_AAD, RDB_HKS_BLOB_TYPE_AAD + strlen(RDB_HKS_BLOB_TYPE_AAD));
    struct HksParamSet *params = nullptr;
    int32_t ret = HksInitParamSet(&params);
    if (ret != HKS_SUCCESS) {
        tempKey.assign(tempKey.size(), 0);
        return {};
    }
    struct HksBlob blobAad = { uint32_t(hksAdd.size()), hksAdd.data() };
    struct HksBlob rootKeyName = { uint32_t(tempRootKeyAlias.size()), tempRootKeyAlias.data() };
    struct HksBlob plainKey = { uint32_t(tempKey.size()), tempKey.data() };
    struct HksBlob blobNonce = { uint32_t(param.nonce_.size()), const_cast<uint8_t *>(&(param.nonce_[0])) };

    struct HksParam hksParams[] = { { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = 0 }, { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE }, { .tag = HKS_TAG_NONCE, .blob = blobNonce },
        { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = blobAad },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE } };

    ret = HksAddParams(params, hksParams, sizeof(hksParams) / sizeof(hksParams[0]));
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&params);
        tempKey.assign(tempKey.size(), 0);
        return {};
    }

    ret = HksBuildParamSet(&params);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&params);
        tempKey.assign(tempKey.size(), 0);
        return {};
    }
    std::vector<uint8_t> encryptedKey(plainKey.size * TIMES + 1);
    struct HksBlob cipherText = { uint32_t(encryptedKey.size()), encryptedKey.data() };
    ret = HksEncryptThreeStage(&rootKeyName, params, &plainKey, &cipherText);
    (void)HksFreeParamSet(&params);
    if (ret != HKS_SUCCESS) {
        encryptedKey.assign(encryptedKey.size(), 0);
        tempKey.assign(tempKey.size(), 0);
        return {};
    }
    encryptedKey.resize(cipherText.size);
    tempKey.assign(tempKey.size(), 0);
    return encryptedKey;
}

bool RdbEncryptUpgradeTest::SaveSecretV0KeyToFile(const std::string &keyPath, RdbSecretKeyDataV0 &keyData)
{
    LOG_INFO("begin keyPath:%{public}s.", SqliteUtils::Anonymous(keyPath).c_str());
    std::string secretKeyInString;
    secretKeyInString.append(reinterpret_cast<const char *>(&keyData.distributed), sizeof(uint8_t));
    secretKeyInString.append(reinterpret_cast<const char *>(&keyData.timeValue), sizeof(time_t));
    secretKeyInString.append(reinterpret_cast<const char *>(keyData.secretKey.data()), keyData.secretKey.size());
    bool ret;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto fd = open(keyPath.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
        if (fd >= 0) {
            ret = OHOS::SaveStringToFd(fd, secretKeyInString);
            close(fd);
        } else {
            ret = false;
        }
    }
    return ret;
}

bool RdbEncryptUpgradeTest::SaveSecretV1KeyToFile(const std::string &keyPath, RDBCryptoParam &keyData)
{
    LOG_INFO("begin keyPath:%{public}s.", SqliteUtils::Anonymous(keyPath).c_str());
    RdbSecretContentV2 contentV2;
    std::string secretKeyInString;
    secretKeyInString.append(reinterpret_cast<const char *>(&contentV2.magicNum), sizeof(uint32_t));
    secretKeyInString.append(reinterpret_cast<const char *>(keyData.nonce_.data()), keyData.nonce_.size());
    secretKeyInString.append(reinterpret_cast<const char *>(keyData.KeyValue.data()), keyData.KeyValue.size());

    bool ret;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto fd = open(keyPath.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
        ret = OHOS::SaveStringToFd(fd, secretKeyInString);
        if (fd >= 0) {
            close(fd);
        }
    }
    return ret;
}

int32_t RdbEncryptUpgradeTest::CheckRootKeyExists(std::vector<uint8_t> &rootKeyAlias)
{
    struct HksBlob rootKeyName = { uint32_t(rootKeyAlias.size()), const_cast<uint8_t *>(rootKeyAlias.data()) };
    struct HksParamSet *params = nullptr;
    int32_t ret = HksInitParamSet(&params);
    if (ret != HKS_SUCCESS) {
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
        HksFreeParamSet(&params);
        return ret;
    }

    ret = HksBuildParamSet(&params);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&params);
        return ret;
    }

    ret = HksKeyExist(&rootKeyName, params);
    HksFreeParamSet(&params);

    return ret;
}

int32_t RdbEncryptUpgradeTest::GenerateRootKey(const std::vector<uint8_t> &rootKeyAlias)
{
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
        { .tag = HKS_TAG_KEY_OVERRIDE, .boolParam = false },
    };

    ret = HksAddParams(params, hksParam, sizeof(hksParam) / sizeof(hksParam[0]));
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&params);
        return ret;
    }

    ret = HksBuildParamSet(&params);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&params);
        return ret;
    }

    ret = HksGenerateKey(&rootKeyName, params, nullptr);
    HksFreeParamSet(&params);
    if (ret == HKS_SUCCESS) {
        return ret;
    }
    if (ret != HKS_ERROR_CODE_KEY_ALREADY_EXIST) {
        return ret;
    }
    return HKS_SUCCESS;
}

void RdbEncryptUpgradeTest::GetKeyFileV0FromV2(
    const std::string &keyPathV2, const std::string &keyPathV0, const std::string &bundleName)
{
    bool isFileExists = OHOS::FileExists(keyPathV2);
    ASSERT_TRUE(isFileExists);

    auto [res, keyDataV2] = RdbSecurityManager::GetInstance().LoadSecretKeyFromDisk(keyPathV2);
    ASSERT_TRUE(res);
    RdbSecretKeyDataV0 keyDataV0;
    keyDataV0.timeValue = keyDataV2.timeValue;
    keyDataV0.secretKey = keyDataV2.secretKey;
    auto rootAlias = GetRootKeyAlias(bundleName);
    keyDataV0.secretKey = Encrypt(keyDataV0.secretKey, rootAlias);
    res = SaveSecretV0KeyToFile(keyPathV0, keyDataV0);

    ASSERT_EQ(res, true);
    isFileExists = OHOS::FileExists(keyPathV0);
    ASSERT_TRUE(isFileExists);
}

void RdbEncryptUpgradeTest::GetKeyFileV1FromV2(
    const std::string &keyPathV2, const std::string &keyPathV1, const std::string &bundleName)
{
    auto [res, keyDataV2] = RdbSecurityManager::GetInstance().LoadSecretKeyFromDisk(keyPathV2);
    ASSERT_TRUE(res);
    std::vector<char> content;
    EXPECT_TRUE(OHOS::LoadBufferFromFile(keyPathV2, content));
    auto [packRet, rdbSecretContent] =
        RdbSecurityManager::GetInstance().Unpack(content);
    EXPECT_TRUE(packRet);

    std::vector<uint8_t> keyContentV1;
    keyContentV1.push_back(char(keyDataV2.version));
    keyContentV1.insert(keyContentV1.end(), reinterpret_cast<uint8_t *>(&keyDataV2.timeValue),
        reinterpret_cast<uint8_t *>(&keyDataV2.timeValue) + sizeof(keyDataV2.timeValue));
    keyContentV1.insert(keyContentV1.end(), keyDataV2.secretKey.begin(), keyDataV2.secretKey.end());
    RDBCryptoParam paramV2;
    paramV2.KeyValue = keyContentV1;
    paramV2.nonce_ = rdbSecretContent.nonce_;
    paramV2.KeyValue = Encryptv1(paramV2, GetRootKeyAlias(bundleName));
    res = SaveSecretV1KeyToFile(keyPathV1, paramV2);
    ASSERT_TRUE(res);
}

/**
 * @tc.name: OTATest_V0toV2_001
 * @tc.desc: security key ota from version0 -> version2 with bundleName test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_V0toV2_001, TestSize.Level1)
{
    // Create a key using version 3.
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, BUNDLE_NAME);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, BUNDLE_NAME_1);
    EXPECT_TRUE(GetRDBStore(config1));
    // Get key from key file save to version1 key file
    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    bool isFileExists = OHOS::FileExists(keyPathV2);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2, keyPathV0, BUNDLE_NAME);
    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    isFileExists = OHOS::FileExists(keyPathV2_1);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2_1, keyPathV0_1, BUNDLE_NAME);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);
    SqliteUtils::DeleteFile(keyPathV2);
    SqliteUtils::DeleteFile(keyPathV2_1);
    ASSERT_FALSE(OHOS::FileExists(keyPathV2));
    ASSERT_FALSE(OHOS::FileExists(keyPathV2_1));

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_V0toV2_002
 * @tc.desc: security key ota from version0 -> version2 with no bundleName test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_V0toV2_002, TestSize.Level1)
{
    // Create a key using version 3.
    std::string bundleNameTmp = "";
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config1));
    // Get key from key file save to version1 key file
    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    bool isFileExists = OHOS::FileExists(keyPathV2);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2, keyPathV0, bundleNameTmp);
    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    isFileExists = OHOS::FileExists(keyPathV2_1);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2_1, keyPathV0_1, bundleNameTmp);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);
    SqliteUtils::DeleteFile(keyPathV2);
    SqliteUtils::DeleteFile(keyPathV2_1);
    ASSERT_FALSE(OHOS::FileExists(keyPathV2));
    ASSERT_FALSE(OHOS::FileExists(keyPathV2_1));

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_V1toV2_001
 * @tc.desc: security key ota from version1 -> version2 with bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_V1toV2_001, TestSize.Level1)
{
    // Create a key using version 2.
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, BUNDLE_NAME);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, BUNDLE_NAME_1);
    EXPECT_TRUE(GetRDBStore(config1));
    // Get key from key file save to version1 key file
    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    bool isFileExists = OHOS::FileExists(keyPathV2);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2, keyPathV1, BUNDLE_NAME);
    SqliteUtils::DeleteFile(keyPathV2);
    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    isFileExists = OHOS::FileExists(keyPathV2_1);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2_1, keyPathV1_1, BUNDLE_NAME_1);
    SqliteUtils::DeleteFile(keyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_V1toV2_002
 * @tc.desc: security key ota from version1 -> version2 with no bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_V1toV2_002, TestSize.Level1)
{
    // Create a key using version 2.
    std::string bundleNameTmp = "";
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config1));
    // Get key from key file save to version1 key file
    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    bool isFileExists = OHOS::FileExists(keyPathV2);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2, keyPathV1, bundleNameTmp);
    SqliteUtils::DeleteFile(keyPathV2);
    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    isFileExists = OHOS::FileExists(keyPathV2_1);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2_1, keyPathV1_1, bundleNameTmp);
    SqliteUtils::DeleteFile(keyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_V0AndV2ToV2_001
 * @tc.desc: security key ota from version0 + version2 -> version2 failed with bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_V0AndV2ToV2_001, TestSize.Level1)
{
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, BUNDLE_NAME);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, BUNDLE_NAME_1);
    EXPECT_TRUE(GetRDBStore(config1));
    // Get key from key file save to version0 key file
    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    bool isFileExists = OHOS::FileExists(keyPathV2);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2, keyPathV0, BUNDLE_NAME);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    isFileExists = OHOS::FileExists(keyPathV2_1);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2_1, keyPathV0_1, BUNDLE_NAME_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_V0AndV2ToV2_002
 * @tc.desc: security key ota from version0 + version2 -> version2 with no bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_V0AndV2ToV2_002, TestSize.Level1)
{
    // Create a key using version 3.
    std::string bundleNameTmp = "";
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config1));
    // Get key from key file save to version0 key file
    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    bool isFileExists = OHOS::FileExists(keyPathV2);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2, keyPathV0, bundleNameTmp);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    isFileExists = OHOS::FileExists(keyPathV2_1);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2_1, keyPathV0_1, bundleNameTmp);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_V0AndV1ToV2_001
 * @tc.desc: security key ota from version0 + version1 -> version2 with bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_V0AndV1ToV2_001, TestSize.Level1)
{
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, BUNDLE_NAME);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, BUNDLE_NAME_1);
    EXPECT_TRUE(GetRDBStore(config1));
    // Get key from key file save to version0 key file
    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    bool isFileExists = OHOS::FileExists(keyPathV2);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2, keyPathV0, BUNDLE_NAME);
    std::string keyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2, keyPathV1, BUNDLE_NAME);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    isFileExists = OHOS::FileExists(keyPathV2_1);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2_1, keyPathV0_1, BUNDLE_NAME_1);
    std::string keyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2_1, keyPathV1_1, BUNDLE_NAME_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_V0AndV1ToV2_002
 * @tc.desc: security key ota from version0 + version1 -> version2 with no bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_V0AndV1ToV2_002, TestSize.Level1)
{
    // Create a key using version 3.
    std::string bundleNameTmp = "";
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config1));
    // Get key from key file save to version0 key file
    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    bool isFileExists = OHOS::FileExists(keyPathV2);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2, keyPathV0, BUNDLE_NAME);
    std::string keyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2, keyPathV1, BUNDLE_NAME);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    isFileExists = OHOS::FileExists(keyPathV2_1);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2_1, keyPathV0_1, bundleNameTmp);
    std::string keyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2_1, keyPathV1_1, bundleNameTmp);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_V1AndV2ToV2_001
 * @tc.desc: security key ota from version1 + version2 -> version2 with bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_V1AndV2ToV2_001, TestSize.Level1)
{
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, BUNDLE_NAME);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, BUNDLE_NAME_1);
    EXPECT_TRUE(GetRDBStore(config1));

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    // Get key from key file save to version0 key file
    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    bool isFileExists = OHOS::FileExists(keyPathV2);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2, keyPathV1, BUNDLE_NAME);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    isFileExists = OHOS::FileExists(keyPathV2_1);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2_1, keyPathV1_1, BUNDLE_NAME_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_V1AndV2ToV2_002
 * @tc.desc: security key ota from version1 + version2 -> version2 with bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_V1AndV2ToV2_002, TestSize.Level1)
{
    std::string bundleNameTmp = "";
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config1));
    // Get key from key file save to version0 key file
    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    bool isFileExists = OHOS::FileExists(keyPathV2);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2, keyPathV1, bundleNameTmp);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    isFileExists = OHOS::FileExists(keyPathV2_1);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2_1, keyPathV1_1, bundleNameTmp);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_V0AndV1AndV2ToV2_001
 * @tc.desc: security key ota from version0 + version1 + version2 -> version2 with bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_V0AndV1AndV2ToV2_001, TestSize.Level1)
{
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, BUNDLE_NAME);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, BUNDLE_NAME_1);
    EXPECT_TRUE(GetRDBStore(config1));

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    // Get key from key file save to version0 key file
    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    bool isFileExists = OHOS::FileExists(keyPathV2);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2, keyPathV0, BUNDLE_NAME);
    std::string keyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2, keyPathV1, BUNDLE_NAME);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    isFileExists = OHOS::FileExists(keyPathV2_1);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2_1, keyPathV0_1, BUNDLE_NAME);
    std::string keyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2_1, keyPathV1_1, BUNDLE_NAME_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_V0AndV1AndV2ToV2_002
 * @tc.desc: security key ota from version0 + version1 + version2 -> version2 with no bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_V0AndV1AndV2ToV2_002, TestSize.Level1)
{
    std::string bundleNameTmp = "";
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config1));
    // Get key from key file save to version0 key file
    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    bool isFileExists = OHOS::FileExists(keyPathV2);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2, keyPathV0, bundleNameTmp);
    std::string keyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2, keyPathV1, bundleNameTmp);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    isFileExists = OHOS::FileExists(keyPathV2_1);
    ASSERT_TRUE(isFileExists);
    std::string keyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2_1, keyPathV0_1, BUNDLE_NAME);
    std::string keyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2_1, keyPathV1_1, bundleNameTmp);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV0AndV0ToV2_001
 * @tc.desc: security key ota from new keyV0(false) + V0(true) -> version2 with bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV0AndV0ToV2_001, TestSize.Level1)
{
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, BUNDLE_NAME);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, BUNDLE_NAME_1);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string keyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2, keyPathV0, BUNDLE_NAME);
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    std::string newKeyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key.new";
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2);
    GetKeyFileV0FromV2(newKeyPathV2, newKeyPathV0, BUNDLE_NAME);
    SqliteUtils::DeleteFile(keyPathV2);
    SqliteUtils::DeleteFile(newKeyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    std::string keyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2_1, keyPathV0_1, BUNDLE_NAME_1);
    std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    std::string newKeyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key.new";
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2_1);
    GetKeyFileV0FromV2(newKeyPathV2_1, newKeyPathV0_1, BUNDLE_NAME_1);
    SqliteUtils::DeleteFile(newKeyPathV2_1);
    SqliteUtils::DeleteFile(keyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV0AndV0ToV2_002
 * @tc.desc: security key ota from new keyV0(false) + V0(true) -> version2 with no bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV0AndV0ToV2_002, TestSize.Level1)
{
    std::string bundleNameTmp = "";
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string keyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2, keyPathV0, bundleNameTmp);
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    std::string newKeyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key.new";
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2);
    GetKeyFileV0FromV2(newKeyPathV2, newKeyPathV0, bundleNameTmp);
    SqliteUtils::DeleteFile(keyPathV2);
    SqliteUtils::DeleteFile(newKeyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    std::string keyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key";
    std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    std::string newKeyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key.new";
    GetKeyFileV0FromV2(keyPathV2_1, keyPathV0_1, bundleNameTmp);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2_1);
    GetKeyFileV0FromV2(newKeyPathV2_1, newKeyPathV0_1, bundleNameTmp);
    SqliteUtils::DeleteFile(newKeyPathV2_1);
    SqliteUtils::DeleteFile(keyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV0AndV0ToV2_003
 * @tc.desc: security key ota from new keyV0(true) + V0(false) -> version2 with bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV0AndV0ToV2_003, TestSize.Level1)
{
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, BUNDLE_NAME);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, BUNDLE_NAME_1);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string keyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key";
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    std::string newKeyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key.new";
    GetKeyFileV0FromV2(keyPathV2, newKeyPathV0, BUNDLE_NAME);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2);
    GetKeyFileV0FromV2(newKeyPathV2, keyPathV0, BUNDLE_NAME);
    SqliteUtils::DeleteFile(keyPathV2);
    SqliteUtils::DeleteFile(newKeyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    std::string keyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key";
        std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    std::string newKeyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key.new";
    GetKeyFileV0FromV2(keyPathV2_1, newKeyPathV0_1, BUNDLE_NAME_1);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2_1);
    GetKeyFileV0FromV2(newKeyPathV2_1, keyPathV0_1, BUNDLE_NAME_1);
    SqliteUtils::DeleteFile(newKeyPathV2_1);
    SqliteUtils::DeleteFile(keyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV0AndV0ToV2_004
 * @tc.desc: security key ota from new keyV0(true) + V0(false) -> version2 with no bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV0AndV0ToV2_004, TestSize.Level1)
{
    std::string bundleNameTmp = "";
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string keyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key";
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    std::string newKeyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key.new";
    GetKeyFileV0FromV2(keyPathV2, newKeyPathV0, bundleNameTmp);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2);
    GetKeyFileV0FromV2(newKeyPathV2, keyPathV0, bundleNameTmp);
    SqliteUtils::DeleteFile(keyPathV2);
    SqliteUtils::DeleteFile(newKeyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    std::string keyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key";
        std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    std::string newKeyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key.new";
    GetKeyFileV0FromV2(keyPathV2_1, newKeyPathV0_1, bundleNameTmp);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2_1);
    GetKeyFileV0FromV2(newKeyPathV2_1, keyPathV0_1, bundleNameTmp);
    SqliteUtils::DeleteFile(newKeyPathV2_1);
    SqliteUtils::DeleteFile(keyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV0AndV0AndV2ToV2_001
 * @tc.desc: security key ota from new keyV0(false) + V0(true) + V2(true) -> version2 with bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV0AndV0AndV2ToV2_001, TestSize.Level1)
{
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, BUNDLE_NAME);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, BUNDLE_NAME_1);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string keyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2, keyPathV0, BUNDLE_NAME);
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    std::string newKeyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key.new";
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2);
    GetKeyFileV0FromV2(newKeyPathV2, newKeyPathV0, BUNDLE_NAME);
    SqliteUtils::DeleteFile(newKeyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    std::string keyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2_1, keyPathV0_1, BUNDLE_NAME_1);
        std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    std::string newKeyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key.new";
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2_1);
    GetKeyFileV0FromV2(newKeyPathV2_1, newKeyPathV0_1, BUNDLE_NAME_1);
    SqliteUtils::DeleteFile(newKeyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV0AndV0AndV2ToV2_002
 * @tc.desc: security key ota from new keyV0(false) +V0(true) + V2(true) -> version2 with no bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV0AndV0AndV2ToV2_002, TestSize.Level1)
{
    std::string bundleNameTmp = "";
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string keyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2, keyPathV0, bundleNameTmp);
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    std::string newKeyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key.new";
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2);
    GetKeyFileV0FromV2(newKeyPathV2, newKeyPathV0, bundleNameTmp);
    SqliteUtils::DeleteFile(newKeyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    std::string keyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key";
        std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    std::string newKeyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key.new";
    GetKeyFileV0FromV2(keyPathV2_1, keyPathV0_1, bundleNameTmp);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2_1);
    GetKeyFileV0FromV2(newKeyPathV2_1, newKeyPathV0_1, bundleNameTmp);
    SqliteUtils::DeleteFile(newKeyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV0AndV0AndV2ToV2_003
 * @tc.desc: security key ota from new keyV0(true) + V0(false) + V2(false)-> version2 with bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV0AndV0AndV2ToV2_003, TestSize.Level1)
{
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, BUNDLE_NAME);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, BUNDLE_NAME_1);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string keyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key";
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    std::string newKeyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key.new";
    GetKeyFileV0FromV2(keyPathV2, newKeyPathV0, BUNDLE_NAME);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2);
    GetKeyFileV0FromV2(newKeyPathV2, keyPathV0, BUNDLE_NAME);
    SqliteUtils::RenameFile(newKeyPathV2, keyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    std::string keyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key";
        std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    std::string newKeyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key.new";
    GetKeyFileV0FromV2(keyPathV2_1, newKeyPathV0_1, BUNDLE_NAME_1);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2_1);
    GetKeyFileV0FromV2(newKeyPathV2_1, keyPathV0_1, BUNDLE_NAME_1);
    SqliteUtils::RenameFile(newKeyPathV2_1, keyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV0AndV0AndV2ToV2_004
 * @tc.desc: security key ota from new keyV0(true) + V0(false) + V2(false)-> version2 with no bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV0AndV0AndV2ToV2_004, TestSize.Level1)
{
    std::string bundleNameTmp = "";
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string keyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key";
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    std::string newKeyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key.new";
    GetKeyFileV0FromV2(keyPathV2, newKeyPathV0, bundleNameTmp);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2);
    GetKeyFileV0FromV2(newKeyPathV2, keyPathV0, bundleNameTmp);
    SqliteUtils::RenameFile(newKeyPathV2, keyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    std::string keyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key";
        std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    std::string newKeyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key.new";
    GetKeyFileV0FromV2(keyPathV2_1, newKeyPathV0_1, bundleNameTmp);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2_1);
    GetKeyFileV0FromV2(newKeyPathV2_1, keyPathV0_1, bundleNameTmp);
    SqliteUtils::RenameFile(newKeyPathV2_1, keyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV1AndV1ToV2_001
 * @tc.desc: security key ota from new keyV1(false) + V1(true) -> version2 with bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV1AndV1ToV2_001, TestSize.Level1)
{
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, BUNDLE_NAME);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, BUNDLE_NAME_1);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string keyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2, keyPathV1, BUNDLE_NAME);
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    std::string newKeyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key.new";
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2);
    GetKeyFileV1FromV2(newKeyPathV2, newKeyPathV1, BUNDLE_NAME);
    SqliteUtils::DeleteFile(keyPathV2);
    SqliteUtils::DeleteFile(newKeyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    std::string keyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2_1, keyPathV1_1, BUNDLE_NAME_1);
        std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    std::string newKeyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key.new";
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2_1);
    GetKeyFileV1FromV2(newKeyPathV2_1, newKeyPathV1_1, BUNDLE_NAME_1);
    SqliteUtils::DeleteFile(newKeyPathV2_1);
    SqliteUtils::DeleteFile(keyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV1AndV1ToV2_002
 * @tc.desc: security key ota from new keyV1(false) + V1(true) -> version2 with no bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV1AndV1ToV2_002, TestSize.Level1)
{
    std::string bundleNameTmp = "";
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string keyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2, keyPathV1, bundleNameTmp);
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    std::string newKeyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key.new";
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2);
    GetKeyFileV1FromV2(newKeyPathV2, newKeyPathV1, bundleNameTmp);
    SqliteUtils::DeleteFile(keyPathV2);
    SqliteUtils::DeleteFile(newKeyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    std::string keyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v1";
        std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    std::string newKeyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key.new";
    GetKeyFileV1FromV2(keyPathV2_1, keyPathV1_1, bundleNameTmp);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2_1);
    GetKeyFileV1FromV2(newKeyPathV2_1, newKeyPathV1_1, bundleNameTmp);
    SqliteUtils::DeleteFile(newKeyPathV2_1);
    SqliteUtils::DeleteFile(keyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV1AndV1ToV2_003
 * @tc.desc: security key ota from new keyV1(true) + V1(false) -> version2 with bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV1AndV1ToV2_003, TestSize.Level1)
{
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, BUNDLE_NAME);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, BUNDLE_NAME_1);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string keyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v1";
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    std::string newKeyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key.new";
    GetKeyFileV1FromV2(keyPathV2, newKeyPathV1, BUNDLE_NAME);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2);
    GetKeyFileV1FromV2(newKeyPathV2, keyPathV1, BUNDLE_NAME);
    SqliteUtils::DeleteFile(keyPathV2);
    SqliteUtils::DeleteFile(newKeyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    std::string keyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v1";
        std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    std::string newKeyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key.new";
    GetKeyFileV1FromV2(keyPathV2_1, newKeyPathV1_1, BUNDLE_NAME_1);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2_1);
    GetKeyFileV1FromV2(newKeyPathV2_1, keyPathV1_1, BUNDLE_NAME_1);
    SqliteUtils::DeleteFile(newKeyPathV2_1);
    SqliteUtils::DeleteFile(keyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV1AndV1ToV2_004
 * @tc.desc: security key ota from new keyV1(true) + V1(false) -> version2 with no bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV1AndV1ToV2_004, TestSize.Level1)
{
    std::string bundleNameTmp = "";
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string keyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v1";
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    std::string newKeyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key.new";
    GetKeyFileV1FromV2(keyPathV2, newKeyPathV1, bundleNameTmp);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2);
    GetKeyFileV1FromV2(newKeyPathV2, keyPathV1, bundleNameTmp);
    SqliteUtils::DeleteFile(keyPathV2);
    SqliteUtils::DeleteFile(newKeyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    std::string keyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v1";
        std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    std::string newKeyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key.new";
    GetKeyFileV1FromV2(keyPathV2_1, newKeyPathV1_1, bundleNameTmp);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2_1);
    GetKeyFileV1FromV2(newKeyPathV2_1, keyPathV1_1, bundleNameTmp);
    SqliteUtils::DeleteFile(newKeyPathV2_1);
    SqliteUtils::DeleteFile(keyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV1AndV1AndV2ToV2_001
 * @tc.desc: security key ota from new keyV1(false) + V1(true) + V2(true) -> version2 with bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV1AndV1AndV2ToV2_001, TestSize.Level1)
{
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, BUNDLE_NAME);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, BUNDLE_NAME_1);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string keyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2, keyPathV1, BUNDLE_NAME);
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    std::string newKeyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key.new";
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2);
    GetKeyFileV1FromV2(newKeyPathV2, newKeyPathV1, BUNDLE_NAME);
    SqliteUtils::DeleteFile(newKeyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    std::string keyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2_1, keyPathV1_1, BUNDLE_NAME_1);
        std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    std::string newKeyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key.new";
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2_1);
    GetKeyFileV1FromV2(newKeyPathV2_1, newKeyPathV1_1, BUNDLE_NAME_1);
    SqliteUtils::DeleteFile(newKeyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV1AndV1AndV2ToV2_002
 * @tc.desc: security key ota from new keyV1(false) + V1(true) + V2(true)-> version2 with no bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV1AndV1AndV2ToV2_002, TestSize.Level1)
{
    std::string bundleNameTmp = "";
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string keyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v1";
    GetKeyFileV1FromV2(keyPathV2, keyPathV1, bundleNameTmp);
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    std::string newKeyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key.new";
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2);
    GetKeyFileV1FromV2(newKeyPathV2, newKeyPathV1, bundleNameTmp);
    SqliteUtils::DeleteFile(newKeyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    std::string keyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v1";
        std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    std::string newKeyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key.new";
    GetKeyFileV1FromV2(keyPathV2_1, keyPathV1_1, bundleNameTmp);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2_1);
    GetKeyFileV1FromV2(newKeyPathV2_1, newKeyPathV1_1, bundleNameTmp);
    SqliteUtils::DeleteFile(newKeyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV1AndV1AndV2ToV2_003
 * @tc.desc: security key ota from new keyV1(true) + V1(false) + V2(false)-> version2 with bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV1AndV1AndV2ToV2_003, TestSize.Level1)
{
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, BUNDLE_NAME);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, BUNDLE_NAME_1);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string keyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v1";
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    std::string newKeyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key.new";
    GetKeyFileV1FromV2(keyPathV2, newKeyPathV1, BUNDLE_NAME);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2);
    GetKeyFileV1FromV2(newKeyPathV2, keyPathV1, BUNDLE_NAME);
    SqliteUtils::RenameFile(newKeyPathV2, keyPathV2);
    RdbStoreManager::GetInstance().Delete(config, true);
    EXPECT_TRUE(GetRDBStore(config));
    RdbHelper::DeleteRdbStore(config);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    std::string keyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v1";
        std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    std::string newKeyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key.new";
    GetKeyFileV1FromV2(keyPathV2_1, newKeyPathV1_1, BUNDLE_NAME_1);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2_1);
    GetKeyFileV1FromV2(newKeyPathV2_1, keyPathV1_1, BUNDLE_NAME_1);
    SqliteUtils::RenameFile(newKeyPathV2_1, keyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV1AndV1AndV2ToV2_004
 * @tc.desc: security key ota from new keyV1(true) + V1(false) + V2(false) -> version2 with no bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV1AndV1AndV2ToV2_004, TestSize.Level1)
{
    std::string bundleNameTmp = "";
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string keyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v1";
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    std::string newKeyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key.new";
    GetKeyFileV1FromV2(keyPathV2, newKeyPathV1, bundleNameTmp);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2);
    GetKeyFileV1FromV2(newKeyPathV2, keyPathV1, bundleNameTmp);
    SqliteUtils::RenameFile(newKeyPathV2, keyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    std::string keyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v1";
        std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    std::string newKeyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key.new";
    GetKeyFileV1FromV2(keyPathV2_1, newKeyPathV1_1, bundleNameTmp);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2_1);
    GetKeyFileV1FromV2(newKeyPathV2_1, keyPathV1_1, bundleNameTmp);
    SqliteUtils::RenameFile(newKeyPathV2_1, keyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV2AndV2ToV2_001
 * @tc.desc: security key ota from new keyV2(false) + V2(true) -> version2 with bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV2AndV2ToV2_001, TestSize.Level1)
{
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, BUNDLE_NAME);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, BUNDLE_NAME_1);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
        std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV2AndV2ToV2_002
 * @tc.desc: security key ota from new keyV2(false) + V2(true) -> version2 with no bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV2AndV2ToV2_002, TestSize.Level1)
{
    std::string bundleNameTmp = "";
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
        std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV2AndV2ToV2_003
 * @tc.desc: security key ota from new keyV2(true) + V2(false) -> version2 with bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV2AndV2ToV2_003, TestSize.Level1)
{
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, BUNDLE_NAME);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, BUNDLE_NAME_1);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    SqliteUtils::RenameFile(keyPathV2, newKeyPathV2);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(keyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
        std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    SqliteUtils::RenameFile(keyPathV2_1, newKeyPathV2_1);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(keyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV2AndV2ToV2_004
 * @tc.desc: security key ota from new keyV2(true) + V2(false) -> version2 with no bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV2AndV2ToV2_004, TestSize.Level1)
{
    std::string bundleNameTmp = "";
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    SqliteUtils::RenameFile(keyPathV2, newKeyPathV2);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(keyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
        std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    SqliteUtils::RenameFile(keyPathV2_1, newKeyPathV2_1);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(keyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV0AndV0AndV1AndV2ToV2_001
 * @tc.desc: security key ota from new keyV0(false) + (V0 + V1 + V2)(true) -> version2 with bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV0AndV0AndV1AndV2ToV2_001, TestSize.Level1)
{
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, BUNDLE_NAME);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, BUNDLE_NAME_1);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string keyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v1";
    std::string keyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2, keyPathV0, BUNDLE_NAME);
    GetKeyFileV1FromV2(keyPathV2, keyPathV1, BUNDLE_NAME);
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    std::string newKeyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key.new";
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2);
    GetKeyFileV0FromV2(newKeyPathV2, newKeyPathV0, BUNDLE_NAME);
    SqliteUtils::DeleteFile(newKeyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    std::string keyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v1";
    std::string keyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2_1, keyPathV0_1, BUNDLE_NAME_1);
    GetKeyFileV1FromV2(keyPathV2_1, keyPathV1_1, BUNDLE_NAME_1);
        std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    std::string newKeyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key.new";
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2_1);
    GetKeyFileV0FromV2(newKeyPathV2_1, newKeyPathV0_1, BUNDLE_NAME_1);
    SqliteUtils::DeleteFile(newKeyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV0AndV0AndV1AndV2ToV2_002
 * @tc.desc: security key ota from new keyV0(false) + (V0 + V1 + V2)(true) -> version2 with no bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV0AndV0AndV1AndV2ToV2_002, TestSize.Level1)
{
    std::string bundleNameTmp = "";
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string keyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v1";
    std::string keyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2, keyPathV0, bundleNameTmp);
    GetKeyFileV1FromV2(keyPathV2, keyPathV1, bundleNameTmp);
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    std::string newKeyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key.new";
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2);
    GetKeyFileV0FromV2(newKeyPathV2, newKeyPathV0, bundleNameTmp);
    SqliteUtils::DeleteFile(newKeyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    std::string keyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v1";
    std::string keyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key";
    GetKeyFileV0FromV2(keyPathV2_1, keyPathV0_1, bundleNameTmp);
    GetKeyFileV1FromV2(keyPathV2_1, keyPathV1_1, bundleNameTmp);
        std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    std::string newKeyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key.new";
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(newKeyPathV2_1);
    GetKeyFileV0FromV2(newKeyPathV2_1, newKeyPathV0_1, bundleNameTmp);
    SqliteUtils::DeleteFile(newKeyPathV2_1);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV0AndV0AndV1AndV2ToV2_003
 * @tc.desc: security key ota from new keyV0(true) + (V0 + V1 + V2)(false) -> version2 with bundlename test
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV0AndV0AndV1AndV2ToV2_003, TestSize.Level1)
{
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, BUNDLE_NAME);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, BUNDLE_NAME_1);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string keyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v1";
    std::string keyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key";
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    std::string newKeyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key.new";
    SqliteUtils::RenameFile(keyPathV2, newKeyPathV2);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(keyPathV2);
    GetKeyFileV0FromV2(keyPathV2, keyPathV0, BUNDLE_NAME);
    GetKeyFileV1FromV2(keyPathV2, keyPathV1, BUNDLE_NAME);
    GetKeyFileV0FromV2(newKeyPathV2, newKeyPathV0, BUNDLE_NAME);
    SqliteUtils::DeleteFile(newKeyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    std::string keyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v1";
    std::string keyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key";
        std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    std::string newKeyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key.new";
    SqliteUtils::RenameFile(keyPathV2_1, newKeyPathV2_1);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(keyPathV2_1);
    GetKeyFileV0FromV2(keyPathV2_1, keyPathV0_1, BUNDLE_NAME_1);
    GetKeyFileV1FromV2(keyPathV2_1, keyPathV1_1, BUNDLE_NAME_1);
    GetKeyFileV0FromV2(newKeyPathV2_1, newKeyPathV0_1, BUNDLE_NAME_1);
    SqliteUtils::DeleteFile(newKeyPathV2);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

/**
 * @tc.name: OTATest_NewKeyV0AndV0AndV1AndV2ToV2_004
 * @tc.desc: security key ota from new keyV0(true) + (V0 + V1 + V2)(false) -> version2 with no bundlename test
 * @tc.type: FUNC
 */
HWTEST_F(RdbEncryptUpgradeTest, OTATest_NewKeyV0AndV0AndV1AndV2ToV2_004, TestSize.Level1)
{
    std::string bundleNameTmp = "";
    RdbStoreConfig config = GetConfig(ENCRYPT_PATH, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config));
    RdbStoreConfig config1 = GetConfig(ENCRYPT_PATH_1, bundleNameTmp);
    EXPECT_TRUE(GetRDBStore(config1));

    std::string keyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2";
    std::string keyPathV1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v1";
    std::string keyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key";
    std::string newKeyPathV2 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key_v2.new";
    std::string newKeyPathV0 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME) + ".pub_key.new";
    SqliteUtils::RenameFile(keyPathV2, newKeyPathV2);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(keyPathV2);
    GetKeyFileV0FromV2(keyPathV2, keyPathV0, bundleNameTmp);
    GetKeyFileV1FromV2(keyPathV2, keyPathV1, bundleNameTmp);
    GetKeyFileV0FromV2(newKeyPathV2, newKeyPathV0, bundleNameTmp);
    SqliteUtils::DeleteFile(newKeyPathV2);

    std::string keyPathV2_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2";
    std::string keyPathV1_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v1";
    std::string keyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key";
    std::string newKeyPathV2_1 =
        ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key_v2.new";
    std::string newKeyPathV0_1 = ENCRYPT_DATABASE_KEY_DIR + SqliteUtils::RemoveSuffix(ENCRYPT_NAME_1) + ".pub_key.new";
    SqliteUtils::RenameFile(keyPathV2_1, newKeyPathV2_1);
    RdbSecurityManager::GetInstance().SaveSecretKeyToFile(keyPathV2_1);
    GetKeyFileV0FromV2(keyPathV2_1, keyPathV0_1, bundleNameTmp);
    GetKeyFileV1FromV2(keyPathV2_1, keyPathV1_1, bundleNameTmp);
    GetKeyFileV0FromV2(newKeyPathV2_1, newKeyPathV0_1, bundleNameTmp);
    SqliteUtils::DeleteFile(newKeyPathV2);

    RdbStoreManager::GetInstance().Delete(config, true);
    RdbStoreManager::GetInstance().Delete(config1, true);

    EXPECT_TRUE(GetRDBStore(config));
    EXPECT_TRUE(GetRDBStore(config1));
    RdbHelper::DeleteRdbStore(config);
    RdbHelper::DeleteRdbStore(config1);
}

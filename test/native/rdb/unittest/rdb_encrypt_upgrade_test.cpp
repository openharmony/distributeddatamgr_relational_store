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
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

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
#include "sqlite_utils.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Rdb;
class RdbEncryptUpgradeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    static std::string RemoveSuffix(const std::string &name);
    std::vector<uint8_t> EncryptV0(std::vector<uint8_t> &key, std::vector<uint8_t> rootKeyAlias);
    bool SaveSecretKeyToV0(const std::string &keyPath, RdbSecretKeyData &keyData);
    int32_t HksLoopUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
        const struct HksBlob *inData, struct HksBlob *outData);
    int32_t HksEncryptThreeStage(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
        const struct HksBlob *plainText, struct HksBlob *cipherText);

    static const std::string encryptedDatabaseName;
    static const std::string encryptedDatabasePath;
    static const std::string encryptedDatabaseKeyDir;
    std::mutex mutex_;
};

const std::string RdbEncryptUpgradeTest::encryptedDatabaseName = "encrypted.db";
const std::string RdbEncryptUpgradeTest::encryptedDatabasePath = RDB_TEST_PATH + encryptedDatabaseName;
const std::string RdbEncryptUpgradeTest::encryptedDatabaseKeyDir = RDB_TEST_PATH + "key/";
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
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(RdbEncryptUpgradeTest::encryptedDatabasePath);
}

void RdbEncryptUpgradeTest::TearDown()
{
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(RdbEncryptUpgradeTest::encryptedDatabasePath);
}

std::string RdbEncryptUpgradeTest::RemoveSuffix(const std::string &name)
{
    std::string suffix(".db");
    auto pos = name.rfind(suffix);
    if (pos == std::string::npos || pos < name.length() - suffix.length()) {
        return name;
    }
    return { name, 0, pos };
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

std::vector<uint8_t> RdbEncryptUpgradeTest::EncryptV0(std::vector<uint8_t> &key, std::vector<uint8_t> rootKeyAlias)
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
    struct HksParam hksParam[] = {{ .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = 0 },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_NONCE, .blob = blobNonce },
        { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = blobAad },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE }};

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
    LOG_ERROR("bai: EncryptOld success ");
    return encryptedKey;
}

bool RdbEncryptUpgradeTest::SaveSecretKeyToV0(const std::string &keyPath, RdbSecretKeyData &keyData)
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


/**
* @tc.name: OTATest_001
* @tc.desc: getRdbStore ota test
* @tc.type: FUNC
*/
HWTEST_F(RdbEncryptUpgradeTest, OTATest_001, TestSize.Level1)
{
    RdbStoreConfig config(RdbEncryptUpgradeTest::encryptedDatabasePath);
    config.SetSecurityLevel(SecurityLevel::S1);
    config.SetEncryptStatus(true);
    RdbEncryptUpgradeTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    std::string keyPathV1 = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key_v1";
    bool isFileExists = OHOS::FileExists(keyPathV1);
    ASSERT_TRUE(isFileExists);
    store = nullptr;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    store = nullptr;

    RdbSecretKeyData keyDataV1;
    auto res = RdbSecurityManager::GetInstance().LoadSecretKeyFromDiskV1(keyPathV1, keyDataV1);
    ASSERT_EQ(res, true);
    std::string keyPathV0 = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key";
    RdbSecretKeyData keyDataV0;
    keyDataV0.timeValue = keyDataV1.timeValue;
    keyDataV0.distributed = 0;
    auto rootKeyAlias = RdbSecurityManager::GetInstance().GetRootKeyAlias();
    auto ret = RdbSecurityManager::GetInstance().CheckRootKeyExists(rootKeyAlias);
    ASSERT_NE(ret, HKS_ERROR_NOT_EXIST);
    keyDataV0.secretKey = EncryptV0(keyDataV1.secretKey, rootKeyAlias);
    res = SaveSecretKeyToV0(keyPathV0, keyDataV0);
    ASSERT_EQ(res, true);
    isFileExists = OHOS::FileExists(keyPathV0);
    ASSERT_TRUE(isFileExists);

    SqliteUtils::DeleteFile(keyPathV1);
    isFileExists = OHOS::FileExists(keyPathV1);
    ASSERT_FALSE(isFileExists);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    isFileExists = OHOS::FileExists(keyPathV1);
    ASSERT_TRUE(isFileExists);
    isFileExists = OHOS::FileExists(keyPathV0);
    ASSERT_FALSE(isFileExists);
}


/**
* @tc.name: OTATest_002
* @tc.desc: keyFileV1 corrupted ota test
* @tc.type: FUNC
*/
HWTEST_F(RdbEncryptUpgradeTest, OTATest_002, TestSize.Level1)
{
    RdbStoreConfig config(RdbEncryptUpgradeTest::encryptedDatabasePath);
    config.SetSecurityLevel(SecurityLevel::S1);
    config.SetEncryptStatus(true);
    RdbEncryptUpgradeTestOpenCallback helper;
    int errCode = E_OK;
    RdbHelper::DeleteRdbStore(config);
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    std::string keyPathV1 = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key_v1";
    bool isFileExists = OHOS::FileExists(keyPathV1);
    ASSERT_TRUE(isFileExists);
    store = nullptr;

    RdbSecretKeyData keyDataV1;
    auto res = RdbSecurityManager::GetInstance().LoadSecretKeyFromDiskV1(keyPathV1, keyDataV1);
    ASSERT_EQ(res, true);
    std::string keyPathV0 = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key";
    RdbSecretKeyData keyDataV0;
    keyDataV0.timeValue = keyDataV1.timeValue;
    keyDataV0.distributed = 0;
    auto rootKeyAlias = RdbSecurityManager::GetInstance().GetRootKeyAlias();
    auto ret = RdbSecurityManager::GetInstance().CheckRootKeyExists(rootKeyAlias);
    ASSERT_NE(ret, HKS_ERROR_NOT_EXIST);
    keyDataV0.secretKey = EncryptV0(keyDataV1.secretKey, rootKeyAlias);
    res = SaveSecretKeyToV0(keyPathV0, keyDataV0);
    ASSERT_EQ(res, true);
    isFileExists = OHOS::FileExists(keyPathV0);
    ASSERT_TRUE(isFileExists);

    std::vector<char> keyfileData;
    ASSERT_TRUE(OHOS::LoadBufferFromFile(keyPathV1, keyfileData));
    std::vector<char> keyCorrupted = keyfileData;
    for (size_t i = 10; i < 20 && i < keyCorrupted.size(); ++i) {
        keyCorrupted[i] = 0;
    }
    ASSERT_TRUE(OHOS::SaveBufferToFile(keyPathV1, keyCorrupted));
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    isFileExists = OHOS::FileExists(keyPathV1);
    ASSERT_TRUE(isFileExists);
    isFileExists = OHOS::FileExists(keyPathV0);
    ASSERT_FALSE(isFileExists);
}

/**
* @tc.name: OTATest_003
* @tc.desc: keyFileV1 and keyFile exit ota test
* @tc.type: FUNC
*/
HWTEST_F(RdbEncryptUpgradeTest, OTATest_003, TestSize.Level1)
{
    RdbStoreConfig config(RdbEncryptUpgradeTest::encryptedDatabasePath);
    config.SetSecurityLevel(SecurityLevel::S1);
    config.SetEncryptStatus(true);
    RdbEncryptUpgradeTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    std::string keyPathV1 = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key_v1";
    bool isFileExists = OHOS::FileExists(keyPathV1);
    ASSERT_TRUE(isFileExists);
    store = nullptr;

    RdbSecretKeyData keyDataV1;
    auto res = RdbSecurityManager::GetInstance().LoadSecretKeyFromDiskV1(keyPathV1, keyDataV1);
    ASSERT_EQ(res, true);
    std::string keyPathV0 = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key";
    RdbSecretKeyData keyDataV0;
    keyDataV0.timeValue = keyDataV1.timeValue;
    keyDataV0.distributed = 0;
    auto rootKeyAlias = RdbSecurityManager::GetInstance().GetRootKeyAlias();
    auto ret = RdbSecurityManager::GetInstance().CheckRootKeyExists(rootKeyAlias);
    ASSERT_NE(ret, HKS_ERROR_NOT_EXIST);
    keyDataV0.secretKey = EncryptV0(keyDataV1.secretKey, rootKeyAlias);
    res = SaveSecretKeyToV0(keyPathV0, keyDataV0);
    ASSERT_EQ(res, true);
    isFileExists = OHOS::FileExists(keyPathV0);
    ASSERT_TRUE(isFileExists);
    
    SqliteUtils::DeleteFile(keyPathV1);
    isFileExists = OHOS::FileExists(keyPathV1);
    ASSERT_FALSE(isFileExists);
    auto fd = open(keyPathV1.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    ASSERT_GT(fd, 0);
    isFileExists = OHOS::FileExists(keyPathV1);
    ASSERT_TRUE(isFileExists);

    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    isFileExists = OHOS::FileExists(keyPathV1);
    ASSERT_TRUE(isFileExists);
    isFileExists = OHOS::FileExists(keyPathV0);
    ASSERT_FALSE(isFileExists);
}

/**
* @tc.name: OTATest_004
* @tc.desc: query after getRdbStore ota test
* @tc.type: FUNC
*/
HWTEST_F(RdbEncryptUpgradeTest, OTATest_004, TestSize.Level1)
{
    RdbStoreConfig config(RdbEncryptUpgradeTest::encryptedDatabasePath);
    config.SetSecurityLevel(SecurityLevel::S1);
    config.SetEncryptStatus(true);
    RdbEncryptUpgradeTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    store->ExecuteSql("CREATE TABLE IF NOT EXISTS test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "name TEXT NOT NULL, age INTEGER)");
    int64_t id;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    int ret = store->Insert(id, "test1", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);
    std::string keyPathV1 = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key_v1";
    store = nullptr;

    RdbSecretKeyData keyDataV1;
    auto res = RdbSecurityManager::GetInstance().LoadSecretKeyFromDiskV1(keyPathV1, keyDataV1);
    ASSERT_EQ(res, true);
    std::string keyPathV0 = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key";
    RdbSecretKeyData keyDataV0;
    keyDataV0.timeValue = keyDataV1.timeValue;
    keyDataV0.distributed = 0;
    auto rootKeyAlias = RdbSecurityManager::GetInstance().GetRootKeyAlias();
    ret = RdbSecurityManager::GetInstance().CheckRootKeyExists(rootKeyAlias);
    ASSERT_NE(ret, HKS_ERROR_NOT_EXIST);
    keyDataV0.secretKey = EncryptV0(keyDataV1.secretKey, rootKeyAlias);
    res = SaveSecretKeyToV0(keyPathV0, keyDataV0);
    ASSERT_EQ(res, true);

    SqliteUtils::DeleteFile(keyPathV1);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(errCode, E_OK);
    auto resultSet = store->QueryByStep("SELECT * FROM test1");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(rowCount, 1);
}
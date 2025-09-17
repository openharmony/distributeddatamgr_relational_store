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
#include "relational_store_crypt.h"
#define LOG_TAG "RDBCryptoFault"

#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include "hks_api.h"
#include "hks_param.h"
#include "logger.h"
#include "rdb_dfx_errno.h"
#include "rdb_errno.h"
#include "rdb_visibility.h"

using RDBCryptoFault = OHOS::NativeRdb::RDBCryptoFault;
using namespace OHOS::Rdb;
using namespace OHOS::NativeRdb;
namespace OHOS {
namespace NativeRdb {
RDBCrypto::~RDBCrypto()
{
}
class RDBCryptoImpl : public RDBCrypto {
public:
    explicit RDBCryptoImpl(const std::vector<uint8_t> &rootKeyAlias);
    ~RDBCryptoImpl() override = default;
    int32_t Init(RDBCryptoFault &rdbFault) override;
    bool RootKeyExists() override;
    std::vector<uint8_t> Encrypt(const RDBCryptoParam &param, RDBCryptoFault &rdbFault) override;
    std::vector<uint8_t> Decrypt(const RDBCryptoParam &param, RDBCryptoFault &rdbFault) override;

private:
    static int32_t GenerateRootKey(const std::vector<uint8_t> &rootKeyAlias, RDBCryptoFault &rdbFault);
    int32_t CheckRootKeyExists();
    const std::vector<uint8_t> rootAlias_;
    std::mutex mutex_;
    bool isInit = false;
};
} // namespace NativeRdb
} // namespace OHOS

API_EXPORT std::shared_ptr<OHOS::NativeRdb::RDBCrypto> Create(
    const std::vector<uint8_t> &rootKeyAlias) asm("CreateRdbCryptoDelegate");

API_EXPORT std::vector<uint8_t> GenerateRandomNum(const uint32_t len, RDBCryptoFault &rdbFault) asm(
    "GenerateRdbRandomNum");

RDBCryptoFault GetDfxFault(int32_t code, const std::string &message)
{
    RDBCryptoFault rdbDfxFault;
    rdbDfxFault.code = code;
    rdbDfxFault.message = message;
    return rdbDfxFault;
}

std::shared_ptr<OHOS::NativeRdb::RDBCrypto> Create(const std::vector<uint8_t> &rootKeyAlias)
{
    return std::make_shared<OHOS::NativeRdb::RDBCryptoImpl>(rootKeyAlias);
}

std::vector<uint8_t> GenerateRandomNum(const uint32_t len, RDBCryptoFault &rdbFault)
{
    std::vector<uint8_t> value(len, 0);
    struct HksBlob blobValue = { .size = len, .data = value.data() };
    auto ret = HksGenerateRandom(nullptr, &blobValue);
    if (ret != HKS_SUCCESS || value.empty()) {
        LOG_ERROR("HksGenerateRandom failed, status: %{public}d", ret);
        rdbFault = GetDfxFault(E_DFX_HUKS_GEN_RANDOM_FAIL, "HksGenerateRandom ret=" + std::to_string(ret));
        return {};
    }
    return value;
}

namespace OHOS {
namespace NativeRdb {
constexpr const char *RDB_HKS_BLOB_TYPE_AAD = "RdbClientAAD";
constexpr uint32_t TIMES = 4;
constexpr uint32_t MAX_UPDATE_SIZE = 64;
constexpr uint32_t MAX_OUTDATA_SIZE = MAX_UPDATE_SIZE * TIMES;
constexpr uint8_t AEAD_LEN = 16;
constexpr uint32_t RETRY_MAX_TIMES = 5;
constexpr int RETRY_TIME_INTERVAL_MILLISECOND = 1 * 1000 * 1000;
static std::vector<uint8_t> g_add(RDB_HKS_BLOB_TYPE_AAD, RDB_HKS_BLOB_TYPE_AAD + strlen(RDB_HKS_BLOB_TYPE_AAD));

int32_t HksLoopUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet, const struct HksBlob *inData,
    struct HksBlob *outData, RDBCryptoFault &rdbFault)
{
    if (outData->size < inData->size * TIMES) {
        HksAbort(handle, paramSet);
        rdbFault = GetDfxFault(E_WORK_KEY_FAIL, "HksLoopUpdate out size not enough");
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
            rdbFault = GetDfxFault(E_WORK_KEY_FAIL, "HksUpdate ret=" + std::to_string(result));
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
        rdbFault = GetDfxFault(E_WORK_KEY_FAIL, "HksFinish ret=" + std::to_string(result));
        LOG_ERROR("HksFinish Failed.");
        return HKS_FAILURE;
    }
    outData->size += output.size;
    return HKS_SUCCESS;
}

int32_t HksDecryptThreeStage(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText, RDBCryptoFault &rdbFault)
{
    uint8_t handle[sizeof(uint64_t)] = { 0 };
    struct HksBlob handleBlob = { sizeof(uint64_t), handle };
    int32_t result = HksInit(keyAlias, paramSet, &handleBlob, nullptr);
    if (result != HKS_SUCCESS) {
        LOG_ERROR("HksEncrypt failed with error %{public}d", result);
        rdbFault = GetDfxFault(E_WORK_KEY_DECRYPT_FAIL, "Decrypt HksInit ret=" + std::to_string(result));
        return result;
    }
    result = HksLoopUpdate(&handleBlob, paramSet, cipherText, plainText, rdbFault);
    if (result != HKS_SUCCESS) {
        rdbFault = GetDfxFault(E_WORK_KEY_DECRYPT_FAIL, "Decrypt HksLoopUpdate ret=" + std::to_string(result));
    }
    return result;
}

int32_t HksEncryptThreeStage(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *plainText, struct HksBlob *cipherText, RDBCryptoFault &rdbFault)
{
    uint8_t handle[sizeof(uint64_t)] = { 0 };
    struct HksBlob handleBlob = { sizeof(uint64_t), handle };
    int32_t result = HksInit(keyAlias, paramSet, &handleBlob, nullptr);
    if (result != HKS_SUCCESS) {
        rdbFault = GetDfxFault(E_WORK_KEY_ENCRYPT_FAIL, "Decrypt HksInit ret=" + std::to_string(result));
        LOG_ERROR("HksEncrypt failed with error %{public}d", result);
        return result;
    }
    return HksLoopUpdate(&handleBlob, paramSet, plainText, cipherText, rdbFault);
}

std::vector<HksParam> CreateHksParams(const HksBlob &blobNonce, const HksBlob &blobAad, const HksBlob &blobAead)
{
    return { { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = 0 }, { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE }, { .tag = HKS_TAG_NONCE, .blob = blobNonce },
        { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = blobAad }, { .tag = HKS_TAG_AE_TAG, .blob = blobAead },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE } };
}

int32_t RDBCryptoImpl::GenerateRootKey(const std::vector<uint8_t> &rootKeyAlias, RDBCryptoFault &rdbFault)
{
    LOG_INFO("RDB GenerateRootKey begin. alia size:%{public}zu", rootKeyAlias.size());
    std::vector<uint8_t> tempRootKeyAlias = rootKeyAlias;
    struct HksBlob rootKeyName = { uint32_t(rootKeyAlias.size()), tempRootKeyAlias.data() };
    struct HksParamSet *params = nullptr;
    int32_t ret = HksInitParamSet(&params);
    if (ret != HKS_SUCCESS) {
        rdbFault = GetDfxFault(E_ROOT_KEY_FAULT, "generator root key, HksInitParamSet ret=" + std::to_string(ret));
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
        rdbFault = GetDfxFault(E_ROOT_KEY_FAULT, "HksAddParams ret=" + std::to_string(ret));
        LOG_ERROR("HksAddParams-client failed with error %{public}d", ret);
        HksFreeParamSet(&params);
        return ret;
    }

    ret = HksBuildParamSet(&params);
    if (ret != HKS_SUCCESS) {
        rdbFault = GetDfxFault(E_ROOT_KEY_FAULT, "HksBuildParamSet ret=" + std::to_string(ret));
        LOG_ERROR("HksBuildParamSet-client failed with error %{public}d", ret);
        HksFreeParamSet(&params);
        return ret;
    }

    ret = HksGenerateKey(&rootKeyName, params, nullptr);
    HksFreeParamSet(&params);
    if (ret == HKS_SUCCESS) {
        LOG_INFO("HksGenerateKey-client success first!");
        return ret;
    }
    if (ret != HKS_ERROR_CODE_KEY_ALREADY_EXIST) {
        rdbFault = GetDfxFault(E_ROOT_KEY_FAULT, "HksGenerateKey ret=" + std::to_string(ret));
        LOG_ERROR("HksGenerateKey-client failed with error %{public}d", ret);
        return ret;
    }
    return HKS_SUCCESS;
}

RDBCryptoImpl::RDBCryptoImpl(const std::vector<uint8_t> &rootKeyAlias) : rootAlias_(rootKeyAlias)
{
}

int32_t RDBCryptoImpl::CheckRootKeyExists()
{
    LOG_DEBUG("RDB checkRootKeyExist begin.");
    struct HksBlob rootKeyName = { uint32_t(rootAlias_.size()), const_cast<uint8_t *>(rootAlias_.data()) };
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

bool RDBCryptoImpl::RootKeyExists()
{
    int32_t ret = HKS_FAILURE;
    uint32_t retryCount = 0;
    while (retryCount < RETRY_MAX_TIMES) {
        ret = CheckRootKeyExists();
        if (ret == HKS_SUCCESS) {
            return true;
        }
        if (ret == HKS_ERROR_NOT_EXIST) {
            return false;
        }
        retryCount++;
        usleep(RETRY_TIME_INTERVAL_MILLISECOND);
    }
    return false;
}

int32_t RDBCryptoImpl::Init(RDBCryptoFault &rdbFault)
{
    if (isInit) {
        return HKS_SUCCESS;
    }
    std::lock_guard<decltype(mutex_)> lock(mutex_);
    if (isInit) {
        return HKS_SUCCESS;
    }
    int32_t ret = HKS_FAILURE;
    uint32_t retryCount = 0;
    while (retryCount < RETRY_MAX_TIMES) {
        ret = GenerateRootKey(rootAlias_, rdbFault);
        if (ret == HKS_SUCCESS) {
            isInit = true;
            break;
        }
        retryCount++;
        usleep(RETRY_TIME_INTERVAL_MILLISECOND);
    }
    LOG_INFO("retry:%{public}u, error:%{public}d", retryCount, ret);
    return ret;
}

std::vector<uint8_t> RDBCryptoImpl::Encrypt(const RDBCryptoParam &param, RDBCryptoFault &rdbFault)
{
    std::vector<uint8_t> tempRootKeyAlias(rootAlias_);
    std::vector<uint8_t> tempKey(param.KeyValue);
    struct HksParamSet *params = nullptr;
    int32_t ret = HksInitParamSet(&params);
    if (ret != HKS_SUCCESS) {
        rdbFault = GetDfxFault(E_WORK_KEY_ENCRYPT_FAIL, "Encrypt HksInitParamSet ret=" + std::to_string(ret));
        LOG_ERROR("HksInitParamSet() failed with error %{public}d", ret);
        tempKey.assign(tempKey.size(), 0);
        return {};
    }
    struct HksBlob blobAad = { uint32_t(g_add.size()), g_add.data() };
    struct HksBlob rootKeyName = { uint32_t(tempRootKeyAlias.size()), tempRootKeyAlias.data() };
    struct HksBlob plainKey = { uint32_t(tempKey.size()), tempKey.data() };
    struct HksBlob blobNonce = { uint32_t(param.nonce_.size()), const_cast<uint8_t*>(&(param.nonce_[0])) };

    std::vector<HksParam> hksParams = { { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = 0 }, { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE }, { .tag = HKS_TAG_NONCE, .blob = blobNonce },
        { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = blobAad },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE } };
    ret = HksAddParams(params, hksParams.data(), hksParams.size());
    if (ret != HKS_SUCCESS) {
        rdbFault = GetDfxFault(E_WORK_KEY_ENCRYPT_FAIL, "Encrypt HksAddParams ret=" + std::to_string(ret));
        LOG_ERROR("HksAddParams failed with error %{public}d", ret);
        HksFreeParamSet(&params);
        tempKey.assign(tempKey.size(), 0);
        return {};
    }

    ret = HksBuildParamSet(&params);
    if (ret != HKS_SUCCESS) {
        rdbFault = GetDfxFault(E_WORK_KEY_ENCRYPT_FAIL, "Encrypt HksBuildParamSet ret=" + std::to_string(ret));
        LOG_ERROR("HksBuildParamSet failed with error %{public}d", ret);
        HksFreeParamSet(&params);
        tempKey.assign(tempKey.size(), 0);
        return {};
    }
    std::vector<uint8_t> encryptedKey(plainKey.size * TIMES + 1);
    struct HksBlob cipherText = { uint32_t(encryptedKey.size()), encryptedKey.data() };
    ret = HksEncryptThreeStage(&rootKeyName, params, &plainKey, &cipherText, rdbFault);
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

std::vector<uint8_t> RDBCryptoImpl::Decrypt(const RDBCryptoParam &param, RDBCryptoFault &rdbFault)
{
    std::vector<uint8_t> tempRootKeyAlias(rootAlias_);
    std::vector<uint8_t> source(param.KeyValue);
    struct HksBlob blobAad = { uint32_t(g_add.size()), &(g_add[0]) };
    struct HksBlob blobNonce = { uint32_t(param.nonce_.size()), const_cast<uint8_t*>(&(param.nonce_[0])) };
    struct HksBlob rootKeyName = { uint32_t(tempRootKeyAlias.size()), &(tempRootKeyAlias[0]) };
    struct HksBlob encryptedKeyBlob = { uint32_t(source.size() - AEAD_LEN), source.data() };
    struct HksBlob blobAead = { AEAD_LEN, source.data() + source.size() - AEAD_LEN };
    struct HksParamSet *params = nullptr;
    int32_t ret = HksInitParamSet(&params);
    if (ret != HKS_SUCCESS) {
        rdbFault = GetDfxFault(E_WORK_KEY_DECRYPT_FAIL, "HksInitParamSet ret=" + std::to_string(ret));
        LOG_ERROR("HksInitParamSet() failed with error %{public}d", ret);
        return {};
    }
    auto hksParams = CreateHksParams(blobNonce, blobAad, blobAead);
    ret = HksAddParams(params, hksParams.data(), hksParams.size());
    if (ret != HKS_SUCCESS) {
        rdbFault = GetDfxFault(E_WORK_KEY_DECRYPT_FAIL, "HksAddParams ret=" + std::to_string(ret));
        LOG_ERROR("HksAddParams failed with error %{public}d", ret);
        HksFreeParamSet(&params);
        return {};
    }
    ret = HksBuildParamSet(&params);
    if (ret != HKS_SUCCESS) {
        rdbFault = GetDfxFault(E_WORK_KEY_DECRYPT_FAIL, "HksBuildParamSet ret=" + std::to_string(ret));
        LOG_ERROR("HksBuildParamSet failed with error %{public}d", ret);
        HksFreeParamSet(&params);
        return {};
    }
    std::vector<uint8_t> decryptKey(encryptedKeyBlob.size * TIMES + 1);
    struct HksBlob plainKeyBlob = { uint32_t(decryptKey.size()), decryptKey.data() };
    ret = HksDecryptThreeStage(&rootKeyName, params, &encryptedKeyBlob, &plainKeyBlob, rdbFault);
    (void)HksFreeParamSet(&params);
    if (ret != HKS_SUCCESS) {
        decryptKey.assign(decryptKey.size(), 0);
        LOG_ERROR("HksDecrypt failed with error %{public}d", ret);
        return {};
    }
    decryptKey.resize(plainKeyBlob.size);
    return decryptKey;
}

} // namespace NativeRdb
} // namespace OHOS
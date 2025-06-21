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
#include <vector>

#include "hks_api.h"
#include "hks_param.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_visibility.h"

using RDBCryptoFault = OHOS::NativeRdb::RDBCryptoFault;
using RdbSecretContent = OHOS::NativeRdb::RdbSecretContent;
namespace OHOS {
namespace NativeRdb {
class RDBCrypto {
public:
    static int32_t CheckRootKeyExists(std::vector<uint8_t> &rootKeyAlias);
    static int32_t GenerateRootKey(const std::vector<uint8_t> &rootKeyAlias, RDBCryptoFault &rdbFault);
    static std::vector<uint8_t> Encrypt(const RDBCryptoParam &param, RDBCryptoFault &rdbFault);
    static std::vector<uint8_t> Decrypt(const RDBCryptoParam &param, RDBCryptoFault &rdbFault);
    static std::vector<uint8_t> GenerateRandomNum(int32_t len);
};
} // namespace NativeRdb
} // namespace OHOS
API_EXPORT int32_t CheckRootKeyExists(std::vector<uint8_t> &rootKeyAlias) asm("checkRootKeyExists");
API_EXPORT int32_t GenerateRootKey(const std::vector<uint8_t> &rootKeyAlias, RDBCryptoFault &rdbFault) asm(
    "generateRootKey");
API_EXPORT std::vector<uint8_t> Encrypt(const OHOS::NativeRdb::RDBCryptoParam &param, RDBCryptoFault &rdbFault) asm(
    "encrypt");
API_EXPORT std::vector<uint8_t> Decrypt(const OHOS::NativeRdb::RDBCryptoParam &param, RDBCryptoFault &rdbFault) asm(
    "decrypt");
int32_t CheckRootKeyExists(std::vector<uint8_t> &rootKeyAlias)
{
    return OHOS::NativeRdb::RDBCrypto::CheckRootKeyExists(rootKeyAlias);
}
int32_t GenerateRootKey(const std::vector<uint8_t> &rootKeyAlias, RDBCryptoFault &rdbFault)
{
    return OHOS::NativeRdb::RDBCrypto::GenerateRootKey(rootKeyAlias, rdbFault);
}
std::vector<uint8_t> Encrypt(const OHOS::NativeRdb::RDBCryptoParam &param, RDBCryptoFault &rdbFault)
{
    return OHOS::NativeRdb::RDBCrypto::Encrypt(param, rdbFault);
}
std::vector<uint8_t> Decrypt(const OHOS::NativeRdb::RDBCryptoParam &param, RDBCryptoFault &rdbFault)
{
    return OHOS::NativeRdb::RDBCrypto::Decrypt(param, rdbFault);
}
namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
constexpr const char *RDB_HKS_BLOB_TYPE_NONCE = "Z5s0Bo571Koq";
constexpr const char *RDB_HKS_BLOB_TYPE_AAD = "RdbClientAAD";
constexpr uint32_t TIMES = 4;
constexpr uint32_t MAX_UPDATE_SIZE = 64;
constexpr uint32_t MAX_OUTDATA_SIZE = MAX_UPDATE_SIZE * TIMES;
constexpr uint8_t AEAD_LEN = 16;
static std::vector<uint8_t> g_nonce(RDB_HKS_BLOB_TYPE_NONCE, RDB_HKS_BLOB_TYPE_NONCE + strlen(RDB_HKS_BLOB_TYPE_NONCE));
static std::vector<uint8_t> g_add(RDB_HKS_BLOB_TYPE_AAD, RDB_HKS_BLOB_TYPE_AAD + strlen(RDB_HKS_BLOB_TYPE_AAD));

RDBCryptoFault GetDfxFault(int32_t code, const std::string &message)
{
    RDBCryptoFault rdbDfxFault;
    rdbDfxFault.code = code;
    rdbDfxFault.message = message;
    return rdbDfxFault;
}

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

int32_t RDBCrypto::CheckRootKeyExists(std::vector<uint8_t> &rootKeyAlias)
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

int32_t RDBCrypto::GenerateRootKey(const std::vector<uint8_t> &rootKeyAlias, RDBCryptoFault &rdbFault)
{
    LOG_INFO("RDB GenerateRootKey begin.");
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
    if (ret != HKS_SUCCESS) {
        rdbFault = GetDfxFault(E_ROOT_KEY_FAULT, "HksGenerateKey ret=" + std::to_string(ret));
        LOG_ERROR("HksGenerateKey-client failed with error %{public}d", ret);
    }
    return ret;
}

std::vector<uint8_t> RDBCrypto::Encrypt(const RDBCryptoParam &param, RDBCryptoFault &rdbFault, RdbSecretContent &content)
{
    std::vector<uint8_t> tempRootKeyAlias(param.rootAlias);
    std::vector<uint8_t> tempKey(param.KeyValue);
    struct HksParamSet *params = nullptr;
    int32_t ret = HksInitParamSet(&params);
    if (ret != HKS_SUCCESS) {
        rdbFault = GetDfxFault(E_WORK_KEY_ENCRYPT_FAIL, "Encrypt HksInitParamSet ret=" + std::to_string(ret));
        LOG_ERROR("HksInitParamSet() failed with error %{public}d", ret);
        return {};
    }
    struct HksBlob blobAad = { uint32_t(g_add.size()), g_add.data() };
    struct HksBlob rootKeyName = { uint32_t(tempRootKeyAlias.size()), tempRootKeyAlias.data() };
    struct HksBlob plainKey = { uint32_t(tempKey.size()), tempKey.data() };
    struct HksBlob blobNonce = { uint32_t(param.nonceValue.size()), const_cast<uint8_t*>(&(param.nonceValue[0])) };

    struct HksParam hksParam[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = 0 },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_NONCE, .blob = blobNonce },
        { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = blobAad },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE } };

    ret = HksAddParams(params, hksParam, sizeof(hksParam) / sizeof(hksParam[0]));
    if (ret != HKS_SUCCESS) {
        rdbFault = GetDfxFault(E_WORK_KEY_ENCRYPT_FAIL, "Encrypt HksAddParams ret=" + std::to_string(ret));
        LOG_ERROR("HksAddParams failed with error %{public}d", ret);
        HksFreeParamSet(&params);
        return {};
    }

    ret = HksBuildParamSet(&params);
    if (ret != HKS_SUCCESS) {
        rdbFault = GetDfxFault(E_WORK_KEY_ENCRYPT_FAIL, "Encrypt HksBuildParamSet ret=" + std::to_string(ret));
        LOG_ERROR("HksBuildParamSet failed with error %{public}d", ret);
        HksFreeParamSet(&params);
        return {};
    }
    std::vector<uint8_t> encryptedKey(plainKey.size * TIMES + 1);
    struct HksBlob cipherText = { uint32_t(encryptedKey.size()), encryptedKey.data() };
    ret = HksEncryptThreeStage(&rootKeyName, params, &plainKey, &cipherText, rdbFault);
    (void)HksFreeParamSet(&params);
    if (ret != HKS_SUCCESS) {
        encryptedKey.assign(encryptedKey.size(), 0);
        return {};
    }
    encryptedKey.resize(cipherText.size);
    return encryptedKey;
}

std::vector<uint8_t> RDBCrypto::Decrypt(const RDBCryptoParam &param, RDBCryptoFault &rdbFault)
{
    std::vector<uint8_t> tempRootKeyAlias(param.rootAlias);
    std::vector<uint8_t> source(param.KeyValue);
    struct HksBlob blobAad = { uint32_t(g_add.size()), &(g_add[0]) };
    struct HksBlob blobNonce = { uint32_t(g_nonce.size()), &(g_nonce[0]) };
    if (!(param.nonceValue.empty())) {
        blobNonce.size = uint32_t(param.nonceValue.size());
        blobNonce.data = const_cast<uint8_t*>(&(param.nonceValue[0]));
    }
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

std::vector<uint8_t> RDBCrypto::GenerateRandomNum(int32_t len)
{
    std::random_device randomDevice;
    std::uniform_int_distribution<int> distribution(0, std::numeric_limits<uint8_t>::max());
    std::vector<uint8_t> key(len);
    for (int32_t i = 0; i < len; i++) {
        key[i] = static_cast<uint8_t>(distribution(randomDevice));
    }
    return key;
}
} // namespace NativeRdb
} // namespace OHOS
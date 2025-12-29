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
#define LOG_TAG "OhRdbCryptoParam"
#include "oh_rdb_crypto_param.h"
#include <vector>
#include "oh_data_define.h"
#include "relational_store_error_code.h"

using namespace OHOS::DistributedRdb;
using namespace OHOS::NativeRdb;

bool OH_Rdb_CryptoParam::IsValid() const
{
    return id == OH_CRYPTO_PARAM_ID;
}

OH_Rdb_CryptoParam *OH_Rdb_CreateCryptoParam(void)
{
    OH_Rdb_CryptoParam *value = new (std::nothrow) OH_Rdb_CryptoParam;
    if (value == nullptr) {
        return nullptr;
    }
    return value;
}

int OH_Rdb_DestroyCryptoParam(OH_Rdb_CryptoParam *cryptoParam)
{
    if (cryptoParam == nullptr || !cryptoParam->IsValid()) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    delete cryptoParam;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Crypto_SetEncryptionKey(OH_Rdb_CryptoParam *param, const uint8_t *key, int32_t length)
{
    if (param == nullptr || !param->IsValid() || (key != nullptr && length < 0)) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    if (key == nullptr || length == 0) {
        param->cryptoParam.encryptKey_.assign(param->cryptoParam.encryptKey_.size(), 0);
    } else {
        param->cryptoParam.encryptKey_ = std::vector<uint8_t>{ key, key + length };
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Crypto_SetIteration(OH_Rdb_CryptoParam *param, int64_t iteration)
{
    if (param == nullptr || !param->IsValid() || iteration < 0) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    param->cryptoParam.iterNum = static_cast<int32_t>(iteration);
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Crypto_SetEncryptionAlgo(OH_Rdb_CryptoParam *param, int32_t algo)
{
    if (param == nullptr || !param->IsValid() ||
        (algo < static_cast<int32_t>(RDB_AES_256_GCM) ||
        algo > static_cast<int32_t>(RDB_PLAIN_TEXT))) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    param->cryptoParam.encryptAlgo = algo;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Crypto_SetHmacAlgo(OH_Rdb_CryptoParam *param, int32_t algo)
{
    if (param == nullptr || !param->IsValid() ||
        algo < static_cast<int32_t>(RDB_HMAC_SHA1) || algo > static_cast<int32_t>(RDB_HMAC_SHA512)) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    param->cryptoParam.hmacAlgo = algo;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Crypto_SetKdfAlgo(OH_Rdb_CryptoParam *param, int32_t algo)
{
    if (param == nullptr || !param->IsValid() ||
        algo < static_cast<int32_t>(RDB_KDF_SHA1) || algo > static_cast<int32_t>(RDB_KDF_SHA512)) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    param->cryptoParam.kdfAlgo = algo;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Crypto_SetCryptoPageSize(OH_Rdb_CryptoParam *param, int64_t size)
{
    if (param == nullptr || !param->IsValid() || size < 0) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    uint32_t value = static_cast<uint32_t>(size);
    if (!((value != 0) && ((value & RdbStoreConfig::DB_INVALID_CRYPTO_PAGE_SIZE_MASK) == 0) &&
        (value & (value - 1)) == 0)) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    param->cryptoParam.cryptoPageSize = value;
    return OH_Rdb_ErrCode::RDB_OK;
}
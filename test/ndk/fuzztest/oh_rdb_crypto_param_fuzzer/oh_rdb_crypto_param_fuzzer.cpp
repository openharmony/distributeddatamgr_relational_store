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

#include "oh_rdb_crypto_param_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "grd_api_manager.h"
#include "oh_data_value.h"
#include "oh_data_values.h"
#include "oh_data_values_buckets.h"
#include "oh_predicates.h"
#include "oh_rdb_crypto_param.h"
#include "oh_value_object.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"

#define LENGTH_MIN 1
#define LENGTH_MAX 10

using namespace OHOS;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbNdk;
using namespace std;

namespace OHOS {

void OH_Rdb_DestroyCryptoParamFuzz(FuzzedDataProvider &provider)
{
    OH_Rdb_CryptoParam *param = OH_Rdb_CreateCryptoParam();
    if (param != nullptr) {
        OH_Rdb_DestroyCryptoParam(param);
    }
}

void OH_Crypto_SetEncryptionKeyFuzz(FuzzedDataProvider &provider)
{
    OH_Rdb_CryptoParam *param = OH_Rdb_CreateCryptoParam();
    if (param != nullptr) {
        size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(LENGTH_MIN, LENGTH_MAX);
        std::vector<uint8_t> blobData = provider.ConsumeBytes<uint8_t>(bytesSize);
        OH_Crypto_SetEncryptionKey(param, blobData.data(), blobData.size());
    }
}

void OH_Crypto_SetIterationFuzz(FuzzedDataProvider &provider)
{
    OH_Rdb_CryptoParam *param = OH_Rdb_CreateCryptoParam();
    if (param != nullptr) {
        const int64_t iteration = provider.ConsumeIntegral<int64_t>();
        OH_Crypto_SetIteration(param, iteration);
    }
}

void OH_Crypto_SetEncryptionAlgoFuzz(FuzzedDataProvider &provider)
{
    OH_Rdb_CryptoParam *param = OH_Rdb_CreateCryptoParam();
    if (param != nullptr) {
        const int32_t algo = provider.ConsumeIntegral<int32_t>();
        OH_Crypto_SetEncryptionAlgo(param, algo);
    }
}

void OH_Crypto_SetHmacAlgoFuzz(FuzzedDataProvider &provider)
{
    OH_Rdb_CryptoParam *param = OH_Rdb_CreateCryptoParam();
    if (param != nullptr) {
        const int32_t algo = provider.ConsumeIntegral<int32_t>();
        OH_Crypto_SetHmacAlgo(param, algo);
    }
}

void OH_Crypto_SetKdfAlgoFuzz(FuzzedDataProvider &provider)
{
    OH_Rdb_CryptoParam *param = OH_Rdb_CreateCryptoParam();
    if (param != nullptr) {
        const int32_t algo = provider.ConsumeIntegral<int32_t>();
        OH_Crypto_SetKdfAlgo(param, algo);
    }
}

void OH_Crypto_SetCryptoPageSizeFuzz(FuzzedDataProvider &provider)
{
    OH_Rdb_CryptoParam *param = OH_Rdb_CreateCryptoParam();
    if (param != nullptr) {
        const int64_t size = provider.ConsumeIntegral<int64_t>();
        OH_Crypto_SetCryptoPageSize(param, size);
    }
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::OH_Rdb_DestroyCryptoParamFuzz(provider);
    OHOS::OH_Crypto_SetEncryptionKeyFuzz(provider);
    OHOS::OH_Crypto_SetIterationFuzz(provider);
    OHOS::OH_Crypto_SetEncryptionAlgoFuzz(provider);
    OHOS::OH_Crypto_SetHmacAlgoFuzz(provider);
    OHOS::OH_Crypto_SetKdfAlgoFuzz(provider);
    OHOS::OH_Crypto_SetCryptoPageSizeFuzz(provider);
    return 0;
}

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

#include "oh_data_value_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "oh_data_value.h"
#include "grd_api_manager.h"
#include "oh_value_object.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"

#define BLOBSIZE_MIN 1
#define BLOBSIZE_MAX 10

using namespace OHOS;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbNdk;

namespace OHOS {
void OH_Value_DestroyFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = provider.ConsumeBool() ? OH_Value_Create() : nullptr;
    OH_Value_Destroy(value);
}

void OH_Value_PutNullFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = OH_Value_Create();
    if (value == nullptr) {
        return;
    }
    OH_Value_PutNull(value);
    OH_Value_Destroy(value);
}

void OH_Value_PutIntFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = OH_Value_Create();
    if (value == nullptr) {
        return;
    }
    int64_t val = provider.ConsumeIntegral<int64_t>();
    OH_Value_PutInt(value, val);
    OH_Value_Destroy(value);
}

void OH_Value_PutRealFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = OH_Value_Create();
    if (value == nullptr) {
        return;
    }
    double val = provider.ConsumeFloatingPoint<double>();
    OH_Value_PutReal(value, val);
    OH_Value_Destroy(value);
}

void OH_Value_PutTextFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = OH_Value_Create();
    if (value == nullptr) {
        return;
    }
    std::string val = provider.ConsumeRandomLengthString();
    OH_Value_PutText(value, val.c_str());
    OH_Value_Destroy(value);
}

void OH_Value_PutBlobFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = OH_Value_Create();
    if (value == nullptr) {
        return;
    }
    size_t blobSize = provider.ConsumeIntegralInRange<size_t>(BLOBSIZE_MIN, BLOBSIZE_MAX);
    std::vector<unsigned char> blobData = provider.ConsumeBytes<unsigned char>(blobSize);
    blobData.resize(blobSize);
    OH_Value_PutBlob(value, blobData.data(), blobSize);
    OH_Value_Destroy(value);
}

void OH_Value_PutAssetFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = OH_Value_Create();
    if (value == nullptr) {
        return;
    }
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    if (asset == nullptr) {
        return;
    }
    OH_Value_PutAsset(value, asset);
    OH_Value_Destroy(value);
}

void OH_Value_PutAssetsFuzz(FuzzedDataProvider &provider) {

    size_t count = provider.ConsumeIntegralInRange<size_t>(BLOBSIZE_MIN, BLOBSIZE_MAX);
    Data_Asset **assets = OH_Data_Asset_CreateMultiple(count);
    if (assets == nullptr) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        int64_t value = provider.ConsumeIntegral<int64_t>();
        OH_Data_Asset_SetCreateTime(assets[i], value);
    }
    OH_Data_Value *value = OH_Value_Create();
    if (value == nullptr) {
        return;
    }
    OH_Value_PutAssets(value, assets, count);
    OH_Value_Destroy(value);
}

void OH_Value_PutFloatVectorFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = OH_Value_Create();
    size_t length = provider.ConsumeIntegralInRange<size_t>(BLOBSIZE_MIN, BLOBSIZE_MAX);
    float floatArr[length];
    for (int i = 0; i < length; i++) {
        float val = provider.ConsumeFloatingPoint<float>();
        floatArr[i] = val;
    }
    OH_Value_PutFloatVector(value, floatArr, length);
    OH_Value_Destroy(value);
}

void OH_Value_PutUnlimitedIntFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = OH_Value_Create();
    if (value == nullptr) {
        return;
    }
    int sign = provider.ConsumeBool() ? 0 : 1;
    size_t length = provider.ConsumeIntegralInRange<size_t>(BLOBSIZE_MIN, BLOBSIZE_MAX);
    uint64_t trueForm[length];
    for (int i = 0; i < length; i++) {
        uint64_t trueFormValue = provider.ConsumeIntegral<uint64_t>();
        trueForm[i] = trueFormValue;
    }
    OH_Value_PutUnlimitedInt(value, sign, trueForm, length);
    OH_Value_Destroy(value);
}

void OH_Value_GetTypeFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = OH_Value_Create();
    if (value == nullptr) {
        return;
    }
    OH_ColumnType type;
    OH_Value_GetType(value, &type);
    OH_Value_Destroy(value);
}

void OH_Value_IsNullFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = OH_Value_Create();
    if (value == nullptr) {
        return;
    }
    bool val;
    OH_Value_IsNull(value, &val);
    OH_Value_Destroy(value);
}

void OH_Value_GetIntFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = OH_Value_Create();
    if (value == nullptr) {
        return;
    }
    int64_t val;
    OH_Value_GetInt(value, &val);
    OH_Value_Destroy(value);
}

void OH_Value_GetRealFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = OH_Value_Create();
    if (value == nullptr) {
        return;
    }
    double val;
    OH_Value_GetReal(value, &val);
    OH_Value_Destroy(value);
}

void OH_Value_GetTextFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = OH_Value_Create();
    if (value == nullptr) {
        return;
    }
    const char *textValue;
    OH_Value_GetText(value, &textValue);
    OH_Value_Destroy(value);
}

void OH_Value_GetBlobFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = OH_Value_Create();
    if (value == nullptr) {
        return;
    }
    const uint8_t *val;
    size_t length;
    OH_Value_GetBlob(value, &val, &length);
    OH_Value_Destroy(value);
}

void OH_Value_GetAssetFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = OH_Value_Create();
    if (value == nullptr) {
        return;
    }
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    if (asset == nullptr) {
        return;
    }
    OH_Value_GetAsset(value,asset);
    OH_Value_Destroy(value);
}

void OH_Value_GetAssetsCountFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = OH_Value_Create();
    size_t length = provider.ConsumeIntegral<size_t>();
    OH_Value_GetAssetsCount(value, &length);
    OH_Value_Destroy(value);
}

void OH_Value_GetAssetsFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = OH_Value_Create();
    if (value == nullptr) {
        return;
    }
    size_t inLen = provider.ConsumeIntegralInRange<size_t>(BLOBSIZE_MIN, BLOBSIZE_MAX);
    Data_Asset *val = OH_Data_Asset_CreateOne();
    if (val == nullptr) {
        return;
    }
    size_t outLen = provider.ConsumeIntegral<size_t>();
    OH_Value_GetAssets(value, &val, inLen, &outLen);
    OH_Value_Destroy(value);
}

void OH_Value_GetFloatVectorCountFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = OH_Value_Create();
    if (value == nullptr) {
        return;
    }
    size_t length = provider.ConsumeIntegral<size_t>();
    OH_Value_GetFloatVectorCount(value, &length);
    OH_Value_Destroy(value);
}

void OH_Value_GetFloatVectorFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = OH_Value_Create();
    if (value == nullptr) {
        return;
    }
    size_t inLen = provider.ConsumeIntegralInRange<size_t>(BLOBSIZE_MIN, BLOBSIZE_MAX);
    float *val = new float[inLen];
    size_t outLen = provider.ConsumeIntegral<size_t>();
    OH_Value_GetFloatVector(value, val, inLen, &outLen);
    delete[] val;
    OH_Value_Destroy(value);
}

void OH_Value_GetUnlimitedIntBandFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = OH_Value_Create();
    if (value == nullptr) {
        return;
    }
    size_t length = provider.ConsumeIntegral<size_t>();
    OH_Value_GetUnlimitedIntBand(value, &length);
    OH_Value_Destroy(value);
}

void OH_Value_GetUnlimitedIntFuzz(FuzzedDataProvider &provider) {
    OH_Data_Value *value = OH_Value_Create();
    if (value == nullptr) {
        return;
    }
    int sign = provider.ConsumeIntegral<int>();
    size_t inLen = provider.ConsumeIntegralInRange<size_t>(BLOBSIZE_MIN, BLOBSIZE_MAX);
    uint64_t *trueForm = new uint64_t[inLen];
    size_t outLen = provider.ConsumeIntegral<size_t>();
    OH_Value_GetUnlimitedInt(value, &sign, trueForm, inLen, &outLen);
    delete[] trueForm;
    OH_Value_Destroy(value);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Run your code on data
    FuzzedDataProvider provider(data, size);
    OHOS::OH_Value_DestroyFuzz(provider);
    OHOS::OH_Value_PutNullFuzz(provider);
    OHOS::OH_Value_PutIntFuzz(provider);
    OHOS::OH_Value_PutRealFuzz(provider);
    OHOS::OH_Value_PutTextFuzz(provider);
    OHOS::OH_Value_PutBlobFuzz(provider);
    OHOS::OH_Value_PutAssetFuzz(provider);
    OHOS::OH_Value_PutAssetsFuzz(provider);
    OHOS::OH_Value_PutFloatVectorFuzz(provider);
    OHOS::OH_Value_PutUnlimitedIntFuzz(provider);
    OHOS::OH_Value_GetTypeFuzz(provider);
    OHOS::OH_Value_IsNullFuzz(provider);
    OHOS::OH_Value_GetIntFuzz(provider);
    OHOS::OH_Value_GetRealFuzz(provider);
    OHOS::OH_Value_GetTextFuzz(provider);
    OHOS::OH_Value_GetBlobFuzz(provider);
    OHOS::OH_Value_GetAssetFuzz(provider);
    OHOS::OH_Value_GetAssetsCountFuzz(provider);
    OHOS::OH_Value_GetAssetsFuzz(provider);
    OHOS::OH_Value_GetFloatVectorCountFuzz(provider);
    OHOS::OH_Value_GetFloatVectorFuzz(provider);
    OHOS::OH_Value_GetUnlimitedIntBandFuzz(provider);
    OHOS::OH_Value_GetUnlimitedIntFuzz(provider);
    return 0;
}

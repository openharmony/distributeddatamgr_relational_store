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

#include "oh_data_values_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "oh_data_values.h"
#include "grd_api_manager.h"
#include "oh_data_value.h"
#include "oh_data_values_buckets.h"
#include "oh_value_object.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"

#define LOOPS_MIN 1
#define LOOPS_MAX 10

using namespace OHOS;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbNdk;

namespace OHOS {

OH_Data_Values *CreateRandomDataValues(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = OH_Values_Create();
    if (values == nullptr) {
        return nullptr;
    }
    size_t loops = provider.ConsumeIntegralInRange<size_t>(LOOPS_MIN, LOOPS_MAX);
    for (size_t i = 0; i < loops; ++i) {
        int64_t intValue = provider.ConsumeIntegral<int64_t>();
        double realValue = provider.ConsumeFloatingPoint<double>();
        std::string textValue = provider.ConsumeRandomLengthString();
        size_t blobLength = provider.ConsumeIntegral<size_t>();
        std::vector<uint8_t> blobValue = provider.ConsumeBytes<uint8_t>(blobLength);

        OH_Values_PutInt(values, intValue);
        OH_Values_PutReal(values, realValue);
        OH_Values_PutText(values, textValue.c_str());
        OH_Values_PutBlob(values, blobValue.data(), blobValue.size());
    }
    return values;
}

void OH_Values_PutFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = OH_Values_Create();
    if (values == nullptr) {
        return;
    }
    OH_Data_Value *dataValue = OH_Value_Create();
    if (dataValue != nullptr) {
        OH_Values_Put(values, dataValue);
    }

    OH_Values_Destroy(values);

    OH_Values_Put(nullptr, nullptr);
    OH_Values_Destroy(nullptr);
}

void OH_Values_PutNullFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = OH_Values_Create();
    if (values == nullptr) {
        return;
    }

    OH_Values_PutNull(values);
    OH_Values_Destroy(values);

    OH_Values_PutNull(nullptr);
    OH_Values_Destroy(nullptr);
}

void OH_Values_PutIntFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = OH_Values_Create();
    if (values == nullptr) {
        return;
    }

    int64_t intValue = provider.ConsumeIntegral<int64_t>();
    OH_Values_PutInt(values, intValue);
    OH_Values_Destroy(values);

    OH_Values_PutInt(nullptr, 0);
    OH_Values_Destroy(nullptr);
}

void OH_Values_PutRealFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = OH_Values_Create();
    if (values == nullptr) {
        return;
    }

    double realValue = provider.ConsumeFloatingPoint<double>();
    OH_Values_PutReal(values, realValue);
    OH_Values_Destroy(values);

    OH_Values_PutReal(nullptr, 0);
    OH_Values_Destroy(nullptr);
}

void OH_Values_PutTextFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = OH_Values_Create();
    if (values == nullptr) {
        return;
    }

    std::string textValue = provider.ConsumeRandomLengthString();
    OH_Values_PutText(values, textValue.c_str());
    OH_Values_Destroy(values);

    OH_Values_PutText(nullptr, nullptr);
    OH_Values_Destroy(nullptr);
}

void OH_Values_PutBlobFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = OH_Values_Create();
    if (values == nullptr) {
        return;
    }
    size_t blobLength = provider.ConsumeIntegralInRange<size_t>(LOOPS_MIN, LOOPS_MAX);
    std::vector<uint8_t> blobValue = provider.ConsumeBytes<uint8_t>(blobLength);
    OH_Values_PutBlob(values, blobValue.data(), blobValue.size());
    OH_Values_Destroy(values);

    OH_Values_PutBlob(nullptr, nullptr, 0);
    OH_Values_Destroy(nullptr);
}

void OH_Values_PutAssetFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = OH_Values_Create();
    if (values == nullptr) {
        return;
    }

    Data_Asset *asset = OH_Data_Asset_CreateOne();
    if (asset == nullptr) {
        OH_Values_Destroy(values);
        return;
    }
    OH_Values_PutAsset(values, asset);
    OH_Values_Destroy(values);

    OH_Values_PutAsset(nullptr, nullptr);
    OH_Values_Destroy(nullptr);
}

void OH_Values_PutAssetsFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = OH_Values_Create();
    if (values == nullptr) {
        return;
    }
    size_t loops = provider.ConsumeIntegralInRange<size_t>(LOOPS_MIN, LOOPS_MAX);
    std::vector<Data_Asset *> assets;
    for (size_t i = 0; i < loops; ++i) {
        Data_Asset *asset = OH_Data_Asset_CreateOne();
        if (asset == nullptr) {
            return;
        }
        assets.push_back(asset);
    }

    if (!assets.empty()) {
        OH_Values_PutAssets(values, assets.data(), assets.size());
    }

    OH_Values_Destroy(values);

    OH_Values_PutAssets(nullptr, nullptr, 0);
    OH_Values_Destroy(nullptr);
}

void OH_Values_PutFloatVectorFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = OH_Values_Create();
    if (values == nullptr) {
        return;
    }
    size_t loops = provider.ConsumeIntegralInRange<size_t>(LOOPS_MIN, LOOPS_MAX);
    std::vector<float> floatVector(loops);
    for (size_t i = 0; i < loops; ++i) {
        floatVector[i] = provider.ConsumeFloatingPoint<float>();
    }

    OH_Values_PutFloatVector(values, floatVector.data(), floatVector.size());
    OH_Values_Destroy(values);

    OH_Values_PutFloatVector(nullptr, nullptr, 0);
    OH_Values_Destroy(nullptr);
}

void OH_Values_PutUnlimitedIntFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = OH_Values_Create();
    if (values == nullptr) {
        return;
    }

    int sign = provider.ConsumeIntegral<int>();
    size_t loops = provider.ConsumeIntegralInRange<size_t>(LOOPS_MIN, LOOPS_MAX);
    std::vector<uint64_t> trueForm(loops);
    for (size_t i = 0; i < loops; ++i) {
        trueForm[i] = provider.ConsumeIntegral<uint64_t>();
    }

    OH_Values_PutUnlimitedInt(values, sign, trueForm.data(), trueForm.size());
    OH_Values_Destroy(values);

    OH_Values_PutUnlimitedInt(nullptr, 0, nullptr, 0);
    OH_Values_Destroy(nullptr);
}

void OH_Values_CountFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = CreateRandomDataValues(provider);
    if (values == nullptr) {
        return;
    }

    size_t count;
    OH_Values_Count(values, &count);
    OH_Values_Destroy(values);

    OH_Values_Count(nullptr, nullptr);
    OH_Values_Destroy(nullptr);
}

void OH_Values_GetTypeFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = CreateRandomDataValues(provider);
    if (values == nullptr) {
        return;
    }

    int index = provider.ConsumeIntegral<int>();
    OH_ColumnType type;
    OH_Values_GetType(values, index, &type);
    OH_Values_Destroy(values);

    OH_Values_GetType(nullptr, 0, nullptr);
    OH_Values_Destroy(nullptr);
}

void OH_Values_GetFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = CreateRandomDataValues(provider);
    if (values == nullptr) {
        return;
    }

    int index = provider.ConsumeIntegral<int>();
    OH_Data_Value *dataValue;
    OH_Values_Get(values, index, &dataValue);
    OH_Values_Destroy(values);

    OH_Values_Get(nullptr, 0, nullptr);
    OH_Values_Destroy(nullptr);
}

void OH_Values_IsNullFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = CreateRandomDataValues(provider);
    if (values == nullptr) {
        return;
    }

    int index = provider.ConsumeIntegral<int>();
    bool isNull;
    OH_Values_IsNull(values, index, &isNull);
    OH_Values_Destroy(values);

    OH_Values_IsNull(nullptr, 0, nullptr);
    OH_Values_Destroy(nullptr);
}

void OH_Values_GetIntFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = CreateRandomDataValues(provider);
    if (values == nullptr) {
        return;
    }

    int index = provider.ConsumeIntegral<int>();
    int64_t intValue;
    OH_Values_GetInt(values, index, &intValue);
    OH_Values_Destroy(values);

    OH_Values_GetInt(nullptr, 0, nullptr);
    OH_Values_Destroy(nullptr);
}

void OH_Values_GetRealFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = CreateRandomDataValues(provider);
    if (values == nullptr) {
        return;
    }

    int index = provider.ConsumeIntegral<int>();
    double realValue;
    OH_Values_GetReal(values, index, &realValue);
    OH_Values_Destroy(values);

    OH_Values_GetReal(nullptr, 0, nullptr);
    OH_Values_Destroy(nullptr);
}

void OH_Values_GetTextFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = CreateRandomDataValues(provider);
    if (values == nullptr) {
        return;
    }

    int index = provider.ConsumeIntegral<int>();
    const char *textValue;
    OH_Values_GetText(values, index, &textValue);
    OH_Values_Destroy(values);

    OH_Values_GetText(nullptr, 0, nullptr);
    OH_Values_Destroy(nullptr);
}

void OH_Values_GetBlobFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = CreateRandomDataValues(provider);
    if (values == nullptr) {
        return;
    }

    int index = provider.ConsumeIntegral<int>();
    const uint8_t *blobValue;
    size_t blobLength;
    OH_Values_GetBlob(values, index, &blobValue, &blobLength);
    OH_Values_Destroy(values);

    OH_Values_GetBlob(nullptr, 0, nullptr, nullptr);
    OH_Values_Destroy(nullptr);
}

void OH_Values_GetAssetFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = CreateRandomDataValues(provider);
    if (values == nullptr) {
        return;
    }

    int index = provider.ConsumeIntegral<int>();
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    if (asset != nullptr) {
        OH_Values_GetAsset(values, index, asset);
    }
    OH_Values_Destroy(values);

    OH_Values_GetAsset(nullptr, 0, nullptr);
    OH_Values_Destroy(nullptr);
}

void OH_Values_GetAssetsCountFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = CreateRandomDataValues(provider);
    if (values == nullptr) {
        return;
    }

    int index = provider.ConsumeIntegral<int>();
    size_t count;
    OH_Values_GetAssetsCount(values, index, &count);
    OH_Values_Destroy(values);

    OH_Values_GetAssetsCount(nullptr, 0, nullptr);
    OH_Values_Destroy(nullptr);
}

void OH_Values_GetAssetsFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = CreateRandomDataValues(provider);
    if (values == nullptr) {
        return;
    }

    int index = provider.ConsumeIntegral<int>();
    size_t inLen;
    OH_Values_GetAssetsCount(values, index, &inLen);
    if (inLen > 0) {
        Data_Asset *asset = OH_Data_Asset_CreateOne();
        if (asset == nullptr) {
            return;
        }
        size_t outLen;
        OH_Values_GetAssets(values, index, &asset, inLen, &outLen);
    }

    OH_Values_Destroy(values);

    OH_Values_GetAssets(nullptr, 0, nullptr, 0, nullptr);
    OH_Values_Destroy(nullptr);
}

void OH_Values_GetFloatVectorCountFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = CreateRandomDataValues(provider);
    if (values == nullptr) {
        return;
    }

    int index = provider.ConsumeIntegral<int>();
    size_t count;
    OH_Values_GetFloatVectorCount(values, index, &count);
    OH_Values_Destroy(values);

    OH_Values_GetFloatVectorCount(nullptr, 0, nullptr);
    OH_Values_Destroy(nullptr);
}

void OH_Values_GetFloatVectorFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = CreateRandomDataValues(provider);
    if (values == nullptr) {
        return;
    }

    int index = provider.ConsumeIntegral<int>();
    size_t inLen;
    OH_Values_GetFloatVectorCount(values, index, &inLen);
    if (inLen > 0) {
        float *floatVector = new float[inLen];
        size_t outLen;
        OH_Values_GetFloatVector(values, index, floatVector, inLen, &outLen);
        delete[] floatVector;
    }

    OH_Values_Destroy(values);

    OH_Values_GetFloatVector(nullptr, 0, nullptr, 0, nullptr);
    OH_Values_Destroy(nullptr);
}

void OH_Values_GetUnlimitedIntBandFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = CreateRandomDataValues(provider);
    if (values == nullptr) {
        return;
    }

    int index = provider.ConsumeIntegral<int>();
    size_t count;
    OH_Values_GetUnlimitedIntBand(values, index, &count);
    OH_Values_Destroy(values);

    OH_Values_GetUnlimitedIntBand(nullptr, 0, nullptr);
    OH_Values_Destroy(nullptr);
}

void OH_Values_GetUnlimitedIntFuzz(FuzzedDataProvider &provider)
{
    OH_Data_Values *values = CreateRandomDataValues(provider);
    if (values == nullptr) {
        return;
    }

    int index = provider.ConsumeIntegral<int>();
    size_t inLen;
    OH_Values_GetUnlimitedIntBand(values, index, &inLen);
    if (inLen > 0) {
        int sign;
        uint64_t *trueForm = new uint64_t[inLen];
        size_t outLen;
        OH_Values_GetUnlimitedInt(values, index, &sign, trueForm, inLen, &outLen);
        delete[] trueForm;
    }

    OH_Values_Destroy(values);

    OH_Values_GetUnlimitedInt(nullptr, 0, nullptr, nullptr, 0, nullptr);
    OH_Values_Destroy(nullptr);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Run your code on data
    FuzzedDataProvider provider(data, size);
    OHOS::OH_Values_PutFuzz(provider);
    OHOS::OH_Values_PutNullFuzz(provider);
    OHOS::OH_Values_PutIntFuzz(provider);
    OHOS::OH_Values_PutRealFuzz(provider);
    OHOS::OH_Values_PutTextFuzz(provider);
    OHOS::OH_Values_PutBlobFuzz(provider);
    OHOS::OH_Values_PutAssetFuzz(provider);
    OHOS::OH_Values_PutAssetsFuzz(provider);
    OHOS::OH_Values_PutFloatVectorFuzz(provider);
    OHOS::OH_Values_PutUnlimitedIntFuzz(provider);
    OHOS::OH_Values_CountFuzz(provider);
    OHOS::OH_Values_GetTypeFuzz(provider);
    OHOS::OH_Values_GetFuzz(provider);
    OHOS::OH_Values_IsNullFuzz(provider);
    OHOS::OH_Values_GetIntFuzz(provider);
    OHOS::OH_Values_GetRealFuzz(provider);
    OHOS::OH_Values_GetTextFuzz(provider);
    OHOS::OH_Values_GetBlobFuzz(provider);
    OHOS::OH_Values_GetAssetFuzz(provider);
    OHOS::OH_Values_GetAssetsCountFuzz(provider);
    OHOS::OH_Values_GetAssetsFuzz(provider);
    OHOS::OH_Values_GetFloatVectorCountFuzz(provider);
    OHOS::OH_Values_GetFloatVectorFuzz(provider);
    OHOS::OH_Values_GetUnlimitedIntBandFuzz(provider);
    OHOS::OH_Values_GetUnlimitedIntFuzz(provider);
    return 0;
}

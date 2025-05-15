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

#include "datavalue_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "grd_api_manager.h"
#include "oh_data_value.h"
#include "oh_value_object.h"
#include "oh_values_bucket.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"

using namespace OHOS::NativeRdb;
using namespace OHOS::RdbNdk;

void OHValuePutAssetsFuzzTest(FuzzedDataProvider &provider, OH_Data_Value *value)
{
    const int minCount = 1;
    const int maxCount = 50;
    size_t count = provider.ConsumeIntegralInRange<size_t>(minCount, maxCount);
    Data_Asset **assets = OH_Data_Asset_CreateMultiple(count);
    if (assets == nullptr) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        int64_t value = provider.ConsumeIntegral<int64_t>();
        OH_Data_Asset_SetCreateTime(assets[i], value);
    }
    OH_Value_PutAssets(value, assets, count);
    OH_Data_Asset_DestroyMultiple(assets, count);
}

void OHValuePutFloatVectorFuzzTest(FuzzedDataProvider &provider, OH_Data_Value *value)
{
    const int minFloatVectorSize = 1;
    const int maxFloatVectorSize = 100;
    size_t floatVectorSize = provider.ConsumeIntegralInRange<size_t>(minFloatVectorSize, maxFloatVectorSize);
    std::vector<float> floatVector(floatVectorSize);
    for (size_t i = 0; i < floatVectorSize; i++) {
        floatVector[i] = provider.ConsumeFloatingPoint<float>();
    }
    OH_Value_PutFloatVector(value, floatVector.data(), floatVectorSize);
}

void OHValuePutUnlimitedIntFuzzTest(FuzzedDataProvider &provider, OH_Data_Value *value)
{
    const int minSign = 0;
    const int maxSign = 1;
    int sign = provider.ConsumeIntegralInRange<int>(minSign, maxSign);
    const int minUnlimitedIntSize = 1;
    const int maxUnlimitedIntSize = 10;
    size_t unlimitedIntSize = provider.ConsumeIntegralInRange<size_t>(minUnlimitedIntSize, maxUnlimitedIntSize);
    std::vector<uint64_t> trueForm(unlimitedIntSize);
    for (size_t i = 0; i < unlimitedIntSize; i++) {
        trueForm[i] = provider.ConsumeIntegral<uint64_t>();
    }
    OH_Value_PutUnlimitedInt(value, sign, trueForm.data(), unlimitedIntSize);
}

void DataValuePutFuzzTest(FuzzedDataProvider &provider, OH_Data_Value *value)
{
    if (value == nullptr) {
        return;
    }
    // Test OH_Value_PutNull
    {
        OH_Value_PutNull(value);
    }

    // Test OH_Value_PutInt
    {
        int64_t intValue = provider.ConsumeIntegral<int64_t>();
        OH_Value_PutInt(value, intValue);
    }

    // Test OH_Value_PutReal
    {
        double realValue = provider.ConsumeFloatingPoint<double>();
        OH_Value_PutReal(value, realValue);
    }

    // Test OH_Value_PutText
    {
        std::string textValue = provider.ConsumeRandomLengthString();
        OH_Value_PutText(value, textValue.c_str());
    }

    // Test OH_Value_PutBlob
    {
        const int minBlobSize = 1;
        const int maxBlobSize = 50;
        size_t blobSize = provider.ConsumeIntegralInRange<size_t>(minBlobSize, maxBlobSize);
        std::vector<uint8_t> blobData = provider.ConsumeBytes<uint8_t>(blobSize);
        OH_Value_PutBlob(value, blobData.data(), blobData.size());
    }

    // Test OH_Value_PutAsset
    {
        Data_Asset *asset = OH_Data_Asset_CreateOne();
        if (asset == nullptr) {
            return;
        }
        OH_Value_PutAsset(value, asset);
        OH_Data_Asset_DestroyOne(asset);
    }

    // Test OH_Value_PutAssets
    OHValuePutAssetsFuzzTest(provider, value);

    // Test OH_Value_PutFloatVector
    OHValuePutFloatVectorFuzzTest(provider, value);

    // Test OH_Value_PutUnlimitedInt
    OHValuePutUnlimitedIntFuzzTest(provider, value);
}

void OHValueGetAssetsFuzzTest(OH_Data_Value *value)
{
    size_t assetsSize;
    OH_Value_GetAssetsCount(value, &assetsSize);

    Data_Asset **assets = OH_Data_Asset_CreateMultiple(assetsSize);
    if (assets == nullptr) {
        return;
    }
    size_t assetsOutLen;
    OH_Value_GetAssets(value, assets, assetsSize, &assetsOutLen);
    OH_Data_Asset_DestroyMultiple(assets, assetsSize);
}

void DataValueGetFuzzTestPartOne(OH_Data_Value *value)
{
    if (value == nullptr) {
        return;
    }
    // Test OH_Value_GetType
    {
        OH_ColumnType type;
        OH_Value_GetType(value, &type);
    }

    // Test OH_Value_IsNull
    {
        bool isNull;
        OH_Value_IsNull(value, &isNull);
    }

    // Test OH_Value_GetInt
    {
        int64_t intValue;
        OH_Value_GetInt(value, &intValue);
    }

    // Test OH_Value_GetReal
    {
        double realValue;
        OH_Value_GetReal(value, &realValue);
    }

    // Test OH_Value_GetText
    {
        const char *textValue;
        OH_Value_GetText(value, &textValue);
    }

    // Test OH_Value_GetBlob
    {
        const uint8_t *blobValue;
        size_t blobLength;
        OH_Value_GetBlob(value, &blobValue, &blobLength);
    }

    // Test OH_Value_GetAsset
    {
        Data_Asset *asset = OH_Data_Asset_CreateOne();
        if (asset == nullptr) {
            return;
        }
        OH_Value_GetAsset(value, asset);
        OH_Data_Asset_DestroyOne(asset);
    }

    // Test OH_Value_GetAssetsCount
    {
        size_t assetsCount;
        OH_Value_GetAssetsCount(value, &assetsCount);
    }

    // Test OH_Value_GetAssets
    OHValueGetAssetsFuzzTest(value);

    // Test OH_Value_GetFloatVectorCount
    {
        size_t floatVectorCount;
        OH_Value_GetFloatVectorCount(value, &floatVectorCount);
    }
}

void DataValueGetFuzzTestPartTwo(OH_Data_Value *value)
{
    if (value == nullptr) {
        return;
    }
    // Test OH_Value_GetFloatVector
    {
        size_t floatVectorSize;
        OH_Value_GetFloatVectorCount(value, &floatVectorSize);
        const size_t maxMallocSize = 100;
        if (floatVectorSize > maxMallocSize) {
            floatVectorSize = maxMallocSize;
        }
        float *floatVector = (float *)malloc(floatVectorSize * sizeof(float));
        if (floatVector == nullptr) {
            return;
        }
        size_t floatVectorOutLen;
        OH_Value_GetFloatVector(value, floatVector, floatVectorSize, &floatVectorOutLen);
        free(floatVector);
    }

    // Test OH_Value_GetUnlimitedIntBand
    {
        size_t unlimitedIntBand;
        OH_Value_GetUnlimitedIntBand(value, &unlimitedIntBand);
    }

    // Test OH_Value_GetUnlimitedInt
    {
        size_t unlimitedIntSize;
        OH_Value_GetUnlimitedIntBand(value, &unlimitedIntSize);
        const size_t maxMallocSize = 100;
        if (unlimitedIntSize > maxMallocSize) {
            unlimitedIntSize = maxMallocSize;
        }
        uint64_t *trueForm = (uint64_t *)malloc(unlimitedIntSize * sizeof(uint64_t));
        if (trueForm == nullptr) {
            return;
        }
        size_t unlimitedIntOutLen;
        int sign;
        OH_Value_GetUnlimitedInt(value, &sign, trueForm, unlimitedIntSize, &unlimitedIntOutLen);
        free(trueForm);
    }
}

void DataValueFuzzTest(FuzzedDataProvider &provider)
{
    OH_Data_Value *value = OH_Value_Create();
    if (value == nullptr) {
        return;
    }
    DataValuePutFuzzTest(provider, value);
    DataValueGetFuzzTestPartOne(value);
    DataValueGetFuzzTestPartTwo(value);
    // Destroy the OH_Data_Value instance
    OH_Value_Destroy(value);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Run your code on data
    FuzzedDataProvider provider(data, size);
    DataValueFuzzTest(provider);
    return 0;
}

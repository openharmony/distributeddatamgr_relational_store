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

#include "valuebucket_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "grd_api_manager.h"
#include "oh_value_object.h"
#include "oh_values_bucket.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"


using namespace OHOS::NativeRdb;
using namespace OHOS::RdbNdk;

void putTextFuzzTest(FuzzedDataProvider &provider, OH_VBucket *valueBucket)
{
    std::string field = provider.ConsumeRandomLengthString();
    std::string value = provider.ConsumeRandomLengthString();
    valueBucket->putText(valueBucket, field.c_str(), value.c_str());
}

void putInt64FuzzTest(FuzzedDataProvider &provider, OH_VBucket *valueBucket)
{
    std::string field = provider.ConsumeRandomLengthString();
    int64_t value = provider.ConsumeIntegral<int64_t>();
    valueBucket->putInt64(valueBucket, field.c_str(), value);
}

void putRealFuzzTest(FuzzedDataProvider &provider, OH_VBucket *valueBucket)
{
    std::string field = provider.ConsumeRandomLengthString();
    double value = static_cast<double>(provider.ConsumeFloatingPoint<float>());
    valueBucket->putReal(valueBucket, field.c_str(), value);
}

void putBlobFuzzTest(FuzzedDataProvider &provider, OH_VBucket *valueBucket)
{
    std::string field = provider.ConsumeRandomLengthString();
    const int minBlobSize = 1;
    const int maxBlobSize = 50;
    size_t blobSize = provider.ConsumeIntegralInRange<size_t>(minBlobSize, maxBlobSize);
    std::vector<uint8_t> value = provider.ConsumeBytes<uint8_t>(blobSize);
    valueBucket->putBlob(valueBucket, field.c_str(), value.data(), value.size());
}

void putNullFuzzTest(FuzzedDataProvider &provider, OH_VBucket *valueBucket)
{
    std::string field = provider.ConsumeRandomLengthString();
    valueBucket->putNull(valueBucket, field.c_str());
}

void putAssetFuzzTest(FuzzedDataProvider &provider, OH_VBucket *valueBucket)
{
    std::string field = provider.ConsumeRandomLengthString();
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    if (asset == nullptr) {
        return;
    }
    int64_t value = provider.ConsumeIntegral<int64_t>();
    OH_Data_Asset_SetCreateTime(asset, value);
    OH_VBucket_PutAsset(valueBucket, field.c_str(), asset);
    OH_Data_Asset_DestroyOne(asset); // Destroy the asset
}

void putAssetsFuzzTest(FuzzedDataProvider &provider, OH_VBucket *valueBucket)
{
    std::string field = provider.ConsumeRandomLengthString();
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
    OH_VBucket_PutAssets(valueBucket, field.c_str(), assets, count);
    OH_Data_Asset_DestroyMultiple(assets, count); // Free the array of pointers
}

void putFloatVectorFuzzTest(FuzzedDataProvider &provider, OH_VBucket *valueBucket)
{
    std::string field = provider.ConsumeRandomLengthString();
    const int minLen = 1;
    const int maxLen = 50;
    size_t len = provider.ConsumeIntegralInRange<size_t>(minLen, maxLen);
    std::vector<float> vec(len);
    for (size_t i = 0; i < len; i++) {
        vec[i] = provider.ConsumeFloatingPoint<float>();
    }
    OH_VBucket_PutFloatVector(valueBucket, field.c_str(), vec.data(), len);
}

void putUnlimitedIntFuzzTest(FuzzedDataProvider &provider, OH_VBucket *valueBucket)
{
    std::string field = provider.ConsumeRandomLengthString();
    const int minSign = 0;
    const int maxSign = 1;
    int sign = provider.ConsumeIntegralInRange<int>(minSign, maxSign);
    const int minLen = 1;
    const int maxLen = 50;
    size_t len = provider.ConsumeIntegralInRange<size_t>(minLen, maxLen);
    std::vector<uint64_t> trueForm(len);
    for (size_t i = 0; i < len; i++) {
        trueForm[i] = provider.ConsumeIntegral<uint64_t>();
    }
    OH_VBucket_PutUnlimitedInt(valueBucket, field.c_str(), sign, trueForm.data(), len);
}

void ValueBucketFuzzTest(FuzzedDataProvider &provider)
{
    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    if (valueBucket == nullptr) {
        return;
    }

    // Test putText
    putTextFuzzTest(provider, valueBucket);

    // Test putInt64
    putInt64FuzzTest(provider, valueBucket);

    // Test putReal
    putRealFuzzTest(provider, valueBucket);

    // Test putBlob
    putBlobFuzzTest(provider, valueBucket);

    // Test putNull
    putNullFuzzTest(provider, valueBucket);

    // Test putAsset
    putAssetFuzzTest(provider, valueBucket);

    // Test putAssets
    putAssetsFuzzTest(provider, valueBucket);

    // Test putFloatVector
    putFloatVectorFuzzTest(provider, valueBucket);

    // Test putUnlimitedInt
    putUnlimitedIntFuzzTest(provider, valueBucket);

    // Test clear
    valueBucket->clear(valueBucket);

    // Destroy valueBucket
    valueBucket->destroy(valueBucket);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Run your code on data
    FuzzedDataProvider provider(data, size);
    ValueBucketFuzzTest(provider);
    return 0;
}
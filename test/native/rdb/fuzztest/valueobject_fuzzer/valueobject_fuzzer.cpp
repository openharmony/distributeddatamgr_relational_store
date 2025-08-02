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
#include "valueobject_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "value_object.h"

#define LOOPS_MIN 0
#define LOOPS_MAX 100

using namespace OHOS;
using namespace OHOS::NativeRdb;

namespace OHOS {
std::vector<AssetValue> ConsumeRandomLengthAssetValueVector(FuzzedDataProvider &provider)
{
    size_t loops = provider.ConsumeIntegralInRange<size_t>(LOOPS_MIN, LOOPS_MAX);
    std::vector<AssetValue> columns;
    for (size_t i = 0; i < loops; ++i) {
        uint32_t status = provider.ConsumeIntegralInRange<uint32_t>(
            AssetValue::Status::STATUS_UNKNOWN, AssetValue::Status::STATUS_BUTT);
        AssetValue asset{
            .version = provider.ConsumeIntegral<uint32_t>(),
            .status = status,
            .expiresTime = provider.ConsumeIntegral<uint64_t>(),
            .id = provider.ConsumeRandomLengthString(),
            .name = provider.ConsumeRandomLengthString(),
            .uri = provider.ConsumeRandomLengthString(),
            .createTime = provider.ConsumeRandomLengthString(),
            .modifyTime = provider.ConsumeRandomLengthString(),
            .size = provider.ConsumeRandomLengthString(),
            .hash = provider.ConsumeRandomLengthString(),
            .path = provider.ConsumeRandomLengthString(),
        };
        columns.emplace_back(asset);
    }
    return columns;
}

std::vector<float> ConsumeFloatingPointVector(FuzzedDataProvider &provider)
{
    size_t loops = provider.ConsumeIntegralInRange<size_t>(LOOPS_MIN, LOOPS_MAX);
    std::vector<float> columns;
    for (size_t i = 0; i < loops; ++i) {
        float value = provider.ConsumeFloatingPoint<float>();
        columns.push_back(value);
    }
    return columns;
}

void ValueObjectGetIntFuzz(FuzzedDataProvider &provider)
{
    int32_t value = provider.ConsumeIntegral<int32_t>();
    ValueObject obj(value);
    int val;
    obj.GetInt(val);
}

void ValueObjectGetLongFuzz(FuzzedDataProvider &provider)
{
    int64_t value = provider.ConsumeIntegral<int64_t>();
    ValueObject obj(value);
    int64_t val;
    obj.GetLong(val);
}

void ValueObjectGetDoubleFuzz(FuzzedDataProvider &provider)
{
    double value = provider.ConsumeFloatingPoint<double>();
    ValueObject obj(value);
    double val;
    obj.GetDouble(val);
}

void ValueObjectGetBoolFuzz(FuzzedDataProvider &provider)
{
    bool value = provider.ConsumeBool();
    ValueObject obj(value);
    bool val;
    obj.GetBool(val);
}

void ValueObjectGetStringFuzz(FuzzedDataProvider &provider)
{
    std::string value = provider.ConsumeRandomLengthString();
    ValueObject obj(value);
    std::string val;
    obj.GetString(val);
}

void ValueObjectGetBlobFuzz(FuzzedDataProvider &provider)
{
    size_t length = provider.ConsumeIntegralInRange<size_t>(LOOPS_MIN, LOOPS_MAX);
    std::vector<uint8_t> blob = provider.ConsumeBytes<uint8_t>(length);
    ValueObject obj(blob);
    std::vector<uint8_t> val;
    obj.GetBlob(val);
}

void ValueObjectGetAssetFuzz(FuzzedDataProvider &provider)
{
    uint32_t status =
        provider.ConsumeIntegralInRange<uint32_t>(AssetValue::Status::STATUS_UNKNOWN, AssetValue::Status::STATUS_BUTT);
    AssetValue asset{
        .version = provider.ConsumeIntegral<uint32_t>(),
        .status = status,
        .expiresTime = provider.ConsumeIntegral<uint64_t>(),
        .id = provider.ConsumeRandomLengthString(),
        .name = provider.ConsumeRandomLengthString(),
        .uri = provider.ConsumeRandomLengthString(),
        .createTime = provider.ConsumeRandomLengthString(),
        .modifyTime = provider.ConsumeRandomLengthString(),
        .size = provider.ConsumeRandomLengthString(),
        .hash = provider.ConsumeRandomLengthString(),
        .path = provider.ConsumeRandomLengthString(),
    };

    ValueObject obj(asset);
    AssetValue val;
    obj.GetAsset(val);
}

void ValueObjectGetAssetsFuzz(FuzzedDataProvider &provider)
{
    std::vector<AssetValue> assets = ConsumeRandomLengthAssetValueVector(provider);
    ValueObject obj(assets);
    std::vector<AssetValue> val;
    obj.GetAssets(val);
}

void ValueObjectGetVecsFuzz(FuzzedDataProvider &provider)
{
    std::vector<float> vecs = ConsumeFloatingPointVector(provider);
    ValueObject obj(vecs);
    std::vector<float> val;
    obj.GetVecs(val);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::ValueObjectGetIntFuzz(provider);
    OHOS::ValueObjectGetLongFuzz(provider);
    OHOS::ValueObjectGetDoubleFuzz(provider);
    OHOS::ValueObjectGetBoolFuzz(provider);
    OHOS::ValueObjectGetStringFuzz(provider);
    OHOS::ValueObjectGetBlobFuzz(provider);
    OHOS::ValueObjectGetAssetFuzz(provider);
    OHOS::ValueObjectGetAssetsFuzz(provider);
    OHOS::ValueObjectGetVecsFuzz(provider);
    return 0;
}

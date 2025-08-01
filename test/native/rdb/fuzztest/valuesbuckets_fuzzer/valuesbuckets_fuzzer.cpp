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
#include "valuesbuckets_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "value_object.h"
#include "values_bucket.h"
#include "values_buckets.h"

#define LOOPS_MIN 0
#define LOOPS_MAX 10

using namespace OHOS;
using namespace OHOS::NativeRdb;

namespace OHOS {

std::vector<ValueObject> ConsumeRandomLengthValueObjectVector(FuzzedDataProvider &provider)
{
    size_t loops = provider.ConsumeIntegralInRange<size_t>(LOOPS_MIN, LOOPS_MAX);
    std::vector<ValueObject> columns;
    for (size_t i = 0; i < loops; ++i) {
        int32_t value = provider.ConsumeIntegral<int32_t>();
        ValueObject obj(value);
        columns.emplace_back(obj);
    }
    return columns;
}

std::vector<std::string> ConsumeRandomLengthStringVector(FuzzedDataProvider &provider)
{
    size_t loops = provider.ConsumeIntegralInRange<size_t>(LOOPS_MIN, LOOPS_MAX);
    std::vector<std::string> columns;
    for (size_t i = 0; i < loops; ++i) {
        int32_t length = provider.ConsumeIntegral<int32_t>();
        auto bytes = provider.ConsumeBytes<char>(length);
        columns.emplace_back(bytes.begin(), bytes.end());
    }
    return columns;
}

void ValuesBucketsReserveFuzz(FuzzedDataProvider &provider)
{
    ValuesBuckets buckets;
    int32_t size = provider.ConsumeIntegralInRange<int32_t>(LOOPS_MIN, LOOPS_MAX);
    buckets.Reserve(size);
}

void ValuesBucketsPutFuzz(FuzzedDataProvider &provider)
{
    ValuesBuckets buckets;
    std::vector<std::string> fields = ConsumeRandomLengthStringVector(provider);
    std::vector<ValueObject> values = ConsumeRandomLengthValueObjectVector(provider);
    size_t loopsNum = fields.size();
    if (loopsNum > values.size()) {
        loopsNum = values.size();
    }
    ValuesBucket bucket;
    for (size_t i = 0; i < loopsNum; i++) {
        bucket.Put(fields[i], values[i]);
    }
    buckets.Put(bucket);
}

void ValuesBucketsGetFuzz(FuzzedDataProvider &provider)
{
    ValuesBuckets buckets;
    std::vector<std::string> fields = ConsumeRandomLengthStringVector(provider);
    std::vector<ValueObject> values = ConsumeRandomLengthValueObjectVector(provider);
    size_t loopsNum = fields.size();
    if (loopsNum > values.size()) {
        loopsNum = values.size();
    }
    ValuesBucket bucket;
    for (size_t i = 0; i < loopsNum; ++i) {
        bucket.Put(fields[i], values[i]);
    }
    buckets.Put(bucket);
    size_t row = provider.ConsumeIntegral<size_t>();
    std::string field = provider.ConsumeRandomLengthString();
    buckets.Get(row, field);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::ValuesBucketsReserveFuzz(provider);
    OHOS::ValuesBucketsPutFuzz(provider);
    OHOS::ValuesBucketsGetFuzz(provider);
    return 0;
}

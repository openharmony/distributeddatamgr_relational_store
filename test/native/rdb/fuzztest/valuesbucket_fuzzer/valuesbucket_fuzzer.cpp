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
#include "valuesbucket_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "value_object.h"
#include "values_bucket.h"


#define LOOPS_MIN 0
#define LOOPS_MAX 100

using namespace OHOS;
using namespace OHOS::NativeRdb;

namespace OHOS {

void ValuesBucketPutStringFuzz(FuzzedDataProvider &provider)
{
    ValuesBucket bucket;
    std::string columnName = provider.ConsumeRandomLengthString();
    std::string value = provider.ConsumeRandomLengthString();
    bucket.PutString(columnName, value);
}

void ValuesBucketPutIntFuzz(FuzzedDataProvider &provider)
{
    ValuesBucket bucket;
    std::string columnName = provider.ConsumeRandomLengthString();
    int value = provider.ConsumeIntegral<int>();
    bucket.PutInt(columnName, value);
}

void ValuesBucketPutLongFuzz(FuzzedDataProvider &provider)
{
    ValuesBucket bucket;
    std::string columnName = provider.ConsumeRandomLengthString();
    int64_t value = provider.ConsumeIntegral<int64_t>();
    bucket.PutLong(columnName, value);
}

void ValuesBucketPutDoubleFuzz(FuzzedDataProvider &provider)
{
    ValuesBucket bucket;
    std::string columnName = provider.ConsumeRandomLengthString();
    double value = provider.ConsumeFloatingPoint<double>();
    bucket.PutDouble(columnName, value);
}

void ValuesBucketPutBoolFuzz(FuzzedDataProvider &provider)
{
    ValuesBucket bucket;
    std::string columnName = provider.ConsumeRandomLengthString();
    bool value = provider.ConsumeBool();
    bucket.PutBool(columnName, value);
}

void ValuesBucketPutBlobFuzz(FuzzedDataProvider &provider)
{
    ValuesBucket bucket;
    std::string columnName = provider.ConsumeRandomLengthString();
    size_t length = provider.ConsumeIntegralInRange<size_t>(LOOPS_MIN, LOOPS_MAX);
    std::vector<uint8_t> value = provider.ConsumeBytes<uint8_t>(length);
    bucket.PutBlob(columnName, value);
}

void ValuesBucketPutNullFuzz(FuzzedDataProvider &provider)
{
    ValuesBucket bucket;
    std::string columnName = provider.ConsumeRandomLengthString();
    bucket.PutNull(columnName);
}

void ValuesBucketPutValueObjectFuzz(FuzzedDataProvider &provider)
{
    ValuesBucket bucket;
    std::string columnName = provider.ConsumeRandomLengthString();
    ValueObject value(provider.ConsumeIntegral<int32_t>());
    bucket.Put(columnName, value);
}

void ValuesBucketPutValueObjectMoveFuzz(FuzzedDataProvider &provider)
{
    ValuesBucket bucket;
    std::string columnName = provider.ConsumeRandomLengthString();
    ValueObject value(provider.ConsumeIntegral<int32_t>());
    bucket.Put(columnName, std::move(value));
}

void ValuesBucketDeleteFuzz(FuzzedDataProvider &provider)
{
    ValuesBucket bucket;
    std::string columnName = provider.ConsumeRandomLengthString();
    bucket.Delete(columnName);
}

void ValuesBucketGetObjectFuzz(FuzzedDataProvider &provider)
{
    ValuesBucket bucket;
    std::string columnName = provider.ConsumeRandomLengthString();
    ValueObject value(provider.ConsumeIntegral<int32_t>());
    bucket.Put(columnName, value);
    ValueObject output;
    bucket.GetObject(columnName, output);
}

void ValuesBucketHasColumnFuzz(FuzzedDataProvider &provider)
{
    ValuesBucket bucket;
    std::string columnName = provider.ConsumeRandomLengthString();
    bucket.HasColumn(columnName);
}

void ValuesBucketGetAllFuzz(FuzzedDataProvider &provider)
{
    ValuesBucket bucket;
    std::string columnName = provider.ConsumeRandomLengthString();
    ValueObject value(provider.ConsumeIntegral<int32_t>());
    bucket.Put(columnName, value);
    std::map<std::string, ValueObject> output;
    bucket.GetAll(output);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::ValuesBucketPutStringFuzz(provider);
    OHOS::ValuesBucketPutIntFuzz(provider);
    OHOS::ValuesBucketPutLongFuzz(provider);
    OHOS::ValuesBucketPutDoubleFuzz(provider);
    OHOS::ValuesBucketPutBoolFuzz(provider);
    OHOS::ValuesBucketPutBlobFuzz(provider);
    OHOS::ValuesBucketPutNullFuzz(provider);
    OHOS::ValuesBucketPutValueObjectFuzz(provider);
    OHOS::ValuesBucketPutValueObjectMoveFuzz(provider);
    OHOS::ValuesBucketDeleteFuzz(provider);
    OHOS::ValuesBucketGetObjectFuzz(provider);
    OHOS::ValuesBucketHasColumnFuzz(provider);
    OHOS::ValuesBucketGetAllFuzz(provider);
    return 0;
}
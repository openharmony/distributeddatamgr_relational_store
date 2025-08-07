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

#include "oh_data_values_buckets_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "grd_api_manager.h"
#include "oh_data_value.h"
#include "oh_data_values_buckets.h"
#include "oh_value_object.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"


#define LENGTH_MIN 1
#define LENGTH_MAX 10

#define STRING_MAX 10

using namespace OHOS;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbNdk;

namespace OHOS {

OH_VBucket *CreateRandomVBucket(FuzzedDataProvider &provider)
{
    OH_VBucket *vBucket = OH_Rdb_CreateValuesBucket();
    if (vBucket == nullptr) {
        return nullptr;
    }
    std::string column = provider.ConsumeRandomLengthString(STRING_MAX);
    int64_t value = provider.ConsumeIntegral<int64_t>();
    if (column.empty()) {
        vBucket->destroy(vBucket);
        return nullptr;
    }
    vBucket->putInt64(vBucket, column.c_str(), value);
    return vBucket;
}

OH_Data_VBuckets *CreateRandomVBuckets(FuzzedDataProvider &provider)
{
    OH_Data_VBuckets *vBuckets = OH_VBuckets_Create();
    if (vBuckets == nullptr) {
        return nullptr;
    }
    OH_VBucket *vBucket = CreateRandomVBucket(provider);
    if (vBucket != nullptr) {
        OH_VBuckets_PutRow(vBuckets, vBucket);
    }
    return vBuckets;
}

void OH_VBuckets_PutRowFuzz(FuzzedDataProvider &provider)
{
    OH_Data_VBuckets *vBuckets = OH_VBuckets_Create();
    if (vBuckets == nullptr) {
        return;
    }

    OH_VBucket *vBucket = CreateRandomVBucket(provider);
    if (vBucket != nullptr) {
        OH_VBuckets_PutRow(vBuckets, vBucket);
        vBucket->destroy(vBucket);
    }
    OH_VBuckets_Destroy(vBuckets);

    OH_VBuckets_Destroy(nullptr);
}

void OH_VBuckets_PutRowsFuzz(FuzzedDataProvider &provider)
{
    OH_Data_VBuckets *vBuckets = OH_VBuckets_Create();
    if (vBuckets == nullptr) {
        return;
    }

    OH_Data_VBuckets *rows = CreateRandomVBuckets(provider);
    if (rows != nullptr) {
        OH_VBuckets_PutRows(vBuckets, rows);
        OH_VBuckets_Destroy(rows);
    }

    OH_VBuckets_Destroy(vBuckets);
}

void OH_VBuckets_RowCountFuzz(FuzzedDataProvider &provider)
{
    OH_Data_VBuckets *vBuckets = CreateRandomVBuckets(provider);
    if (vBuckets == nullptr) {
        return;
    }
    size_t count;
    OH_VBuckets_RowCount(vBuckets, &count);
    OH_VBuckets_Destroy(vBuckets);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Run your code on data
    FuzzedDataProvider provider(data, size);
    OHOS::OH_VBuckets_PutRowFuzz(provider);
    OHOS::OH_VBuckets_PutRowsFuzz(provider);
    OHOS::OH_VBuckets_RowCountFuzz(provider);
    return 0;
}

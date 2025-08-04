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

#include "dataasset_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "data_asset.h"
#include "grd_api_manager.h"
#include "oh_value_object.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"

#define MAX_STRING_LENGTH 20

using namespace OHOS;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbNdk;

namespace OHOS {
void OH_Data_Asset_SetNameFuzz(FuzzedDataProvider &provider)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    if (asset == nullptr) {
        return;
    }
    std::string name = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    OH_Data_Asset_SetName(asset, name.c_str());
    OH_Data_Asset_DestroyOne(asset);
}

void OH_Data_Asset_SetUriFuzz(FuzzedDataProvider &provider)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    if (asset == nullptr) {
        return;
    }
    std::string uri = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    OH_Data_Asset_SetUri(asset, uri.c_str());
    OH_Data_Asset_DestroyOne(asset);
}

void OH_Data_Asset_SetPathFuzz(FuzzedDataProvider &provider)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    if (asset == nullptr) {
        return;
    }
    std::string path = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    OH_Data_Asset_SetPath(asset, path.c_str());
    OH_Data_Asset_DestroyOne(asset);
}

void OH_Data_Asset_SetCreateTimeFuzz(FuzzedDataProvider &provider)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    if (asset == nullptr) {
        return;
    }
    int64_t createTime = provider.ConsumeIntegral<int64_t>();
    OH_Data_Asset_SetCreateTime(asset, createTime);
    OH_Data_Asset_DestroyOne(asset);
}

void OH_Data_Asset_SetModifyTimeFuzz(FuzzedDataProvider &provider)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    if (asset == nullptr) {
        return;
    }
    int64_t modifyTime = provider.ConsumeIntegral<int64_t>();
    OH_Data_Asset_SetModifyTime(asset, modifyTime);
    OH_Data_Asset_DestroyOne(asset);
}

void OH_Data_Asset_SetSizeFuzz(FuzzedDataProvider &provider)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    if (asset == nullptr) {
        return;
    }
    size_t size = provider.ConsumeIntegral<size_t>();
    OH_Data_Asset_SetSize(asset, size);
    OH_Data_Asset_DestroyOne(asset);
}

void OH_Data_Asset_SetStatusFuzz(FuzzedDataProvider &provider)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    if (asset == nullptr) {
        return;
    }
    const int min = 0;
    const int max = 6;
    Data_AssetStatus status = static_cast<Data_AssetStatus>(provider.ConsumeIntegralInRange<int>(min, max));
    OH_Data_Asset_SetStatus(asset, status);
    OH_Data_Asset_DestroyOne(asset);
}

void OH_Data_Asset_GetNameFuzz(FuzzedDataProvider &provider)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    if (asset == nullptr) {
        return;
    }
    char name[MAX_STRING_LENGTH];
    size_t length = MAX_STRING_LENGTH;
    OH_Data_Asset_GetName(asset, name, &length);
    OH_Data_Asset_DestroyOne(asset);
}

void OH_Data_Asset_GetUriFuzz(FuzzedDataProvider &provider)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    if (asset == nullptr) {
        return;
    }
    char uri[MAX_STRING_LENGTH];
    size_t length = MAX_STRING_LENGTH;
    OH_Data_Asset_GetUri(asset, uri, &length);
    OH_Data_Asset_DestroyOne(asset);
}

void OH_Data_Asset_GetPathFuzz(FuzzedDataProvider &provider)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    if (asset == nullptr) {
        return;
    }
    char path[MAX_STRING_LENGTH];
    size_t length = MAX_STRING_LENGTH;
    OH_Data_Asset_GetPath(asset, path, &length);
    OH_Data_Asset_DestroyOne(asset);
}

void OH_Data_Asset_GetCreateTimeFuzz(FuzzedDataProvider &provider)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    if (asset == nullptr) {
        return;
    }
    int64_t createTime;
    OH_Data_Asset_GetCreateTime(asset, &createTime);
    OH_Data_Asset_DestroyOne(asset);
}

void OH_Data_Asset_GetModifyTimeFuzz(FuzzedDataProvider &provider)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    if (asset == nullptr) {
        return;
    }
    int64_t modifyTime;
    OH_Data_Asset_GetModifyTime(asset, &modifyTime);
    OH_Data_Asset_DestroyOne(asset);
}

void OH_Data_Asset_GetSizeFuzz(FuzzedDataProvider &provider)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    if (asset == nullptr) {
        return;
    }
    size_t size;
    OH_Data_Asset_GetSize(asset, &size);
    OH_Data_Asset_DestroyOne(asset);
}

void OH_Data_Asset_GetStatusFuzz(FuzzedDataProvider &provider)
{
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    if (asset == nullptr) {
        return;
    }
    Data_AssetStatus status;
    OH_Data_Asset_GetStatus(asset, &status);
    OH_Data_Asset_DestroyOne(asset);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Run your code on data
    FuzzedDataProvider provider(data, size);
    OHOS::OH_Data_Asset_SetNameFuzz(provider);
    OHOS::OH_Data_Asset_SetUriFuzz(provider);
    OHOS::OH_Data_Asset_SetPathFuzz(provider);
    OHOS::OH_Data_Asset_SetCreateTimeFuzz(provider);
    OHOS::OH_Data_Asset_SetModifyTimeFuzz(provider);
    OHOS::OH_Data_Asset_SetSizeFuzz(provider);
    OHOS::OH_Data_Asset_SetStatusFuzz(provider);
    OHOS::OH_Data_Asset_GetNameFuzz(provider);
    OHOS::OH_Data_Asset_GetUriFuzz(provider);
    OHOS::OH_Data_Asset_GetPathFuzz(provider);
    OHOS::OH_Data_Asset_GetCreateTimeFuzz(provider);
    OHOS::OH_Data_Asset_GetModifyTimeFuzz(provider);
    OHOS::OH_Data_Asset_GetSizeFuzz(provider);
    OHOS::OH_Data_Asset_GetStatusFuzz(provider);
    return 0;
}

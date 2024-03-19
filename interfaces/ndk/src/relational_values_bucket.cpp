/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#define LOG_TAG "RelationalValuesBucket"
#include "relational_values_bucket.h"

#include <map>

#include "logger.h"
#include "oh_values_bucket.h"
#include "relational_asset.h"
#include "relational_store_error_code.h"
#include "securec.h"
#include "value_object.h"

namespace OHOS {
namespace RdbNdk {
constexpr int RDB_VBUCKET_CID = 1234562; // The class id used to uniquely identify the OH_Rdb_VBucket class.
int RelationalValuesBucket::PutText(OH_VBucket *bucket, const char *field, const char *value)
{
    return PutValueObject(bucket, field, OHOS::NativeRdb::ValueObject(value));
}

int RelationalValuesBucket::PutInt64(OH_VBucket *bucket, const char *field, int64_t value)
{
    return PutValueObject(bucket, field, OHOS::NativeRdb::ValueObject(value));
}

int RelationalValuesBucket::PutReal(OH_VBucket *bucket, const char *field, double value)
{
    return PutValueObject(bucket, field, OHOS::NativeRdb::ValueObject(value));
}

int RelationalValuesBucket::PutBlob(OH_VBucket *bucket, const char *field, const uint8_t *value, uint32_t size)
{
    std::vector<uint8_t> blobValue;
    if (value != nullptr) {
        blobValue.reserve(size);
        for (uint32_t i = 0; i < size; i++) {
            blobValue.push_back(value[i]);
        }
    }

    return PutValueObject(bucket, field, OHOS::NativeRdb::ValueObject(blobValue));
}

int RelationalValuesBucket::PutNull(OH_VBucket *bucket, const char *field)
{
    return PutValueObject(bucket, field, OHOS::NativeRdb::ValueObject());
}

int RelationalValuesBucket::Clear(OH_VBucket *bucket)
{
    auto self = GetSelf(bucket);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    self->valuesBucket_.Clear();
    self->capability = 0;
    return OH_Rdb_ErrCode::RDB_OK;
}

int RelationalValuesBucket::Destroy(OH_VBucket *bucket)
{
    auto self = GetSelf(bucket);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }

    delete self;
    return OH_Rdb_ErrCode::RDB_OK;
}

RelationalValuesBucket::RelationalValuesBucket()
{
    id = RDB_VBUCKET_CID;
    capability = 0;
    putText = PutText;
    putInt64 = PutInt64;
    putReal = PutReal;
    putBlob = PutBlob;
    putNull = PutNull;
    clear = Clear;
    destroy = Destroy;
}

OHOS::NativeRdb::ValuesBucket &RelationalValuesBucket::Get()
{
    return valuesBucket_;
}

RelationalValuesBucket *RelationalValuesBucket::GetSelf(OH_VBucket *bucket)
{
    if (bucket == nullptr || bucket->id != OHOS::RdbNdk::RDB_VBUCKET_CID) {
        LOG_ERROR("Parameters set error:bucket is NULL ? %{public}d", (bucket == nullptr));
        return nullptr;
    }
    return static_cast<OHOS::RdbNdk::RelationalValuesBucket *>(bucket);
}

int RelationalValuesBucket::PutValueObject(OH_VBucket *bucket, const char *field, OHOS::NativeRdb::ValueObject &&value)
{
    auto self = GetSelf(bucket);
    if (self == nullptr || field == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    self->valuesBucket_.Put(field, value);
    self->capability++;
    return OH_Rdb_ErrCode::RDB_OK;
}
} // namespace RdbNdk
} // namespace OHOS

using namespace OHOS::RdbNdk;
using namespace OHOS::NativeRdb;
int OH_VBucket_PutAsset(OH_VBucket *bucket, const char *field, Data_Asset *value)
{
    auto self = RelationalValuesBucket::GetSelf(bucket);
    if (self == nullptr || field == nullptr || value == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    self->Get().Put(field, OHOS::NativeRdb::ValueObject(value->asset_));
    self->capability++;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_VBucket_PutAssets(OH_VBucket *bucket, const char *field, Data_Asset **value, uint32_t count)
{
    auto self = RelationalValuesBucket::GetSelf(bucket);
    if (self == nullptr || field == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    std::vector<AssetValue> assets;
    for (uint32_t i = 0; i < count; i++) {
        if (value[i] == nullptr) {
            return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
        }
        assets.emplace_back(value[i]->asset_);
    }
    self->Get().Put(field, ValueObject(assets));
    self->capability++;

    return OH_Rdb_ErrCode::RDB_OK;
}

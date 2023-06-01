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

#include <map>
#include "oh_values_bucket.h"
#include "relational_values_bucket_impl.h"
#include "relational_error_code.h"
#include "value_object.h"
#include "securec.h"
#include "logger.h"

using OHOS::RdbNdk::RDB_NDK_LABEL;

int Rdb_VBucket_PutText(OH_VBucket *bucket, const char *field, const char *value)
{
    if (bucket == nullptr || field == nullptr || bucket->id != OHOS::RdbNdk::RDB_VBUCKET_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    static_cast<OHOS::RdbNdk::ValuesBucketImpl *>(bucket)->getValuesBucket().Put(
        field, OHOS::NativeRdb::ValueObject(value));
    bucket->capability += 1;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int Rdb_VBucket_PutInt64(OH_VBucket *bucket, const char *field, int64_t value)
{
    if (bucket == nullptr || field == nullptr || bucket->id != OHOS::RdbNdk::RDB_VBUCKET_CID) {
        LOG_ERROR("Parameters set error:bucket is NULL ? %{public}d, field is NULL ? %{public}d", (bucket == nullptr),
            (field == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    static_cast<OHOS::RdbNdk::ValuesBucketImpl *>(bucket)->getValuesBucket().Put(
        field, OHOS::NativeRdb::ValueObject(value));
    bucket->capability += 1;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int Rdb_VBucket_PutReal(OH_VBucket *bucket, const char *field, double value)
{
    if (bucket == nullptr || field == nullptr || bucket->id != OHOS::RdbNdk::RDB_VBUCKET_CID) {
        LOG_ERROR("Parameters set error:bucket is NULL ? %{public}d, field is NULL ? %{public}d", (bucket == nullptr),
            (field == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    static_cast<OHOS::RdbNdk::ValuesBucketImpl *>(bucket)->getValuesBucket().Put(
        field, OHOS::NativeRdb::ValueObject(value));
    bucket->capability += 1;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int Rdb_VBucket_PutBlob(OH_VBucket *bucket, const char *field, const uint8_t *value, uint32_t size)
{
    if (bucket == nullptr || field == nullptr || bucket->id != OHOS::RdbNdk::RDB_VBUCKET_CID) {
        LOG_ERROR("Parameters set error:bucket is NULL ? %{public}d, field is NULL ? %{public}d", (bucket == nullptr),
            (field == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    std::vector<uint8_t> blobValue;
    if (value != nullptr) {
        blobValue.reserve(size);
        for (uint32_t i = 0; i < size; i++) {
            blobValue.push_back(value[i]);
        }
    }

    static_cast<OHOS::RdbNdk::ValuesBucketImpl *>(bucket)->getValuesBucket().Put(
        field, OHOS::NativeRdb::ValueObject(blobValue));
    bucket->capability += 1;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int Rdb_VBucket_PutNull(OH_VBucket *bucket, const char *field)
{
    if (bucket == nullptr || field == nullptr || bucket->id != OHOS::RdbNdk::RDB_VBUCKET_CID) {
        LOG_ERROR("Parameters set error:bucket is NULL ? %{public}d, field is NULL ? %{public}d", (bucket == nullptr),
            (field == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    static_cast<OHOS::RdbNdk::ValuesBucketImpl *>(bucket)->getValuesBucket().Put(field, OHOS::NativeRdb::ValueObject());
    bucket->capability += 1;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int Rdb_VBucket_Clear(OH_VBucket *bucket)
{
    if (bucket == nullptr || bucket->id != OHOS::RdbNdk::RDB_VBUCKET_CID) {
        LOG_ERROR("Parameters set error:bucket is NULL ? %{public}d", (bucket == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    static_cast<OHOS::RdbNdk::ValuesBucketImpl *>(bucket)->getValuesBucket().Clear();
    bucket->capability = 0;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int Rdb_DestroyValuesBucket(OH_VBucket *bucket)
{
    if (bucket == nullptr || bucket->id != OHOS::RdbNdk::RDB_VBUCKET_CID) {
        LOG_ERROR("Parameters set error:bucket is NULL ? %{public}d", (bucket == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    delete bucket;
    bucket = nullptr;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

OHOS::RdbNdk::ValuesBucketImpl::ValuesBucketImpl()
{
    id = RDB_VBUCKET_CID;
    capability = 0;

    putText = Rdb_VBucket_PutText;
    putInt64 = Rdb_VBucket_PutInt64;
    putReal = Rdb_VBucket_PutReal;
    putBlob = Rdb_VBucket_PutBlob;
    putNull = Rdb_VBucket_PutNull;
    clear = Rdb_VBucket_Clear;
    destroyValuesBucket = Rdb_DestroyValuesBucket;
}

OH_VBucket *OH_Rdb_CreateValuesBucket()
{
    return new OHOS::RdbNdk::ValuesBucketImpl();
}

OHOS::NativeRdb::ValuesBucket &OHOS::RdbNdk::ValuesBucketImpl::getValuesBucket()
{
    return valuesBucket_;
}
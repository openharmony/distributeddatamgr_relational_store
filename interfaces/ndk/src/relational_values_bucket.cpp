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
#include "relational_values_bucket.h"
#include "relational_values_bucket_impl.h"
#include "relational_error_code.h"
#include "value_object.h"
#include "securec.h"
#include "ndk_logger.h"

using OHOS::RdbNdk::RDB_NDK_LABEL;
OH_Rdb_VBucket *OH_Rdb_CreateValuesBucket()
{
    return new OHOS::RdbNdk::ValuesBucketImpl();
}

OHOS::NativeRdb::ValuesBucket &OHOS::RdbNdk::ValuesBucketImpl::getValuesBucket()
{
    return valuesBucket_;
}
int OH_Rdb_DestroyValuesBucket(OH_Rdb_VBucket *bucket)
{
    if (bucket == nullptr || bucket->id != OHOS::RdbNdk::RDB_VBUCKET_CID) {
        LOG_ERROR("Parameters set error:bucket is NULL ? %{public}d", (bucket == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    delete static_cast<OHOS::RdbNdk::ValuesBucketImpl *>(bucket);
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int OH_VBucket_PutText(OH_Rdb_VBucket *bucket, const char *field, const char *value)
{
    if (bucket == nullptr || field == nullptr || bucket->id != OHOS::RdbNdk::RDB_VBUCKET_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    static_cast<OHOS::RdbNdk::ValuesBucketImpl *>(bucket)->getValuesBucket().Put(field, OHOS::NativeRdb::ValueObject(value));
    bucket->capability += 1;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int OH_VBucket_PutInt64(OH_Rdb_VBucket *bucket, const char *field, int64_t value)
{
    if (bucket == nullptr || field == nullptr || bucket->id != OHOS::RdbNdk::RDB_VBUCKET_CID) {
        LOG_ERROR("Parameters set error:bucket is NULL ? %{public}d, field is NULL ? %{public}d",
                 (bucket == nullptr), (field == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    static_cast<OHOS::RdbNdk::ValuesBucketImpl *>(bucket)->getValuesBucket().Put(field, OHOS::NativeRdb::ValueObject(value));
    bucket->capability += 1;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int OH_VBucket_PutReal(OH_Rdb_VBucket *bucket, const char *field, double value)
{
    if (bucket == nullptr || field == nullptr || bucket->id != OHOS::RdbNdk::RDB_VBUCKET_CID) {
        LOG_ERROR("Parameters set error:bucket is NULL ? %{public}d, field is NULL ? %{public}d",
                 (bucket == nullptr), (field == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    static_cast<OHOS::RdbNdk::ValuesBucketImpl *>(bucket)->getValuesBucket().Put(field, OHOS::NativeRdb::ValueObject(value));
    bucket->capability += 1;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int OH_VBucket_PutBlob(OH_Rdb_VBucket *bucket, const char *field, const uint8_t *value, uint32_t size)
{
    if (bucket == nullptr || field == nullptr || bucket->id != OHOS::RdbNdk::RDB_VBUCKET_CID) {
        LOG_ERROR("Parameters set error:bucket is NULL ? %{public}d, field is NULL ? %{public}d",
                 (bucket == nullptr), (field == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    std::vector<uint8_t> blobValue;
    if (value != nullptr) {
        blobValue.reserve(size);
        for (uint32_t i = 0; i < size; i++) {
            blobValue.push_back(value[i]);
        }
    }

    static_cast<OHOS::RdbNdk::ValuesBucketImpl *>(bucket)->getValuesBucket().Put(field, OHOS::NativeRdb::ValueObject(blobValue));
    bucket->capability += 1;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int OH_VBucket_PutNull(OH_Rdb_VBucket *bucket, const char *field)
{
    if (bucket == nullptr || field == nullptr || bucket->id != OHOS::RdbNdk::RDB_VBUCKET_CID) {
        LOG_ERROR("Parameters set error:bucket is NULL ? %{public}d, field is NULL ? %{public}d",
                 (bucket == nullptr), (field == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    static_cast<OHOS::RdbNdk::ValuesBucketImpl *>(bucket)->getValuesBucket().Put(field, OHOS::NativeRdb::ValueObject());
    bucket->capability += 1;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int OH_VBucket_Clear(OH_Rdb_VBucket *bucket)
{
    if (bucket == nullptr || bucket->id != OHOS::RdbNdk::RDB_VBUCKET_CID) {
        LOG_ERROR("Parameters set error:bucket is NULL ? %{public}d", (bucket == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    static_cast<OHOS::RdbNdk::ValuesBucketImpl *>(bucket)->getValuesBucket().Clear();
    bucket->capability = 0;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int OH_VBucket_Close(OH_Rdb_VBucket *bucket)
{
    if (bucket == nullptr || bucket->id != OHOS::RdbNdk::RDB_VBUCKET_CID) {
        LOG_ERROR("Parameters set error:bucket is NULL ? %{public}d", (bucket == nullptr));
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    auto bucketTemp = static_cast<OHOS::RdbNdk::ValuesBucketImpl *>(bucket);
    delete bucketTemp;
    bucketTemp = nullptr;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}
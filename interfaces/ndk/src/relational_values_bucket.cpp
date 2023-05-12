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

OH_Rdb_ValuesBucket *OH_Rdb_CreateValuesBucket()
{
    return new OHOS::NativeRdb::ValuesBucketImpl();
}

int OH_Rdb_DestroyValuesBucket(OH_Rdb_ValuesBucket *bucket)
{
    if (bucket == nullptr || bucket->id != OHOS::NativeRdb::RDB_VALUESBUCKET_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    delete static_cast<OHOS::NativeRdb::ValuesBucketImpl *>(bucket);
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int OH_VBucket_PutText(OH_Rdb_ValuesBucket *bucket, const char *name, const char *value)
{
    if (bucket == nullptr || name == nullptr || bucket->id != OHOS::NativeRdb::RDB_VALUESBUCKET_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    static_cast<OHOS::NativeRdb::ValuesBucketImpl *>(bucket)->valuesBucket_.Put(name, OHOS::NativeRdb::ValueObject(value));
    bucket->capability += 1;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int OH_VBucket_PutInt64(OH_Rdb_ValuesBucket *bucket, const char *name, int64_t value)
{
    if (bucket == nullptr || name == nullptr || bucket->id != OHOS::NativeRdb::RDB_VALUESBUCKET_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    static_cast<OHOS::NativeRdb::ValuesBucketImpl *>(bucket)->valuesBucket_.Put(name, OHOS::NativeRdb::ValueObject(value));
    bucket->capability += 1;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int OH_VBucket_PutReal(OH_Rdb_ValuesBucket *bucket, const char *name, double value)
{
    if (bucket == nullptr || bucket->id != OHOS::NativeRdb::RDB_VALUESBUCKET_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    static_cast<OHOS::NativeRdb::ValuesBucketImpl *>(bucket)->valuesBucket_.Put(name, OHOS::NativeRdb::ValueObject(value));
    bucket->capability += 1;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int OH_VBucket_PutBlob(OH_Rdb_ValuesBucket *bucket, const char *name, const uint8_t *value, uint32_t size)
{
    if (bucket == nullptr || name == nullptr || bucket->id != OHOS::NativeRdb::RDB_VALUESBUCKET_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    std::vector<uint8_t> vector(size);
    errno_t result = memcpy_s(vector.data(), size, value, size);
    if (result != EOK) {
        return OH_Rdb_ErrCode::RDB_ERR;
    }
    static_cast<OHOS::NativeRdb::ValuesBucketImpl *>(bucket)->valuesBucket_.Put(name, OHOS::NativeRdb::ValueObject(vector));
    bucket->capability += 1;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int OH_VBucket_PutNull(OH_Rdb_ValuesBucket *bucket, const char *name)
{
    if (bucket == nullptr || name == nullptr || bucket->id != OHOS::NativeRdb::RDB_VALUESBUCKET_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    static_cast<OHOS::NativeRdb::ValuesBucketImpl *>(bucket)->valuesBucket_.Put(name, OHOS::NativeRdb::ValueObject());
    bucket->capability += 1;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}

int OH_VBucket_Clear(OH_Rdb_ValuesBucket *bucket)
{
    if (bucket == nullptr || bucket->id != OHOS::NativeRdb::RDB_VALUESBUCKET_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    static_cast<OHOS::NativeRdb::ValuesBucketImpl *>(bucket)->valuesBucket_.Clear();
    bucket->capability = 0;
    return OH_Rdb_ErrCode::RDB_ERR_OK;
}
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

#include "relational_values_bucket.h"

#include <map>

#include "relational_values_bucket_impl.h"
#include "relational_error_code.h"
#include "value_object.h"

RDB_ValuesBucket *RDB_CreateValuesBucket()
{
    return new OHOS::NativeRdb::ValuesBucketImpl();
}

int RDB_DestroyValuesBucket(RDB_ValuesBucket *bucket)
{
    if (bucket == nullptr || bucket->id != OHOS::NativeRdb::RDB_VALUESBUCKET_CID) {
        return E_INVALID_ARG;
    }
    delete static_cast<OHOS::NativeRdb::ValuesBucketImpl *>(bucket);
    return E_OK;
}

int VBUCKET_PutText(RDB_ValuesBucket *bucket, const char *name, const char *value)
{
    if (bucket == nullptr || bucket->id != OHOS::NativeRdb::RDB_VALUESBUCKET_CID) {
        return E_INVALID_ARG;
    }
    static_cast<OHOS::NativeRdb::ValuesBucketImpl *>(bucket)->valuesBucket_.Put(name, OHOS::NativeRdb::ValueObject(value));
    bucket->capability += 1;
    return E_OK;
}

int VBUCKET_PutInt64(RDB_ValuesBucket *bucket, const char *name, int64_t value)
{
    if (bucket == nullptr || bucket->id != OHOS::NativeRdb::RDB_VALUESBUCKET_CID) {
        return E_INVALID_ARG;
    }
    static_cast<OHOS::NativeRdb::ValuesBucketImpl *>(bucket)->valuesBucket_.Put(name, OHOS::NativeRdb::ValueObject(value));
    bucket->capability += 1;
    return E_OK;
}

int VBUCKET_PutReal(RDB_ValuesBucket *bucket, const char *name, double value)
{
    if (bucket == nullptr || bucket->id != OHOS::NativeRdb::RDB_VALUESBUCKET_CID) {
        return E_INVALID_ARG;
    }
    static_cast<OHOS::NativeRdb::ValuesBucketImpl *>(bucket)->valuesBucket_.Put(name, OHOS::NativeRdb::ValueObject(value));
    bucket->capability += 1;
    return E_OK;
}

int VBUCKET_PutBlob(RDB_ValuesBucket *bucket, const char *name, const uint8_t *value, uint32_t size)
{
    if (bucket == nullptr || bucket->id != OHOS::NativeRdb::RDB_VALUESBUCKET_CID) {
        return E_INVALID_ARG;
    }
    std::vector<uint8_t> vector(size);

//    memcpy_s(vector.begin(), size, value, size);
    std::copy(value, value + size, vector.begin());
    static_cast<OHOS::NativeRdb::ValuesBucketImpl *>(bucket)->valuesBucket_.Put(name, OHOS::NativeRdb::ValueObject(vector));
    bucket->capability += 1;
    return E_OK;
}

int VBUCKET_PutNull(RDB_ValuesBucket *bucket, const char *name)
{
    if (bucket == nullptr || bucket->id != OHOS::NativeRdb::RDB_VALUESBUCKET_CID) {
        return E_INVALID_ARG;
    }
    static_cast<OHOS::NativeRdb::ValuesBucketImpl *>(bucket)->valuesBucket_.Put(name, OHOS::NativeRdb::ValueObject());
    bucket->capability += 1;
    return E_OK;
}
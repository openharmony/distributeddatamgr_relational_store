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

#ifndef RELATIONAL_VALUES_BUCKET_IMPL_H
#define RELATIONAL_VALUES_BUCKET_IMPL_H

#include "native_values_bucket.h"
#include "values_bucket.h"

int Rdb_VBucket_PutText(OH_VBucket *bucket, const char *field, const char *value);
int Rdb_VBucket_PutInt64(OH_VBucket *bucket, const char *field, int64_t value);
int Rdb_VBucket_PutReal(OH_VBucket *bucket, const char *field, double value);
int Rdb_VBucket_PutBlob(OH_VBucket *bucket, const char *field, const uint8_t *value, uint32_t size);
int Rdb_VBucket_PutNull(OH_VBucket *bucket, const char *field);
int Rdb_VBucket_Clear(OH_VBucket *bucket);
int Rdb_DestroyValuesBucket(OH_VBucket *bucket);

namespace OHOS {
namespace RdbNdk {
constexpr int RDB_VBUCKET_CID = 1234562; // The class id used to uniquely identify the OH_Rdb_VBucket class.
class ValuesBucketImpl : public OH_VBucket {
public:
    ValuesBucketImpl()
    {
        id = RDB_VBUCKET_CID;
        capability = 0;

        PutText = Rdb_VBucket_PutText;
        PutInt64 = Rdb_VBucket_PutInt64;
        PutReal = Rdb_VBucket_PutReal;
        PutBlob = Rdb_VBucket_PutBlob;
        PutNull = Rdb_VBucket_PutNull;
        Clear = Rdb_VBucket_Clear;
        DestroyValuesBucket = Rdb_DestroyValuesBucket;
    }
    OHOS::NativeRdb::ValuesBucket &getValuesBucket();
private:
    OHOS::NativeRdb::ValuesBucket valuesBucket_;
};
} // namespace RdbNdk
} // namespace OHOS
#endif // RELATIONAL_VALUES_BUCKET_IMPL_H

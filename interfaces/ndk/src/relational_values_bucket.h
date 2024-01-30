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

#include "oh_values_bucket.h"
#include "values_bucket.h"

namespace OHOS {
namespace RdbNdk {
class RelationalValuesBucket : public OH_VBucket {
public:
    RelationalValuesBucket();
    static RelationalValuesBucket *GetSelf(OH_VBucket *bucket);
    OHOS::NativeRdb::ValuesBucket &Get();

private:
    static int PutText(OH_VBucket *bucket, const char *field, const char *value);
    static int PutInt64(OH_VBucket *bucket, const char *field, int64_t value);
    static int PutReal(OH_VBucket *bucket, const char *field, double value);
    static int PutBlob(OH_VBucket *bucket, const char *field, const uint8_t *value, uint32_t size);
    static int PutNull(OH_VBucket *bucket, const char *field);
    static int Clear(OH_VBucket *bucket);
    static int Destroy(OH_VBucket *bucket);
    static int PutValueObject(OH_VBucket *bucket, const char *field, OHOS::NativeRdb::ValueObject &&value);
    OHOS::NativeRdb::ValuesBucket valuesBucket_;
};
} // namespace RdbNdk
} // namespace OHOS
#endif // RELATIONAL_VALUES_BUCKET_IMPL_H

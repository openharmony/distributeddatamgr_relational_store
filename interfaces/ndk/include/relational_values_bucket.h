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

#ifndef RELATIONAL_VALUES_BUCKET_H
#define RELATIONAL_VALUES_BUCKET_H

#include <cstdint>
#ifdef __cplusplus
extern "C" {
#endif

struct RDB_ValuesBucket {
    int id;
    uint16_t capability;
};

RDB_ValuesBucket *OH_Rdb_CreateValuesBucket();
int OH_Rdb_DestroyValuesBucket(RDB_ValuesBucket *bucket);

int OH_VBucket_PutText(RDB_ValuesBucket *bucket, const char *name, const char *value);
int OH_VBucket_PutInt64(RDB_ValuesBucket *bucket, const char *name, int64_t value);
int OH_VBucket_PutReal(RDB_ValuesBucket *bucket, const char *name, double value);
int OH_VBucket_PutBlob(RDB_ValuesBucket *bucket, const char *name, const uint8_t *value, uint32_t size);
int OH_VBucket_PutNull(RDB_ValuesBucket *bucket, const char *name);
int OH_VBucket_Clear(RDB_ValuesBucket *bucket);

#ifdef __cplusplus
};
#endif

#endif //RELATIONAL_VALUES_BUCKET_H

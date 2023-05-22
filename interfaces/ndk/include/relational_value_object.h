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

#ifndef RELATIONAL_VALUE_OBJECT_H
#define RELATIONAL_VALUE_OBJECT_H

#include <cstdint>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
   int64_t id;
} OH_Rdb_VObject;

OH_Rdb_VObject *OH_Rdb_CreateValueObject();
int OH_Rdb_DestroyValueObject(OH_Rdb_VObject *valueObject);

int OH_ValueObject_PutInt64(OH_Rdb_VObject *valueObject, int64_t *value, uint32_t count);
int OH_ValueObject_PutDouble(OH_Rdb_VObject *valueObject, double *value, uint32_t count);
int OH_ValueObject_PutText(OH_Rdb_VObject *valueObject, const char *value);
int OH_ValueObject_PutTexts(OH_Rdb_VObject *valueObject, const char **value, uint32_t count);

#ifdef __cplusplus
};
#endif

#endif // RELATIONAL_VALUE_OBJECT_H

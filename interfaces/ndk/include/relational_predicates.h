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

#ifndef RELATIONAL_PREDICATES_H
#define RELATIONAL_PREDICATES_H

#include <cstdint>
#include <stddef.h>
#include "relational_value_object.h"

#ifdef __cplusplus
extern "C" {
#endif

enum OH_Rdb_OrderType {
    ASC = 0,
    DESC = 1,
};

typedef struct OH_Predicates {
    int64_t id;
    OH_Predicates (*OH_Predicates_EqualTo)(OH_Predicates *, const char *, OH_Rdb_VObject *);
    OH_Predicates (*OH_Predicates_NotEqualTo)(OH_Predicates *, const char *, OH_Rdb_VObject *);
    OH_Predicates (*OH_Predicates_BeginWrap)(OH_Predicates *);
    OH_Predicates (*OH_Predicates_EndWrap)(OH_Predicates *);
    OH_Predicates (*OH_Predicates_Or)(OH_Predicates *);
    OH_Predicates (*OH_Predicates_And)(OH_Predicates *);
    OH_Predicates (*OH_Predicates_IsNull)(OH_Predicates *, const char *);
    OH_Predicates (*OH_Predicates_IsNotNull)(OH_Predicates *, const char *);
    OH_Predicates (*OH_Predicates_Like)(OH_Predicates *, const char *, OH_Rdb_VObject *);
    OH_Predicates (*OH_Predicates_Between)(OH_Predicates *, const char *, OH_Rdb_VObject *);
    OH_Predicates (*OH_Predicates_NotBetween)(OH_Predicates *, const char *, OH_Rdb_VObject *);
    OH_Predicates (*OH_Predicates_GreaterThan)(OH_Predicates *, const char *, OH_Rdb_VObject *);
    OH_Predicates (*OH_Predicates_LessThan)(OH_Predicates *, const char *, OH_Rdb_VObject *);
    OH_Predicates (*OH_Predicates_GreaterThanOrEqualTo)(OH_Predicates *, const char *, OH_Rdb_VObject *);
    OH_Predicates (*OH_Predicates_LessThanOrEqualTo)(OH_Predicates *, const char *, OH_Rdb_VObject *);
    OH_Predicates (*OH_Predicates_OrderBy)(OH_Predicates *, const char *, OH_Rdb_OrderType);
    OH_Predicates (*OH_Predicates_Distinct)(OH_Predicates *);
    OH_Predicates (*OH_Predicates_Limit)(OH_Predicates *, unsigned int);
    OH_Predicates (*OH_Predicates_Offset)(OH_Predicates *, unsigned int);
    OH_Predicates (*OH_Predicates_GroupBy)(OH_Predicates *, OH_Rdb_VObject *);
    OH_Predicates (*OH_Predicates_In)(OH_Predicates *, const char *, OH_Rdb_VObject *);
    OH_Predicates (*OH_Predicates_NotIn)(OH_Predicates *, const char *, OH_Rdb_VObject *);
    OH_Predicates (*OH_Predicates_Clear)(OH_Predicates *);
    int (*OH_Predicates_Close)(OH_Predicates *);
} OH_Predicates;

OH_Predicates *OH_Rdb_CreatePredicates(const char *table);
int OH_Rdb_DestroyPredicates(OH_Predicates *predicates);

#ifdef __cplusplus
};
#endif

#endif // RELATIONAL_PREDICATES_H

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

#ifdef __cplusplus
extern "C" {
#endif

enum OrderByType {
    ASC = 0,
    DESC = 1,
};

struct OH_Predicates{
    int id;
    int (*OH_Predicates_EqualTo)(OH_Predicates *, const char *, const char *);
    int (*OH_Predicates_NotEqualTo)(OH_Predicates *, const char *, const char *);
    int (*OH_Predicates_BeginWrap)(OH_Predicates *);
    int (*OH_Predicates_EndWrap)(OH_Predicates *);
    int (*OH_Predicates_Or)(OH_Predicates *);
    int (*OH_Predicates_And)(OH_Predicates *);
    int (*OH_Predicates_IsNull)(OH_Predicates *, const char *);
    int (*OH_Predicates_IsNotNull)(OH_Predicates *, const char *);
    int (*OH_Predicates_Like)(OH_Predicates *, const char *, const char *);
    int (*OH_Predicates_Between)(OH_Predicates *, const char *, const char *, const char *);
    int (*OH_Predicates_NotBetween)(OH_Predicates *, const char *, const char *, const char *);
    int (*OH_Predicates_GreaterThan)(OH_Predicates *, const char *, const char *);
    int (*OH_Predicates_LessThan)(OH_Predicates *, const char *, const char *);
    int (*OH_Predicates_GreaterThanOrEqualTo)(OH_Predicates *, const char *, const char *);
    int (*OH_Predicates_LessThanOrEqualTo)(OH_Predicates *, const char *, const char *);
    int (*OH_Predicates_OrderBy)(OH_Predicates *, const char *, OrderByType);
    int (*OH_Predicates_Distinct)(OH_Predicates *);
    int (*OH_Predicates_Limit)(OH_Predicates *, unsigned int);
    int (*OH_Predicates_Offset)(OH_Predicates *, unsigned int);
    int (*OH_Predicates_GroupBy)(OH_Predicates *, char const *const *, const int);
    int (*OH_Predicates_In)(OH_Predicates *, char const *, char const *const *, const int);
    int (*OH_Predicates_NotIn)(OH_Predicates *, char const *, char const *const *, const int);
    int (*OH_Predicates_Clear)(OH_Predicates *);
};

OH_Predicates *OH_Rdb_CreatePredicates(char const *table);
int OH_Rdb_DestroyPredicates(OH_Predicates *predicates);

int PREDICATES_EqualTo(OH_Predicates *predicates, const char *field, const char *value);
int PREDICATES_NotEqualTo(OH_Predicates *predicates, const char *field, const char *value);
int PREDICATES_BeginWrap(OH_Predicates *predicates);
int PREDICATES_EndWrap(OH_Predicates *predicates);
int PREDICATES_Or(OH_Predicates *predicates);
int PREDICATES_And(OH_Predicates *predicates);
int PREDICATES_IsNull(OH_Predicates *predicates, const char *field);
int PREDICATES_IsNotNull(OH_Predicates *predicates, const char *field);
int PREDICATES_Like(OH_Predicates *predicates, const char *field, const char *value);
int PREDICATES_Between(OH_Predicates *predicates, const char *field, const char *betweenValue, const char *andValue);
int PREDICATES_NotBetween(OH_Predicates *predicates, const char *field, const char *betweenValue, const char *andValue);
int PREDICATES_GreaterThan(OH_Predicates *predicates, const char *field, const char *value);
int PREDICATES_LessThan(OH_Predicates *predicates, const char *field, const char *value);
int PREDICATES_GreaterThanOrEqualTo(OH_Predicates *predicates, const char *field, const char *value);
int PREDICATES_LessThanOrEqualTo(OH_Predicates *predicates, const char *field, const char *value);
int PREDICATES_OrderBy(OH_Predicates *predicates, const char *field, OrderByType type);
int PREDICATES_Distinct(OH_Predicates *predicates);
int PREDICATES_Limit(OH_Predicates *predicates, unsigned int value);
int PREDICATES_Offset(OH_Predicates *predicates, unsigned int rowOffset);
int PREDICATES_GroupBy(OH_Predicates *predicates, char const *const *fields, int length);
int PREDICATES_In(OH_Predicates *predicates, char const *filed, char const *const *values, const int length);
int PREDICATES_NotIn(OH_Predicates *predicates, char const *filed, char const *const *values, const int length);
int PREDICATES_Clear(OH_Predicates *predicates);

#ifdef __cplusplus
};
#endif

#endif //RELATIONAL_PREDICATES_H

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

#define OH_Predicates_EqualTo(predicates, field, value) predicates->equalTo(predicates, field, value)
#define OH_Predicates_NotEqualTo(predicates, field, value) predicates->notEqualTo(predicates, field, value)
#define OH_Predicates_BeginWrap(predicates) predicates->beginWrap(predicates)
#define OH_Predicates_EndWrap(predicates) predicates->endWrap(predicates)
#define OH_Predicates_Or(predicates) predicates->OR(predicates)
#define OH_Predicates_And(predicates) predicates->AND(predicates)
#define OH_Predicates_IsNull(predicates, field) predicates->isNull(predicates, field)
#define OH_Predicates_IsNotNull(predicates, field) predicates->isNotNull(predicates, field)
#define OH_Predicates_Like(predicates, field, value) predicates->like(predicates, field, value)
#define OH_Predicates_Between(predicates, field, betweenValue, andValue) predicates->between(predicates, field, value)
#define OH_Predicates_NotBetween(predicates, field, Value) predicates->notBetween(predicates, field, value)
#define OH_Predicates_GreaterThan(predicates, field, value) predicates->greaterThan(predicates, field, value)
#define OH_Predicates_LessThan(predicates, field, value) predicates->lessThan(predicates, field, value)
#define OH_Predicates_GreaterThanOrEqualTo(predicates, field, value) predicates->greaterThanOrEqualTo(predicates, field, value)
#define OH_Predicates_LessThanOrEqualTo(predicates, field, value) predicates->lessThanOrEqualTo(predicates, field, value)
#define OH_Predicates_OrderBy(predicates, field, type) predicates->orderBy(predicates, field, type)
#define OH_Predicates_Distinct(predicates) predicates->distinct(predicates)
#define OH_Predicates_Limit(predicates, value) predicates->limit(predicates, value)
#define OH_Predicates_Offset(predicates, rowOffset) predicates->limit(predicates, rowOffset)
#define OH_Predicates_GroupBy(predicates, fields, length) predicates->groupBy(predicates, fields, length)
#define OH_Predicates_In(predicates, filed, values, length) predicates->in(predicates, filed, values, length)
#define OH_Predicates_NotIn(predicates, filed, values, length) predicates->in(predicates, filed, values, length)

enum OrderByType {
    ASC = 0,
    DESC = 1,
};

struct OH_Predicates{
    int id;
    int (*equalTo)(OH_Predicates *, const char *, const char *);
    int (*notEqualTo)(OH_Predicates *, const char *, const char *);
    int (*beginWrap)(OH_Predicates *);
    int (*endWrap)(OH_Predicates *);
    int (*OR)(OH_Predicates *);
    int (*AND)(OH_Predicates *);
    int (*isNull)(OH_Predicates *, const char *);
    int (*isNotNull)(OH_Predicates *, const char *);
    int (*like)(OH_Predicates *, const char *, const char *);
    int (*between)(OH_Predicates *, const char *, const char *, const char *);
    int (*notBetween)(OH_Predicates *, const char *, const char *, const char *);
    int (*greaterThan)(OH_Predicates *, const char *, const char *);
    int (*lessThan)(OH_Predicates *, const char *, const char *);
    int (*greaterThanOrEqualTo)(OH_Predicates *, const char *, const char *);
    int (*lessThanOrEqualTo)(OH_Predicates *, const char *, const char *);
    int (*orderBy)(OH_Predicates *, const char *, OrderByType);
    int (*distinct)(OH_Predicates *);
    int (*limit)(OH_Predicates *, unsigned int);
    int (*offset)(OH_Predicates *, unsigned int);
    int (*groupBy)(OH_Predicates *, char const *const *, const int);
    int (*in)(OH_Predicates *, char const *, char const *const *, const int);
    int (*notIn)(OH_Predicates *, char const *, char const *const *, const int);
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
int PREDICATES_OrderBy(OH_Predicates *predicates, const char *field, OrderByType type = OrderByType::DESC);
int PREDICATES_Distinct(OH_Predicates *predicates);
int PREDICATES_Limit(OH_Predicates *predicates, unsigned int value);
int PREDICATES_Offset(OH_Predicates *predicates, unsigned int rowOffset);
int PREDICATES_GroupBy(OH_Predicates *predicates, char const *const *fields, int length);
int PREDICATES_In(OH_Predicates *predicates, char const *filed, char const *const *values, const int length);
int PREDICATES_NotIn(OH_Predicates *predicates, char const *filed, char const *const *values, const int length);

#ifdef __cplusplus
};
#endif

#endif //RELATIONAL_PREDICATES_H

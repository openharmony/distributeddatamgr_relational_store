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

struct RDB_Predicates {
    int id;
};

enum OrderByType {
    ASC = 0,
    DESC = 1,
};

RDB_Predicates *RDB_CreatePredicates(char const *table);
int RDB_DestroyPredicates(RDB_Predicates *predicates);

int PREDICATES_EqualTo(RDB_Predicates *predicates, const char *field, const char *value);
int PREDICATES_NotEqualTo(RDB_Predicates *predicates, const char *field, const char *value);
int PREDICATES_BeginWrap(RDB_Predicates *predicates);
int PREDICATES_EndWrap(RDB_Predicates *predicates);
int PREDICATES_Or(RDB_Predicates *predicates);
int PREDICATES_And(RDB_Predicates *predicates);
int PREDICATES_IsNull(RDB_Predicates *predicates, const char *field);
int PREDICATES_IsNotNull(RDB_Predicates *predicates, const char *field);
int PREDICATES_Like(RDB_Predicates *predicates, const char *field, const char *value);
int PREDICATES_Between(RDB_Predicates *predicates, const char *field, const char *betweenValue, const char *andValue);
int PREDICATES_NotBetween(RDB_Predicates *predicates, const char *field, const char *betweenValue, const char *andValue);
int PREDICATES_GreaterThan(RDB_Predicates *predicates, const char *field, const char *value);
int PREDICATES_LessThan(RDB_Predicates *predicates, const char *field, const char *value);
int PREDICATES_GreaterThanOrEqualTo(RDB_Predicates *predicates, const char *field, const char *value);
int PREDICATES_LessThanOrEqualTo(RDB_Predicates *predicates, const char *field, const char *value);
int PREDICATES_OrderBy(RDB_Predicates *predicates, const char *field, OrderByType type = OrderByType::DESC);
int PREDICATES_Distinct(RDB_Predicates *predicates);
int PREDICATES_Limit(RDB_Predicates *predicates, unsigned int value);
int PREDICATES_Offset(RDB_Predicates *predicates, unsigned int rowOffset);
int PREDICATES_GroupBy(RDB_Predicates *predicates, char const *const *fields, int length);
int PREDICATES_In(RDB_Predicates *predicates, char const *filed, char const *const *values, const int length);
int PREDICATES_NotIn(RDB_Predicates *predicates, char const *filed, char const *const *values, const int length);

#ifdef __cplusplus
};
#endif

#endif //RELATIONAL_PREDICATES_H

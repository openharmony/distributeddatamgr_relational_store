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

#ifndef RELATIONAL_PREDICATES_IMPL_H
#define RELATIONAL_PREDICATES_IMPL_H

#include "rdb_predicates.h"
#include "relational_predicates.h"

OH_Predicates PREDICATES_EqualTo(OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject);
OH_Predicates PREDICATES_NotEqualTo(OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject);
OH_Predicates PREDICATES_BeginWrap(OH_Predicates *predicates);
OH_Predicates PREDICATES_EndWrap(OH_Predicates *predicates);
OH_Predicates PREDICATES_Or(OH_Predicates *predicates);
OH_Predicates PREDICATES_And(OH_Predicates *predicates);
OH_Predicates PREDICATES_IsNull(OH_Predicates *predicates, const char *field);
OH_Predicates PREDICATES_IsNotNull(OH_Predicates *predicates, const char *field);
OH_Predicates PREDICATES_Like(OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject);
OH_Predicates PREDICATES_Between(OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject);
OH_Predicates PREDICATES_NotBetween(OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject);
OH_Predicates PREDICATES_GreaterThan(OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject);
OH_Predicates PREDICATES_LessThan(OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject);
OH_Predicates PREDICATES_GreaterThanOrEqualTo(
    OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject);
OH_Predicates PREDICATES_LessThanOrEqualTo(OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject);
OH_Predicates PREDICATES_OrderBy(OH_Predicates *predicates, const char *field, OH_Rdb_OrderType type);
OH_Predicates PREDICATES_Distinct(OH_Predicates *predicates);
OH_Predicates PREDICATES_Limit(OH_Predicates *predicates, unsigned int value);
OH_Predicates PREDICATES_Offset(OH_Predicates *predicates, unsigned int rowOffset);
OH_Predicates PREDICATES_GroupBy(OH_Predicates *predicates, char const *const *fields, int length);
OH_Predicates PREDICATES_In(OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject);
OH_Predicates PREDICATES_NotIn(OH_Predicates *predicates, const char *field, OH_Rdb_VObject *valueObject);
OH_Predicates PREDICATES_Clear(OH_Predicates *predicates);

namespace OHOS {
namespace RdbNdk {
constexpr int RDB_PREDICATES_CID = 1234561; // The class id used to uniquely identify the OH_Predicates class.
class PredicateImpl : public OH_Predicates {
public:
    explicit PredicateImpl(const char *table) : predicates_(table)
    {
        id = RDB_PREDICATES_CID;
        OH_Predicates_EqualTo = PREDICATES_EqualTo;
        OH_Predicates_NotEqualTo = PREDICATES_NotEqualTo;
        OH_Predicates_BeginWrap = PREDICATES_BeginWrap;
        OH_Predicates_EndWrap = PREDICATES_EndWrap;
        OH_Predicates_Or = PREDICATES_Or;
        OH_Predicates_And = PREDICATES_And;
        OH_Predicates_IsNull = PREDICATES_IsNull;
        OH_Predicates_IsNotNull = PREDICATES_IsNotNull;
        OH_Predicates_Like = PREDICATES_Like;
        OH_Predicates_Between = PREDICATES_Between;
        OH_Predicates_NotBetween = PREDICATES_NotBetween;
        OH_Predicates_GreaterThan = PREDICATES_GreaterThan;
        OH_Predicates_LessThan = PREDICATES_LessThan;
        OH_Predicates_GreaterThanOrEqualTo = PREDICATES_GreaterThanOrEqualTo;
        OH_Predicates_LessThanOrEqualTo = PREDICATES_LessThanOrEqualTo;
        OH_Predicates_OrderBy = PREDICATES_OrderBy;
        OH_Predicates_Distinct = PREDICATES_Distinct;
        OH_Predicates_Limit = PREDICATES_Limit;
        OH_Predicates_Offset = PREDICATES_Offset;
        OH_Predicates_GroupBy = PREDICATES_GroupBy;
        OH_Predicates_In = PREDICATES_In;
        OH_Predicates_NotIn = PREDICATES_NotIn;
        OH_Predicates_Clear = PREDICATES_Clear;
    }
    OHOS::NativeRdb::RdbPredicates &GetPredicates();

private:
    OHOS::NativeRdb::RdbPredicates predicates_;
};
} // namespace RdbNdk
} // namespace OHOS
#endif // RELATIONAL_PREDICATES_IMPL_H

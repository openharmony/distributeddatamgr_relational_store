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
#include "predicates.h"

OH_Predicates Rdb_Predicates_EqualTo(OH_Predicates *predicates, const char *field, OH_VObject *valueObject);
OH_Predicates Rdb_Predicates_NotEqualTo(OH_Predicates *predicates, const char *field, OH_VObject *valueObject);
OH_Predicates Rdb_Predicates_BeginWrap(OH_Predicates *predicates);
OH_Predicates Rdb_Predicates_EndWrap(OH_Predicates *predicates);
OH_Predicates Rdb_Predicates_Or(OH_Predicates *predicates);
OH_Predicates Rdb_Predicates_And(OH_Predicates *predicates);
OH_Predicates Rdb_Predicates_IsNull(OH_Predicates *predicates, const char *field);
OH_Predicates Rdb_Predicates_IsNotNull(OH_Predicates *predicates, const char *field);
OH_Predicates Rdb_Predicates_Like(OH_Predicates *predicates, const char *field, OH_VObject *valueObject);
OH_Predicates Rdb_Predicates_Between(OH_Predicates *predicates, const char *field, OH_VObject *valueObject);
OH_Predicates Rdb_Predicates_NotBetween(OH_Predicates *predicates, const char *field, OH_VObject *valueObject);
OH_Predicates Rdb_Predicates_GreaterThan(OH_Predicates *predicates, const char *field, OH_VObject *valueObject);
OH_Predicates Rdb_Predicates_LessThan(OH_Predicates *predicates, const char *field, OH_VObject *valueObject);
OH_Predicates Rdb_Predicates_GreaterThanOrEqualTo(
    OH_Predicates *predicates, const char *field, OH_VObject *valueObject);
OH_Predicates Rdb_Predicates_LessThanOrEqualTo(OH_Predicates *predicates, const char *field, OH_VObject *valueObject);
OH_Predicates Rdb_Predicates_OrderBy(OH_Predicates *predicates, const char *field, OH_OrderType type);
OH_Predicates Rdb_Predicates_Distinct(OH_Predicates *predicates);
OH_Predicates Rdb_Predicates_Limit(OH_Predicates *predicates, unsigned int value);
OH_Predicates Rdb_Predicates_Offset(OH_Predicates *predicates, unsigned int rowOffset);
OH_Predicates Rdb_Predicates_GroupBy(OH_Predicates *predicates, char const *const *fields, int length);
OH_Predicates Rdb_Predicates_In(OH_Predicates *predicates, const char *field, OH_VObject *valueObject);
OH_Predicates Rdb_Predicates_NotIn(OH_Predicates *predicates, const char *field, OH_VObject *valueObject);
OH_Predicates Rdb_Predicates_Clear(OH_Predicates *predicates);
int Rdb_DestroyPredicates(OH_Predicates *predicates);

namespace OHOS {
namespace RdbNdk {
constexpr int RDB_PREDICATES_CID = 1234561; // The class id used to uniquely identify the OH_Predicates class.
class PredicateImpl : public OH_Predicates {
public:
    explicit PredicateImpl(const char *table) : predicates_(table)
    {
        id = RDB_PREDICATES_CID;
        EqualTo = Rdb_Predicates_EqualTo;
        NotEqualTo = Rdb_Predicates_NotEqualTo;
        BeginWrap = Rdb_Predicates_BeginWrap;
        EndWrap = Rdb_Predicates_EndWrap;
        Or = Rdb_Predicates_Or;
        And = Rdb_Predicates_And;
        IsNull = Rdb_Predicates_IsNull;
        IsNotNull = Rdb_Predicates_IsNotNull;
        Like = Rdb_Predicates_Like;
        Between = Rdb_Predicates_Between;
        NotBetween = Rdb_Predicates_NotBetween;
        GreaterThan = Rdb_Predicates_GreaterThan;
        LessThan = Rdb_Predicates_LessThan;
        GreaterThanOrEqualTo = Rdb_Predicates_GreaterThanOrEqualTo;
        LessThanOrEqualTo = Rdb_Predicates_LessThanOrEqualTo;
        OrderBy = Rdb_Predicates_OrderBy;
        Distinct = Rdb_Predicates_Distinct;
        Limit = Rdb_Predicates_Limit;
        Offset = Rdb_Predicates_Offset;
        GroupBy = Rdb_Predicates_GroupBy;
        In = Rdb_Predicates_In;
        NotIn = Rdb_Predicates_NotIn;
        Clear = Rdb_Predicates_Clear;
        DestroyPredicates = Rdb_DestroyPredicates;
    }
    OHOS::NativeRdb::RdbPredicates &GetPredicates();

private:
    OHOS::NativeRdb::RdbPredicates predicates_;
};
} // namespace RdbNdk
} // namespace OHOS
#endif // RELATIONAL_PREDICATES_IMPL_H

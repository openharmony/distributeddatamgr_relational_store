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

namespace OHOS {
namespace NativeRdb {
constexpr int RDB_PREDICATES_CID = 1234561;
class PredicateImpl : public OH_Predicates {
public:
    PredicateImpl(const char *table) : predicates_(table)
    {
        id = RDB_PREDICATES_CID;
        equalTo = PREDICATES_EqualTo;
        notEqualTo = PREDICATES_NotEqualTo;
        beginWrap = PREDICATES_BeginWrap;
        endWrap = PREDICATES_EndWrap;
        OR = PREDICATES_Or;
        AND = PREDICATES_And;
        isNull = PREDICATES_IsNull;
        isNotNull = PREDICATES_IsNotNull;
        like = PREDICATES_Like;
        between = PREDICATES_Between;
        notBetween = PREDICATES_NotBetween;
        greaterThan = PREDICATES_GreaterThan;
        lessThan = PREDICATES_LessThan;
        greaterThanOrEqualTo = PREDICATES_GreaterThanOrEqualTo;
        lessThanOrEqualTo = PREDICATES_LessThanOrEqualTo;
        orderBy = PREDICATES_OrderBy;
        distinct = PREDICATES_Distinct;
        limit = PREDICATES_Limit;
        offset = PREDICATES_Offset;
        groupBy = PREDICATES_GroupBy;
        in = PREDICATES_In;
        notIn = PREDICATES_NotIn;
    }
    RdbPredicates GetPredicates();

private:
    RdbPredicates predicates_;
};
} // namespace NativeRdb
} // namespace OHOS
#endif //RELATIONAL_PREDICATES_IMPL_H

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
#include "oh_predicates.h"

namespace OHOS {
namespace RdbNdk {
constexpr int RDB_PREDICATES_CID = 1234561; // The class id used to uniquely identify the OH_Predicates class.
class RelationalPredicate : public OH_Predicates {
public:
    explicit RelationalPredicate(const char *table);
    static RelationalPredicate *GetSelf(OH_Predicates *predicates);
    OHOS::NativeRdb::RdbPredicates &Get();
private:
    static OH_Predicates *EqualTo(OH_Predicates *predicates, const char *field, OH_VObject *valueObject);
    static OH_Predicates *NotEqualTo(OH_Predicates *predicates, const char *field, OH_VObject *valueObject);
    static OH_Predicates *BeginWrap(OH_Predicates *predicates);
    static OH_Predicates *EndWrap(OH_Predicates *predicates);
    static OH_Predicates *Or(OH_Predicates *predicates);
    static OH_Predicates *And(OH_Predicates *predicates);
    static OH_Predicates *IsNull(OH_Predicates *predicates, const char *field);
    static OH_Predicates *IsNotNull(OH_Predicates *predicates, const char *field);
    static OH_Predicates *Like(OH_Predicates *predicates, const char *field, OH_VObject *valueObject);
    static OH_Predicates *Between(OH_Predicates *predicates, const char *field, OH_VObject *valueObject);
    static OH_Predicates *NotBetween(OH_Predicates *predicates, const char *field, OH_VObject *valueObject);
    static OH_Predicates *GreaterThan(OH_Predicates *predicates, const char *field, OH_VObject *valueObject);
    static OH_Predicates *LessThan(OH_Predicates *predicates, const char *field, OH_VObject *valueObject);
    static OH_Predicates *GreaterThanOrEqualTo(OH_Predicates *predicates, const char *field,
        OH_VObject *valueObject);
    static OH_Predicates *LessThanOrEqualTo(OH_Predicates *predicates, const char *field,
        OH_VObject *valueObject);
    static OH_Predicates *OrderBy(OH_Predicates *predicates, const char *field, OH_OrderType type);
    static OH_Predicates *Distinct(OH_Predicates *predicates);
    static OH_Predicates *Limit(OH_Predicates *predicates, unsigned int value);
    static OH_Predicates *Offset(OH_Predicates *predicates, unsigned int rowOffset);
    static OH_Predicates *GroupBy(OH_Predicates *predicates, char const *const *fields, int length);
    static OH_Predicates *In(OH_Predicates *predicates, const char *field, OH_VObject *valueObject);
    static OH_Predicates *NotIn(OH_Predicates *predicates, const char *field, OH_VObject *valueObject);
    static OH_Predicates *Clear(OH_Predicates *predicates);
    static int Destroy(OH_Predicates *predicates);
    static bool GetObjects(OH_Predicates *predicates, OH_VObject *valueObject,
        std::vector<std::string> &values);
    OHOS::NativeRdb::RdbPredicates predicates_;
};
} // namespace RdbNdk
} // namespace OHOS
#endif // RELATIONAL_PREDICATES_IMPL_H

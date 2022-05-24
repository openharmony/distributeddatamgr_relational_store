/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef DATASHARE_ABSPREDICATES_H
#define DATASHARE_ABSPREDICATES_H

#include <string>
#include <vector>
#include <list>
#include "datashare_predicates_def.h"

namespace OHOS {
namespace DataShare {
class DataShareAbsPredicates {
public:
    virtual ~DataShareAbsPredicates() {}
    virtual DataShareAbsPredicates *EqualTo(const std::string &field, const DataSharePredicatesObject &value) = 0;
    virtual DataShareAbsPredicates *NotEqualTo(const std::string &field, const DataSharePredicatesObject &value) = 0;
    virtual DataShareAbsPredicates *GreaterThan(const std::string &field, const DataSharePredicatesObject &value) = 0;
    virtual DataShareAbsPredicates *LessThan(const std::string &field, const DataSharePredicatesObject &value) = 0;
    virtual DataShareAbsPredicates *GreaterThanOrEqualTo(const std::string &field, const DataSharePredicatesObject &value) = 0;
    virtual DataShareAbsPredicates *LessThanOrEqualTo(const std::string &field, const DataSharePredicatesObject & value) = 0;
    virtual DataShareAbsPredicates *In(const std::string &field, const DataSharePredicatesObject &value) = 0;
    virtual DataShareAbsPredicates *NotIn(const std::string &field, const DataSharePredicatesObject &value) = 0;
    virtual DataShareAbsPredicates *BeginWrap() = 0;
    virtual DataShareAbsPredicates *EndWrap() = 0;
    virtual DataShareAbsPredicates *Or() = 0;
    virtual DataShareAbsPredicates *And() = 0;
    virtual DataShareAbsPredicates *Contains(const std::string &field, const std::string &value) = 0;
    virtual DataShareAbsPredicates *BeginsWith(const std::string &field, const std::string &value) = 0;
    virtual DataShareAbsPredicates *EndsWith(const std::string &field, const std::string &value) = 0;
    virtual DataShareAbsPredicates *IsNull(const std::string &field) = 0;
    virtual DataShareAbsPredicates *IsNotNull(const std::string &field) = 0;
    virtual DataShareAbsPredicates *Like(const std::string &field, const std::string &value) = 0;
    virtual DataShareAbsPredicates *Glob(const std::string &field, const std::string &value) = 0;
    virtual DataShareAbsPredicates *Between(const std::string &field,
        const std::string &low, const std::string &high) = 0;
    virtual DataShareAbsPredicates *NotBetween(const std::string &field,
        const std::string &low, const std::string &high) = 0;
    virtual DataShareAbsPredicates *OrderByAsc(const std::string &field) = 0;
    virtual DataShareAbsPredicates *OrderByDesc(const std::string &field) = 0;
    virtual DataShareAbsPredicates *Distinct() = 0;
    virtual DataShareAbsPredicates *Limit(const int number, const int offset) = 0;
    virtual DataShareAbsPredicates *GroupBy(const std::vector<std::string> &fields) = 0;
    virtual DataShareAbsPredicates *IndexedBy(const std::string &indexName) = 0;
    virtual DataShareAbsPredicates *KeyPrefix(const std::string &prefix) = 0;
    virtual DataShareAbsPredicates *InKeys(const std::vector<std::string> &keys) = 0;
    virtual const std::list<OperationItem>& GetOperationList() const = 0;
    virtual std::string GetWhereClause() const = 0;
    virtual int SetWhereClause(const std::string &whereClause) = 0;
    virtual std::vector<std::string> GetWhereArgs() const = 0;
    virtual int SetWhereArgs(const std::vector<std::string> &whereArgs) = 0;
    virtual std::string GetOrder() const = 0;
    virtual int SetOrder(const std::string &order) = 0;
    virtual SettingMode GetSettingMode() const = 0;
};
} // namespace DataShare
} // namespace OHOS

#endif
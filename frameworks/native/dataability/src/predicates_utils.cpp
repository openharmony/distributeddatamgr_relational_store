/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "predicates_utils.h"

#include <sstream>

namespace OHOS {
namespace NativeRdb {
PredicatesUtils::PredicatesUtils()
{
}

/**
 * Set the param of whereClause and bindArgs of the specified Predicates.
 */
void PredicatesUtils::SetWhereClauseAndArgs(
    AbsPredicates *predicates, const std::string &whereClause, const std::vector<std::string> &whereArgs)
{
    predicates->SetWhereClause(whereClause);
    predicates->SetWhereArgs(whereArgs);
}

/**
 * Set the param of whereClause and bindArgs of the specified Predicates.
 */
void PredicatesUtils::SetWhereClauseAndArgs(AbsPredicates *predicates, const std::string &whereClause,
    const std::vector<ValueObject> &bindArgs)
{
    predicates->SetWhereClause(whereClause);
    predicates->SetBindArgs(bindArgs);
}

/**
 * Sets params of the specified Predicates including distinct, index, group, order, limit and offset.
 */
void PredicatesUtils::SetAttributes(AbsPredicates *predicates, bool isDistinct, const std::string &index,
    const std::string &group, const std::string &order, const int limit, const int offset)
{
    if (isDistinct) {
        predicates->Distinct();
    }
    if (!index.empty()) {
        predicates->IndexedBy(index);
    }
    if (!group.empty()) {
        std::vector<std::string> groupArray;
        std::istringstream iss(group);
        std::string temp;
        while (getline(iss, temp, ',')) {
            groupArray.push_back(temp);
        }
        predicates->GroupBy(groupArray);
    }
    if (!order.empty()) {
        predicates->SetOrder(order);
    }
    if (limit != AbsPredicates::INIT_LIMIT_VALUE) {
        predicates->Limit(limit);
    }
    if (offset != AbsPredicates::INIT_OFFSET_VALUE) {
        predicates->Offset(offset);
    }
}
} // namespace NativeRdb
} // namespace OHOS
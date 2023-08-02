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


#ifndef NATIVE_RDB_PREDICATES_UTILS_H
#define NATIVE_RDB_PREDICATES_UTILS_H

#include <string>
#include <vector>

#include "abs_predicates.h"
#include "value_object.h"

namespace OHOS {
namespace NativeRdb {
/**
 * The Predicates class of Utils.
 */
class API_EXPORT PredicatesUtils {
public:
    /**
     * @brief Constructor.
     */
    API_EXPORT PredicatesUtils();

    /**
     * @brief Destructor.
     */
    API_EXPORT ~PredicatesUtils() {}

    /**
     * @brief Set the parameter of whereClause and bindArgs of the specified Predicates.
     */
    [[deprecated("Use SetWhereClauseAndArgs(AbsPredicates *, const std::string &,"
                 " const std::vector<ValueObject> &) instead.")]]
    API_EXPORT static void SetWhereClauseAndArgs(AbsPredicates *predicates, const std::string &whereClause,
        const std::vector<std::string> &whereArgs);

    /**
     * @brief Set the parameter of whereClause and bindArgs of the specified Predicates.
     */
    API_EXPORT static void SetWhereClauseAndArgs(AbsPredicates *predicates, const std::string &whereClause,
        const std::vector<ValueObject> &bindArgs);

    /**
     * @brief Sets parameters of the specified Predicates including distinct, index, group, order, limit and offset.
     */
    API_EXPORT static void SetAttributes(AbsPredicates *predicates, bool isDistinct, const std::string &index,
        const std::string &group, const std::string &order, const int limit, const int offset);
};
} // namespace NativeRdb
} // namespace OHOS

#endif

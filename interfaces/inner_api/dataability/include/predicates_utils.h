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
namespace OHOS {
namespace NativeRdb {
/**
 * The Predicates class of Utils.
 */
class PredicatesUtils {
public:
    /**
     * @brief Constructor.
     */
    PredicatesUtils();

    /**
     * @brief Destructor.
     */
    ~PredicatesUtils() {}

    /**
     * @brief Set the parameter of whereClause and whereArgs of the specified Predicates.
     */
    static void SetWhereClauseAndArgs(AbsPredicates *predicates, std::string whereClause,
        std::vector<std::string> whereArgs);

    /**
     * @brief Sets parameters of the specified Predicates including distinct, index, group, order, limit and offset.
     */
    static void SetAttributes(AbsPredicates *predicates, bool isDistinct, std::string index, std::string group,
        std::string order, int limit, int offset);
};
} // namespace NativeRdb
} // namespace OHOS

#endif

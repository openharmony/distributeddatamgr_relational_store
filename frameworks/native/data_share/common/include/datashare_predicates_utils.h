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


#ifndef DATASHARE_PREDICATES_UTILS_H
#define DATASHARE_PREDICATES_UTILS_H

#include <string>
#include <vector>

#include "datashare_abs_predicates.h"
namespace OHOS {
namespace DataShare {
class DataSharePredicatesUtils {
public:
    DataSharePredicatesUtils();
    ~DataSharePredicatesUtils() {}
    static void SetWhereClauseAndArgs(DataShareAbsPredicates *predicates, std::string whereClause,
        std::vector<std::string> whereArgs);
    static void SetAttributes(DataShareAbsPredicates *predicates, bool isDistinct, std::string index, std::string group,
        std::string order, int limit, int offset);
};
} // namespace DataShare
} // namespace OHOS

#endif

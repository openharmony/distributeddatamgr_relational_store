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
#ifndef RELATIONAL_STORE_RELATIONAL_STORE_MANAGER_H
#define RELATIONAL_STORE_RELATIONAL_STORE_MANAGER_H

#include <map>
#include <string>

#include "store_types.h"

namespace DistributedDB {
class RelationalStoreManager final {
public:
    static std::string GetDistributedLogTableName(const std::string &tableName);
    // key:colName value:real value
    static std::vector<uint8_t> CalcPrimaryKeyHash(
        const std::map<std::string, Type> &primaryKey, const std::map<std::string, CollateType> &collateTypeMap = {});
};
} // namespace DistributedDB
#endif // RELATIONAL_STORE_RELATIONAL_STORE_MANAGER_H

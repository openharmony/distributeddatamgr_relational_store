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

#include "data_properties.h"
#include "string_ex.h"

namespace OHOS::RdbBMSAdapter {
static const std::string SEPARATOR = "/";
const std::string DataProperties::MODULE_SCOPE = "module";
const std::string DataProperties::APPLICATION_SCOPE = "application";
const std::string DataProperties::RDB_TYPE = "rdb";
const std::string DataProperties::PUBLISHED_DATA_TYPE = "publishedData";
bool DataProperties::Marshal(json &node) const
{
    SetValue(node[GET_NAME(path)], storeName + SEPARATOR + tableName);
    SetValue(node[GET_NAME(scope)], scope);
    SetValue(node[GET_NAME(type)], type);
    return true;
}

bool DataProperties::Unmarshal(const json &node)
{
    std::string path;
    bool ret = GetValue(node, GET_NAME(path), path);
    if (!ret) {
        return false;
    }
    std::vector<std::string> splitPath;
    SplitStr(path, SEPARATOR, splitPath);
    if (splitPath.size() < 2) {
        return false;
    }

    if (splitPath[0].empty() || splitPath[1].empty()) {
        return false;
    }
    storeName = splitPath[0];
    tableName = splitPath[1];
    GetValue(node, GET_NAME(scope), scope);
    GetValue(node, GET_NAME(type), type);
    return true;
}
} // namespace OHOS::RdbBMSAdapter
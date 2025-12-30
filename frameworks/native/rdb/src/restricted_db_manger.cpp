/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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
#define LOG_TAG "RestrictedDBManger"
#include "restricted_db_manger.h"
#include <sstream>
#include <fstream>

#include "logger.h"
namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;
static constexpr const char *FAULT_CONF_PATH = "/system/etc/faultdblist/conf/";
static constexpr const char *FAULT_LIST_JSON_PATH = "faultdblist_config.json";
RestrictedDBManger &RestrictedDBManger::GetInstance()
{
    static RestrictedDBManger restrictedDBManger;
    return restrictedDBManger;
}

bool RestrictedDBManger::IsDbAccessOutOfBounds(const std::string &storeName, const std::string &caller)
{
    if (isInitialized_) {
        return storeName_ == storeName && owner_ != caller;
    }
    std::lock_guard<std::mutex> lock(initMutex_);
    if (isInitialized_) {
        return storeName_ == storeName && owner_ != caller;
    }
    std::ifstream fin(std::string(FAULT_CONF_PATH) + std::string(FAULT_LIST_JSON_PATH));
    if (!fin.good()) {
        return false;
    }
    std::string jsonStr;
    std::string line;
    while (fin.good()) {
        std::string line;
        std::getline(fin, line);
        jsonStr += line;
    }
    RestrictedDBManger::DBInfo dbInfo;
    dbInfo.Unmarshall(jsonStr);
    owner_ = dbInfo.owner;
    storeName_ = dbInfo.storeName;
    fin.close();
    isInitialized_ = true;
    return storeName_ == storeName && owner_ != caller;
}

bool RestrictedDBManger::DBInfo::Marshal(Serializable::json &node) const
{
    SetValue(node[GET_NAME(owner)], owner);
    SetValue(node[GET_NAME(storeName)], storeName);
    return true;
}

bool RestrictedDBManger::DBInfo::Unmarshal(const Serializable::json &node)
{
    GetValue(node, GET_NAME(owner), owner);
    GetValue(node, GET_NAME(storeName), storeName);
    return true;
}

} // namespace OHOS::NativeRdb
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
#define LOG_TAG "RestrictedDBManager"
#include "restricted_db_manager.h"
#include <sstream>
#include <fstream>

#include "logger.h"
namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;
static constexpr const char *RESTRICTED_DB_CONF_PATH = "/system/etc/restricteddb/conf/";
static constexpr const char *RESTRICTED_DB_JSON_PATH = "restricted_db_config.json";
RestrictedDBManager &RestrictedDBManager::GetInstance()
{
    static RestrictedDBManager restrictedDBManager;
    return restrictedDBManager;
}

bool RestrictedDBManager::IsDbAccessOutOfBounds(const std::string &storeName, const std::string &caller)
{
    if (isInitialized_) {
        return storeName_ == storeName && owner_ != caller;
    }
    std::lock_guard<std::mutex> lock(initMutex_);
    if (isInitialized_) {
        return storeName_ == storeName && owner_ != caller;
    }
    std::ifstream fin(std::string(RESTRICTED_DB_CONF_PATH) + std::string(RESTRICTED_DB_JSON_PATH));
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
    RestrictedDBManager::DBInfo dbInfo;
    dbInfo.Unmarshall(jsonStr);
    owner_ = dbInfo.owner;
    storeName_ = dbInfo.storeName;
    fin.close();
    isInitialized_ = true;
    return storeName_ == storeName && owner_ != caller;
}

bool RestrictedDBManager::DBInfo::Marshal(Serializable::json &node) const
{
    SetValue(node[GET_NAME(owner)], owner);
    SetValue(node[GET_NAME(storeName)], storeName);
    return true;
}

bool RestrictedDBManager::DBInfo::Unmarshal(const Serializable::json &node)
{
    GetValue(node, GET_NAME(owner), owner);
    GetValue(node, GET_NAME(storeName), storeName);
    return true;
}

} // namespace OHOS::NativeRdb
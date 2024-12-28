/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_DISTRIBUTED_DATA_NATIVE_GDB_DB_STORE_MANAGER_H
#define OHOS_DISTRIBUTED_DATA_NATIVE_GDB_DB_STORE_MANAGER_H
#include <map>
#include <mutex>

#include "db_store_impl.h"

namespace OHOS::DistributedDataAip {
class StoreManager {
public:
    static StoreManager &GetInstance();
    ~StoreManager();
    std::shared_ptr<DBStore> GetDBStore(const StoreConfig &config, int &errCode);
    void Clear();
    bool Delete(const std::string &path);

private:
    StoreManager();
    bool DeleteFile(const std::string &path);
    int SetSecurityLabel(const StoreConfig &config);
    std::string GetSecurityLevelValue(SecurityLevel securityLevel);
    std::string GetFileSecurityLevel(const std::string &filePath);
    bool IsValidName(const std::string& name);
    bool IsValidSecurityLevel(const int32_t securityLevel);
    std::mutex mutex_;
    std::string bundleName_;
    std::map<std::string, std::weak_ptr<DBStoreImpl>> storeCache_;
    static constexpr const char *GRD_POST_FIXES[] = {
        "",
        ".redo",
        ".undo",
        ".ctrl",
        ".ctrl.dwr",
        ".safe",
        ".map",
        ".corruptedflg",
    };
};
} // namespace OHOS::DistributedDataAip
#endif
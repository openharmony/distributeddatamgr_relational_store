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
#ifndef OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_ICU_MANAGER_H
#define OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_ICU_MANAGER_H
#include <functional>
#include <mutex>
#include <string>
struct sqlite3;
namespace OHOS {
namespace NativeRdb {
class RdbICUManager {
public:
    static RdbICUManager &GetInstance();
    int32_t ConfigLocale(sqlite3 *, const std::string &);
private:
    RdbICUManager();
    ~RdbICUManager();
    int32_t CleanUp();
    using ConfigICULocaleFunc = int32_t(*)(sqlite3 *, const std::string &);
    using CleanUpFunc = int32_t(*)();
    struct ICUAPIInfo {
        ConfigICULocaleFunc configIcuLocaleFunc = nullptr;
        CleanUpFunc cleanUpFunc = nullptr;
    };
    ICUAPIInfo GetApiInfo();
    std::mutex mutex_;
    void *handle_ = nullptr;
    ICUAPIInfo apiInfo_;
};

} // namespace NativeRdb
} // namespace OHOS
#endif //LDBPROJ_RDB_ICU_MANAGER_H

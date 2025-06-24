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

#define LOG_TAG "RdbICUManger"
#include "rdb_icu_manager.h"

#include <dlfcn.h>

#include "global_resource.h"
#include "logger.h"
#include "rdb_errno.h"
namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;
RdbICUManager &RdbICUManager::GetInstance()
{
    static RdbICUManager instance;
    return instance;
}

int32_t RdbICUManager::ConfigLocale(sqlite3 *db, const std::string &localeStr)
{
    auto handle = GetApiInfo();
    if (handle.configIcuLocaleFunc == nullptr) {
        LOG_ERROR("dlsym(ConfigLocal) failed!");
        return E_NOT_SUPPORT;
    }
    return handle.configIcuLocaleFunc(db, localeStr);
}

RdbICUManager::RdbICUManager()
{
    handle_ = nullptr;
}

RdbICUManager::~RdbICUManager()
{
    if (handle_ != nullptr) {
        dlclose(handle_);
        handle_ = nullptr;
    }
}

int32_t RdbICUManager::CleanUp()
{
    auto handle = GetApiInfo();
    if (handle.cleanUpFunc == nullptr) {
        LOG_ERROR("dlsym(CleanUp) failed!");
        return E_NOT_SUPPORT;
    }
    auto code = handle.cleanUpFunc();
    if (code != E_OK) {
        return code;
    }
    std::lock_guard<decltype(mutex_)> lock(mutex_);
    dlclose(handle_);
    handle_ = nullptr;
    apiInfo_.cleanUpFunc = nullptr;
    apiInfo_.configIcuLocaleFunc = nullptr;
    return E_OK;
}

RdbICUManager::ICUAPIInfo RdbICUManager::GetApiInfo()
{
    std::lock_guard<decltype(mutex_)> lock(mutex_);
    if (handle_ != nullptr) {
        return apiInfo_;
    }
    handle_ = dlopen("librelational_store_icu.z.so", RTLD_LAZY);
    if (handle_ == nullptr) {
        LOG_ERROR("dlopen(librelational_store_icu) failed!");
        return apiInfo_;
    }
    GlobalResource::RegisterClean(GlobalResource::ICU, []() { return RdbICUManager::GetInstance().CleanUp(); });
    apiInfo_.configIcuLocaleFunc = reinterpret_cast<ConfigICULocaleFunc>(dlsym(handle_, "ConfigICULocale"));
    apiInfo_.cleanUpFunc = reinterpret_cast<CleanUpFunc>(dlsym(handle_, "CleanUp"));
    return apiInfo_;
}
} // namespace OHOS::NativeRdb
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
#define LOG_TAG "JSAbility"
#include "js_ability.h"

#include <cstdlib>

#include "logger.h"
#if defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
#include "napi_base_context.h"
#endif

namespace OHOS {
namespace AppDataMgrJsKit {
using namespace OHOS::Rdb;

Context::Context()
{
    std::string baseDir = "";
#ifdef WINDOWS_PLATFORM
    baseDir = getenv("TEMP");
    if (!baseDir.empty()) {
        databaseDir_ = baseDir + "\\HuaweiDevEcoStudioDatabases";
    }
#endif

#ifdef MAC_PLATFORM
    baseDir = getenv("LOGNAME");
    baseDir = "/Users/" + baseDir + "/Library/Caches";
    if (!baseDir.empty()) {
        databaseDir_ = baseDir + "/HuaweiDevEcoStudioDatabases";
    }
#endif
    bundleName_ = "com.example.myapplication";
}

#if defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
Context::Context(std::shared_ptr<AbilityRuntime::Platform::Context> stageContext)
{
    if (stageContext != nullptr) {
        databaseDir_ = stageContext->GetDatabaseDir();
    }
}
#endif

std::string Context::GetDatabaseDir()
{
    return databaseDir_;
}

std::string Context::GetBundleName()
{
    return bundleName_;
}

std::string Context::GetModuleName()
{
    return moduleName_;
}

int32_t Context::GetArea() const
{
    return area_;
}

std::string Context::GetUri()
{
    return uri_;
}

std::string Context::GetReadPermission()
{
    return readPermission_;
}

std::string Context::GetWritePermission()
{
    return writePermission_;
}

bool Context::IsSystemAppCalled()
{
    return isSystemAppCalled_;
}

bool JSAbility::CheckContext(napi_env env, napi_callback_info info)
{
    return true;
}

std::shared_ptr<Context> JSAbility::GetContext(napi_env env, napi_value value)
{
    return GetStageModeContext(env, value);
}


std::shared_ptr<Context> JSAbility::GetStageModeContext(napi_env env, napi_value value)
{
#if defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
    LOG_DEBUG("Get context as stage mode.");
    auto stageContext = AbilityRuntime::Platform::GetStageModeContext(env, value);
    if (stageContext == nullptr) {
        LOG_ERROR("GetStageModeContext failed.");
        return nullptr;
    }
    return std::make_shared<Context>(stageContext);
#else
    return std::make_shared<Context>();
#endif
}


std::shared_ptr<Context> JSAbility::GetCurrentAbility(napi_env env, napi_value value)
{
    LOG_ERROR("Get context as feature ability mode.");
    return std::make_shared<Context>();
}


bool Context::IsHasProxyDataConfig() const
{
    return hasProxyDataConfig_;
}

bool Context::IsStageMode() const
{
    return isStageMode_;
}

int Context::GetSystemDatabaseDir(const std::string &dataGroupId, std::string &databaseDir)
{
    databaseDir = databaseDir_;
    return 0;
}
} // namespace AppDataMgrJsKit
} // namespace OHOS

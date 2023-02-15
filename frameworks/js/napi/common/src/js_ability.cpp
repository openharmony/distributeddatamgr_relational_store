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

#include "js_ability.h"

#include "extension_context.h"
#include "js_logger.h"

namespace OHOS {
namespace AppDataMgrJsKit {
Context::Context(std::shared_ptr<AbilityRuntime::Context> stageContext)
{
    databaseDir_ = stageContext->GetDatabaseDir();
    preferencesDir_ = stageContext->GetPreferencesDir();
    bundleName_ = stageContext->GetBundleName();
    area_ = stageContext->GetArea();
    auto hapInfo = stageContext->GetHapModuleInfo();
    if (hapInfo != nullptr) {
        moduleName_ = hapInfo->moduleName;
    }
    auto extensionContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::ExtensionContext>(stageContext);
    if (extensionContext != nullptr) {
        auto abilityInfo = extensionContext->GetAbilityInfo();
        if (abilityInfo != nullptr) {
            uri_ = abilityInfo->uri;
            writePermission_ = abilityInfo->writePermission;
            readPermission_ = abilityInfo->readPermission;
            LOG_INFO("QueryAbilityInfo, uri: %{private}s, readPermission: %{public}s, writePermission: %{public}s.",
                abilityInfo->uri.c_str(), abilityInfo->readPermission.c_str(), abilityInfo->writePermission.c_str());
        }
    }
    LOG_DEBUG("Stage: area:%{public}d, bundleName:%{public}s, moduleName:%{public}s", area_, bundleName_.c_str(),
        moduleName_.c_str());
}

Context::Context(std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext)
{
    databaseDir_ = abilityContext->GetDatabaseDir();
    preferencesDir_ = abilityContext->GetPreferencesDir();
    bundleName_ = abilityContext->GetBundleName();
    area_ = abilityContext->GetArea();
    auto abilityInfo = abilityContext->GetAbilityInfo();
    if (abilityInfo != nullptr) {
        moduleName_ = abilityInfo->moduleName;
    }
    LOG_DEBUG("FA: area:%{public}d database:%{private}s preferences:%{private}s bundle:%{public}s hap:%{public}s",
              area_, databaseDir_.c_str(), preferencesDir_.c_str(), bundleName_.c_str(), moduleName_.c_str());
}

std::string Context::GetDatabaseDir()
{
    return databaseDir_;
}

std::string Context::GetPreferencesDir()
{
    return preferencesDir_;
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

bool JSAbility::CheckContext(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value args[1] = { 0 };
    bool mode = false;
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    napi_status status = AbilityRuntime::IsStageContext(env, args[0], mode);
    return status == napi_ok;
}

std::shared_ptr<Context> JSAbility::GetContext(napi_env env, napi_value value)
{
    bool mode = false;
    AbilityRuntime::IsStageContext(env, value, mode);
    if (mode) {
        LOG_DEBUG("Get context as stage mode.");
        auto stageContext = AbilityRuntime::GetStageModeContext(env, value);
        if (stageContext == nullptr) {
            LOG_ERROR("GetStageModeContext failed.");
            return nullptr;
        }
        return std::make_shared<Context>(stageContext);
    }

    LOG_DEBUG("Get context as feature ability mode.");
    auto ability = AbilityRuntime::GetCurrentAbility(env);
    if (ability == nullptr) {
        LOG_ERROR("GetCurrentAbility failed.");
        return nullptr;
    }
    auto abilityContext = ability->GetAbilityContext();
    if (abilityContext == nullptr) {
        LOG_ERROR("GetAbilityContext failed.");
        return nullptr;
    }
    return std::make_shared<Context>(abilityContext);
}
} // namespace AppDataMgrJsKit
} // namespace OHOS

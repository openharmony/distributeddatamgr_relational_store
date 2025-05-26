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
#define LOG_TAG "AniAbilityUtils"
#include "ani_ability_utils.h"
#include "ani_utils.h"
#include "logger.h"

#include <string>

#include "js_utils.h"
#include "js_ability.h"
#include "rdb_sql_utils.h"
#include "rdb_store_config.h"
#include "napi_rdb_error.h"
#include "rdb_helper.h"
#include "ani_base_context.h"

namespace ani_abilityutils {

using namespace taihe;
using namespace OHOS::Rdb;

static constexpr int32_t INVALID_HAP_VERSION = -1;
#define API_VERSION_MOD 100

#define ASSERT(condition, message, retVal)                       \
    do {                                                         \
        if (!(condition)) {                                      \
            LOG_ERROR("test (" #condition ") failed: " message); \
            return retVal;                                       \
        }                                                        \
    } while (0)


int32_t GetHapVersion(ani_env *env, ani_object value)
{
    auto stageContext = OHOS::AbilityRuntime::GetStageModeContext(env, value);
    if (stageContext == nullptr) {
        LOG_ERROR("GetStageModeContext failed.");
        return INVALID_HAP_VERSION ;
    }
    auto appInfo = stageContext->GetApplicationInfo();
    if (appInfo != nullptr) {
        return appInfo->apiTargetVersion % API_VERSION_MOD;
    }
    LOG_WARN("GetApplicationInfo failed.");
    return INVALID_HAP_VERSION ;
}

std::shared_ptr<OHOS::AppDataMgrJsKit::Context> GetStageModeContext(ani_env *env, ani_object value)
{
    LOG_DEBUG("Get context as stage mode.");
    auto stageContext = OHOS::AbilityRuntime::GetStageModeContext(env, value);
    if (stageContext == nullptr) {
        LOG_ERROR("GetStageModeContext failed.");
        return nullptr;
    }
    return std::make_shared<OHOS::AppDataMgrJsKit::Context>(stageContext);
}

std::shared_ptr<OHOS::AppDataMgrJsKit::Context> GetCurrentAbility(ani_env *env, ani_object value)
{
    LOG_DEBUG("Get context as feature ability mode.");
    auto ability = OHOS::AbilityRuntime::GetCurrentAbility(env);
    if (ability == nullptr) {
        LOG_ERROR("GetCurrentAbility failed.");
        return nullptr;
    }
    auto abilityContext = ability->GetAbilityContext();
    if (abilityContext == nullptr) {
        LOG_ERROR("GetAbilityContext failed.");
        return nullptr;
    }
    return std::make_shared<OHOS::AppDataMgrJsKit::Context>(abilityContext);
}

int32_t GetCurrentAbilityParam(ani_env *env, ani_object jsValue, OHOS::AppDataMgrJsKit::JSUtils::ContextParam &param)
{
    std::shared_ptr<OHOS::AppDataMgrJsKit::Context> context = GetCurrentAbility(env, jsValue);
    if (context == nullptr) {
        return ANI_INVALID_ARGS;
    }
    param.baseDir = context->GetDatabaseDir();
    param.moduleName = context->GetModuleName();
    param.area = context->GetArea();
    param.bundleName = context->GetBundleName();
    param.isSystemApp = context->IsSystemAppCalled();
    return ANI_OK;
}

int32_t AniGetContext(ani_object jsValue, OHOS::AppDataMgrJsKit::JSUtils::ContextParam &param)
{
    LOG_INFO("AniGetContext");
    ani_env *env = taihe::get_env();
    if (jsValue == nullptr) {
        LOG_INFO("hasProp is false -> fa stage");
        param.isStageMode = false;
        return GetCurrentAbilityParam(env, jsValue, param);
    }
    param.isStageMode = true;

    int32_t status = ani_utils::AniGetProperty(env, jsValue, "databaseDir", param.baseDir);
    ASSERT(status == ANI_OK, "get databaseDir failed.", ANI_INVALID_ARGS);

    status = ani_utils::AniGetProperty(env, jsValue, "area", param.area, true);
    ASSERT(status == ANI_OK, "get area failed.", ANI_INVALID_ARGS);

    ani_object hapInfo = nullptr;
    ani_utils::AniGetProperty(env, jsValue, "currentHapModuleInfo", hapInfo);
    if (hapInfo != nullptr) {
        status = ani_utils::AniGetProperty(env, hapInfo, "name", param.moduleName);
        ASSERT(status == ANI_OK, "get currentHapModuleInfo.name failed.", ANI_INVALID_ARGS);
    }

    ani_object appInfo = nullptr;
    ani_utils::AniGetProperty(env, jsValue, "applicationInfo", appInfo);
    if (appInfo != nullptr) {
        status = ani_utils::AniGetProperty(env, appInfo, "name", param.bundleName);
        ASSERT(status == ANI_OK, "get applicationInfo.name failed.", ANI_INVALID_ARGS);
        status = ani_utils::AniGetProperty(env, appInfo, "systemApp", param.isSystemApp, true);
        ASSERT(status == ANI_OK, "get applicationInfo.systemApp failed.", ANI_INVALID_ARGS);
        int32_t hapVersion = GetHapVersion(env, jsValue);
        OHOS::AppDataMgrJsKit::JSUtils::SetHapVersion(hapVersion);
    }
    return ANI_OK;
}

} //namespace ani_abilityutils
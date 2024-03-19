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
#define LOG_TAG "JsConstProperties"
#include "js_const_properties.h"

#include "cloud_service.h"
#include "cloud_types.h"
#include "napi_queue.h"
#include "js_utils.h"

using namespace OHOS::Rdb;
using Action = OHOS::CloudData::CloudService::Action;

namespace OHOS::CloudData {
static napi_status SetNamedProperty(napi_env env, napi_value &obj, const std::string &name, int32_t value)
{
    napi_value property = nullptr;
    napi_status status = napi_create_int32(env, value, &property);
    ASSERT(status == napi_ok, "int32_t to napi_value failed!", status);
    status = napi_set_named_property(env, obj, name.c_str(), property);
    ASSERT(status == napi_ok, "napi_set_named_property failed!", status);
    return status;
}

static napi_value ExportAction(napi_env env)
{
    napi_value action = nullptr;
    napi_create_object(env, &action);
    SetNamedProperty(env, action, "CLEAR_CLOUD_INFO", (int32_t)Action::CLEAR_CLOUD_INFO);
    SetNamedProperty(env, action, "CLEAR_CLOUD_DATA_AND_INFO", (int32_t)Action::CLEAR_CLOUD_DATA_AND_INFO);
    napi_object_freeze(env, action);
    return action;
}

static napi_value ExportRole(napi_env env)
{
    napi_value role = nullptr;
    napi_create_object(env, &role);
    SetNamedProperty(env, role, "ROLE_INVITER", Role::ROLE_INVITER);
    SetNamedProperty(env, role, "ROLE_INVITEE", Role::ROLE_INVITEE);
    napi_object_freeze(env, role);
    return role;
}

static napi_value ExportShareState(napi_env env)
{
    napi_value state = nullptr;
    napi_create_object(env, &state);
    SetNamedProperty(env, state, "STATE_UNKNOWN", Confirmation::CFM_UNKNOWN);
    SetNamedProperty(env, state, "STATE_ACCEPTED", Confirmation::CFM_ACCEPTED);
    SetNamedProperty(env, state, "STATE_REJECTED", Confirmation::CFM_REJECTED);
    SetNamedProperty(env, state, "STATE_SUSPENDED", Confirmation::CFM_SUSPENDED);
    SetNamedProperty(env, state, "STATE_UNAVAILABLE", Confirmation::CFM_UNAVAILABLE);
    napi_object_freeze(env, state);
    return state;
}

static napi_value ExportShareCode(napi_env env)
{
    napi_value code = nullptr;
    napi_create_object(env, &code);
    SetNamedProperty(env, code, "SUCCESS", SharingCode::SUCCESS);
    SetNamedProperty(env, code, "REPEATED_REQUEST", SharingCode::REPEATED_REQUEST);
    SetNamedProperty(env, code, "NOT_INVITER", SharingCode::NOT_INVITER);
    SetNamedProperty(env, code, "NOT_INVITER_OR_INVITEE", SharingCode::NOT_INVITER_OR_INVITEE);
    SetNamedProperty(env, code, "OVER_QUOTA", SharingCode::OVER_QUOTA);
    SetNamedProperty(env, code, "TOO_MANY_PARTICIPANTS", SharingCode::TOO_MANY_PARTICIPANTS);
    SetNamedProperty(env, code, "INVALID_ARGS", SharingCode::INVALID_ARGS);
    SetNamedProperty(env, code, "NETWORK_ERROR", SharingCode::NETWORK_ERROR);
    SetNamedProperty(env, code, "CLOUD_DISABLED", SharingCode::CLOUD_DISABLED);
    SetNamedProperty(env, code, "SERVER_ERROR", SharingCode::SERVER_ERROR);
    SetNamedProperty(env, code, "INNER_ERROR", SharingCode::INNER_ERROR);
    SetNamedProperty(env, code, "INVALID_INVITATION", SharingCode::INVALID_INVITATION);
    SetNamedProperty(env, code, "RATE_LIMIT", SharingCode::RATE_LIMIT);
    SetNamedProperty(env, code, "CUSTOM_ERROR", SharingCode::CUSTOM_ERROR);
    napi_object_freeze(env, code);
    return code;
}

static napi_value ExportStrategy(napi_env env)
{
    napi_value strategy = nullptr;
    napi_create_object(env, &strategy);
    SetNamedProperty(env, strategy, "NETWORK", Strategy::STRATEGY_NETWORK);
    napi_object_freeze(env, strategy);
    return strategy;
}

static napi_value ExportNetWorkStrategy(napi_env env)
{
    napi_value netStrategy = nullptr;
    napi_create_object(env, &netStrategy);
    SetNamedProperty(env, netStrategy, "WIFI", NetWorkStrategy::WIFI);
    SetNamedProperty(env, netStrategy, "CELLULAR", NetWorkStrategy::CELLULAR);
    napi_object_freeze(env, netStrategy);
    return netStrategy;
}

napi_status InitConstProperties(napi_env env, napi_value exports)
{
    const napi_property_descriptor properties[] = {
        DECLARE_NAPI_PROPERTY("Action", ExportAction(env)),
        DECLARE_NAPI_PROPERTY("ClearAction", ExportAction(env)),
        DECLARE_NAPI_PROPERTY("DATA_CHANGE_EVENT_ID", AppDataMgrJsKit::JSUtils::Convert2JSValue(env,
            std::string(CloudData::DATA_CHANGE_EVENT_ID))),
    };
    size_t count = sizeof(properties) / sizeof(properties[0]);

    return napi_define_properties(env, exports, count, properties);
}

napi_status InitSharingConstProperties(napi_env env, napi_value exports)
{
    if (exports == nullptr) {
        return napi_generic_failure;
    }
    const napi_property_descriptor properties[] = {
        DECLARE_NAPI_PROPERTY("Role", ExportRole(env)),
        DECLARE_NAPI_PROPERTY("State", ExportShareState(env)),
        DECLARE_NAPI_PROPERTY("SharingCode", ExportShareCode(env)),
    };
    size_t count = sizeof(properties) / sizeof(properties[0]);

    return napi_define_properties(env, exports, count, properties);
}

napi_status InitClientProperties(napi_env env, napi_value exports)
{
    if (exports == nullptr) {
        return napi_generic_failure;
    }
    const napi_property_descriptor properties[] = {
        DECLARE_NAPI_PROPERTY("StrategyType", ExportStrategy(env)),
        DECLARE_NAPI_PROPERTY("NetWorkStrategy", ExportNetWorkStrategy(env)),
    };
    size_t count = sizeof(properties) / sizeof(properties[0]);

    return napi_define_properties(env, exports, count, properties);
}
} // namespace OHOS::CloudData

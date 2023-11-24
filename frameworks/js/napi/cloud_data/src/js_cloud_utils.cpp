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

#include "js_cloud_utils.h"
#include "logger.h"

#define NAPI_CALL_RETURN_ERR(call, ret)    \
    do {                                   \
        if ((call) != napi_ok) {           \
            return ret;                    \
        }                                  \
    } while (0)

namespace OHOS::AppDataMgrJsKit {
namespace JSUtils {
using namespace OHOS::Rdb;
template<>
int32_t Convert2Value(napi_env env, napi_value input, Participant &output)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, input, &type);
    if (status != napi_ok || type != napi_object) {
        LOG_DEBUG("napi_typeof failed status = %{public}d type = %{public}d", status, type);
        return napi_invalid_arg;
    }
    NAPI_CALL_RETURN_ERR(GET_PROPERTY(env, input, output, identity), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GetOptionalValue(env, input, "role", output.role), napi_invalid_arg);
    if (output.role < CloudData::Role::ROLE_INVITER || output.role > CloudData::Role::ROLE_INVITEE) {
        return napi_invalid_arg;
    }
    NAPI_CALL_RETURN_ERR(GetOptionalValue(env, input, "status", output.status), napi_invalid_arg);
    if (output.status < CloudData::Confirmation::CFM_UNKNOWN ||
        output.status > CloudData::Confirmation::CFM_SUSPENDED) {
        return napi_invalid_arg;
    }
    NAPI_CALL_RETURN_ERR(GetOptionalValue(env, input, "privilege", output.privilege), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GetOptionalValue(env, input, "attachInfo", output.attachInfo), napi_invalid_arg);
    return napi_ok;
}

template<>
int32_t Convert2Value(napi_env env, napi_value input, Privilege &output)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, input, &type);
    if (status != napi_ok || type != napi_object) {
        LOG_DEBUG("napi_typeof failed status = %{public}d type = %{public}d", status, type);
        return napi_invalid_arg;
    }
    NAPI_CALL_RETURN_ERR(GetOptionalValue(env, input, "writeable", output.writeable), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GetOptionalValue(env, input, "readable", output.readable), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GetOptionalValue(env, input, "creatable", output.creatable), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GetOptionalValue(env, input, "deletable", output.deletable), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GetOptionalValue(env, input, "shareable", output.shareable), napi_invalid_arg);
    return napi_ok;
}

template<>
int32_t Convert2Value(napi_env env, napi_value input, std::shared_ptr<RdbPredicates> &output)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, input, &type);
    if (status != napi_ok || type != napi_object) {
        LOG_DEBUG("napi_typeof failed status = %{public}d type = %{public}d", status, type);
        return napi_invalid_arg;
    }
    NativeRdb::RdbPredicates::JsProxy *jsProxy = nullptr;
    status = napi_unwrap(env, input, reinterpret_cast<void **>(&jsProxy));
    NAPI_CALL_RETURN_ERR(status==napi_ok && jsProxy != nullptr && jsProxy->predicates_ != nullptr, napi_invalid_arg);
    output = jsProxy->predicates_;
    return napi_ok;
}

template<>
napi_value Convert2JSValue(napi_env env, const Participant &value)
{
    napi_value jsValue = nullptr;
    napi_status status = napi_create_object(env, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }
    napi_value identity = Convert2JSValue(env, value.identity);
    napi_value role = Convert2JSValue(env, value.role);
    napi_value sharingStatus = Convert2JSValue(env, value.status);
    napi_value privilege = Convert2JSValue(env, value.privilege);
    if (privilege == nullptr) {
        return nullptr;
    }
    napi_value attachInfo = Convert2JSValue(env, value.attachInfo);
    napi_set_named_property(env, jsValue, "identity", identity);
    napi_set_named_property(env, jsValue, "role", role);
    napi_set_named_property(env, jsValue, "status", sharingStatus);
    napi_set_named_property(env, jsValue, "privilege", privilege);
    napi_set_named_property(env, jsValue, "attachInfo", attachInfo);
    return jsValue;
}

template<>
napi_value Convert2JSValue(napi_env env, const Privilege &value)
{
    napi_value jsValue = nullptr;
    napi_status status = napi_create_object(env, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }

    napi_set_named_property(env, jsValue, "writeable", Convert2JSValue(env, value.writeable));
    napi_set_named_property(env, jsValue, "readable", Convert2JSValue(env, value.readable));
    napi_set_named_property(env, jsValue, "creatable", Convert2JSValue(env, value.creatable));
    napi_set_named_property(env, jsValue, "deletable", Convert2JSValue(env, value.deletable));
    napi_set_named_property(env, jsValue, "shareable", Convert2JSValue(env, value.shareable));
    return jsValue;
}

template<>
napi_value Convert2JSValue(napi_env env, const std::shared_ptr<ResultSet> &value)
{
    auto constructor = JSUtils::GetClass(env, "ohos.data.relationalStore", "ResultSet");
    if (constructor == nullptr) {
        LOG_ERROR("Constructor of ResultSet is nullptr!");
        return nullptr;
    }
    napi_value instance = nullptr;
    napi_status status = napi_new_instance(env, constructor, 0, nullptr, &instance);
    if (status != napi_ok) {
        LOG_ERROR("NewInstance ResultSet failed! code:%{public}d!", status);
        return nullptr;
    }
    NativeRdb::ResultSet::JsProxy *proxy = nullptr;
    status = napi_unwrap(env, instance, reinterpret_cast<void **>(&proxy));
    if (proxy == nullptr) {
        LOG_ERROR("napi_unwrap failed! code:%{public}d!", status);
    }
    proxy->resultSet_ = value;
    return instance;
}
}; // namespace JSUtils
} // namespace OHOS::AppDataMgrJsKit
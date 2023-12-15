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
#include "js_proxy.h"
#include "result_set.h"
#include "result_set_bridge.h"
#include "logger.h"

#define NAPI_CALL_RETURN_ERR(call, ret)  \
    ASSERT_RETURN((call) == napi_ok, ret)

#define ASSERT_RETURN(call, ret) \
    do {                         \
        if (!(call)) {           \
            return ret;          \
        }                        \
    } while (0)

namespace OHOS::AppDataMgrJsKit {
namespace JSUtils {
using namespace OHOS::Rdb;

template<>
int32_t Convert2Value(napi_env env, napi_value input, ExtraData &output)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, input, &type);
    if (status != napi_ok || type != napi_object) {
        return napi_invalid_arg;
    }
    int32_t result = GET_PROPERTY(env, input, output, eventId);
    if (result != napi_ok) {
        return napi_invalid_arg;
    }
    return GET_PROPERTY(env, input, output, extraData);
}

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
    if (output.role < CloudData::Role::ROLE_NIL || output.role >= CloudData::Role::ROLE_BUTT) {
        return napi_invalid_arg;
    }
    NAPI_CALL_RETURN_ERR(GetOptionalValue(env, input, "state", output.state), napi_invalid_arg);
    if (output.state < CloudData::Confirmation::CFM_NIL ||
        output.state >= CloudData::Confirmation::CFM_BUTT) {
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
    NAPI_CALL_RETURN_ERR(GetOptionalValue(env, input, "writable", output.writable), napi_invalid_arg);
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
    JSProxy::JSProxy<NativeRdb::RdbPredicates> *jsProxy = nullptr;
    status = napi_unwrap(env, input, reinterpret_cast<void **>(&jsProxy));
    ASSERT_RETURN(status == napi_ok && jsProxy != nullptr && jsProxy->GetInstance() != nullptr, napi_invalid_arg);
    output = jsProxy->GetInstance();
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
    napi_value role = nullptr;
    if (value.role == CloudData::Role::ROLE_NIL) {
        napi_get_undefined(env, &role);
    } else {
        role = Convert2JSValue(env, value.role);
    }
    napi_value state = nullptr;
    if (value.state == CloudData::Confirmation::CFM_NIL) {
        napi_get_undefined(env, &state);
    } else {
        state = Convert2JSValue(env, value.state);
    }
    napi_value privilege = Convert2JSValue(env, value.privilege);
    if (privilege == nullptr) {
        return nullptr;
    }
    napi_value attachInfo = Convert2JSValue(env, value.attachInfo);
    napi_set_named_property(env, jsValue, "identity", identity);
    napi_set_named_property(env, jsValue, "role", role);
    napi_set_named_property(env, jsValue, "state", state);
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

    napi_set_named_property(env, jsValue, "writable", Convert2JSValue(env, value.writable));
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
        LOG_ERROR("NewInstance ResultSet failed! status:%{public}d!", status);
        return nullptr;
    }
    JSProxy::JSEntity<NativeRdb::ResultSet, DataShare::ResultSetBridge> *proxy = nullptr;
    status = napi_unwrap(env, instance, reinterpret_cast<void **>(&proxy));
    if (status != napi_ok || proxy == nullptr) {
        LOG_ERROR("napi_unwrap failed! status:%{public}d!", status);
        return nullptr;
    }
    proxy->SetInstance(value);
    return instance;
}

template<>
napi_value Convert2JSValue(napi_env env, const std::pair<int32_t, std::string> &value)
{
    napi_value jsValue;
    napi_status status = napi_create_object(env, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }
    napi_value code = Convert2JSValue(env, value.first);
    napi_value description = Convert2JSValue(env, value.second);
    napi_value val;
    napi_get_undefined(env, &val);
    napi_set_named_property(env, jsValue, "code", code);
    napi_set_named_property(env, jsValue, "description", description);
    napi_set_named_property(env, jsValue, "value", val);
    return jsValue;
}
}; // namespace JSUtils
} // namespace OHOS::AppDataMgrJsKit
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

#include "napi_datashare_abstract_result_set.h"
#include <functional>
#include "datashare_js_utils.h"
#include "napi_datashare_async_proxy.h"
#include "string_ex.h"
#include "datashare_log.h"

namespace OHOS {
namespace DataShare {
static napi_ref __thread ctorRef_ = nullptr;
napi_value NapiDataShareAbstractResultSet::NewInstance(napi_env env,
    std::shared_ptr<ResultSetBridge> resultSet)
{
    napi_value cons = GetConstructor(env);
    if (cons == nullptr) {
        LOG_ERROR("NewInstance GetConstructor is nullptr!");
        return nullptr;
    }
    napi_value instance;
    napi_status status = napi_new_instance(env, cons, 0, nullptr, &instance);
    if (status != napi_ok) {
        LOG_ERROR("NewInstance napi_new_instance failed! code:%{public}d!", status);
        return nullptr;
    }

    NapiDataShareAbstractResultSet *proxy = nullptr;
    status = napi_unwrap(env, instance, reinterpret_cast<void **>(&proxy));
    if (proxy == nullptr) {
        LOG_ERROR("NewInstance native instance is nullptr! code:%{public}d!", status);
        return instance;
    }

    *proxy = std::move(resultSet);
    return instance;
}

std::shared_ptr<ResultSetBridge> NapiDataShareAbstractResultSet::GetNativeObject(
    napi_env const &env, napi_value const &arg)
{
    if (arg == nullptr) {
        LOG_ERROR("NapiDataShareAbstractResultSet GetNativeObject arg is null.");
        return nullptr;
    }
    NapiDataShareAbstractResultSet *proxy = nullptr;
    napi_unwrap(env, arg, reinterpret_cast<void **>(&proxy));
    if (proxy == nullptr) {
        LOG_ERROR("NapiDataShareAbstractResultSet GetNativeObject proxy is null.");
        return nullptr;
    }
    return proxy->resultSet_;
}

napi_value NapiDataShareAbstractResultSet::GetConstructor(napi_env env)
{
    napi_value cons;
    if (ctorRef_ != nullptr) {
        NAPI_CALL(env, napi_get_reference_value(env, ctorRef_, &cons));
        return cons;
    }
    LOG_INFO("GetConstructor ResultSetBridge constructor");
    napi_property_descriptor clzDes[] = {};
    NAPI_CALL(env, napi_define_class(env, "ResultSetBridge", NAPI_AUTO_LENGTH, Initialize, nullptr,
        sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
    NAPI_CALL(env, napi_create_reference(env, cons, 1, &ctorRef_));
    return cons;
}

napi_value NapiDataShareAbstractResultSet::Initialize(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &self, nullptr));
    auto *proxy = new NapiDataShareAbstractResultSet();
    auto finalize = [](napi_env env, void *data, void *hint) {
        NapiDataShareAbstractResultSet *proxy = reinterpret_cast<NapiDataShareAbstractResultSet *>(data);
        delete proxy;
    };
    napi_status status = napi_wrap(env, self, proxy, finalize, nullptr, nullptr);
    if (status != napi_ok) {
        LOG_ERROR("NapiDataShareAbstractResultSet napi_wrap failed! code:%{public}d!", status);
        finalize(env, proxy, nullptr);
        return nullptr;
    }
    return self;
}

NapiDataShareAbstractResultSet::~NapiDataShareAbstractResultSet()
{
    LOG_INFO("NapiDataShareAbstractResultSet destructor!");
}

NapiDataShareAbstractResultSet::NapiDataShareAbstractResultSet(std::shared_ptr<ResultSetBridge> resultSet)
{
    if (resultSet_ == resultSet) {
        return;
    }
    resultSet_ = std::move(resultSet);
}

NapiDataShareAbstractResultSet &NapiDataShareAbstractResultSet::operator=(
    std::shared_ptr<ResultSetBridge> resultSet)
{
    if (resultSet_ == resultSet) {
        return *this;
    }
    resultSet_ = std::move(resultSet);
    return *this;
}

std::shared_ptr<ResultSetBridge> &NapiDataShareAbstractResultSet::GetInnerAbstractResultSet(napi_env env,
    napi_callback_info info)
{
    NapiDataShareAbstractResultSet *resultSet = nullptr;
    napi_value self = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &self, nullptr);
    napi_unwrap(env, self, reinterpret_cast<void **>(&resultSet));
    return resultSet->resultSet_;
}

napi_value GetNapiAbstractResultSetObject(napi_env env, ResultSetBridge *resultSet)
{
    return NapiDataShareAbstractResultSet::NewInstance(env, std::shared_ptr<ResultSetBridge>(resultSet));
}

ResultSetBridge *GetNativeAbstractResultSetObject(const napi_env &env, const napi_value &arg)
{
    auto resultSet = NapiDataShareAbstractResultSet::GetNativeObject(env, arg);
    return resultSet.get();
}
} // namespace DataShare
} // namespace OHOS

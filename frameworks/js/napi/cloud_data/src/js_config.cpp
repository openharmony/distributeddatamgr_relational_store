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
#define LOG_TAG "JsConfig"
#include "js_config.h"

#include <cstddef.h>

#include <memory>

#include "cloud_manager.h"
#include "cloud_service.h"
#include "js_error_utils.h"
#include "js_utils.h"
#include "log_print.h"
#include "napi_queue.h"

using namespace OHOS::CloudData;
using namespace OHOS::AppDataMgrJsKit;
JsConfig::JsConfig()
{
}

JsConfig::~JsConfig()
{
}

/*
 * [JS API Prototype]
 * [AsyncCallback]
 *      enableCloud(accountId: string, switches: {[bundleName: string]: boolean}, callback: AsyncCallback<void>): void;
 * [Promise]
 *      enableCloud(accountId: string, switches: {[bundleName: string]: boolean}): Promise<void>;
 */
napi_value JsConfig::EnableCloud(napi_env env, napi_callback_info info)
{
    struct EnableCloudContext : public ContextBase {
        std::string accountId;
        std::map<std::string, bool> tempSwitches;
        std::map<std::string, int32_t> switches;
    };
    auto ctxt = std::make_shared<EnableCloudContext>();
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        // required 2 arguments :: <accountId> <switches>
        ASSERT_BUSINESS_ERR(ctxt, argc >= 2, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        // 0 is the index of argument accountId, 1 is the index of argument switches
        int status = JSUtils::Convert2Value(env, argv[0], ctxt->accountId);
        ASSERT_BUSINESS_ERR(
            ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT, "The type of accountId must be string.");
        status = JSUtils::Convert2Value(env, argv[1], ctxt->tempSwitches);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT,
            "The type of switches must be {[bundleName: string]: boolean}.");
        for (auto item : ctxt->tempSwitches) {
            ctxt->switches.insert(std::pair<std::string, int32_t>(item.first, static_cast<int32_t>(item.second)));
        }
    });

    ASSERT_NULL(!ctxt->isThrowError, "EnableCloud exit");

    auto execute = [ctxt]() {
        auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
        if (proxy == nullptr) {
            if (state != CloudService::SERVER_UNAVAILABLE) {
                state = CloudService::NOT_SUPPORT;
            }
            ctxt->status = (GenerateNapiError(state, ctxt->jsCode, ctxt->error) == Status::SUCCESS)
                               ? napi_ok
                               : napi_generic_failure;
            return;
        }
        int32_t cStatus = proxy->EnableCloud(ctxt->accountId, ctxt->switches);
        ZLOGD("EnableCloud return %{public}d", cStatus);
        ctxt->status = (GenerateNapiError(cStatus, ctxt->jsCode, ctxt->error) == Status::SUCCESS)
                           ? napi_ok
                           : napi_generic_failure;
    };
    return NapiQueue::AsyncWork(env, ctxt, std::string(__FUNCTION__), execute);
}

/*
 * [JS API Prototype]
 * [AsyncCallback]
 *      disableCloud(accountId: string, callback: AsyncCallback<void>): void;
 * [Promise]
 *      disableCloud(accountId: string): Promise<void>;
 */
napi_value JsConfig::DisableCloud(napi_env env, napi_callback_info info)
{
    struct DisableCloudContext : public ContextBase {
        std::string accountId;
    };
    auto ctxt = std::make_shared<DisableCloudContext>();
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        // required 1 arguments :: <accountId>
        ASSERT_BUSINESS_ERR(ctxt, argc >= 1, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        // 0 is the index of argument accountId
        int status = JSUtils::Convert2Value(env, argv[0], ctxt->accountId);
        ASSERT_BUSINESS_ERR(
            ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT, "The type of accountId must be string.");
    });

    ASSERT_NULL(!ctxt->isThrowError, "DisableCloud exit");

    auto execute = [ctxt]() {
        auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
        if (proxy == nullptr) {
            if (state != CloudService::SERVER_UNAVAILABLE) {
                state = CloudService::NOT_SUPPORT;
            }
            ctxt->status = (GenerateNapiError(state, ctxt->jsCode, ctxt->error) == Status::SUCCESS)
                               ? napi_ok
                               : napi_generic_failure;
            return;
        }
        int32_t cStatus = proxy->DisableCloud(ctxt->accountId);
        ZLOGD("DisableCloud return %{public}d", cStatus);
        ctxt->status = (GenerateNapiError(cStatus, ctxt->jsCode, ctxt->error) == Status::SUCCESS)
                           ? napi_ok
                           : napi_generic_failure;
    };
    return NapiQueue::AsyncWork(env, ctxt, std::string(__FUNCTION__), execute);
}

/*
 * [JS API Prototype]
 * [AsyncCallback]
 *      changeAppCloudSwitch(accountId: string, bundleName: string, status :boolean,
 *      callback: AsyncCallback<void>): void;
 * [Promise]
 *      changeAppCloudSwitch(accountId: string, bundleName: string, status :boolean): Promise<void>;
 */

napi_value JsConfig::ChangeAppCloudSwitch(napi_env env, napi_callback_info info)
{
    struct ChangeAppSwitchContext : public ContextBase {
        std::string accountId;
        std::string bundleName;
        bool state;
    };
    auto ctxt = std::make_shared<ChangeAppSwitchContext>();
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        // required 3 arguments :: <accountId> <bundleName> <state>
        ASSERT_BUSINESS_ERR(ctxt, argc >= 3, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        // 0 is the index of argument accountId, 1 is the index of argument bundleName, 2 is the index of argument state
        int status = JSUtils::Convert2Value(env, argv[0], ctxt->accountId);
        ASSERT_BUSINESS_ERR(
            ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT, "The type of accountId must be string.");
        status = JSUtils::Convert2Value(env, argv[1], ctxt->bundleName);
        ASSERT_BUSINESS_ERR(
            ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT, "The type of bundleName must be string.");
        status = JSUtils::Convert2Value(env, argv[2], ctxt->state);
        ASSERT_BUSINESS_ERR(
            ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT, "The type of status must be boolean.");
    });

    ASSERT_NULL(!ctxt->isThrowError, "ChangeAppCloudSwitch exit");

    auto execute = [ctxt]() {
        auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
        if (proxy == nullptr) {
            if (state != CloudService::SERVER_UNAVAILABLE) {
                state = CloudService::NOT_SUPPORT;
            }
            ctxt->status = (GenerateNapiError(state, ctxt->jsCode, ctxt->error) == Status::SUCCESS)
                               ? napi_ok
                               : napi_generic_failure;
            return;
        }
        int32_t cStatus = proxy->ChangeAppSwitch(ctxt->accountId, ctxt->bundleName, ctxt->state);
        ZLOGD("ChangeAppCloudSwitch return %{public}d", cStatus);
        ctxt->status = (GenerateNapiError(cStatus, ctxt->jsCode, ctxt->error) == Status::SUCCESS)
                           ? napi_ok
                           : napi_generic_failure;
    };
    return NapiQueue::AsyncWork(env, ctxt, std::string(__FUNCTION__), execute);
}

/*
 * [JS API Prototype]
 * [AsyncCallback]
 *      clean(accountId: string, appActions: {[bundleName: string]: Action}, callback: AsyncCallback<void>): void;
 * [Promise]
 *      clean(accountId: string, appActions: {[bundleName: string]: Action}): Promise<void>;
 */
napi_value JsConfig::Clean(napi_env env, napi_callback_info info)
{
    struct CleanContext : public ContextBase {
        std::string accountId;
        std::map<std::string, int32_t> appActions;
    };
    auto ctxt = std::make_shared<CleanContext>();
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        // required 2 arguments :: <accountId> <appActions>
        ASSERT_BUSINESS_ERR(ctxt, argc >= 2, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        // 0 is the index of argument accountId, 1 is the index of argument
        int status = JSUtils::Convert2Value(env, argv[0], ctxt->accountId);
        ASSERT_BUSINESS_ERR(
            ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT, "The type of accountId must be string.");
        status = JSUtils::Convert2Value(env, argv[1], ctxt->appActions);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT,
            "The type of actions must be {[bundleName: string]: int32_t}.");
        for (auto item : ctxt->appActions) {
            ASSERT_BUSINESS_ERR(ctxt, ValidSubscribeType(item.second), Status::INVALID_ARGUMENT,
                "Action in map appActions is incorrect.");
        }
    });

    ASSERT_NULL(!ctxt->isThrowError, "Clean exit");

    auto execute = [ctxt]() {
        auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
        if (proxy == nullptr) {
            if (state != CloudService::SERVER_UNAVAILABLE) {
                state = CloudService::NOT_SUPPORT;
            }
            ctxt->status = (GenerateNapiError(state, ctxt->jsCode, ctxt->error) == Status::SUCCESS)
                               ? napi_ok
                               : napi_generic_failure;
            return;
        }
        int32_t cStatus = proxy->Clean(ctxt->accountId, ctxt->appActions);
        ZLOGD("Clean return %{public}d", cStatus);
        ctxt->status = (GenerateNapiError(cStatus, ctxt->jsCode, ctxt->error) == Status::SUCCESS)
                           ? napi_ok
                           : napi_generic_failure;
    };
    return NapiQueue::AsyncWork(env, ctxt, std::string(__FUNCTION__), execute);
}

/*
 * [JS API Prototype]
 * [AsyncCallback]
 *      notifyDataChange(accountId: string, bundleName: string, callback: AsyncCallback<void>): void;
 * [Promise]
 *      notifyDataChange(accountId: string, bundleName: string): Promise<void>;
 */
napi_value JsConfig::NotifyDataChange(napi_env env, napi_callback_info info)
{
    struct ChangeAppSwitchContext : public ContextBase {
        std::string accountId;
        std::string bundleName;
    };
    auto ctxt = std::make_shared<ChangeAppSwitchContext>();
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        // required 2 arguments :: <accountId> <bundleName>
        ASSERT_BUSINESS_ERR(ctxt, argc >= 2, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        // 0 is the index of argument accountId, 1 is the index of argument bundleName
        int status = JSUtils::Convert2Value(env, argv[0], ctxt->accountId);
        ASSERT_BUSINESS_ERR(
            ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT, "The type of accountId must be string.");
        status = JSUtils::Convert2Value(env, argv[1], ctxt->bundleName);
        ASSERT_BUSINESS_ERR(
            ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT, "The type of bundleName must be string.");
    });

    ASSERT_NULL(!ctxt->isThrowError, "NotifyDataChange exit");

    auto execute = [ctxt]() {
        auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
        if (proxy == nullptr) {
            if (state != CloudService::SERVER_UNAVAILABLE) {
                state = CloudService::NOT_SUPPORT;
            }
            ctxt->status = (GenerateNapiError(state, ctxt->jsCode, ctxt->error) == Status::SUCCESS)
                               ? napi_ok
                               : napi_generic_failure;
            return;
        }
        int32_t cStatus = proxy->NotifyDataChange(ctxt->accountId, ctxt->bundleName);
        ZLOGD("NotifyDataChange return %{public}d", cStatus);
        ctxt->status = (GenerateNapiError(cStatus, ctxt->jsCode, ctxt->error) == Status::SUCCESS)
                           ? napi_ok
                           : napi_generic_failure;
    };
    return NapiQueue::AsyncWork(env, ctxt, std::string(__FUNCTION__), execute);
}

napi_value JsConfig::New(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    size_t argc = ARGC_MAX;
    napi_value argv[ARGC_MAX] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &self, nullptr));
    if (self == nullptr) {
        napi_new_instance(env, JSUtils::GetClass(env, "ohos.cloudData", "Config"), argc, argv, &self);
        return self;
    }

    auto finalize = [](napi_env env, void *data, void *hint) {
        ZLOGD("cloudConfig finalize.");
        auto *config = reinterpret_cast<JsConfig *>(data);
        ASSERT_VOID(config != nullptr, "finalize null!");
        delete config;
    };
    JsConfig *cloudConfig = new (std::nothrow) JsConfig();
    ASSERT_ERR(env, cloudConfig != nullptr, Status::INVALID_ARGUMENT, "no memory for cloudConfig.");
    napi_status status = napi_wrap(env, self, cloudConfig, finalize, nullptr, nullptr);
    if (status != napi_ok) {
        ZLOGE("JsConfig::Initialize napi_wrap failed! code:%{public}d!", status);
        finalize(env, cloudConfig, nullptr);
        return nullptr;
    }
    return self;
}

napi_value JsConfig::InitConfig(napi_env env, napi_value exports)
{
    auto lambda = []() -> std::vector<napi_property_descriptor> {
        std::vector<napi_property_descriptor> properties = {
            DECLARE_NAPI_STATIC_FUNCTION("enableCloud", JsConfig::EnableCloud),
            DECLARE_NAPI_STATIC_FUNCTION("disableCloud", JsConfig::DisableCloud),
            DECLARE_NAPI_STATIC_FUNCTION("changeAppCloudSwitch", JsConfig::ChangeAppCloudSwitch),
            DECLARE_NAPI_STATIC_FUNCTION("clean", JsConfig::Clean),
            DECLARE_NAPI_STATIC_FUNCTION("notifyDataChange", JsConfig::NotifyDataChange),
        };
        return properties;
    };
    auto jsCtor = JSUtils::DefineClass(env, "Config", lambda, JsConfig::New);
    NAPI_CALL(env, napi_set_named_property(env, exports, "Config", jsCtor));
    return exports;
}
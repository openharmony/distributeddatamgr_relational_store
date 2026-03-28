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
#define LOG_TAG "JSConfig"
#include "js_config.h"

#include <cstddef>
#include <memory>
#include <vector>

#include "cloud_manager.h"
#include "cloud_service.h"
#include "js_cloud_utils.h"
#include "js_df_manager.h"
#include "js_error_utils.h"
#include "js_strategy_context.h"
#include "js_utils.h"
#include "logger.h"

using namespace OHOS::Rdb;
using namespace OHOS::CloudData;
std::atomic<uint32_t> JsConfig::seqNum_{};
std::mutex JsConfig::syncInfoObserversMutex_;
std::list<JsConfig::SyncInfoObserverRecord> JsConfig::syncInfoObservers_;
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
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->accountId.empty(), Status::INVALID_ARGUMENT,
            "The type of accountId must be string and not empty.");
        status = JSUtils::Convert2Value(env, argv[1], ctxt->tempSwitches);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT,
            "The type of switches must be {[bundleName: string]: boolean}.");
        for (const auto &item : ctxt->tempSwitches) {
            ctxt->switches[item.first] = item.second ? CloudService::Switch::SWITCH_ON
                                                     : CloudService::Switch::SWITCH_OFF;
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
        LOG_DEBUG("EnableCloud return %{public}d", cStatus);
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
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->accountId.empty(), Status::INVALID_ARGUMENT,
            "The type of accountId must be string and not empty.");
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
        LOG_DEBUG("DisableCloud return %{public}d", cStatus);
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
 *      changeAppCloudSwitch(accountId: string, bundleName: string, status :boolean,
 *          config?: SwitchConfig): Promise<void>;
 */

napi_value JsConfig::ChangeAppCloudSwitch(napi_env env, napi_callback_info info)
{
    struct ChangeAppSwitchContext : public ContextBase {
        std::string accountId;
        std::string bundleName;
        CloudService::Switch state;
        CloudData::SwitchConfig config;
    };
    auto ctxt = std::make_shared<ChangeAppSwitchContext>();
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        // required 3 arguments :: <accountId> <bundleName> <state>
        ASSERT_BUSINESS_ERR(ctxt, argc >= 3, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        // 0 is the index of argument accountId
        int status = JSUtils::Convert2Value(env, argv[0], ctxt->accountId);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->accountId.empty(), Status::INVALID_ARGUMENT,
            "The type of accountId must be string and not empty.");
        // 1 is the index of argument bundleName
        status = JSUtils::Convert2Value(env, argv[1], ctxt->bundleName);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->bundleName.empty(), Status::INVALID_ARGUMENT,
            "The type of bundleName must be string and not empty.");
        bool state = false;
        // 2 is the index of argument state
        status = JSUtils::Convert2Value(env, argv[2], state);
        ASSERT_BUSINESS_ERR(
            ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT, "The type of status must be boolean.");
        ctxt->state = state ? CloudService::Switch::SWITCH_ON : CloudService::Switch::SWITCH_OFF;
        napi_valuetype type = napi_undefined;
        if (argc >= 4 && napi_typeof(env, argv[3], &type) == napi_ok && type != napi_function) {
            status = JSUtils::Convert2Value(env, argv[3], ctxt->config);
            ASSERT_BUSINESS_ERR(
                ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT, "The type of status must be SwitchConfig.");
        }
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
        int32_t cStatus = proxy->ChangeAppSwitch(ctxt->accountId, ctxt->bundleName, ctxt->state, ctxt->config);
        LOG_DEBUG("ChangeAppCloudSwitch return %{public}d", cStatus);
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
 *      clean(accountId: string, appActions: {[bundleName: string]: Action},
 *          config?: {[bundleName: string] : ClearConfig}): Promise<void>;
 */
napi_value JsConfig::Clean(napi_env env, napi_callback_info info)
{
    struct CleanContext : public ContextBase {
        std::string accountId;
        std::map<std::string, int32_t> appActions;
        std::map<std::string, CloudData::ClearConfig> configs;
    };
    auto ctxt = std::make_shared<CleanContext>();
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        // required 2 arguments :: <accountId> <appActions>
        ASSERT_BUSINESS_ERR(ctxt, argc >= 2, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        // 0 is the index of argument accountId, 1 is the index of argument
        int status = JSUtils::Convert2Value(env, argv[0], ctxt->accountId);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->accountId.empty(), Status::INVALID_ARGUMENT,
            "The type of accountId must be string and not empty.");
        status = JSUtils::Convert2Value(env, argv[1], ctxt->appActions);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT,
            "The type of actions must be {[bundleName: string]: int32_t}.");
        for (auto item : ctxt->appActions) {
            ASSERT_BUSINESS_ERR(ctxt, ValidSubscribeType(item.second), Status::INVALID_ARGUMENT,
                "Action in map appActions is incorrect.");
        }
        napi_valuetype type = napi_undefined;
        if (argc >= 3 && napi_typeof(env, argv[2], &type) == napi_ok && type != napi_function) {
            status = JSUtils::Convert2Value(env, argv[2], ctxt->configs);
            ASSERT_BUSINESS_ERR(
                ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT, "The type of config must be ClearConfig.");
            ASSERT_BUSINESS_ERR(ctxt, ValidClearConfig(ctxt->configs), Status::INVALID_ARGUMENT,
                "The type of config must be ClearConfig.");
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
        int32_t cStatus = proxy->Clean(ctxt->accountId, ctxt->appActions, ctxt->configs);
        LOG_DEBUG("Clean return %{public}d", cStatus);
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
 *      notifyDataChange(extInfo: ExtraData, callback: AsyncCallback<void>): void;
 *      notifyDataChange(extInfo: ExtraData, userId: number,callback: AsyncCallback<void>): void;
 * [Promise]
 *      notifyDataChange(accountId: string, bundleName: string): Promise<void>;
 *      notifyDataChange(extInfo: ExtraData, userId?: number): Promise<void>;
 */
struct ChangeAppSwitchContext : public ContextBase {
    std::string accountId;
    std::string bundleName;
    int32_t userId = CloudService::INVALID_USER_ID;
    bool notifyStatus = false;
    OHOS::CloudData::JsConfig::ExtraData extInfo;
};
napi_value JsConfig::NotifyDataChange(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<ChangeAppSwitchContext>();
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        // required 2 arguments :: <accountId> <bundleName>
        ASSERT_BUSINESS_ERR(ctxt, argc >= 1, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        napi_valuetype type = napi_undefined;
        if (argc > 1 && napi_typeof(env, argv[0], &type) == napi_ok && type != napi_object) {
            // 0 is the index of argument accountId, 1 is the index of argument bundleName
            int status = JSUtils::Convert2Value(env, argv[0], ctxt->accountId);
            ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->accountId.empty(), Status::INVALID_ARGUMENT,
                "The type of accountId must be string and not empty.");
            status = JSUtils::Convert2Value(env, argv[1], ctxt->bundleName);
            ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->bundleName.empty(), Status::INVALID_ARGUMENT,
                "The type of bundleName must be string and not empty.");
        } else {
            int status = JSUtils::Convert2Value(env, argv[0], ctxt->extInfo);
            ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && VerifyExtraData(ctxt->extInfo),
                Status::INVALID_ARGUMENT, "The type of extInfo must be Extradata and not empty.");
            if (argc > 1) {
                status = JSUtils::Convert2ValueExt(env, argv[1], ctxt->userId);
                ASSERT_BUSINESS_ERR(
                    ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT, "The type of user must be number.");
            }
            ctxt->notifyStatus = true;
        }
    });

    ASSERT_NULL(!ctxt->isThrowError, "NotifyDataChange exit");

    auto execute = [ctxt]() {
        auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
        if (proxy == nullptr) {
            if (state != CloudService::SERVER_UNAVAILABLE) {
                state = CloudService::NOT_SUPPORT;
            }
            ctxt->status = (GenerateNapiError(state, ctxt->jsCode, ctxt->error) == Status::SUCCESS)
                ? napi_ok : napi_generic_failure;
            return;
        }
        int32_t status;
        if (ctxt->notifyStatus == true) {
            status = proxy->NotifyDataChange(ctxt->extInfo.eventId, ctxt->extInfo.extraData, ctxt->userId);
        } else {
            status = proxy->NotifyDataChange(ctxt->accountId, ctxt->bundleName);
        }
        LOG_DEBUG("NotifyDataChange return %{public}d", status);
        ctxt->status =
            (GenerateNapiError(status, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ? napi_ok : napi_generic_failure;
        if (status == Status::INVALID_ARGUMENT) {
            ctxt->error += "The parameter required is a valid value.";
        }
    };
    return NapiQueue::AsyncWork(env, ctxt, std::string(__FUNCTION__), execute);
}

/*
 * [JS API Prototype]
 * [Promise]
 *      QueryStatistics(accountId: string, bundleName: string,
 *      storeId?: number): Promise<Record<string, Array<StatisticInfo>>>;
 */
napi_value JsConfig::QueryStatistics(napi_env env, napi_callback_info info)
{
    struct QueryStatisticsContext : public ContextBase {
        std::string accountId;
        std::string bundleName;
        std::string storeId = "";
        std::map<std::string, StatisticInfos> result;
    };
    auto ctxt = std::make_shared<QueryStatisticsContext>();
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        // required 2 arguments :: <accountId> <bundleName>
        ASSERT_BUSINESS_ERR(ctxt, argc >= 2, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        // 0 is the index of argument accountId
        int status = JSUtils::Convert2Value(env, argv[0], ctxt->accountId);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->accountId.empty(), Status::INVALID_ARGUMENT,
            "The type of accountId must be string and not empty.");
        // 1 is the index of argument bundleName
        status = JSUtils::Convert2Value(env, argv[1], ctxt->bundleName);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->bundleName.empty(), Status::INVALID_ARGUMENT,
            "The type of bundleName must be string and not empty.");
        // 2 is the index of argument storeId
        if (argc > 2 && !JSUtils::IsNull(ctxt->env, argv[2])) {
            // 2 is the index of argument storeId
            status = JSUtils::Convert2Value(env, argv[2], ctxt->storeId);
            ASSERT_BUSINESS_ERR(
                ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT, "The type of storeId must be string.");
        }
    });

    ASSERT_NULL(!ctxt->isThrowError, "QueryStatistics exit");

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
        auto [status, result] = proxy->QueryStatistics(ctxt->accountId, ctxt->bundleName, ctxt->storeId);
        ctxt->status =
            (GenerateNapiError(status, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ? napi_ok : napi_generic_failure;
        ctxt->result = std::move(result);
    };
    auto output = [env, ctxt](napi_value &result) {
        result = JSUtils::Convert2JSValue(env, ctxt->result);
        ASSERT_VALUE(ctxt, result != nullptr, napi_generic_failure, "output failed");
    };
    return NapiQueue::AsyncWork(env, ctxt, std::string(__FUNCTION__), execute, output);
}

napi_value JsConfig::SetGlobalCloudStrategy(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<CloudStrategyContext>();
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        // strategy 1 required parameter, param 1 Optional parameter
        ASSERT_BUSINESS_ERR(ctxt, argc >= 1, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        int32_t strategy = -1;
        int status = JSUtils::Convert2ValueExt(env, argv[0], strategy);
        ASSERT_BUSINESS_ERR(ctxt,
            status == JSUtils::OK && strategy >= 0 && strategy < static_cast<int32_t>(Strategy::STRATEGY_BUTT),
            Status::INVALID_ARGUMENT, "The type of strategy must be StrategyType.");
        ctxt->strategy = static_cast<Strategy>(strategy);
        // 'argv[1]' represents a vector<CommonType::Value> param or null
        if (argc == 1 || JSUtils::IsNull(env, argv[1])) {
            ctxt->SetDefault();
        } else {
            // 'argv[1]' represents a vector<CommonType::Value> param
            status = JSUtils::Convert2Value(env, argv[1], ctxt->param);
            ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT,
                "The type of param must be Array<commonType.ValueType>");
            auto res = ctxt->CheckParam();
            ASSERT_BUSINESS_ERR(ctxt, res.first == JSUtils::OK, Status::INVALID_ARGUMENT, res.second);
        }
    });
    ASSERT_NULL(!ctxt->isThrowError, "SetGlobalCloudStrategy exit");
    auto execute = [env, ctxt]() {
        auto [status, proxy] = CloudManager::GetInstance().GetCloudService();
        if (proxy == nullptr) {
            if (status != CloudService::SERVER_UNAVAILABLE) {
                status = CloudService::NOT_SUPPORT;
            }
            ctxt->status = (GenerateNapiError(status, ctxt->jsCode, ctxt->error) == Status::SUCCESS)
                               ? napi_ok: napi_generic_failure;
            return;
        }
        LOG_DEBUG("SetGlobalCloudStrategy execute.");

        auto res = proxy->SetGlobalCloudStrategy(ctxt->strategy, ctxt->param);
        ctxt->status =
            (GenerateNapiError(res, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ? napi_ok : napi_generic_failure;
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
        if (data == nullptr) {
            LOG_ERROR("data is nullptr.");
            return;
        }
        auto tid = JSDFManager::GetInstance().GetFreedTid(data);
        if (tid != 0) {
            LOG_ERROR("(T:%{public}d) freed! data:0x%016" PRIXPTR, tid, uintptr_t(data) & LOWER_24_BITS_MASK);
        }
        LOG_DEBUG("CloudConfig finalize.");
        auto *config = reinterpret_cast<JsConfig *>(data);
        ASSERT_VOID(config != nullptr, "finalize null!");
        delete config;
    };
    JsConfig *cloudConfig = new (std::nothrow) JsConfig();
    ASSERT_ERR(env, cloudConfig != nullptr, Status::INVALID_ARGUMENT, "no memory for cloudConfig.");
    napi_status status = napi_wrap(env, self, cloudConfig, finalize, nullptr, nullptr);
    if (status != napi_ok) {
        LOG_ERROR("JsConfig::Initialize napi_wrap failed! code:%{public}d!", status);
        finalize(env, cloudConfig, nullptr);
        return nullptr;
    }
    JSDFManager::GetInstance().AddNewInfo(cloudConfig);
    return self;
}

void JsConfig::ParseQueryParams(napi_env env, napi_callback_info info, std::shared_ptr<QueryLastSyncInfoContext> ctxt)
{
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        // 2 is The Number of parameters
        ASSERT_BUSINESS_ERR(ctxt, argc >= 2, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        napi_valuetype type = napi_undefined;
        napi_typeof(env, argv[1], &type);

        if (type == napi_string) {
            ctxt->isBatch = false;
            int status = JSUtils::Convert2Value(env, argv[0], ctxt->accountId);
            ASSERT_BUSINESS_ERR(
                ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT, "The type of accountId must be string.");
            status = JSUtils::Convert2Value(env, argv[1], ctxt->bundleName);
            ASSERT_BUSINESS_ERR(
                ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT, "The type of bundleName must be string.");
            if (argc > 2 && !JSUtils::IsNull(ctxt->env, argv[2])) { // 2 is The third parameter
                status = JSUtils::Convert2Value(env, argv[2], ctxt->storeId); // 2 is The third parameter
                ASSERT_BUSINESS_ERR(
                    ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT, "The type of storeId must be string.");
            }
        } else {
            ctxt->isBatch = true;
            int status = JSUtils::Convert2Value(env, argv[0], ctxt->accountId);
            ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->accountId.empty(), Status::INVALID_ARGUMENT_V20,
                "The type of accountId must be string.");
            status = JSUtils::Convert2Value(env, argv[1], ctxt->bundleInfos);
            ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT_V20,
                "The type of bundleInfos must be Array<BundleInfo>.");
            ASSERT_BUSINESS_ERR(ctxt, ctxt->bundleInfos.size() > 0, Status::INVALID_ARGUMENT_V20,
                "The size of bundleInfos must be greater than 0.");
            //30 is max bundleInfos size
            ASSERT_BUSINESS_ERR(ctxt, ctxt->bundleInfos.size() <= 30, Status::INVALID_ARGUMENT_V20,
                "The size of bundleInfos must be less than or equal to 30.");
        }
    });
}

napi_value JsConfig::QueryLastSyncInfo(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<QueryLastSyncInfoContext>();
    ParseQueryParams(env, info, ctxt);

    ASSERT_NULL(!ctxt->isThrowError, "QueryLastSyncInfo exit");

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
        if (ctxt->isBatch) {
            auto [status, batchResults] = proxy->QueryLastSyncInfoBatch(ctxt->accountId, ctxt->bundleInfos);
            ctxt->status = (GenerateNapiError(status, ctxt->jsCode, ctxt->error) == Status::SUCCESS)
                               ? napi_ok : napi_generic_failure;
            ctxt->batchResults = std::move(batchResults);
        } else {
            auto [status, results] = proxy->QueryLastSyncInfo(ctxt->accountId, ctxt->bundleName, ctxt->storeId);
            ctxt->status = (GenerateNapiError(status, ctxt->jsCode, ctxt->error) == Status::SUCCESS)
                               ? napi_ok : napi_generic_failure;
            ctxt->results = std::move(results);
        }
    };
    auto output = [env, ctxt](napi_value &result) {
        if (ctxt->isBatch) {
            result = JSUtils::Convert2JSValue(env, ctxt->batchResults);
        } else {
            result = JSUtils::Convert2JSValue(env, ctxt->results);
        }
        ASSERT_VALUE(ctxt, result != nullptr, napi_generic_failure, "output failed");
    };
    return NapiQueue::AsyncWork(env, ctxt, std::string(__FUNCTION__), execute, output);
}

void JsConfig::HandleCloudSyncArgs(napi_env env, napi_callback_info info, std::shared_ptr<CloudSyncContext> ctxt)
{
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        // less required 4 arguments :: <bundleName> <storeId> <mode> <progress>
        ASSERT_BUSINESS_ERR(ctxt, argc >= 4, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        // 0 is the index of argument bundleName
        int status = JSUtils::Convert2Value(env, argv[0], ctxt->bundleName);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT,
            "The type of bundleName must be string and not empty.");
        // 1 is the index of argument storeId
        status = JSUtils::Convert2Value(env, argv[1], ctxt->storeId);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT,
            "The type of storeId must be string and not empty.");
        // 2 is the index of argument syncMode
        status = JSUtils::Convert2ValueExt(env, argv[2], ctxt->syncMode);
        ASSERT_BUSINESS_ERR(
            ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT, "The type of syncMode must be number.");
        // 3 is the index of argument progress, it should be a founction
        napi_valuetype valueType = napi_undefined;
        napi_status ret = napi_typeof(env, argv[3], &valueType);
        ASSERT_BUSINESS_ERR(
            ctxt, ret == napi_ok && valueType == napi_function, Status::INVALID_ARGUMENT,
            "The type of progress should be function.");
        ASSERT_BUSINESS_ERR(
            ctxt, napi_create_reference(env, argv[3], 1, &ctxt->asyncHolder) == napi_ok,    // 3 means the progress
            Status::INVALID_ARGUMENT, "create refrence failed.");
    }, true);
}

/*
 * [JS API Prototype]
 * [Promise]
 *   cloudSync(bundleName: string, storeId: string, mode: relationalStore.SyncMode,
 * progress: Callback<relationalStore.ProgressDetails>: Promise<void>;
 */
napi_value JsConfig::CloudSync(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<CloudSyncContext>();
    ctxt->queue = std::make_shared<AppDataMgrJsKit::UvQueue>(env);
    HandleCloudSyncArgs(env, info, ctxt);
    ASSERT_NULL(!ctxt->isThrowError, "CloudSync exit");

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
        auto async = [ctxt, queue = ctxt->queue, cb = ctxt->asyncHolder](const DistributedRdb::Details &details) {
            if (queue == nullptr || cb == nullptr) {
                return;
            }
            bool repeate = !details.empty() && details.begin()->second.progress != DistributedRdb::SYNC_FINISH;
            queue->AsyncCallInOrder({ cb, repeate }, [details](napi_env env, int &argc, napi_value *argv) -> void {
                argc = 1;
                argv[0] = details.empty() ? nullptr : JSUtils::Convert2JSValue(env, details.begin()->second);
            }, {}, "CloudSync");
        };
        CloudService::Option option;
        option.syncMode = ctxt->syncMode;
        option.seqNum = GetSeqNum();
        auto status = proxy->CloudSync(ctxt->bundleName, ctxt->storeId, option, async);
        if (status == Status::INVALID_ARGUMENT) {
            status = Status::INVALID_ARGUMENT_V20;
        }
        ctxt->status =
            (GenerateNapiError(status, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ? napi_ok : napi_generic_failure;
    };
    auto output = [env, ctxt](napi_value &result) {
        if (ctxt->status != napi_ok && ctxt->asyncHolder != nullptr) {
            napi_delete_reference(env, ctxt->asyncHolder);
        }
        napi_get_undefined(env, &result);
    };
    return NapiQueue::AsyncWork(env, ctxt, std::string(__FUNCTION__), execute, output);
}

uint32_t JsConfig::GetSeqNum()
{
    uint32_t value = ++seqNum_;
    if (value == 0) {
        value = ++seqNum_;
    }
    return value;
}

napi_value JsConfig::OnSyncInfoChanged(napi_env env, napi_callback_info info)
{
    size_t argc = ARGC_MAX;
    napi_value argv[ARGC_MAX] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    struct SyncInfoContext : public ContextBase {
        std::vector<CloudData::BundleInfo> bundleInfos;
        napi_value callback = nullptr;
        std::shared_ptr<UvQueue> queue;
    };
    auto ctxt = std::make_shared<SyncInfoContext>();
    ctxt->queue = std::make_shared<UvQueue>(env);
    // 2 is Number of parameters
    ASSERT_ERR(env, argc >= 2, Status::INVALID_ARGUMENT_V20, "The number of parameters is incorrect.");
    auto status = JSUtils::Convert2Value(env, argv[0], ctxt->bundleInfos);
    ASSERT_ERR(env, status == JSUtils::OK && !ctxt->bundleInfos.empty(),
        Status::INVALID_ARGUMENT_V20, "The type of bundleInfos must be Array<BundleInfo>.");
    napi_valuetype type = napi_undefined;
    ASSERT_ERR(env, napi_typeof(env, argv[1], &type) == napi_ok && type == napi_function,
        Status::INVALID_ARGUMENT_V20, "The type of callback must be function.");
    ctxt->callback = argv[1];
    {
        std::lock_guard<std::mutex> lock(syncInfoObserversMutex_);
        bool isDuplicate = std::any_of(syncInfoObservers_.begin(), syncInfoObservers_.end(),
            [&ctxt](const SyncInfoObserverRecord &record) {
                return record.bundleInfos == ctxt->bundleInfos && (*record.observer == ctxt->callback);
            });
        if (isDuplicate) {
            LOG_INFO("Duplicate subscribe for sync info changed.");
            return nullptr;
        }
    }
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (proxy == nullptr) {
        if (state != CloudService::SERVER_UNAVAILABLE) {
            state = CloudService::NOT_SUPPORT;
        }
        ThrowNapiError(env, state, "");
        return nullptr;
    }
    auto observer = std::make_shared<NapiCloudSyncInfoObserver>(env, ctxt->callback, ctxt->queue);
    status = proxy->Subscribe(CloudSubscribeType::SYNC_INFO_CHANGED, ctxt->bundleInfos, observer);
    if (status != CloudService::SUCCESS) {
        observer->Clear();
        ThrowNapiError(env, status, "");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(syncInfoObserversMutex_);
    SyncInfoObserverRecord record{ctxt->bundleInfos, observer};
    syncInfoObservers_.push_back(std::move(record));
    return nullptr;
}

napi_value JsConfig::OffSyncInfoChanged(napi_env env, napi_callback_info info)
{
    size_t argc = ARGC_MAX;
    napi_value argv[ARGC_MAX] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    struct UnsubscribeContext : public ContextBase {
        std::vector<CloudData::BundleInfo> bundleInfos;
        napi_value callback = nullptr;
        bool hasCallback = false;
    };
    auto ctxt = std::make_shared<UnsubscribeContext>();
    ASSERT_ERR(env, argc >= 1, Status::INVALID_ARGUMENT_V20, "The number of parameters is incorrect.");
    int status = JSUtils::Convert2Value(env, argv[0], ctxt->bundleInfos);
    ASSERT_ERR(env, status == JSUtils::OK && !ctxt->bundleInfos.empty(), Status::INVALID_ARGUMENT_V20,
        "The type of bundleInfos must be Array<BundleInfo>.");
    if (argc >= 2) { // 2 is Number of parameters
        napi_valuetype type = napi_undefined;
        if (napi_typeof(env, argv[1], &type) == napi_ok && type == napi_function) {
            ctxt->callback = argv[1];
            ctxt->hasCallback = true;
        }
    }
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (proxy == nullptr) {
        if (state != CloudService::SERVER_UNAVAILABLE) {
            state = CloudService::NOT_SUPPORT;
        }
        ThrowNapiError(env, state, "");
        return nullptr;
    }

    auto unsubscribeInfos = CollectUnsubscribeInfos(ctxt->bundleInfos, ctxt->callback, ctxt->hasCallback);
    for (const auto &[observer, bundleInfos] : unsubscribeInfos) {
        proxy->Unsubscribe(CloudSubscribeType::SYNC_INFO_CHANGED, bundleInfos, observer);
    }
    return nullptr;
}

JsConfig::UnsubscribeInfoList JsConfig::CollectUnsubscribeInfos(
    const std::vector<CloudData::BundleInfo>& toUnsubscribe, napi_value callback, bool hasCallback)
{
    UnsubscribeInfoList unsubscribeInfos;
    std::lock_guard<std::mutex> lock(syncInfoObserversMutex_);
    auto it = syncInfoObservers_.begin();
    while (it != syncInfoObservers_.end()) {
        std::vector<CloudData::BundleInfo> intersection;
        for (const auto &info : toUnsubscribe) {
            if (std::find(it->bundleInfos.begin(), it->bundleInfos.end(), info) != it->bundleInfos.end()) {
                intersection.push_back(info);
            }
        }
        
        if (intersection.empty() || (hasCallback && !(*it->observer == callback))) {
            ++it;
            continue;
        }
        
        for (const auto &info : intersection) {
            auto removeIt = std::remove(it->bundleInfos.begin(), it->bundleInfos.end(), info);
            it->bundleInfos.erase(removeIt, it->bundleInfos.end());
        }
        
        unsubscribeInfos.emplace_back(it->observer, std::move(intersection));
        
        if (it->bundleInfos.empty()) {
            it->observer->Clear();
            it = syncInfoObservers_.erase(it);
        } else {
            ++it;
        }
    }
    return unsubscribeInfos;
}

napi_value JsConfig::InitConfig(napi_env env, napi_value exports)
{
    auto lambda = []() -> std::vector<napi_property_descriptor> {
        std::vector<napi_property_descriptor> properties = {
            DECLARE_NAPI_STATIC_FUNCTION("enableCloud", JsConfig::EnableCloud),
            DECLARE_NAPI_STATIC_FUNCTION("disableCloud", JsConfig::DisableCloud),
            DECLARE_NAPI_STATIC_FUNCTION("changeAppCloudSwitch", JsConfig::ChangeAppCloudSwitch),
            DECLARE_NAPI_STATIC_FUNCTION("clear", JsConfig::Clean),
            DECLARE_NAPI_STATIC_FUNCTION("clean", JsConfig::Clean),
            DECLARE_NAPI_STATIC_FUNCTION("notifyDataChange", JsConfig::NotifyDataChange),
            DECLARE_NAPI_STATIC_FUNCTION("queryStatistics", JsConfig::QueryStatistics),
            DECLARE_NAPI_STATIC_FUNCTION("setGlobalCloudStrategy", JsConfig::SetGlobalCloudStrategy),
            DECLARE_NAPI_STATIC_FUNCTION("queryLastSyncInfo", JsConfig::QueryLastSyncInfo),
            DECLARE_NAPI_STATIC_FUNCTION("cloudSync", JsConfig::CloudSync),
            DECLARE_NAPI_STATIC_FUNCTION("onSyncInfoChanged", JsConfig::OnSyncInfoChanged),
            DECLARE_NAPI_STATIC_FUNCTION("offSyncInfoChanged", JsConfig::OffSyncInfoChanged),
        };
        return properties;
    };
    auto jsCtor = JSUtils::DefineClass(env, "ohos.data.cloudData", "Config", lambda, JsConfig::New);
    NAPI_CALL(env, napi_set_named_property(env, exports, "Config", jsCtor));
    return exports;
}

bool JsConfig::ValidClearConfig(const std::map<std::string, CloudData::ClearConfig> &configs)
{
    for (const auto &[key, config] : configs) {
        if (!IsDbInfoValid(config.dbInfo)) {
            return false;
        }
    }
    return true;
}
bool JsConfig::IsDbInfoValid(const std::map<std::string, CloudData::DBActionInfo> &dbInfos)
{
    for (const auto &[dbName, dbInfo] : dbInfos) {
        if (!ValidSubscribeType(dbInfo.action)) {
            return false;
        }

        if (!IsTablesValid(dbInfo.tableInfo)) {
            return false;
        }
    }
    return true;
}
bool JsConfig::IsTablesValid(const std::map<std::string, int32_t> &tableInfo)
{
    for (const auto &[tableName, action] : tableInfo) {
        if (!ValidSubscribeType(action)) {
            return false;
        }
    }
    return true;
}

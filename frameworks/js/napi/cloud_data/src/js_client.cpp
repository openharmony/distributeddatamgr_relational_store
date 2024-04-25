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
#define LOG_TAG "JSClient"
#include "js_client.h"

#include <functional>
#include <string>
#include <vector>
#include "cloud_types.h"
#include "common_types.h"
#include "js_cloud_utils.h"
#include "js_error_utils.h"
#include "js_strategy_context.h"
#include "js_utils.h"
#include "logger.h"
#include "napi_queue.h"
#include "traits.h"

namespace OHOS {
namespace CloudData {
using namespace OHOS::AppDataMgrJsKit;
/*
 * [JS API Prototype]
 *     function setCloudStrategy(strategy: StrategyType, param?: Array<commonType.ValueType>): Promise<void>;
 */
napi_value SetCloudStrategy(napi_env env, napi_callback_info info)
{
    auto ctxt = std::make_shared<CloudStrategyContext>();
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        // strategy 1 required parameter， param 1 Optional parameter
        ASSERT_BUSINESS_ERR(ctxt, argc >= 1, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        int32_t strategy = -1;
        int status = JSUtils::Convert2ValueExt(env, argv[0], strategy);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && strategy >= 0 &&
            strategy < static_cast<int32_t>(Strategy::STRATEGY_BUTT), Status::INVALID_ARGUMENT,
            "The type of strategy must be StrategyType.");
        ctxt->strategy = static_cast<Strategy>(strategy);
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
    ASSERT_NULL(!ctxt->isThrowError, "SetCloudStrategy exit");
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
        LOG_DEBUG("SetCloudStrategy execute");

        auto res = proxy->SetCloudStrategy(ctxt->strategy, ctxt->param);
        ctxt->status =
            (GenerateNapiError(res, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ? napi_ok : napi_generic_failure;
    };
    return NapiQueue::AsyncWork(env, ctxt, std::string(__FUNCTION__), execute);
}

napi_value InitClient(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("setCloudStrategy", SetCloudStrategy)
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(*properties), properties));
    return exports;
}
} // namespace CloudData
} // namespace OHOS

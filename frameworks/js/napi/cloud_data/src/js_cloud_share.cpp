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

#include "js_cloud_share.h"

#include "cache_result_set.h"
#include "cloud_manager.h"
#include "cloud_service.h"
#include "cloud_types.h"
#include "js_utils.h"
#include "js_cloud_utils.h"
#include "js_error_utils.h"
#include "logger.h"
#include "napi_queue.h"
#include "rdb_predicates.h"
#include "result_set.h"

namespace OHOS::CloudData {
using namespace OHOS::NativeRdb;
using namespace OHOS::AppDataMgrJsKit;
/*
 * [JS API Prototype]
 * [AsyncCallback]
 *      allocResourceAndShare(storeId: string, predicates: relationalStore.RdbPredicates,
 *          participants: Array<Participant>, callback: AsyncCallback<relationalStore.ResultSet>): void;
 *      allocResourceAndShare(storeId: string, predicates: relationalStore.RdbPredicates,
 *          participants: Array<Participant>, columns: Array<string>,
 *          callback: AsyncCallback<relationalStore.ResultSet> ): void;
 *
 * [Promise]
 *     allocResourceAndShare(storeId: string, predicates: relationalStore.RdbPredicates,
 *         participants: Array<Participant>, columns?: Array<string>): Promise<relationalStore.ResultSet>;
 */
napi_value AllocResourceAndShare(napi_env env, napi_callback_info info)
{
    struct AllocResAndShareContext : public ContextBase {
        std::string storeId;
        std::vector<Participant> participants;
        std::vector<std::string> columns;
        std::shared_ptr<RdbPredicates> predicates = nullptr;
        std::shared_ptr<ResultSet> resultSet;
    };
    auto ctxt = std::make_shared<AllocResAndShareContext>();
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        ASSERT_BUSINESS_ERR(ctxt, argc >= 3, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        int status = JSUtils::Convert2Value(env, argv[0], ctxt->storeId);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK,
            Status::INVALID_ARGUMENT, "The type of storeId must be string.");
        status = JSUtils::Convert2Value(env, argv[1], ctxt->predicates);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT,
            "The type of predicates must be relationalStore.RdbPredicates");
        status = JSUtils::Convert2Value(env, argv[2], ctxt->participants);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK,
            Status::INVALID_ARGUMENT, "The type of participants must be Array<Participant>.");
        if (argc > 3) {
            status = JSUtils::Convert2Value(env, argv[3], ctxt->columns);
            ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK,
                Status::INVALID_ARGUMENT, "The type of columns must be Array<string>.");
        }
    });
    ASSERT_NULL(!ctxt->isThrowError, "AllocResourceAndShare exit");

    auto execute = [env, ctxt]() {
        auto [status, proxy] = CloudManager::GetInstance().GetCloudService();
        if (proxy == nullptr) {
            if (status != CloudService::SERVER_UNAVAILABLE) {
                status = CloudService::NOT_SUPPORT;
            }
            ctxt->status = (GenerateNapiError(status, ctxt->jsCode, ctxt->error) == Status::SUCCESS)
                               ? napi_ok
                               : napi_generic_failure;
            return;
        }

        auto [result, valueBuckets] = proxy->AllocResourceAndShare(
            ctxt->storeId, ctxt->predicates->GetDistributedPredicates(), ctxt->columns, ctxt->participants);
        ctxt->resultSet = std::make_shared<CacheResultSet>(std::move(valueBuckets));
        LOG_DEBUG("AllocResourceAndShare result: %{public}d, size:%{public}zu", result, valueBuckets.size());
        ctxt->status =
            (GenerateNapiError(result, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ? napi_ok : napi_generic_failure;
    };
    auto output = [env, ctxt](napi_value& result) {
        result = JSUtils::Convert2JSValue(env, ctxt->resultSet);
        ASSERT_VALUE(ctxt, result != nullptr, napi_generic_failure, "output failed");
    };
    return NapiQueue::AsyncWork(env, ctxt, std::string(__FUNCTION__), execute, output);
}

napi_value InitCloudSharing(napi_env env, napi_value exports)
{
    napi_value sharing = nullptr;
    napi_status status = napi_create_object(env, &sharing);
    if (status != napi_ok || sharing == nullptr) {
        return nullptr;
    }
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("allocResourceAndShare", AllocResourceAndShare),
    };
    NAPI_CALL(env, napi_define_properties(env, sharing, sizeof(properties) / sizeof(*properties), properties));
    NAPI_CALL(env, napi_set_named_property(env, exports, "sharing", sharing));
    return sharing;
}
} // namespace OHOS::CloudData
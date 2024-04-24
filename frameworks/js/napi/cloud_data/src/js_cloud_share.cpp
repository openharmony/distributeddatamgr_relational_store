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
#define LOG_TAG "JSCloudShare"
#include "js_cloud_share.h"

#include "cache_result_set.h"
#include "cloud_manager.h"
#include "cloud_service.h"
#include "cloud_types.h"
#include "js_cloud_utils.h"
#include "js_error_utils.h"
#include "js_utils.h"
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
        Participants participants;
        std::vector<std::string> columns;
        std::shared_ptr<RdbPredicates> predicates = nullptr;
        std::shared_ptr<ResultSet> resultSet;
    };
    auto ctxt = std::make_shared<AllocResAndShareContext>();
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        // allocResourceAndShare storeId, predicates, participants 3 required parameter， columns 1 Optional parameter
        ASSERT_BUSINESS_ERR(ctxt, argc >= 3, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        int status = JSUtils::Convert2Value(env, argv[0], ctxt->storeId);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->storeId.empty(), Status::INVALID_ARGUMENT,
            "The type of storeId must be string and not empty.");
        // 'argv[1]' represents a RdbPredicates parameter
        status = JSUtils::Convert2Value(env, argv[1], ctxt->predicates);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK, Status::INVALID_ARGUMENT,
            "The type of predicates must be relationalStore.RdbPredicates");
        // 'argv[2]' represents a Participants parameter
        status = JSUtils::Convert2Value(env, argv[2], ctxt->participants);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->participants.empty(), Status::INVALID_ARGUMENT,
            "The type of participants must be Array<Participant> and not empty.");
        // 'argv[3]' represents an optional std::vector<std::string> parameter
        if (argc > 3 && !JSUtils::IsNull(env, argv[3])) {
            // 'argv[3]' represents the columns optional parameter
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
                               ? napi_ok: napi_generic_failure;
            return;
        }

        auto [result, valueBuckets] = proxy->AllocResourceAndShare(
            ctxt->storeId, ctxt->predicates->GetDistributedPredicates(), ctxt->columns, ctxt->participants);
        LOG_DEBUG("AllocResourceAndShare result: %{public}d, size:%{public}zu", result, valueBuckets.size());
        ctxt->resultSet = std::make_shared<CacheResultSet>(std::move(valueBuckets));
        ctxt->status =
            (GenerateNapiError(result, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ? napi_ok : napi_generic_failure;
    };
    auto output = [env, ctxt](napi_value& result) {
        result = JSUtils::Convert2JSValue(env, ctxt->resultSet);
        ASSERT_VALUE(ctxt, result != nullptr, napi_generic_failure, "output failed");
    };
    return NapiQueue::AsyncWork(env, ctxt, std::string(__FUNCTION__), execute, output);
}

/*
 * [JS API Prototype]
 * [AsyncCallback]
 *     share(sharingRes: string, participants: Array<Participant>,
 *         callback: AsyncCallback<Result<Array<Result<Participant>>>>): void;
 *
 * [Promise]
 *     share(sharingRes: string, participants: Array<Participant>): Promise<Result<Array<Result<Participant>>>>;
 */
napi_value Share(napi_env env, napi_callback_info info)
{
    struct ShareContext : public ContextBase {
        std::string sharingRes;
        Participants participants;
        Results results;
    };
    auto ctxt = std::make_shared<ShareContext>();
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        // ShareContext have sharingRes, participants 2 required parameter
        ASSERT_BUSINESS_ERR(ctxt, argc >= 2, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        int status = JSUtils::Convert2Value(env, argv[0], ctxt->sharingRes);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->sharingRes.empty(),
            Status::INVALID_ARGUMENT, "The type of sharingRes must be string and not empty.");
        status = JSUtils::Convert2Value(env, argv[1], ctxt->participants);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->participants.empty(),
            Status::INVALID_ARGUMENT, "The type of participants must be Array<Participant> and not empty.");
    });
    ASSERT_NULL(!ctxt->isThrowError, "share exit");

    auto execute = [env, ctxt]() {
        auto [status, proxy] = CloudManager::GetInstance().GetCloudService();
        if (proxy == nullptr) {
            if (status != CloudService::SERVER_UNAVAILABLE) {
                status = CloudService::NOT_SUPPORT;
            }
            ctxt->status = (GenerateNapiError(status, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ?
                napi_ok : napi_generic_failure;
            return;
        }
        int32_t result = proxy->Share(ctxt->sharingRes, ctxt->participants, ctxt->results);
        LOG_DEBUG("share result %{public}d", result);
        ctxt->status = (GenerateNapiError(result, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ?
            napi_ok : napi_generic_failure;
    };
    auto output = [env, ctxt](napi_value& result) {
        result = JSUtils::Convert2JSValue(env, ctxt->results);
        ASSERT_VALUE(ctxt,  result != nullptr, napi_generic_failure, "output failed");
    };
    return NapiQueue::AsyncWork(env, ctxt, std::string(__FUNCTION__), execute, output);
}

/*
 * [JS API Prototype]
 * [AsyncCallback]
 *     unshare(sharingRes: string, participants: Array<Participant>,
 *         callback: AsyncCallback<Result<Array<Result<Participant>>>>): void;
 *
 * [Promise]
 *     unshare(sharingRes: string, participants: Array<Participant>): Promise<Result<Array<Result<Participant>>>>;
 */
napi_value Unshare(napi_env env, napi_callback_info info)
{
    struct UnshareContext : public ContextBase {
        std::string sharingRes;
        Participants participants;
        Results results;
    };
    auto ctxt = std::make_shared<UnshareContext>();
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        // ShareContext have sharingRes, participants 2 required parameter
        ASSERT_BUSINESS_ERR(ctxt, argc >= 2, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        int status = JSUtils::Convert2Value(env, argv[0], ctxt->sharingRes);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->sharingRes.empty(),
            Status::INVALID_ARGUMENT, "The type of sharingRes must be string and not empty.");
        status = JSUtils::Convert2Value(env, argv[1], ctxt->participants);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->participants.empty(),
            Status::INVALID_ARGUMENT, "The type of participants must be Array<Participant> and not empty.");
    });
    ASSERT_NULL(!ctxt->isThrowError, "unShare exit");
    auto execute = [env, ctxt]() {
        auto [status, proxy] = CloudManager::GetInstance().GetCloudService();
        if (proxy == nullptr) {
            if (status != CloudService::SERVER_UNAVAILABLE) {
                status = CloudService::NOT_SUPPORT;
            }
            ctxt->status = (GenerateNapiError(status, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ?
                napi_ok : napi_generic_failure;
            return;
        }
        int32_t result = proxy->Unshare(ctxt->sharingRes, ctxt->participants, ctxt->results);
        LOG_DEBUG("unshare result %{public}d", result);
        ctxt->status = (GenerateNapiError(result, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ?
            napi_ok : napi_generic_failure;
    };
    auto output = [env, ctxt](napi_value& result) {
        result = JSUtils::Convert2JSValue(env, ctxt->results);
        ASSERT_VALUE(ctxt,  result != nullptr, napi_generic_failure, "output failed");
    };
    return NapiQueue::AsyncWork(env, ctxt, std::string(__FUNCTION__), execute, output);
}

/*
 * [JS API Prototype]
 * [AsyncCallback]
 *     exit(sharingRes: string, callback: AsyncCallback<Result<void>>): void;
 *
 * [Promise]
 *     exit(sharingRes: string): Promise<Result<void>>;
 */
napi_value Exit(napi_env env, napi_callback_info info)
{
    struct ExitContext : public ContextBase {
        std::string sharingRes;
        std::pair<int32_t, std::string> result;
    };
    auto ctxt = std::make_shared<ExitContext>();
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        ASSERT_BUSINESS_ERR(ctxt, argc >= 1, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        int status = JSUtils::Convert2Value(env, argv[0], ctxt->sharingRes);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->sharingRes.empty(),
            Status::INVALID_ARGUMENT, "The type of sharingRes must be string and not empty.");
    });
    ASSERT_NULL(!ctxt->isThrowError, "exit exit");
    auto execute = [env, ctxt]() {
        auto [status, proxy] = CloudManager::GetInstance().GetCloudService();
        if (proxy == nullptr) {
            if (status != CloudService::SERVER_UNAVAILABLE) {
                status = CloudService::NOT_SUPPORT;
            }
            ctxt->status = (GenerateNapiError(status, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ?
                napi_ok : napi_generic_failure;
            return;
        }
        int32_t result = proxy->Exit(ctxt->sharingRes, ctxt->result);
        LOG_DEBUG("exit sharing result %{public}d", result);
        ctxt->status = (GenerateNapiError(result, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ?
            napi_ok : napi_generic_failure;
    };
    auto output = [env, ctxt](napi_value& result) {
        result = JSUtils::Convert2JSValue(env, ctxt->result);
        ASSERT_VALUE(ctxt,  result != nullptr, napi_generic_failure, "output failed");
    };
    return NapiQueue::AsyncWork(env, ctxt, std::string(__FUNCTION__), execute, output);
}

/*
 * [JS API Prototype]
 * [AsyncCallback]
 *     changePrivilege(sharingRes: string, participants: Array<Participant>,
 *         callback: AsyncCallback<Result<Array<Result<Participant>>>>): void;
 *
 * [Promise]
 *     changePrivilege(
 *         sharingRes: string,
 *         participants: Array<Participant>): Promise<Result<Array<Result<Participant>>>>;
 */
napi_value ChangePrivilege(napi_env env, napi_callback_info info)
{
    struct ChangePrivilegeContext : public ContextBase {
        std::string sharingRes;
        Participants participants;
        Results results;
    };
    auto ctxt = std::make_shared<ChangePrivilegeContext>();
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        // ShareContext have sharingRes, participants 2 required parameter
        ASSERT_BUSINESS_ERR(ctxt, argc >= 2, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        int status = JSUtils::Convert2Value(env, argv[0], ctxt->sharingRes);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->sharingRes.empty(),
            Status::INVALID_ARGUMENT, "The type of sharingRes must be string and not empty.");
        status = JSUtils::Convert2Value(env, argv[1], ctxt->participants);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->participants.empty(),
            Status::INVALID_ARGUMENT, "The type of participants must be Array<Participant> and not empty.");
    });
    ASSERT_NULL(!ctxt->isThrowError, "changePrivilege exit");
    auto execute = [env, ctxt]() {
        auto [status, proxy] = CloudManager::GetInstance().GetCloudService();
        if (proxy == nullptr) {
            if (status != CloudService::SERVER_UNAVAILABLE) {
                status = CloudService::NOT_SUPPORT;
            }
            ctxt->status = (GenerateNapiError(status, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ?
                napi_ok : napi_generic_failure;
            return;
        }
        int32_t result = proxy->ChangePrivilege(ctxt->sharingRes, ctxt->participants, ctxt->results);
        LOG_DEBUG("change privilege result %{public}d", result);
        ctxt->status = (GenerateNapiError(result, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ?
            napi_ok : napi_generic_failure;
    };
    auto output = [env, ctxt](napi_value& result) {
        result = JSUtils::Convert2JSValue(env, ctxt->results);
        ASSERT_VALUE(ctxt,  result != nullptr, napi_generic_failure, "output failed");
    };
    return NapiQueue::AsyncWork(env, ctxt, std::string(__FUNCTION__), execute, output);
}

/*
 * [JS API Prototype]
 * [AsyncCallback]
 *     queryParticipants(sharingRes: string, callback: AsyncCallback<Result<Array<Participant>>>): void;
 *
 * [Promise]
 *     queryParticipants(sharingRes: string): Promise<Result<Array<Participant>>>;
 */
napi_value Query(napi_env env, napi_callback_info info)
{
    struct QueryContext : public ContextBase {
        std::string sharingRes;
        QueryResults results;
    };
    auto ctxt = std::make_shared<QueryContext>();
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        ASSERT_BUSINESS_ERR(ctxt, argc >= 1, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        int status = JSUtils::Convert2Value(env, argv[0], ctxt->sharingRes);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->sharingRes.empty(),
            Status::INVALID_ARGUMENT, "The type of sharingRes must be string and not empty.");
    });
    ASSERT_NULL(!ctxt->isThrowError, "query exit");
    auto execute = [env, ctxt]() {
        auto [status, proxy] = CloudManager::GetInstance().GetCloudService();
        if (proxy == nullptr) {
            if (status != CloudService::SERVER_UNAVAILABLE) {
                status = CloudService::NOT_SUPPORT;
            }
            ctxt->status = (GenerateNapiError(status, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ?
                napi_ok : napi_generic_failure;
            return;
        }
        int32_t result = proxy->Query(ctxt->sharingRes, ctxt->results);
        LOG_DEBUG("query participants result %{public}d", result);
        ctxt->status = (GenerateNapiError(result, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ?
            napi_ok : napi_generic_failure;
    };
    auto output = [env, ctxt](napi_value& result) {
        result = JSUtils::Convert2JSValue(env, ctxt->results);
        ASSERT_VALUE(ctxt,  result != nullptr, napi_generic_failure, "output failed");
    };
    return NapiQueue::AsyncWork(env, ctxt, std::string(__FUNCTION__), execute, output);
}

/*
 * [JS API Prototype]
 * [AsyncCallback]
 *     queryParticipantsByInvitation(invitationCode: string,
 *         callback: AsyncCallback<Result<Array<Participant>>>): void;
 *
 * [Promise]
 *     queryParticipantsByInvitation(invitationCode: string): Promise<Result<Array<Participant>>>;
 */
napi_value QueryByInvitation(napi_env env, napi_callback_info info)
{
    struct QueryByInvitationContext : public ContextBase {
        std::string invitationCode;
        QueryResults results;
    };
    auto ctxt = std::make_shared<QueryByInvitationContext>();
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        ASSERT_BUSINESS_ERR(ctxt, argc >= 1, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        int status = JSUtils::Convert2Value(env, argv[0], ctxt->invitationCode);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->invitationCode.empty(),
            Status::INVALID_ARGUMENT, "The type of invitationCode must be string and not empty.");
    });
    ASSERT_NULL(!ctxt->isThrowError, "queryByInvitation exit");
    auto execute = [env, ctxt]() {
        auto [status, proxy] = CloudManager::GetInstance().GetCloudService();
        if (proxy == nullptr) {
            if (status != CloudService::SERVER_UNAVAILABLE) {
                status = CloudService::NOT_SUPPORT;
            }
            ctxt->status = (GenerateNapiError(status, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ?
                napi_ok : napi_generic_failure;
            return;
        }
        int32_t result = proxy->QueryByInvitation(ctxt->invitationCode, ctxt->results);
        LOG_DEBUG("query participants by invitation result %{public}d", result);
        ctxt->status = (GenerateNapiError(result, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ?
            napi_ok : napi_generic_failure;
    };
    auto output = [env, ctxt](napi_value& result) {
        result = JSUtils::Convert2JSValue(env, ctxt->results);
        ASSERT_VALUE(ctxt,  result != nullptr, napi_generic_failure, "output failed");
    };
    return NapiQueue::AsyncWork(env, ctxt, std::string(__FUNCTION__), execute, output);
}

/*
 * [JS API Prototype]
 * [AsyncCallback]
 *     confirmInvitation(invitationCode: string, status: Status, callback: AsyncCallback<Result<string>>): void;
 *
 * [Promise]
 *     confirmInvitation(invitationCode: string, status: Status): Promise<Result<string>>;
 */
napi_value ConfirmInvitation(napi_env env, napi_callback_info info)
{
    struct ConfirmInvitationContext : public ContextBase {
        std::string invitationCode;
        int32_t confirmation;
        std::tuple<int32_t, std::string, std::string> result;
    };
    auto ctxt = std::make_shared<ConfirmInvitationContext>();
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        // ShareContext have sharingRes, participants 2 required parameter
        ASSERT_BUSINESS_ERR(ctxt, argc >= 2, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        int status = JSUtils::Convert2Value(env, argv[0], ctxt->invitationCode);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->invitationCode.empty(),
        Status::INVALID_ARGUMENT, "The type of invitationCode must be string and not empty.");
        int32_t confirmation;
        status = JSUtils::Convert2ValueExt(env, argv[1], confirmation);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK &&
                confirmation > Confirmation::CFM_NIL && confirmation <= Confirmation::CFM_BUTT,
            Status::INVALID_ARGUMENT, "The type of status must be Status.");
        ctxt->confirmation = confirmation;
    });
    ASSERT_NULL(!ctxt->isThrowError, "confirmInvitation exit");
    auto execute = [env, ctxt]() {
        auto [status, proxy] = CloudManager::GetInstance().GetCloudService();
        if (proxy == nullptr) {
            if (status != CloudService::SERVER_UNAVAILABLE) {
                status = CloudService::NOT_SUPPORT;
            }
            ctxt->status = (GenerateNapiError(status, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ?
                napi_ok : napi_generic_failure;
            return;
        }
        int32_t result = proxy->ConfirmInvitation(ctxt->invitationCode, ctxt->confirmation, ctxt->result);
        LOG_DEBUG("confirm invitation result %{public}d", result);
        ctxt->status = (GenerateNapiError(result, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ?
            napi_ok : napi_generic_failure;
    };
    auto output = [env, ctxt](napi_value& result) {
        result = JSUtils::Convert2JSValue(env, ctxt->result);
        ASSERT_VALUE(ctxt,  result != nullptr, napi_generic_failure, "output failed");
    };
    return NapiQueue::AsyncWork(env, ctxt, std::string(__FUNCTION__), execute, output);
}

/*
 * [JS API Prototype]
 * [AsyncCallback]
 *     changeConfirmation(sharingRes: string, status: Status, callback: AsyncCallback<Result<void>>): void;
 *
 * [Promise]
 *     changeConfirmation(sharingRes: string, status: Status): Promise<Result<void>>;
 */
napi_value ChangeConfirmation(napi_env env, napi_callback_info info)
{
    struct ChangeConfirmationContext : public ContextBase {
        std::string sharingRes;
        int32_t confirmation;
        std::pair<int32_t, std::string> results;
    };
    auto ctxt = std::make_shared<ChangeConfirmationContext>();
    ctxt->GetCbInfo(env, info, [env, ctxt](size_t argc, napi_value *argv) {
        // ShareContext have sharingRes, participants 2 required parameter
        ASSERT_BUSINESS_ERR(ctxt, argc >= 2, Status::INVALID_ARGUMENT, "The number of parameters is incorrect.");
        int status = JSUtils::Convert2Value(env, argv[0], ctxt->sharingRes);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK && !ctxt->sharingRes.empty(),
            Status::INVALID_ARGUMENT, "The type of sharingRes must be string and not empty.");
        int32_t confirmation;
        status = JSUtils::Convert2ValueExt(env, argv[1], confirmation);
        ASSERT_BUSINESS_ERR(ctxt, status == JSUtils::OK &&
                confirmation > Confirmation::CFM_NIL && confirmation < Confirmation::CFM_BUTT,
            Status::INVALID_ARGUMENT, "The type of status must be Status.");
        ctxt->confirmation = confirmation;
    });
    ASSERT_NULL(!ctxt->isThrowError, "changeConfirmation exit");
    auto execute = [env, ctxt]() {
        auto [status, proxy] = CloudManager::GetInstance().GetCloudService();
        if (proxy == nullptr) {
            if (status != CloudService::SERVER_UNAVAILABLE) {
                status = CloudService::NOT_SUPPORT;
            }
            ctxt->status = (GenerateNapiError(status, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ?
                napi_ok : napi_generic_failure;
            return;
        }
        int32_t result = proxy->ChangeConfirmation(ctxt->sharingRes, ctxt->confirmation, ctxt->results);
        LOG_DEBUG("change confirmation result %{public}d", result);
        ctxt->status = (GenerateNapiError(result, ctxt->jsCode, ctxt->error) == Status::SUCCESS) ?
            napi_ok : napi_generic_failure;
    };
    auto output = [env, ctxt](napi_value& result) {
        result = JSUtils::Convert2JSValue(env, ctxt->results);
        ASSERT_VALUE(ctxt,  result != nullptr, napi_generic_failure, "output failed");
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
        DECLARE_NAPI_FUNCTION("share", Share),
        DECLARE_NAPI_FUNCTION("unshare", Unshare),
        DECLARE_NAPI_FUNCTION("exit", Exit),
        DECLARE_NAPI_FUNCTION("changePrivilege", ChangePrivilege),
        DECLARE_NAPI_FUNCTION("queryParticipants", Query),
        DECLARE_NAPI_FUNCTION("queryParticipantsByInvitation", QueryByInvitation),
        DECLARE_NAPI_FUNCTION("confirmInvitation", ConfirmInvitation),
        DECLARE_NAPI_FUNCTION("changeConfirmation", ChangeConfirmation),
    };
    NAPI_CALL(env, napi_define_properties(env, sharing, sizeof(properties) / sizeof(*properties), properties));
    NAPI_CALL(env, napi_set_named_property(env, exports, "sharing", sharing));
    return sharing;
}
} // namespace OHOS::CloudData
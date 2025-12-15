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
#define LOG_TAG "AniCloudDataSharingImpl"
#include "logger.h"
#include "ani_cloud_data.h"
#include "ani_error_code.h"
#include "rdb_predicates_impl.h"
#include "cache_result_set.h"
#include "ani_cloud_data_utils.h"
#include "result_set_impl.h"

namespace AniCloudData{
namespace AniSharing {
using namespace OHOS::Rdb;

ResultSet AllocResourceAndSharePromise(string_view storeId, RdbPredicates_TH predicates,
    array_view<Participant_TH> participants, optional_view<array<string>> columns)
{
    std::optional<std::pair<int32_t, std::vector<OHOS::NativeRdb::ValuesBucket>>> result;
    auto work = [&storeId, &predicates, &participants, &columns, &result](std::shared_ptr<CloudService> proxy) {
        Participants info;
        std::vector<std::string> realColumns;
        ParticipantConvert(participants, info);
        if (columns.has_value()) {
            for (auto it = columns.value().begin(); it != columns.value().end(); ++it) {
                realColumns.push_back(it->c_str());
            }
        }
        OHOS::RdbTaihe::RdbPredicatesImpl* impl = reinterpret_cast<OHOS::RdbTaihe::RdbPredicatesImpl*>(
            predicates->GetSpecificImplPtr());
        std::shared_ptr<OHOS::NativeRdb::RdbPredicates> rdbPredicateNative = impl->GetNativePtr();
        result = proxy->AllocResourceAndShare(std::string(storeId),
            rdbPredicateNative->GetDistributedPredicates(), realColumns, info);
    };
    RequestIPC(work);
    int errCode = CloudService::Status::ERROR;
    if (result.has_value()) {
        errCode = result.value().first;
        if (errCode == CloudService::Status::SUCCESS) {
            std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet =
                std::make_shared<OHOS::NativeRdb::CacheResultSet>(std::move(result.value().second));
            return taihe::make_holder<OHOS::RdbTaihe::ResultSetImpl, ResultSet>(resultSet);
        }
    }
    if (errCode != CloudService::Status::SUCCESS) {
        ThrowAniError(errCode);
    }
    return taihe::make_holder<OHOS::RdbTaihe::ResultSetImpl, ResultSet>();
}

ResultSet AllocResourceAndShareImpl(string_view storeId, RdbPredicates_TH predicates,
    array_view<Participant_TH> participants)
{
    return AllocResourceAndSharePromise(storeId, predicates, participants, optional_view<array<string>>(std::nullopt));
}

ResultSet AllocResourceAndShareImplWithColumns(string_view storeId, RdbPredicates_TH predicates,
    array_view<Participant_TH> participants, array_view<string> columns)
{
    optional_view<array<string>> realColumns = optional<array<string>>(std::in_place, columns);
    return AllocResourceAndSharePromise(storeId, predicates, participants, realColumns);
}

Result_TH ShareImpl(string_view sharingResource, array_view<Participant_TH> participants)
{
    Result_TH ret;
    Results ipcRet;
    int32_t code = CloudService::Status::ERROR; 
    auto work = [&sharingResource, &participants, &ipcRet, &code](std::shared_ptr<CloudService> proxy) {
        Participants info;
        ParticipantConvert(participants, info);
        code = proxy->Share(std::string(sharingResource), info, ipcRet);
    };
    RequestIPC(work);
    if (code != CloudService::Status::SUCCESS) {
        LOG_ERROR("request, errcode = %{public}d", code);
        ThrowAniError(code);
        return ret;
    }
    ResultsConvert(ipcRet, ret);
    return ret;
}

Result_TH UnshareImpl(string_view sharingResource, array_view<Participant_TH> participants)
{
    Result_TH ret;
    Results ipcRet;
    int32_t code = CloudService::Status::ERROR;   
    auto work = [&sharingResource, &participants, &ipcRet, &code](std::shared_ptr<CloudService> proxy) {
        Participants info;
        ParticipantConvert(participants, info);
        code = proxy->Unshare(std::string(sharingResource), info, ipcRet);
    };
    RequestIPC(work);
    if (code != CloudService::Status::SUCCESS) {
        LOG_ERROR("request, errcode = %{public}d", code);
        ThrowAniError(code);
        return ret;
    }
    ResultsConvert(ipcRet, ret);
    return ret;
}

Result_TH ExitImpl(string_view sharingResource)
{
    Result_TH ret;
    int32_t code = CloudService::Status::ERROR;    
    std::pair<int32_t, std::string> ipcRet;
    auto work = [&sharingResource, &ipcRet, &code](std::shared_ptr<CloudService> proxy) {
        code = proxy->Exit(std::string(sharingResource), ipcRet);
    };
    RequestIPC(work);
    if (code != CloudService::Status::SUCCESS) {
        LOG_ERROR("request, errcode = %{public}d", code);
        ThrowAniError(code);
        return ret;
    }
    ret.code = ipcRet.first;
    ret.description = optional<string>(std::in_place, ipcRet.second);
    return ret;
}

Result_TH ChangePrivilegeImpl(string_view sharingResource, array_view<Participant_TH> participants)
{
    Result_TH ret;
    Results ipcRet;
    int32_t code = CloudService::Status::ERROR;
    auto work = [&sharingResource, &participants, &ipcRet, &code](std::shared_ptr<CloudService> proxy) {
        Participants info;
        ParticipantConvert(participants, info);
        code = proxy->ChangePrivilege(std::string(sharingResource), info, ipcRet);
    };
    RequestIPC(work);
    if (code != CloudService::Status::SUCCESS) {
        LOG_ERROR("request, errcode = %{public}d", code);
        ThrowAniError(code);
        return ret;
    }
    ResultsConvert(ipcRet, ret);
    return ret;
}

Result_TH QueryParticipantsImpl(string_view sharingResource)
{
    Result_TH ret;
    QueryResults ipcRet;
    int32_t code = CloudService::Status::ERROR;
    auto work = [&sharingResource, &ipcRet, &code](std::shared_ptr<CloudService> proxy) {
        code = proxy->Query(std::string(sharingResource), ipcRet);
    };
    RequestIPC(work);
    if (code != CloudService::Status::SUCCESS) {
        LOG_ERROR("request, errcode = %{public}d", code);
        ThrowAniError(code);
        return ret;
    }
    QueryResultsConvert(ipcRet, ret);
    return ret;
}

Result_TH QueryParticipantsByInvitationImpl(string_view invitationCode)
{
    Result_TH ret;
    QueryResults ipcRet;
    int32_t code = CloudService::Status::ERROR;
    auto work = [&invitationCode, &ipcRet, &code](std::shared_ptr<CloudService> proxy) {
        code = proxy->QueryByInvitation(std::string(invitationCode), ipcRet);
    };
    RequestIPC(work);
    if (code != CloudService::Status::SUCCESS) {
        LOG_ERROR("request, errcode = %{public}d", code);
        ThrowAniError(code);
        return ret;
    }
    QueryResultsConvert(ipcRet, ret);
    return ret;
}

Result_TH ConfirmInvitationImpl(string_view invitationCode, State state)
{
    Result_TH ret;
    std::tuple<int32_t, std::string, std::string> ipcRet;
    int32_t code = CloudService::Status::ERROR;
    auto work = [&invitationCode, &state, &ipcRet, &code](std::shared_ptr<CloudService> proxy) {
        if (!(state.get_value() > Confirmation::CFM_NIL && state.get_value() <= Confirmation::CFM_BUTT)) {
            LOG_ERROR("status type error");
            code = CloudService::Status::INVALID_ARGUMENT;
            return;
        }
        code = proxy->ConfirmInvitation(std::string(invitationCode), state.get_value(), ipcRet);
    };
    RequestIPC(work);
    if (code != CloudService::Status::SUCCESS) {
        LOG_ERROR("request, errcode = %{public}d", code);
        ThrowAniError(code);
        return ret;
    }
    ret.code = std::get<0>(ipcRet);
    ret.description = optional<string>(std::in_place, std::get<1>(ipcRet));
    ret.value = optional<ResultValue>(std::in_place, ResultValue::make_stringValue(std::get<2>(ipcRet)));
    return ret;
}

Result_TH ChangeConfirmationImpl(string_view sharingResource, State state)
{
    Result_TH ret;
    std::pair<int32_t, std::string> ipcRet;
    int32_t code = CloudService::Status::ERROR;
    auto work = [&sharingResource, &state, &ipcRet, &code](std::shared_ptr<CloudService> proxy) {
        if (!(state.get_value() > Confirmation::CFM_NIL && state.get_value() <= Confirmation::CFM_BUTT)) {
            LOG_ERROR("status type error");
            code = CloudService::Status::INVALID_ARGUMENT;
            return;
        }
        code = proxy->ChangeConfirmation(std::string(sharingResource), state.get_value(), ipcRet);
    };
    RequestIPC(work);
    if (code != CloudService::Status::SUCCESS) {
        LOG_ERROR("request, errcode = %{public}d", code);
        ThrowAniError(code);
        return ret;
    }
    ret.code = ipcRet.first;
    ret.description = optional<string>(std::in_place, ipcRet.second);
    return ret;
}
}  // namespace
}

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_AllocResourceAndSharePromise(AniCloudData::AniSharing::AllocResourceAndSharePromise);
TH_EXPORT_CPP_API_AllocResourceAndShareImpl(AniCloudData::AniSharing::AllocResourceAndShareImpl);
TH_EXPORT_CPP_API_AllocResourceAndShareImplWithColumns(AniCloudData::AniSharing::AllocResourceAndShareImplWithColumns);
TH_EXPORT_CPP_API_ShareImpl(AniCloudData::AniSharing::ShareImpl);
TH_EXPORT_CPP_API_UnshareImpl(AniCloudData::AniSharing::UnshareImpl);
TH_EXPORT_CPP_API_ExitImpl(AniCloudData::AniSharing::ExitImpl);
TH_EXPORT_CPP_API_ChangePrivilegeImpl(AniCloudData::AniSharing::ChangePrivilegeImpl);
TH_EXPORT_CPP_API_QueryParticipantsImpl(AniCloudData::AniSharing::QueryParticipantsImpl);
TH_EXPORT_CPP_API_QueryParticipantsByInvitationImpl(AniCloudData::AniSharing::QueryParticipantsByInvitationImpl);
TH_EXPORT_CPP_API_ConfirmInvitationImpl(AniCloudData::AniSharing::ConfirmInvitationImpl);
TH_EXPORT_CPP_API_ChangeConfirmationImpl(AniCloudData::AniSharing::ChangeConfirmationImpl);
// NOLINTEND

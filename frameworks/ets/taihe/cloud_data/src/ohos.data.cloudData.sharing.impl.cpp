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
#include "ani_cloud_data_config.h"
#include "ani_cloud_data_sharing.h"
#include "ani_error_code.h"
#include "rdb_predicates_impl.h"
#include "cache_result_set.h"
#include "ani_cloud_data_utils.h"
#include "result_set_impl.h"

namespace AniCloudData {
namespace AniSharing {
using namespace OHOS::Rdb;

ResultSet AllocResourceAndSharePromise(string_view storeId, const TaiHeRdbPredicates &predicates,
    array_view<TaiHeParticipant> participants, optional_view<array<string>> columns)
{
    if (storeId.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of storeId must be string and not empty.");
        return taihe::make_holder<OHOS::RdbTaihe::ResultSetImpl, ResultSet>();
    }
    if (participants.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT,
            "The type of participants must be Array<Participant> and not empty.");
        return taihe::make_holder<OHOS::RdbTaihe::ResultSetImpl, ResultSet>();
    }
    std::optional<std::pair<int32_t, std::vector<OHOS::NativeRdb::ValuesBucket>>> result;
    auto work = [&storeId, &predicates, &participants, &columns, &result](std::shared_ptr<CloudService> proxy) {
        Participants info = ConvertParticipant(participants);
        std::vector<std::string> realColumns;
        if (columns.has_value()) {
            for (auto it = columns.value().begin(); it != columns.value().end(); ++it) {
                realColumns.push_back(it->c_str());
            }
        }
        OHOS::RdbTaihe::RdbPredicatesImpl* impl = reinterpret_cast<OHOS::RdbTaihe::RdbPredicatesImpl*>(
            predicates->GetSpecificImplPtr());
        if (impl == nullptr) {
            LOG_ERROR("RdbPredicatesImpl is nullptr");
            return;
        }
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

ResultSet AllocResourceAndShareImpl(string_view storeId, TaiHeRdbPredicates predicates,
    array_view<TaiHeParticipant> participants)
{
    return AllocResourceAndSharePromise(storeId, predicates, participants, optional_view<array<string>>(std::nullopt));
}

ResultSet AllocResourceAndShareImplWithColumns(string_view storeId, TaiHeRdbPredicates predicates,
    array_view<TaiHeParticipant> participants, array_view<string> columns)
{
    optional_view<array<string>> realColumns = optional<array<string>>(std::in_place, columns);
    return AllocResourceAndSharePromise(storeId, predicates, participants, realColumns);
}

TaiHeResult ShareImpl(string_view sharingResource, array_view<TaiHeParticipant> participants)
{
    TaiHeResult ret;
    if (sharingResource.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of sharingRes must be string and not empty.");
        return ret;
    }
    if (participants.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT,
            "The type of participants must be Array<Participant> and not empty.");
        return ret;
    }
    auto work = [&sharingResource, &participants, &ret](std::shared_ptr<CloudService> proxy) {
        Results ipcRet;
        Participants info = ConvertParticipant(participants);
        int32_t code = proxy->Share(std::string(sharingResource), info, ipcRet);
        if (code == CloudService::Status::SUCCESS) {
            ret = ConvertResults(ipcRet);
        } else {
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
    return ret;
}

TaiHeResult UnshareImpl(string_view sharingResource, array_view<TaiHeParticipant> participants)
{
    TaiHeResult ret;
    if (sharingResource.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of sharingRes must be string and not empty.");
        return ret;
    }
    if (participants.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT,
            "The type of participants must be Array<Participant> and not empty.");
        return ret;
    }
    auto work = [&sharingResource, &participants, &ret](std::shared_ptr<CloudService> proxy) {
        Results ipcRet;
        Participants info = ConvertParticipant(participants);
        int32_t code = proxy->Unshare(std::string(sharingResource), info, ipcRet);
        if (code == CloudService::Status::SUCCESS) {
            ret = ConvertResults(ipcRet);
        } else {
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
    return ret;
}

TaiHeResult ExitImpl(string_view sharingResource)
{
    TaiHeResult ret;
    if (sharingResource.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of sharingRes must be string and not empty.");
        return ret;
    }
    auto work = [&sharingResource, &ret](std::shared_ptr<CloudService> proxy) {
        std::pair<int32_t, std::string> ipcRet;
        int32_t code = proxy->Exit(std::string(sharingResource), ipcRet);
        if (code == CloudService::Status::SUCCESS) {
            ret.code = ipcRet.first;
            ret.description = optional<string>(std::in_place, ipcRet.second);
        } else {
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
    return ret;
}

TaiHeResult ChangePrivilegeImpl(string_view sharingResource, array_view<TaiHeParticipant> participants)
{
    TaiHeResult ret;
    if (sharingResource.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of sharingRes must be string and not empty.");
        return ret;
    }
    if (participants.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT,
            "The type of participants must be Array<Participant> and not empty.");
        return ret;
    }
    auto work = [&sharingResource, &participants, &ret](std::shared_ptr<CloudService> proxy) {
        Results ipcRet;
        Participants info = ConvertParticipant(participants);
        int32_t code = proxy->ChangePrivilege(std::string(sharingResource), info, ipcRet);
        if (code == CloudService::Status::SUCCESS) {
            ret = ConvertResults(ipcRet);
        } else {
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
    return ret;
}

TaiHeResult QueryParticipantsImpl(string_view sharingResource)
{
    TaiHeResult ret;
    if (sharingResource.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of sharingRes must be string and not empty.");
        return ret;
    }
    auto work = [&sharingResource, &ret](std::shared_ptr<CloudService> proxy) {
        QueryResults ipcRet;
        int32_t code = proxy->Query(std::string(sharingResource), ipcRet);
        if (code == CloudService::Status::SUCCESS) {
            ret = ConvertQueryResults(ipcRet);
        } else {
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
    return ret;
}

TaiHeResult QueryParticipantsByInvitationImpl(string_view invitationCode)
{
    TaiHeResult ret;
    if (invitationCode.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT,
            "The type of invitationCode must be string and not empty.");
        return ret;
    }
    auto work = [&invitationCode, &ret](std::shared_ptr<CloudService> proxy) {
        QueryResults ipcRet;
        int32_t code = proxy->QueryByInvitation(std::string(invitationCode), ipcRet);
        if (code == CloudService::Status::SUCCESS) {
            ret = ConvertQueryResults(ipcRet);
        } else {
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
    return ret;
}

TaiHeResult ConfirmInvitationImpl(string_view invitationCode, State state)
{
    TaiHeResult ret;
    if (invitationCode.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT,
            "The type of invitationCode must be string and not empty.");
        return ret;
    }
    if (state.get_value() <= Confirmation::CFM_NIL || state.get_value() > Confirmation::CFM_BUTT) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of status must be Status.");
        return ret;
    }
    auto work = [&invitationCode, &state, &ret](std::shared_ptr<CloudService> proxy) {
        std::tuple<int32_t, std::string, std::string> ipcRet;
        int32_t code = proxy->ConfirmInvitation(std::string(invitationCode), state.get_value(), ipcRet);
        if (code == CloudService::Status::SUCCESS) {
            ret.code = std::get<0>(ipcRet);
            ret.description = optional<string>(std::in_place, std::get<1>(ipcRet));
            std::string strValue = std::get<2>(ipcRet); // 2 is of std::string type
            ret.value = optional<ResultValue>(std::in_place, ResultValue::make_stringValue(strValue));
        } else {
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
    return ret;
}

TaiHeResult ChangeConfirmationImpl(string_view sharingResource, State state)
{
    TaiHeResult ret;
    if (sharingResource.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT,
            "The type of sharingResource must be string and not empty.");
        return ret;
    }
    if (!(state.get_value() > Confirmation::CFM_NIL && state.get_value() <= Confirmation::CFM_BUTT)) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of status must be Status.");
        return ret;
    }
    auto work = [&sharingResource, &state, &ret](std::shared_ptr<CloudService> proxy) {
        std::pair<int32_t, std::string> ipcRet;
        int32_t code = proxy->ChangeConfirmation(std::string(sharingResource), state.get_value(), ipcRet);
        if (code == CloudService::Status::SUCCESS) {
            ret.code = ipcRet.first;
            ret.description = optional<string>(std::in_place, ipcRet.second);
        } else {
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
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

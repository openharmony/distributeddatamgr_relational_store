/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifndef OHOS_RELATION_STORE_ANI_CLOUD_DATA_SHARING_H
#define OHOS_RELATION_STORE_ANI_CLOUD_DATA_SHARING_H
#include <functional>
#include "ohos.data.cloudData.sharing.proj.hpp"
#include "ohos.data.cloudData.sharing.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"
#include "cloud_service.h"
#include "cloud_manager.h"

namespace AniCloudData {
namespace AniSharing {
using TaiHeRdbPredicates = ::ohos::data::relationalStore::weak::RdbPredicates;
ResultSet AllocResourceAndSharePromise(string_view storeId, const TaiHeRdbPredicates &predicates,
    array_view<TaiHeParticipant> participants, optional_view<array<string>> columns);
ResultSet AllocResourceAndShareImpl(string_view storeId, TaiHeRdbPredicates predicates,
    array_view<TaiHeParticipant> participants);
ResultSet AllocResourceAndShareImplWithColumns(string_view storeId, TaiHeRdbPredicates predicates,
    array_view<TaiHeParticipant> participants, array_view<string> columns);
TaiHeResult ShareImpl(string_view sharingResource, array_view<TaiHeParticipant> participants);
TaiHeResult UnshareImpl(string_view sharingResource, array_view<TaiHeParticipant> participants);
TaiHeResult ExitImpl(string_view sharingResource);
TaiHeResult ChangePrivilegeImpl(string_view sharingResource, array_view<TaiHeParticipant> participants);
TaiHeResult QueryParticipantsImpl(string_view sharingResource);
TaiHeResult QueryParticipantsByInvitationImpl(string_view invitationCode);
TaiHeResult ConfirmInvitationImpl(string_view invitationCode, State state);
TaiHeResult ChangeConfirmationImpl(string_view sharingResource, State state);
} // namespace AniSharing
} // namespace AniCloudData
#endif
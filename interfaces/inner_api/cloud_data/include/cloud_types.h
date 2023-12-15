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

#ifndef OHOS_DISTRIBUTED_DATA_CLOUD_CLOUD_TYPES_H
#define OHOS_DISTRIBUTED_DATA_CLOUD_CLOUD_TYPES_H

#include <string>

namespace OHOS::CloudData {
enum Role : int32_t {
    ROLE_NIL = -1,
    ROLE_INVITER,
    ROLE_INVITEE,
    ROLE_BUTT
};

enum Confirmation : int32_t {
    CFM_NIL = -1,
    CFM_UNKNOWN,
    CFM_ACCEPTED,
    CFM_REJECTED,
    CFM_SUSPENDED,
    CFM_BUTT
};

struct Privilege {
    bool writable = false;
    bool readable = false;
    bool creatable = false;
    bool deletable = false;
    bool shareable = false;
};

struct Participant {
    std::string identity;
    int32_t role = Role::ROLE_NIL;
    int32_t state = Confirmation::CFM_NIL;
    Privilege privilege;
    std::string attachInfo;
};

using Participants = std::vector<Participant>;
using Results = std::tuple<int32_t, std::string, std::vector<std::pair<int32_t, std::string>>>;
using QueryResults = std::tuple<int32_t, std::string, Participants>;

constexpr const char *DATA_CHANGE_EVENT_ID = "cloud_data_change";

/**
 * Enumerates the error code of sharing invitation.
 */
enum SharingCode : int32_t {
    /**
     * @brief means sharing success.
     */
    SUCCESS = 0,

    /**
     * @brief means the user has been invited.
     */
    REPEATED_REQUEST,

    /**
     * @brief means the participant is not inviter.
     */
    NOT_INVITER,

    /**
     * @brief means the participant is not inviter or invitee.
     */
    NOT_INVITER_OR_INVITEE,

    /**
     * @brief means the number of sharing times today of current user has reached maximum.
     */
    OVER_QUOTA,

    /**
     * @brief means the number of participants reaches the maximum.
     */
    TOO_MANY_PARTICIPANTS,

    /**
     * @brief means invalid arguments.
     */
    INVALID_ARGS,

    /**
     * @brief means the network is unavailable.
     */
    NETWORK_ERROR,

    /**
     * @brief means cloud is disabled.
     */
    CLOUD_DISABLED,

    /**
     * @brief means invoke cloud space failed.
     */
    SERVER_ERROR,

    /**
     * @brief means an unknown error has occurred.
     */
    INNER_ERROR,

    /**
     * @brief means the invitation has expired or does not exist.
     */
    INVALID_INVITATION,

    /**
     * @brief means the data transfer is rate-limited.
     */
    RATE_LIMIT,

    /**
     * @brief means error codes that exceed this enumerated value are custom error codes.
     */
    CUSTOM_ERROR = 1000,
};
} // namespace OHOS::CloudData
#endif // OHOS_DISTRIBUTED_DATA_CLOUD_CLOUD_TYPES_H
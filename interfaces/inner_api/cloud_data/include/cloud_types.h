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

#include <map>
#include <string>
#include <tuple>
#include <vector>

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
    CFM_UNAVAILABLE,
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

struct StatisticInfo {
    std::string table;
    int32_t inserted = 0;
    int32_t updated = 0;
    int32_t normal = 0;
};

struct QueryKey {
    int32_t user;
    std::string accountId;
    std::string bundleName;
    std::string storeId;
    bool operator<(const QueryKey &queryKey) const
    {
        return std::tie(accountId, user, bundleName, storeId) <
            std::tie(queryKey.accountId, queryKey.user, queryKey.bundleName, queryKey.storeId);
    }
};

enum SyncStatus : int32_t {
    RUNNING,
    FINISHED
};

struct CloudSyncInfo {
    int64_t startTime = 0;
    int64_t finishTime = 0;
    int32_t code = -1;
    int32_t syncStatus = SyncStatus::RUNNING;
};

using StatisticInfos = std::vector<StatisticInfo>;
using Participants = std::vector<Participant>;
using Results = std::tuple<int32_t, std::string, std::vector<std::pair<int32_t, std::string>>>;
using QueryResults = std::tuple<int32_t, std::string, Participants>;
using QueryLastResults = std::map<std::string, CloudSyncInfo>;

struct BundleInfo {
    std::string bundleName;
    std::string storeId;
    bool operator==(const BundleInfo &info) const
    {
        return std::tie(bundleName, storeId) == std::tie(info.bundleName, info.storeId);
    }
};

using BatchQueryLastResults = std::map<std::string, QueryLastResults>;

class ISyncInfoObserver {
public:
    virtual ~ISyncInfoObserver() = default;
    virtual void OnSyncInfoChanged(const std::map<std::string, QueryLastResults> &data) {};
    virtual void OnSyncInfoChanged(const int32_t mode) {};
};

constexpr const char *DATA_CHANGE_EVENT_ID = "cloud_data_change";

enum class CloudSubscribeType : int32_t {
    SYNC_INFO_CHANGED = 0,
    SUBSCRIBE_TYPE_MAX
};

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

enum Strategy : uint32_t {
    STRATEGY_HEAD,
    STRATEGY_NETWORK = STRATEGY_HEAD,
    STRATEGY_BUTT
};

enum NetWorkStrategy : uint32_t {
    WIFI = 0x01,
    CELLULAR = 0x02,
    NETWORK_STRATEGY_BUTT
};

struct DBSwitchInfo {
    bool enable = true;
    std::map<std::string, bool> tableInfo;
};

struct SwitchConfig {
    std::map<std::string, DBSwitchInfo> dbInfo;
};

struct DBActionInfo {
    int32_t action;
    std::map<std::string, int32_t> tableInfo;
};

struct ClearConfig {
    std::map<std::string, DBActionInfo> dbInfo;
};
enum CloudSyncScene : int32_t {
    /**
    * @brief Enable cloud sync
    */
    ENABLE_CLOUD = 0,
    
    /**
    * @brief Disable cloud sync
    */
    DISABLE_CLOUD = 1,
    
    /**
    * @brief Switch on app cloud sync
    */
    SWITCH_ON = 2,
    
    /**
    * @brief Switch off app cloud sync
    */
    SWITCH_OFF = 3,
    
    /**
    * @brief Query sync info
    */
    QUERY_SYNC_INFO = 4,
    
    /**
    * @brief User change
    */
    USER_CHANGE = 5,
    
    /**
    * @brief User unlock
    */
    USER_UNLOCK = 6,
    
    /**
    * @brief Network recovery
    */
    NETWORK_RECOVERY = 7,
    
    /**
    * @brief Service initialization
    */
    SERVICE_INIT = 8,
    
    /**
    * @brief Account stop
    */
    ACCOUNT_STOP = 9,
    /**
    * @brief Push from server
    */
    PUSH = 10,
};

enum TriggerScene : int32_t {
    /**
    * @brief Trigger when enable cloud sync
    */
    TRIGGER_ENABLE_CLOUD = 0,
    
    /**
    * @brief Trigger when switch on app cloud sync
    */
    TRIGGER_SWITCH_ON = 1,

    /**
    * @brief Trigger when network recovery
    */
    TRIGGER_NETWORK_RECOVERY = 2,
   
    /**
    * @brief Trigger when p from server
    */
    TRIGGER_PUSH = 3,

    /**
    * @brief Trigger when user change
    */
    TRIGGER_USER_CHANGE = 4,
};

} // namespace OHOS::CloudData
#endif // OHOS_DISTRIBUTED_DATA_CLOUD_CLOUD_TYPES_H
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

#ifndef OHOS_DISTRIBUTED_DATA_CLOUD_CLOUD_SERVICE_H
#define OHOS_DISTRIBUTED_DATA_CLOUD_CLOUD_SERVICE_H
#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include "cloud_types.h"
#include "common_types.h"
#include "rdb_types.h"
#include "values_bucket.h"
namespace OHOS {
namespace CloudData {
class CloudService {
public:
    enum TransId : int32_t {
        TRANS_HEAD,
        TRANS_CONFIG_HEAD = TRANS_HEAD,
        TRANS_ENABLE_CLOUD = TRANS_CONFIG_HEAD,
        TRANS_DISABLE_CLOUD,
        TRANS_CHANGE_APP_SWITCH,
        TRANS_CLEAN,
        TRANS_NOTIFY_DATA_CHANGE,
        TRANS_NOTIFY_DATA_CHANGE_EXT,
        TRANS_QUERY_STATISTICS,
        TRANS_QUERY_LAST_SYNC_INFO,
        TRANS_SET_GLOBAL_CLOUD_STRATEGY,
        TRANS_CONFIG_BUTT,
        TRANS_SHARE_HEAD = TRANS_CONFIG_BUTT,
        TRANS_ALLOC_RESOURCE_AND_SHARE = TRANS_SHARE_HEAD,
        TRANS_SHARE,
        TRANS_UNSHARE,
        TRANS_EXIT,
        TRANS_CHANGE_PRIVILEGE,
        TRANS_QUERY,
        TRANS_QUERY_BY_INVITATION,
        TRANS_CONFIRM_INVITATION,
        TRANS_CHANGE_CONFIRMATION,
        TRANS_SHARE_BUTT,
        TRANS_CLIENT_HEAD = TRANS_SHARE_BUTT,
        TRANS_SET_CLOUD_STRATEGY = TRANS_CLIENT_HEAD,
        TRANS_CLIENT_BUTT,
        TRANS_BUTT = TRANS_CLIENT_BUTT,
    };
    enum Action : int32_t {
        CLEAR_CLOUD_INFO,
        CLEAR_CLOUD_DATA_AND_INFO,
        CLEAR_CLOUD_BUTT
    };

    enum Switch : int32_t {
        SWITCH_ON,
        SWITCH_OFF
    };

    enum Status : int32_t {
        SUCCESS = 0,
        ERROR,
        INVALID_ARGUMENT,
        SERVER_UNAVAILABLE,
        FEATURE_UNAVAILABLE,
        NOT_SUPPORT,
        CLOUD_DISABLE,
        CLOUD_DISABLE_SWITCH,
        IPC_ERROR,
        IPC_PARCEL_ERROR,
        PERMISSION_DENIED,
        CLOUD_CONFIG_PERMISSION_DENIED
    };

    static const int INVALID_USER_ID = -1;

    virtual ~CloudService() = default;
    virtual int32_t EnableCloud(const std::string &id, const std::map<std::string, int32_t> &switches) = 0;
    virtual int32_t DisableCloud(const std::string &id) = 0;
    virtual int32_t ChangeAppSwitch(const std::string &id, const std::string &bundleName, int32_t appSwitch) = 0;
    virtual int32_t Clean(const std::string &id, const std::map<std::string, int32_t> &actions) = 0;
    virtual int32_t NotifyDataChange(const std::string &id, const std::string &bundleName) = 0;
    virtual int32_t NotifyDataChange(const std::string &eventId, const std::string &extraData, int32_t userId) = 0;
    virtual std::pair<int32_t, std::map<std::string, StatisticInfos>> QueryStatistics(const std::string &id,
        const std::string &bundleName, const std::string &storeId) = 0;
    virtual int32_t SetGlobalCloudStrategy(Strategy strategy, const std::vector<CommonType::Value>& values) = 0;

    virtual std::pair<int32_t, std::vector<NativeRdb::ValuesBucket>> AllocResourceAndShare(const std::string &storeId,
        const DistributedRdb::PredicatesMemo &predicates, const std::vector<std::string> &columns,
        const Participants &participants) = 0;
    virtual int32_t Share(const std::string &sharingRes, const Participants &participants, Results &results) = 0;
    virtual int32_t Unshare(const std::string &sharingRes, const Participants &participants, Results &results) = 0;
    virtual int32_t Exit(const std::string &sharingRes, std::pair<int32_t, std::string> &result) = 0;
    virtual int32_t ChangePrivilege(
        const std::string &sharingRes, const Participants &participants, Results &results) = 0;
    virtual int32_t Query(const std::string &sharingRes, QueryResults &results) = 0;
    virtual int32_t QueryByInvitation(const std::string &invitation, QueryResults &results) = 0;
    virtual int32_t ConfirmInvitation(const std::string &invitation, int32_t confirmation,
        std::tuple<int32_t, std::string, std::string> &result) = 0;
    virtual int32_t ChangeConfirmation(const std::string &sharingRes,
        int32_t confirmation, std::pair<int32_t, std::string> &result) = 0;

    virtual int32_t SetCloudStrategy(Strategy strategy, const std::vector<CommonType::Value>& values) = 0;
    virtual std::pair<int32_t, QueryLastResults> QueryLastSyncInfo(
        const std::string &id, const std::string &bundleName, const std::string &storeId) = 0;

    inline static constexpr const char *SERVICE_NAME = "cloud";
};
} // namespace CloudData
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DATA_CLOUD_CLOUD_SERVICE_H
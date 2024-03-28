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

#ifndef OHOS_DISTRIBUTED_DATA_CLOUD_CLOUD_SERVICE_PROXY_H
#define OHOS_DISTRIBUTED_DATA_CLOUD_CLOUD_SERVICE_PROXY_H

#include "icloud_service.h"
#include "iremote_object.h"
#include "iremote_proxy.h"

namespace OHOS::CloudData {
class CloudServiceProxy : public IRemoteProxy<ICloudService> {
public:
    explicit CloudServiceProxy(const sptr<IRemoteObject> &object);
    virtual ~CloudServiceProxy() = default;
    int32_t EnableCloud(const std::string &id, const std::map<std::string, int32_t> &switches) override;
    int32_t DisableCloud(const std::string &id) override;
    int32_t ChangeAppSwitch(const std::string &id, const std::string &bundleName, int32_t appSwitch) override;
    int32_t Clean(const std::string &id, const std::map<std::string, int32_t> &actions) override;
    int32_t NotifyDataChange(const std::string &id, const std::string &bundleName) override;
    int32_t NotifyDataChange(const std::string &eventId, const std::string &extraData, int32_t userId) override;
    std::pair<int32_t, std::map<std::string, StatisticInfos>> QueryStatistics(const std::string& id,
        const std::string& bundleName, const std::string& storeId) override;
    int32_t SetGlobalCloudStrategy(Strategy strategy, const std::vector<CommonType::Value>& values) override;

    std::pair<int32_t, std::vector<NativeRdb::ValuesBucket>> AllocResourceAndShare(const std::string& storeId,
        const DistributedRdb::PredicatesMemo& predicates, const std::vector<std::string>& columns,
        const Participants& participants) override;
    int32_t Share(const std::string &sharingRes, const Participants &participants, Results &results) override;
    int32_t Unshare(const std::string &sharingRes, const Participants &participants, Results &results) override;
    int32_t Exit(const std::string &sharingRes, std::pair<int32_t, std::string> &result) override;
    int32_t ChangePrivilege(
        const std::string &sharingRes, const Participants &participants, Results &results) override;
    int32_t Query(const std::string &sharingRes, QueryResults &results) override;
    int32_t QueryByInvitation(const std::string &invitation, QueryResults &results) override;
    int32_t ConfirmInvitation(const std::string &invitation,
        int32_t confirmation, std::tuple<int32_t, std::string, std::string> &result) override;
    int32_t ChangeConfirmation(const std::string &sharingRes,
        int32_t confirmation, std::pair<int32_t, std::string> &result) override;

    int32_t SetCloudStrategy(Strategy strategy, const std::vector<CommonType::Value>& values) override;
    std::pair<int32_t, QueryLastResults> QueryLastSyncInfo(
        const std::string &id, const std::string &bundleName, const std::string &storeId) override;

private:
    sptr<IRemoteObject> remote_;
};
} // namespace OHOS::CloudData
#endif // OHOS_DISTRIBUTED_DATA_CLOUD_CLOUD_SERVICE_PROXY_H
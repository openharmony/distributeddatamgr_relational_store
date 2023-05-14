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

private:
    sptr<IRemoteObject> remote_;
};
} // namespace OHOS::CloudData
#endif // OHOS_DISTRIBUTED_DATA_CLOUD_CLOUD_SERVICE_PROXY_H

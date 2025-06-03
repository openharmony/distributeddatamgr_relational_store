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

#ifndef OHOS_DISTRIBUTED_DATA_DATA_MGR_SERVICE_H
#define OHOS_DISTRIBUTED_DATA_DATA_MGR_SERVICE_H

#include "cloud_service.h"
#include "icloud_service.h"
#include "iremote_proxy.h"

namespace OHOS::CloudData {
class DataMgrService : public IRemoteProxy<CloudData::IKvStoreDataService> {
public:
    explicit DataMgrService(const sptr<IRemoteObject> &impl);
    ~DataMgrService() = default;
    sptr<IRemoteObject> GetFeatureInterface(const std::string &name) override;
    int32_t RegisterClientDeathObserver(const std::string &bundleName, sptr<IRemoteObject> observer) override;
};
} // namespace OHOS::CloudData
#endif // OHOS_DISTRIBUTED_DATA_DATA_MGR_SERVICE_H

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

#ifndef OHOS_DISTRIBUTED_DATA_CLOUD_ICLOUD_CLIENT_DEATH_OBSERVER_H
#define OHOS_DISTRIBUTED_DATA_CLOUD_ICLOUD_CLIENT_DEATH_OBSERVER_H

#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"

namespace OHOS::CloudData {
class ICloudClientDeathObserver : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.CloudData.ICloudClientDeathObserver");
};

class CloudClientDeathObserverStub : public IRemoteStub<ICloudClientDeathObserver> {
public:
    CloudClientDeathObserverStub();
    ~CloudClientDeathObserverStub();
};

class CloudClientDeathObserverProxy : public IRemoteProxy<ICloudClientDeathObserver> {
public:
    explicit CloudClientDeathObserverProxy(const sptr<IRemoteObject> &impl)
        : IRemoteProxy<ICloudClientDeathObserver>(impl)
    {}
    ~CloudClientDeathObserverProxy() = default;
private:
    static inline BrokerDelegator<CloudClientDeathObserverProxy> delegator_;
};
} // namespace OHOS::CloudData
#endif // OHOS_DISTRIBUTED_DATA_CLOUD_ICLOUD_CLIENT_DEATH_OBSERVER_H

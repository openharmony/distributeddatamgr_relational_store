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

#ifndef RDB_DEVICE_MANAGER_ADAPTER_H
#define RDB_DEVICE_MANAGER_ADAPTER_H

#include "device_manager.h"
#include "device_manager_callback.h"

namespace OHOS {
namespace DeviceManagerAdaptor {
class RdbDeviceManagerAdaptor {
public:
    static RdbDeviceManagerAdaptor &GetInstance(const std::string &packageName);
    int GetEncryptedUuidByNetworkId(const std::string &networkId, std::string &uuid);

private:
    RdbDeviceManagerAdaptor(const std::string &packageName);
    ~RdbDeviceManagerAdaptor();

    void Init();
    void UnInit();

    std::string packageName_;
};

class InitDeviceManagerCallback final : public DistributedHardware::DmInitCallback {
public:
    InitDeviceManagerCallback() {};
    ~InitDeviceManagerCallback() {};
    void OnRemoteDied() override {};
};
}  // namespace DeviceManagerAdaptor
}  // namespace OHOS
#endif // RDB_DEVICE_MANAGER_ADAPTER_H

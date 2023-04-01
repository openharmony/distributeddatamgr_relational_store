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

#define LOG_TAG "RdbDeviceManagerAdaptor"

#include <string>

#include "rdb_device_manager_adapter.h"

namespace OHOS {
namespace DeviceManagerAdaptor {
using namespace OHOS::DistributedHardware;
constexpr int32_t DM_OK = 0;
constexpr int32_t DM_ERROR = -1;
RdbDeviceManagerAdaptor::RdbDeviceManagerAdaptor(const std::string &packageName)
    :packageName_(packageName)
{
    Init();
}

RdbDeviceManagerAdaptor::~RdbDeviceManagerAdaptor()
{
    UnInit();
}

RdbDeviceManagerAdaptor& RdbDeviceManagerAdaptor::GetInstance(const std::string &packageName)
{
    static RdbDeviceManagerAdaptor instance(packageName);
    return instance;
}

void RdbDeviceManagerAdaptor::Init()
{
    auto callback = std::make_shared<InitDeviceManagerCallback>();
    DeviceManager::GetInstance().InitDeviceManager(packageName_, callback);
}

void RdbDeviceManagerAdaptor::UnInit()
{
    DeviceManager::GetInstance().UnInitDeviceManager(packageName_);
}

int RdbDeviceManagerAdaptor::GetEncryptedUuidByNetworkId(const std::string &networkId, std::string &uuid)
{
    int ret = DeviceManager::GetInstance().GetEncryptedUuidByNetworkId(packageName_, networkId, uuid);
    if (ret != DM_OK) {
        return DM_ERROR;
    }
    return DM_OK;
}
} // namespace DeviceManagerAdaptor
} // namespace OHOS
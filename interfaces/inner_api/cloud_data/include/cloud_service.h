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
namespace OHOS::CloudData {
class CloudService {
public:
    enum TransId : int32_t {
        TRANS_HEAD,
        TRANS_ENABLE_CLOUD = TRANS_HEAD,
        TRANS_DISABLE_CLOUD,
        TRANS_CHANGE_APP_SWITCH,
        TRANS_CLEAN,
        TRANS_NOTIFY_DATA_CHANGE,
        TRANS_BUTT,
    };
    enum Action : int32_t { CLEAR_CLOUD_INFO, CLEAR_CLOUD_DATA_AND_INFO, CLEAR_CLOUD_BUTT };

    enum Switch : int32_t { SWITCH_ON, SWITCH_OFF };

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
        PERMISSION_DENIED
    };

    virtual ~CloudService() = default;
    virtual int32_t EnableCloud(const std::string &id, const std::map<std::string, int32_t> &switches) = 0;
    virtual int32_t DisableCloud(const std::string &id) = 0;
    virtual int32_t ChangeAppSwitch(const std::string &id, const std::string &bundleName, int32_t appSwitch) = 0;
    virtual int32_t Clean(const std::string &id, const std::map<std::string, int32_t> &actions) = 0;
    virtual int32_t NotifyDataChange(const std::string &id, const std::string &bundleName) = 0;

    inline static constexpr const char *SERVICE_NAME = "cloud";
};
} // namespace OHOS::CloudData
#endif // OHOS_DISTRIBUTED_DATA_CLOUD_CLOUD_SERVICE_H

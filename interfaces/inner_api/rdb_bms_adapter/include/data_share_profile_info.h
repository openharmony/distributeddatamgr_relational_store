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

#ifndef RDB_BMS_ADAPTER_PROFILE_INFO_H
#define RDB_BMS_ADAPTER_PROFILE_INFO_H

#include "bundle_info.h"
#include "data_properties.h"
#include "rdb_visibility.h"
#include "resource_manager.h"
#include "serializable.h"

namespace OHOS::RdbBMSAdapter {
using namespace OHOS::Global::Resource;
struct API_EXPORT Config final : public Serializable {
    std::string uri = "*";
    int crossUserMode = 0;
    std::string writePermission = "";
    std::string readPermission = "";
    bool Marshal(json &node) const override;
    bool Unmarshal(const json &node) override;
};

struct API_EXPORT ProfileInfo : public Serializable {
    std::vector<Config> tableConfig;
    bool Marshal(json &node) const override;
    bool Unmarshal(const json &node) override;
};

class API_EXPORT DataShareProfileInfo {
public:
    static bool GetResConfigFile(
        const AppExecFwk::ExtensionAbilityInfo &extensionInfo, std::vector<std::string> &profileInfos);

    static bool GetDataPropertiesFromProxyDatas(const OHOS::AppExecFwk::ProxyData &proxyData,
        const std::string &resourcePath, bool isCompressed, DataProperties &dataProperties);

private:
    static std::shared_ptr<ResourceManager> InitResMgr(const std::string &resourcePath);
    static std::vector<std::string> GetResProfileByMetadata(const std::vector<AppExecFwk::Metadata> &metadata,
        const std::string &resourcePath, bool isCompressed);
    static std::vector<std::string> GetResProfileByMetadata(const AppExecFwk::Metadata &metadata,
        const std::string &resourcePath, bool isCompressed);
    static std::vector<std::string> GetResFromResMgr(const std::string &resName, ResourceManager &resMgr,
        bool isCompressed);
    static std::string ReadProfile(const std::string &resPath);
    static bool IsFileExisted(const std::string &filePath);
};
} // namespace OHOS::RdbBMSAdapter
#endif // RDB_BMS_ADAPTER_PROFILE_INFO_H

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

#include "data_share_profile_info.h"

#include <algorithm>
#include <cerrno>
#include <fstream>
#include <sstream>
#include <unistd.h>

#include "logger.h"
#include "bundle_info.h"
#include "hilog/log.h"
namespace OHOS::RdbBMSAdapter {
using namespace OHOS::Rdb;

std::mutex DataShareProfileInfo::infosMutex_;

constexpr const char *DATA_SHARE_PROFILE_META = "ohos.extension.dataShare";
constexpr const char *PROFILE_FILE_PREFIX = "$profile:";
const size_t PROFILE_PREFIX_LEN = strlen(PROFILE_FILE_PREFIX);
bool Config::Marshal(json &node) const
{
    SetValue(node[GET_NAME(uri)], uri);
    SetValue(node[GET_NAME(crossUserMode)], crossUserMode);
    SetValue(node[GET_NAME(readPermission)], readPermission);
    SetValue(node[GET_NAME(writePermission)], writePermission);
    return true;
}

bool Config::Unmarshal(const json &node)
{
    bool ret = GetValue(node, GET_NAME(uri), uri);
    GetValue(node, GET_NAME(crossUserMode), crossUserMode);
    GetValue(node, GET_NAME(readPermission), readPermission);
    GetValue(node, GET_NAME(writePermission), writePermission);
    return ret;
}

bool ProfileInfo::Marshal(json &node) const
{
    SetValue(node[GET_NAME(tableConfig)], tableConfig);
    return true;
}

bool ProfileInfo::Unmarshal(const json &node)
{
    return GetValue(node, GET_NAME(tableConfig), tableConfig);
}

bool DataShareProfileInfo::GetResConfigFile(
    const AppExecFwk::ExtensionAbilityInfo &extensionInfo, std::vector<std::string> &profileInfos)
{
    bool isCompressed = !extensionInfo.hapPath.empty();
    std::string resourcePath = isCompressed ? extensionInfo.hapPath : extensionInfo.resourcePath;
    profileInfos = GetResProfileByMetadata(extensionInfo.metadata, resourcePath, isCompressed);
    if (profileInfos.empty()) {
        return false;
    }
    return true;
}

bool DataShareProfileInfo::GetDataPropertiesFromProxyDatas(const OHOS::AppExecFwk::ProxyData &proxyData,
    const std::string &resourcePath, bool isCompressed, DataProperties &dataProperties)
{
    std::vector<std::string> infos;
    infos = GetResProfileByMetadata(proxyData.metadata, resourcePath, isCompressed);
    if (infos.empty()) {
        return false;
    }
    return dataProperties.Unmarshall(infos[0]);
}

std::vector<std::string> DataShareProfileInfo::GetResProfileByMetadata(
    const AppExecFwk::Metadata &metadata, const std::string &resourcePath, bool isCompressed)
{
    std::vector<std::string> infos;
    if (metadata.name.empty() || resourcePath.empty()) {
        return infos;
    }
    std::shared_ptr<ResourceManager> resMgr = InitResMgr(resourcePath);
    if (resMgr == nullptr) {
        return infos;
    }
    if (metadata.name == "dataProperties") {
        infos = GetResFromResMgr(metadata.resource, *resMgr, isCompressed);
    }
    return infos;
}

std::vector<std::string> DataShareProfileInfo::GetResProfileByMetadata(
    const std::vector<AppExecFwk::Metadata> &metadata, const std::string &resourcePath, bool isCompressed)
{
    std::vector<std::string> profileInfos;
    if (metadata.empty() || resourcePath.empty()) {
        return profileInfos;
    }
    std::shared_ptr<ResourceManager> resMgr = InitResMgr(resourcePath);
    if (resMgr == nullptr) {
        return profileInfos;
    }

    auto it = std::find_if(metadata.begin(), metadata.end(), [](AppExecFwk::Metadata meta) {
        return meta.name == DATA_SHARE_PROFILE_META;
    });
    if (it != metadata.end()) {
        return GetResFromResMgr((*it).resource, *resMgr, isCompressed);
    }

    return profileInfos;
}

std::shared_ptr<ResourceManager> DataShareProfileInfo::InitResMgr(const std::string &resourcePath)
{
    std::lock_guard<std::mutex> lock(infosMutex_);
    static std::shared_ptr<ResourceManager> resMgr(CreateResourceManager());
    if (resMgr == nullptr) {
        return nullptr;
    }

    std::unique_ptr<ResConfig> resConfig(CreateResConfig());
    if (resConfig == nullptr) {
        return nullptr;
    }
    resMgr->UpdateResConfig(*resConfig);
    resMgr->AddResource(resourcePath.c_str());
    return resMgr;
}

std::vector<std::string> DataShareProfileInfo::GetResFromResMgr(
    const std::string &resName, ResourceManager &resMgr, bool isCompressed)
{
    std::vector<std::string> profileInfos;
    if (resName.empty()) {
        return profileInfos;
    }

    size_t pos = resName.rfind(PROFILE_FILE_PREFIX);
    if ((pos == std::string::npos) || (pos == resName.length() - PROFILE_PREFIX_LEN)) {
        LOG_ERROR("res name invalid, resName is %{public}s", resName.c_str());
        return profileInfos;
    }
    std::string profileName = resName.substr(pos + PROFILE_PREFIX_LEN);
    // hap is compressed status, get file content.
    if (isCompressed) {
        LOG_DEBUG("compressed status.");
        std::unique_ptr<uint8_t[]> fileContent = nullptr;
        size_t len = 0;
        RState ret = resMgr.GetProfileDataByName(profileName.c_str(), len, fileContent);
        if (ret != SUCCESS || fileContent == nullptr) {
            LOG_ERROR("failed, ret is %{public}d, profileName is %{public}s", ret, profileName.c_str());
            return profileInfos;
        }
        if (len == 0) {
            LOG_ERROR("fileContent is empty, profileName is %{public}s", profileName.c_str());
            return profileInfos;
        }
        std::string rawData(fileContent.get(), fileContent.get() + len);
        if (!Config::IsJson(rawData)) {
            LOG_ERROR("rawData is not json, profileName is %{public}s", profileName.c_str());
            return profileInfos;
        }
        profileInfos.push_back(std::move(rawData));
        return profileInfos;
    }
    // hap is decompressed status, get file path then read file.
    std::string resPath;
    RState ret = resMgr.GetProfileByName(profileName.c_str(), resPath);
    if (ret != SUCCESS) {
        LOG_ERROR("profileName not found, ret is %{public}d, profileName is %{public}s", ret, profileName.c_str());
        return profileInfos;
    }
    std::string profile = ReadProfile(resPath);
    if (profile.empty()) {
        LOG_ERROR("Read profile failed, resPath is %{public}s", resPath.c_str());
        return profileInfos;
    }
    profileInfos.push_back(std::move(profile));
    return profileInfos;
}

bool DataShareProfileInfo::IsFileExisted(const std::string &filePath)
{
    if (filePath.empty()) {
        return false;
    }
    if (access(filePath.c_str(), F_OK) != 0) {
        LOG_ERROR("can not access file, errno is %{public}d, filePath is %{public}s", errno, filePath.c_str());
        return false;
    }
    return true;
}

std::string DataShareProfileInfo::ReadProfile(const std::string &resPath)
{
    if (!IsFileExisted(resPath)) {
        return "";
    }
    std::fstream in;
    in.open(resPath, std::ios_base::in | std::ios_base::binary);
    if (!in.is_open()) {
        LOG_ERROR("the file can not open, errno is %{public}d", errno);
        return "";
    }
    in.seekg(0, std::ios::end);
    int64_t size = in.tellg();
    if (size <= 0) {
        LOG_ERROR("the file is empty, resPath is %{public}s", resPath.c_str());
        return "";
    }
    in.seekg(0, std::ios::beg);
    std::ostringstream tmp;
    tmp << in.rdbuf();
    return tmp.str();
}
} // namespace OHOS::RdbBMSAdapter
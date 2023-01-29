/*
* Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "security_policy.h"

#include "logger.h"
#include "rdb_errno.h"
#include "security_label.h"

namespace OHOS {
namespace NativeRdb {
int SecurityPolicy::SetFileSecurityLevel(const std::string &filePath, const std::string &securityLevel)
{
    bool result = DistributedFS::ModuleSecurityLabel::SecurityLabel::SetSecurityLabel(filePath, securityLevel);
    return result ? E_OK : E_ERROR;
}

std::string SecurityPolicy::GetSecurityLevelValue(SecurityLevel securityLevel)
{
    switch (securityLevel) {
        case SecurityLevel::S1:
            return "s1";
        case SecurityLevel::S2:
            return "s2";
        case SecurityLevel::S3:
            return "s3";
        case SecurityLevel::S4:
            return "s4";
        default:
            return "";
    }
}

std::string SecurityPolicy::GetFileSecurityLevel(const std::string &filePath)
{
    return DistributedFS::ModuleSecurityLabel::SecurityLabel::GetSecurityLabel(filePath);
}

int SecurityPolicy::SetSecurityLabel(const RdbStoreConfig &config)
{
    if (config.GetStorageMode() != StorageMode::MODE_MEMORY && config.GetSecurityLevel() != SecurityLevel::LAST) {
        std::string currentLevel = GetFileSecurityLevel(config.GetPath());
        std::string toSetLevel = GetSecurityLevelValue(config.GetSecurityLevel());
        if (currentLevel.empty()) {
            return SetFileSecurityLevel(config.GetPath(), toSetLevel);
        }
        return currentLevel == toSetLevel ? E_OK : E_ERROR;
    }
    return E_OK;
}
} // namespace NativeRdb
} // namespace OHOS
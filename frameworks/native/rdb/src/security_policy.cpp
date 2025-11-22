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
#define LOG_TAG "SecurityPolicy"
#include "security_policy.h"

#include "logger.h"
#include "rdb_errno.h"
#include "security_label.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using namespace FileManagement::ModuleSecurityLabel;
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
    return SecurityLabel::GetSecurityLabel(filePath);
}

int SecurityPolicy::SetSecurityLabel(const RdbStoreConfig &config)
{
    if (config.GetStorageMode() != StorageMode::MODE_MEMORY && config.GetSecurityLevel() != SecurityLevel::LAST) {
        auto toSetLevel = GetSecurityLevelValue(config.GetSecurityLevel());
        auto errCode = SecurityLabel::SetSecurityLabel(config.GetPath(), toSetLevel) ? E_OK : E_CONFIG_INVALID_CHANGE;
        if (errCode != E_OK) {
            auto setLabelErrno = errno;
            auto currentLevel = GetFileSecurityLevel(config.GetPath());
            LOG_ERROR("storeName:%{public}s SetSecurityLabel failed. Set security level from %{public}s to %{public}s,"
                      "result:%{public}d, setLabelErrno:%{public}d, errno:%{public}d.",
                SqliteUtils::Anonymous(config.GetName()).c_str(), currentLevel.c_str(), toSetLevel.c_str(), errCode,
                setLabelErrno, errno);
        }
        return errCode;
    }
    return E_OK;
}
} // namespace NativeRdb
} // namespace OHOS
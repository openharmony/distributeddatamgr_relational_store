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

#ifndef DISTRIBUTEDDATAMGR_RELATIONAL_STORE_SLAGAIN_SECURITY_POLICY_H
#define DISTRIBUTEDDATAMGR_RELATIONAL_STORE_SLAGAIN_SECURITY_POLICY_H

#include "rdb_store_config.h"

namespace OHOS {
namespace NativeRdb {
class SecurityPolicy {
public:
    static int SetSecurityLabel(const RdbStoreConfig &config);

private:
    inline static std::string GetSecurityLevelValue(SecurityLevel securityLevel);
    inline static std::string GetFileSecurityLevel(const std::string &filePath);
};
} // namespace NativeRdb
} // namespace OHOS
#endif

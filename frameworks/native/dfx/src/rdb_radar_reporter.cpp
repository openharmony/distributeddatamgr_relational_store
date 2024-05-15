/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "rdb_radar_reporter.h"
#include "rdb_errno.h"
#include "hisysevent.h"
#include "ipc_skeleton.h"
#include "accesstoken_kit.h"

namespace OHOS::NativeRdb {

using namespace Security::AccessToken;

bool RdbRadar::hasHostPkg_ = false;
std::string RdbRadar::hostPkg_{ "" };

RdbRadar::RdbRadar(Scene scene, const char* funcName, std::string bundleName) : scene_(scene), funcName_(funcName)
{
    if (funcName_ == nullptr) {
        funcName_ = UNKNOW;
    }
    GetHostPkgInfo(bundleName);
    LocalReport(scene_, funcName_, STATE_START);
}

RdbRadar::~RdbRadar()
{
    LocalReport(scene_, funcName_, STATE_FINISH, errCode_);
}

RdbRadar& RdbRadar::operator=(int errCode)
{
    errCode_ = errCode;
    return *this;
}

RdbRadar::operator int() const
{
    return errCode_;
}

void RdbRadar::LocalReport(int bizSence, const char* funcName, int state, int errCode)
{
    int stageRes = static_cast<int>(StageRes::RES_SUCCESS);
    if (errCode != E_OK) {
        stageRes = static_cast<int>(StageRes::RES_FAILED);
    }

    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::DISTRIBUTED_DATAMGR,
        RdbRadar::EVENT_NAME,
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        RdbRadar::ORG_PKG_LABEL, RdbRadar::ORG_PKG_VALUE,
        RdbRadar::FUNC_LABEL, funcName,
        RdbRadar::BIZ_SCENE_LABEL, bizSence,
        RdbRadar::BIZ_STAGE_LABEL, SYNC_STAGE_RUN,
        RdbRadar::STAGE_RES_LABEL, stageRes,
        RdbRadar::ERROR_CODE_LABEL, errCode,
        RdbRadar::BIZ_STATE_LABEL, state,
        RdbRadar::HOST_PKG, hostPkg_.c_str());
    return;
}

void RdbRadar::GetHostPkgInfo(std::string bundleName)
{
    if (hasHostPkg_) {
        return;
    }
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto tokenType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if ((tokenType == TOKEN_NATIVE) || (tokenType == TOKEN_SHELL)) {
        NativeTokenInfo tokenInfo;
        if (AccessTokenKit::GetNativeTokenInfo(tokenId, tokenInfo) == 0) {
            hostPkg_ = tokenInfo.processName;
            hasHostPkg_ = true;
        }
    } else {
        hostPkg_ = bundleName;
        hasHostPkg_ = true;
    }
}
}
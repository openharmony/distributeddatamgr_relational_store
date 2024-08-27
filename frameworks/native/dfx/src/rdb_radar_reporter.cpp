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
#include "ipc_skeleton.h"
#include "accesstoken_kit.h"
#include "hisysevent_c.h"

namespace OHOS::NativeRdb {

using namespace Security::AccessToken;

static constexpr const char* ORG_PKG_VALUE = "distributeddata";
static constexpr const char* EVENT_NAME = "DISTRIBUTED_RDB_BEHAVIOR";
static constexpr const char* UNKNOW = "unknow";
static constexpr const char* DISTRIBUTED_DATAMGR = "DISTDATAMGR";

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
    hostPkgMutex_.lock();
    char *hostPkg = const_cast<char *>(hostPkg_.c_str());
    hostPkgMutex_.unlock();
    HiSysEventParam params[] = {
        {.name = "ORG_PKG", .t = HISYSEVENT_STRING, .v = { .s = const_cast<char *>(ORG_PKG_VALUE) }, .arraySize = 0, },
        {.name = "FUNC", .t = HISYSEVENT_STRING, .v = { .s = const_cast<char *>(funcName) }, .arraySize = 0, },
        {.name = "BIZ_SCENE", .t = HISYSEVENT_INT32, .v = { .i32 = bizSence }, .arraySize = 0, },
        {.name = "BIZ_STAGE", .t = HISYSEVENT_INT32, .v = { .i32 = SYNC_STAGE_RUN }, .arraySize = 0, },
        {.name = "STAGE_RES", .t = HISYSEVENT_INT32, .v = { .i32 = stageRes }, .arraySize = 0, },
        {.name = "ERROR_CODE", .t = HISYSEVENT_INT32, .v = { .i32 = errCode }, .arraySize = 0, },
        {.name = "BIZ_STATE", .t = HISYSEVENT_INT32, .v = { .i32 = state }, .arraySize = 0, },
        {.name = "HOST_PKG", .t = HISYSEVENT_STRING, .v = { .s = hostPkg }, .arraySize = 0, },
    };

    OH_HiSysEvent_Write(DISTRIBUTED_DATAMGR, EVENT_NAME,
        HISYSEVENT_BEHAVIOR, params, sizeof(params) / sizeof(params[0]));
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
            hostPkgMutex_.lock();
            hostPkg_ = tokenInfo.processName;
            hostPkgMutex_.unlock();
            hasHostPkg_ = true;
        }
    } else {
        hostPkgMutex_.lock();
        hostPkg_ = bundleName;
        hostPkgMutex_.unlock();
        hasHostPkg_ = true;
    }
}
}
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

#ifndef DATASHARE_COMMON_H
#define DATASHARE_COMMON_H
#include "ability.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_common.h"
#include "datashare_helper.h"

using Ability = OHOS::AppExecFwk::Ability;

namespace OHOS {
namespace DataShare {
using namespace AppExecFwk;

struct CBBase {
    CallbackInfo cbInfo;
    napi_async_work asyncWork;
    napi_deferred deferred;
    Ability *ability = nullptr;
    AbilityType abilityType = AbilityType::UNKNOWN;
    int errCode = 0;
};

class NAPIDataShareObserver;
struct DSHelperOnOffCB {
    CBBase cbBase;
    DataShareHelper *dataShareHelper = nullptr;
    sptr<NAPIDataShareObserver> observer;
    std::string uri;
    int result = 0;
    std::vector<DSHelperOnOffCB *> NotifyList;
    std::vector<DSHelperOnOffCB *> DestoryList;
};
}  // namespace DataShare
}  // namespace OHOS
#endif /* DATASHARE_COMMON_H */

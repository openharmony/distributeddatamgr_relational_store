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

#ifndef NAPI_DATASHARE_OBSERVER_H
#define NAPI_DATASHARE_OBSERVER_H
#include "data_ability_observer_stub.h"
#include "data_share_common.h"

namespace OHOS {
namespace DataShare {
class NAPIDataShareObserver : public AAFwk::DataAbilityObserverStub {
public:
    void OnChange() override;
    void SetEnv(const napi_env &env);
    void SetCallbackRef(const napi_ref &ref);
    void ReleaseJSCallback();

    void SetAssociatedObject(DSHelperOnOffCB* object);
    const DSHelperOnOffCB* GetAssociatedObject(void);

    void ChangeWorkPre();
    void ChangeWorkRun();
    void ChangeWorkInt();
    void ChangeWorkPreDone();
    void ChangeWorkRunDone();
    int GetWorkPre();
    int GetWorkRun();
    int GetWorkInt();

private:
    napi_env env_ = nullptr;
    napi_ref ref_ = nullptr;
    DSHelperOnOffCB* onCB_ = nullptr;
    int workPre_ = 0;
    int workRun_ = 0;
    int intrust_ = 0;
    std::mutex mutex_;
};
}  // namespace DataShare
}  // namespace OHOS
#endif /* DATASHARE_COMMON_H */

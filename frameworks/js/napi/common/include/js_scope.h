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

#ifndef DISTRIBUTEDDATAMGR_APPDATAMGR_SCOPE_H
#define DISTRIBUTEDDATAMGR_APPDATAMGR_SCOPE_H
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
namespace OHOS::AppDataMgrJsKit {
class Scope {
public:
    Scope(napi_env env);
    ~Scope();

private:
    napi_env env_ = nullptr;
    napi_handle_scope scope_ = nullptr;
};
} // namespace OHOS::AppDataMgrJsKit
#endif // DISTRIBUTEDDATAMGR_APPDATAMGR_SCOPE_H

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

#ifndef DISTRIBUTEDDATAMGR_APPDATAMGR_JSABILITY_H
#define DISTRIBUTEDDATAMGR_APPDATAMGR_JSABILITY_H
#include <iostream>
#include <string>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AppDataMgrJsKit {
class Context {
public:
    explicit Context();

    std::string GetDatabaseDir();
    std::string GetPreferencesDir();
    std::string GetBundleName();
    std::string GetModuleName();
    std::string GetUri();
    std::string GetReadPermission();
    std::string GetWritePermission();
    int32_t GetArea() const;

private:
    int32_t area_ = 0;
    std::string databaseDir_;
    std::string preferencesDir_;
    std::string bundleName_;
    std::string moduleName_;
    std::string uri_;
    std::string readPermission_;
    std::string writePermission_;
};

class JSAbility final {
public:
    static bool CheckContext(napi_env env, napi_callback_info info);
    static std::shared_ptr<Context> GetContext(napi_env env, napi_value object);
};
} // namespace AppDataMgrJsKit
} // namespace OHOS

#endif // DISTRIBUTEDDATAMGR_APPDATAMGR_JSABILITY_H

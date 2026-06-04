/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef BASE_EVENTHANDLER_FRAMEWORKS_EVENTHANDLER_INCLUDE_LOCAL_HANDLER_ADAPTER_H
#define BASE_EVENTHANDLER_FRAMEWORKS_EVENTHANDLER_INCLUDE_LOCAL_HANDLER_ADAPTER_H

#include <cstdint>
 
namespace OHOS {
namespace AppExecFwk {

using EventOpenLocalHandleFunc = void(*)(void* napi_value, void** handle);
using EventCloseLocalHandleFunc = void(*)(void* napi_value, void* handle);

class LocalHandleAdapter final {
public:
    static LocalHandleAdapter& GetInstance();
    /**
     * set EventOpenLocalHandleFunc and EventCloseLocalHandleFunc
     *
     * @param openFunc eventOpenLocalHandleFunc
     * @param closeFunc eventCloseLocalHandleFunc
     */
    void SetLocalHandleFunc(EventOpenLocalHandleFunc openFunc, EventCloseLocalHandleFunc closeFunc);
    
    EventOpenLocalHandleFunc openLocalHandleFunc = nullptr;
    EventCloseLocalHandleFunc closeLocalHandleFunc = nullptr;
private:
    LocalHandleAdapter();
    ~LocalHandleAdapter();
};
}  // namespace AppExecFwk
}  // namespace OHOS
 
#endif  // #ifndef BASE_EVENTHANDLER_FRAMEWORKS_EVENTHANDLER_INCLUDE_LOCAL_HANDLER_ADAPTER_H
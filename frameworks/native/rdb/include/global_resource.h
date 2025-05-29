/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef NATIVE_RDB_GLOBAL_RESOURCE_H
#define NATIVE_RDB_GLOBAL_RESOURCE_H
#include <cstdint>
namespace OHOS {
namespace NativeRdb {
class GlobalResource {
public:
    enum CleanType {
        OPEN_SSL,
        ICU,
        OBS,
        IPC,
        CLEAN_BUTT
    };
    using Cleaner = int32_t (*)();
    static int32_t RegisterClean(int32_t type, Cleaner clean);
    static int32_t CleanUp(int32_t type);
};

} // namespace NativeRdb
} // namespace OHOS
#endif //LDBPROJ_GLOBAL_RESOURCE_H

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

#ifndef OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_JS_NAPI_COMMON_JSUAF_MANAGER_H
#define OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_JS_NAPI_COMMON_JSUAF_MANAGER_H
#include <stdint.h>

#include <map>
#include <mutex>
namespace OHOS::AppDataMgrJsKit {
class JSDFManager {
public:
    static JSDFManager &GetInstance();
    void AddNewInfo(void *data);
    int32_t GetFreedTid(void *data);

private:
    std::map<void *, int32_t> instances_;
    std::mutex mapMutex;
};
} // namespace OHOS::AppDataMgrJsKit

constexpr auto LOWER_24_BITS_MASK = (1u << 24) - 1;
#endif // OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_JS_NAPI_COMMON_JSUAF_MANAGER_H

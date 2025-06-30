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
#ifndef RDB_NDK_UTILS_H
#define RDB_NDK_UTILS_H
#include "rdb_store_config.h"
typedef struct OH_Rdb_ConfigV2 OH_Rdb_ConfigV2;
namespace OHOS::RdbNdk {
class API_EXPORT RdbNdkUtils {
public:
    static std::pair<int32_t, OHOS::NativeRdb::RdbStoreConfig> GetRdbStoreConfig(const OH_Rdb_ConfigV2 *config);
};
} // namespace OHOS::RdbNdk
#endif // RDB_NDK_UTILS_H
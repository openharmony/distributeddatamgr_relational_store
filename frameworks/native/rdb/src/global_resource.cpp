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

#define LOG_TAG "global_resource"
#include "global_resource.h"
#include "rdb_errno.h"

namespace OHOS::NativeRdb {
static GlobalResource::Cleaner g_cleaners[GlobalResource::CLEAN_BUTT];
int32_t GlobalResource::RegisterClean(CleanType type, Cleaner clean)
{
    if (type < static_cast<int32_t>(GlobalResource::ICU) || type >= static_cast<int32_t>(GlobalResource::CLEAN_BUTT) ||
        clean == nullptr) {
        return E_INVALID_ARGS;
    }

    if (g_cleaners[type] != nullptr) {
        return E_OK;
    }

    g_cleaners[type] = clean;
    return E_OK;
}

int32_t GlobalResource::CleanUp(int32_t type)
{
    if (type < static_cast<int32_t>(GlobalResource::ICU) || type >= static_cast<int32_t>(GlobalResource::CLEAN_BUTT)) {
        return E_INVALID_ARGS;
    }

    int32_t ret = E_OK;
    if (g_cleaners[type] != nullptr) {
        ret = g_cleaners[type]();
    }

    return ret;
}
} // namespace OHOS::NativeRdb
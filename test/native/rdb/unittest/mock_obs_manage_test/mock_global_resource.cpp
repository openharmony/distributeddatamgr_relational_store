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

#include "mock_global_resource.h"
#include "rdb_errno.h"
namespace OHOS::NativeRdb {
    
int32_t GlobalResource::CleanUp(int32_t type)
{
    if (BGlobalResource::globalResource_ == nullptr) {
        return NativeRdb::E_ERROR;
    }
    return BGlobalResource::globalResource_->CleanUp(type);
}

int32_t GlobalResource::RegisterClean(GlobalResource::CleanType type, GlobalResource::Cleaner clean)
{
    if (BGlobalResource::globalResource_ == nullptr) {
        return NativeRdb::E_ERROR;
    }
    return BGlobalResource::globalResource_->RegisterClean(type, clean);
}
} // namespace OHOS::NativeRdb
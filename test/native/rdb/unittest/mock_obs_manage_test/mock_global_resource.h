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

#ifndef DISTRIBUTED_GLOBAL_RESOURCE_MOCK_H
#define DISTRIBUTED_GLOBAL_RESOURCE_MOCK_H

#include <gmock/gmock.h>

#include "global_resource.h"
namespace OHOS::NativeRdb {
class BGlobalResource {
public:
    BGlobalResource() = default;
    virtual ~BGlobalResource() = default;
    virtual int32_t CleanUp(int32_t type) = 0;
    virtual int32_t RegisterClean(GlobalResource::CleanType type, GlobalResource::Cleaner clean) = 0;

public:
    static inline std::shared_ptr<BGlobalResource> globalResource_ = nullptr;
};

class MockGlobalResource : public BGlobalResource {
public:
    MOCK_METHOD(int32_t, CleanUp, (int32_t type), (override));
    MOCK_METHOD(int32_t, RegisterClean,
        (GlobalResource::CleanType type, GlobalResource::Cleaner clean), (override));
};
} // namespace OHOS::NativeRdb
#endif
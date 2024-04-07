/*
* Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef MULTI_PLATFORM_EDIAN
#define MULTI_PLATFORM_EDIAN

#include <cstdint>
#include "rdb_visibility.h"
namespace OHOS {
class API_EXPORT Endian final {
public:
    static uint16_t LeToH(uint16_t value);
    static uint16_t HToLe(uint16_t value);
    static uint32_t LeToH(uint32_t value);
    static uint32_t HToLe(uint32_t value);
    static uint64_t LeToH(uint64_t value);
    static uint64_t HToLe(uint64_t value);
};
} // namespace OHOS

#endif // MULTI_PLATFORM_EDIAN

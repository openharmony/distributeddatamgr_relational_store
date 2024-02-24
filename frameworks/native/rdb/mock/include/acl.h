/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_DATA_DATABASE_UTILS_ACL_H
#define OHOS_DISTRIBUTED_DATA_DATABASE_UTILS_ACL_H

#include <stdint.h>
#include <string>
namespace OHOS {
namespace DATABASE_UTILS {

class Acl {
public:
    static constexpr uint16_t R_RIGHT = 4;
    static constexpr uint16_t W_RIGHT = 2;
    static constexpr uint16_t E_RIGHT = 1;
    Acl(const std::string &path)
    {
    }

    int32_t SetDefaultGroup(const uint32_t gid, const uint16_t mode)
    {
        return 0;
    }

    int32_t SetDefaultUser(const uint32_t uid, const uint16_t mode)
    {
        return 0;
    }
};
} // DATABASE_UTILS
} // namespace OHOS

#endif // OHOS_DISTRIBUTED_DATA_DATABASE_UTILS_ACL_H
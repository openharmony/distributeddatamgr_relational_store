/*
* Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "multi_platform_endian.h"
#include <endian.h>

namespace OHOS {
uint16_t Endian::LeToH(uint16_t value)
{
    return le16toh(value);
}

uint16_t Endian::HToLe(uint16_t value)
{
    return htole16(value);
}

uint32_t Endian::LeToH(uint32_t value)
{
    return le32toh(value);
}

uint32_t Endian::HToLe(uint32_t value)
{
    return htole32(value);
}

uint64_t Endian::LeToH(uint64_t value)
{
    return le64toh(value);
}

uint64_t Endian::HToLe(uint64_t value)
{
    return htole64(value);
}
}

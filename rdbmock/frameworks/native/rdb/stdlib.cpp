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
#include "stdlib.h"
#define IOC(a, b, c, d) (((a) << 30) | ((b) << 8) | (c) | ((d) << 16))
#define IOC_READ 2U
#define IOR(a, b, c) IOC(IOC_READ, (a), (b), sizeof(c))
namespace OHOS {
namespace NativeRdb {
#ifdef __cplusplus
extern "C" {
#endif
static char *realpath(const char *__restrict path, char *__restrict resolved_path)
{
    return nullptr;
}
#ifdef __cplusplus
}
#endif
} // namespace NativeRdb
} // namespace OHOS
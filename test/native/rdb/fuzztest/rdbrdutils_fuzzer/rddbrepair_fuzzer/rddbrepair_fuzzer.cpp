/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "rdb_store_config.h"
#include "rdb_errno.h"
#include "rdb_store_impl.h"
#include "rd_utils.h"
using namespace OHOS;
using namespace OHOS::NativeRdb;
namespace OHOS {

void rddbrepairFuzzer(const uint8_t *data, size_t size)
{
    RdUtils::RdDbRepair(reinterpret_cast<const char *>(data), reinterpret_cast<const char *>(data));
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::rddbrepairFuzzer(data, size);
    return 0;
}

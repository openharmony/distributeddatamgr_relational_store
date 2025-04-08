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

#include "rd_utils.h"
#include "rdb_errno.h"
#include "rdb_store_config.h"
#include "rdb_store_impl.h"
using namespace OHOS;
using namespace OHOS::NativeRdb;
namespace OHOS {

uint32_t ConvertToUint32(const uint8_t *ptr, size_t size)
{
    if (ptr == nullptr || (size < sizeof(uint32_t))) {
        return 0;
    }
    return *(reinterpret_cast<const uint32_t *>(ptr));
}

void rddbrepairFuzzer(const uint8_t *data, size_t size)
{
    if (data == nullptr || (size < sizeof(char *))) {
        return;
    }
    std::string pathStr(reinterpret_cast<const char *>(data), size);
    uint32_t unit32t = ConvertToUint32(data, size);
    GRD_DB *dbHandle_ = nullptr;
    RdUtils::RdDbOpen(pathStr.c_str(), pathStr.c_str(), unit32t, &dbHandle_);
    RdUtils::RdDbRepair(pathStr.c_str(), pathStr.c_str());
    RdUtils::RdDbClose(dbHandle_, unit32t);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::rddbrepairFuzzer(data, size);
    return 0;
}

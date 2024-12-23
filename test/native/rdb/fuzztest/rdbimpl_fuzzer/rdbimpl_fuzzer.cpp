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

#include "rdbimpl_fuzzer.h"

#include "rdb_errno.h"
#include "rdb_store_config.h"
#include "rdb_store_impl.h"
using namespace OHOS;
using namespace OHOS::NativeRdb;
namespace OHOS {
void RdbStoreImplFuzz(const uint8_t *data, size_t size)
{
    int errorCode = E_ERROR;
    RdbStoreImpl rdbStoreImpl(RdbStoreConfig("name"), errorCode);
    if (errorCode != E_OK) {
        return;
    }
    std::string rawString(reinterpret_cast<const char *>(data), size);
    std::vector<std::string> tables;
    tables.push_back(rawString);
    rdbStoreImpl.SetDistributedTables(tables, size & 0x1, { size & 0x1 });
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::RdbStoreImplFuzz(data, size);
    return 0;
}

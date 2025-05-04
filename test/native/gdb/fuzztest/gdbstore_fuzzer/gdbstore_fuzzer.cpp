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
#include "gdbstore_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "gdb_helper.h"

using namespace OHOS;
using namespace OHOS::DistributedDataAip;

namespace OHOS {
const std::string DATABASE_NAME = "gdbStoreFuzz";
const std::string DATABASE_PATH = "/data/test";
StoreConfig config_(DATABASE_NAME, DATABASE_PATH);

std::shared_ptr<DBStore> GetStore()
{
    int errCode = 0;
    auto store = GDBHelper::GetDBStore(config_, errCode);
    return store;
}

void GdbQueryFuzz(FuzzedDataProvider &provider)
{
    auto store = GetStore();
    if (store == nullptr) {
        return;
    }
    std::string gql = provider.ConsumeRandomLengthString();
    store->QueryGql(gql);
    GDBHelper::DeleteDBStore(config_);
}

void GdbExecuteFuzz(FuzzedDataProvider &provider)
{
    auto store = GetStore();
    if (store == nullptr) {
        return;
    }
    std::string gql = provider.ConsumeRandomLengthString();
    store->ExecuteGql(gql);
    GDBHelper::DeleteDBStore(config_);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::GdbQueryFuzz(provider);
    OHOS::GdbExecuteFuzz(provider);
    return 0;
}
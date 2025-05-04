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

#include <fuzzer/FuzzedDataProvider.h>

#include "rdb_errno.h"
#include "rdb_store_config.h"
#include "rdb_store_impl.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"

using namespace OHOS;
using namespace OHOS::NativeRdb;
namespace OHOS {

static const std::string RDB_PATH = "/data/test/RdbImplFuzzer.db";

class RdbTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};
const std::string RdbTestOpenCallback::CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test "
                                                           "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                           "name TEXT NOT NULL, age INTEGER, salary REAL, "
                                                           "blobType BLOB)";

int RdbTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int RdbTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbStoreImplFuzz(const uint8_t *data, size_t size)
{
    int errCode = E_OK;
    RdbStoreConfig config(RDB_PATH);
    RdbTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    if (store == nullptr || errCode != E_OK) {
        return;
    }

    FuzzedDataProvider provider(data, size);
    std::vector<std::string> tables;
    std::string rawString = provider.ConsumeRandomLengthString();
    tables.push_back(rawString);

    OHOS::DistributedRdb::DistributedConfig distributedConfig;
    distributedConfig.autoSync = provider.ConsumeBool();

    OHOS::DistributedRdb::Reference reference;
    reference.sourceTable = provider.ConsumeRandomLengthString();
    reference.targetTable = provider.ConsumeRandomLengthString();
    const int mapSize = 10;
    for (int i = 0; i < mapSize; i++) {
        reference.refFields.insert(
            std::make_pair(provider.ConsumeRandomLengthString(), provider.ConsumeRandomLengthString()));
    }

    distributedConfig.references.push_back(reference);
    distributedConfig.isRebuild = provider.ConsumeBool();
    distributedConfig.asyncDownloadAsset = provider.ConsumeBool();
    distributedConfig.enableCloud = provider.ConsumeBool();

    DistributedRdb::DistributedTableType::DISTRIBUTED_DEVICE type =
        provider.ConsumeEnum<DistributedRdb::DistributedTableType::DISTRIBUTED_DEVICE>();
    store->SetDistributedTables(tables, type, distributedConfig);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::RdbStoreImplFuzz(data, size);
    return 0;
}

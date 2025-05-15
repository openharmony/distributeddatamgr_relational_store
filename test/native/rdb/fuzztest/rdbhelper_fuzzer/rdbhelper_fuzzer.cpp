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
#include <fuzzer/FuzzedDataProvider.h>
#include <rdb_helper.h>
#include <rdb_store.h>
#include <rdb_store_config.h>
#include <securec.h>
#include <values_bucket.h>

#include <memory>

using namespace OHOS;
using namespace OHOS::NativeRdb;
namespace OHOS {

class FuzzRdbOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &rdbStore) override
    {
        return 0;
    }
    int OnUpgrade(RdbStore &rdbStore, int currentVersion, int targetVersion) override
    {
        return 0;
    }
    int OnOpen(RdbStore &rdbStore) override
    {
        return 0;
    }
    int OnDowngrade(RdbStore &rdbStore, int currentVersion, int targetVersion) override
    {
        return 0;
    }
};

void ExecuteSqlFuzzTest(FuzzedDataProvider &provider)
{
    std::string path = provider.ConsumeRandomLengthString();
    RdbStoreConfig config(path);
    config.SetReadOnly(provider.ConsumeBool());
    config.SetPageSize(provider.ConsumeIntegral<int>());
    config.SetBundleName(provider.ConsumeRandomLengthString());
    config.SetSearchable(provider.ConsumeBool());
    config.SetStorageMode(provider.ConsumeBool() ? StorageMode::MODE_MEMORY : StorageMode::MODE_DISK);

    FuzzRdbOpenCallback openCallback;
    int errCode = 0;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, openCallback, errCode);
    if (!store)
        return;

    {
        std::string sql = provider.ConsumeRandomLengthString();
        store->ExecuteSql(sql);
    }

    ValuesBucket valuesBucket;
    {
        std::string columnName = provider.ConsumeRandomLengthString();
        valuesBucket.PutInt(columnName, provider.ConsumeIntegral<int>());
    }

    {
        std::string columnName = provider.ConsumeRandomLengthString();
        valuesBucket.PutInt(columnName, provider.ConsumeIntegral<int>());
    }

    int64_t outRowId = 0;
    std::string tableName = provider.ConsumeRandomLengthString();
    store->Insert(outRowId, tableName, valuesBucket);
}

void OnDowngradeFuzzTest(FuzzedDataProvider &provider)
{
    // Construct RdbStoreConfig
    std::string path = provider.ConsumeRandomLengthString();
    RdbStoreConfig config(path);
    config.SetHaMode(provider.ConsumeIntegral<int32_t>());

    // Construct RdbOpenCallback
    FuzzRdbOpenCallback openCallback;

    // Construct RdbStore
    int errCode = 0;
    std::shared_ptr<RdbStore> rdbStore =
        RdbHelper::GetRdbStore(config, provider.ConsumeIntegral<int>(), openCallback, errCode);
    if (!rdbStore)
        return;

    // Test GetBackupStatus
    rdbStore->GetBackupStatus();

    // Test InterruptBackup
    rdbStore->InterruptBackup();

    // Test OnOpen
    openCallback.OnOpen(*rdbStore);

    // Test OnDowngrade
    openCallback.OnDowngrade(*rdbStore, provider.ConsumeIntegral<int>(), provider.ConsumeIntegral<int>());
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    FuzzedDataProvider provider(Data, Size);
    OHOS::ExecuteSqlFuzzTest(provider);
    OHOS::OnDowngradeFuzzTest(provider);
    return 0;
}
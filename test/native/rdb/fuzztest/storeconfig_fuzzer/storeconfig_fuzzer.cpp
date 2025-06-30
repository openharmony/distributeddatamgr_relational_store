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
#include "storeconfig_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include <memory>

#include "rdb_store_config.h"

using namespace OHOS;
using namespace OHOS::NativeRdb;
namespace OHOS {

void FuzzSetPath(FuzzedDataProvider &provider, RdbStoreConfig &config)
{
    std::string path = provider.ConsumeRandomLengthString();
    config.SetPath(path);
}

void FuzzSetJournalMode(FuzzedDataProvider &provider, RdbStoreConfig &config)
{
    JournalMode min = JournalMode::MODE_DELETE;
    int intValueMin = static_cast<int>(min);

    JournalMode max = JournalMode::MODE_OFF;
    int intValueMax = static_cast<int>(max);

    JournalMode journalMode = static_cast<JournalMode>(provider.ConsumeIntegralInRange<int>(intValueMin, intValueMax));
    config.SetJournalMode(journalMode);
}

void FuzzSetReadOnly(FuzzedDataProvider &provider, RdbStoreConfig &config)
{
    bool readOnly = provider.ConsumeBool();
    config.SetReadOnly(readOnly);
}

void FuzzSetStorageMode(FuzzedDataProvider &provider, RdbStoreConfig &config)
{
    StorageMode min = StorageMode::MODE_MEMORY;
    int intValueMin = static_cast<int>(min);

    StorageMode max = StorageMode::MODE_DISK;
    int intValueMax = static_cast<int>(max);

    StorageMode storageMode = static_cast<StorageMode>(provider.ConsumeIntegralInRange<int>(intValueMin, intValueMax));
    config.SetStorageMode(storageMode);
}

void FuzzSetDatabaseFileType(FuzzedDataProvider &provider, RdbStoreConfig &config)
{
    DatabaseFileType min = DatabaseFileType::NORMAL;
    int intValueMin = static_cast<int>(min);

    DatabaseFileType max = DatabaseFileType::CORRUPT;
    int intValueMax = static_cast<int>(max);

    DatabaseFileType databaseFileType =
        static_cast<DatabaseFileType>(provider.ConsumeIntegralInRange<int>(intValueMin, intValueMax));
    config.SetDatabaseFileType(databaseFileType);
}

void FuzzSetSecurityLevel(FuzzedDataProvider &provider, RdbStoreConfig &config)
{
    SecurityLevel min = SecurityLevel::S1;
    int intValueMin = static_cast<int>(min);

    SecurityLevel max = SecurityLevel::S4;
    int intValueMax = static_cast<int>(max);

    SecurityLevel securityLevel =
        static_cast<SecurityLevel>(provider.ConsumeIntegralInRange<int>(intValueMin, intValueMax));
    config.SetSecurityLevel(securityLevel);
}

void FuzzSetCreateNecessary(FuzzedDataProvider &provider, RdbStoreConfig &config)
{
    bool isCreateNecessary = provider.ConsumeBool();
    config.SetCreateNecessary(isCreateNecessary);
}

void FuzzSetTokenizer(FuzzedDataProvider &provider, RdbStoreConfig &config)
{
    Tokenizer min = Tokenizer::NONE_TOKENIZER;
    int intValueMin = static_cast<int>(min);

    Tokenizer max = Tokenizer::TOKENIZER_END;
    int intValueMax = static_cast<int>(max);

    Tokenizer tokenizer = static_cast<Tokenizer>(provider.ConsumeIntegralInRange<int>(intValueMin, intValueMax));
    config.SetTokenizer(tokenizer);
}

void FuzzSetEncryptKey(FuzzedDataProvider &provider, RdbStoreConfig &config)
{
    const int min = 0;
    const int max = 100;
    std::vector<uint8_t> encryptKey(provider.ConsumeIntegralInRange<size_t>(min, max));
    config.SetEncryptKey(encryptKey);
}

void FuzzSetEncryptAlgo(FuzzedDataProvider &provider, RdbStoreConfig &config)
{
    EncryptAlgo min = EncryptAlgo::AES_256_GCM;
    int intValueMin = static_cast<int>(min);

    EncryptAlgo max = EncryptAlgo::AES_256_CBC;
    int intValueMax = static_cast<int>(max);

    EncryptAlgo encryptAlgo = static_cast<EncryptAlgo>(provider.ConsumeIntegralInRange<int>(intValueMin, intValueMax));
    config.SetEncryptAlgo(encryptAlgo);
}

void FuzzSetJournalSize(FuzzedDataProvider &provider, RdbStoreConfig &config)
{
    const int min = 1;
    const int max = 1024 * 1024;
    int journalSize = provider.ConsumeIntegralInRange<int>(min, max);
    config.SetJournalSize(journalSize);
}

void FuzzSetPageSize(FuzzedDataProvider &provider, RdbStoreConfig &config)
{
    const int min = 1;
    const int max = 4096;
    int pageSize = provider.ConsumeIntegralInRange<int>(min, max);
    config.SetPageSize(pageSize);
}

void FuzzSetScalarFunction(FuzzedDataProvider &provider, RdbStoreConfig &config)
{
    std::string functionName = provider.ConsumeRandomLengthString();
    const int min = 1;
    const int max = 5;
    int argc = provider.ConsumeIntegralInRange<int>(min, max);
    ScalarFunction function = [](const std::vector<std::string> &args) -> std::string {
        return args.empty() ? "" : args[0];
    };
    config.SetScalarFunction(functionName, argc, function);
}

} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);

    // Generate random inputs
    std::string path = provider.ConsumeRandomLengthString();
    int intValueMin = static_cast<int>(StorageMode::MODE_MEMORY);
    int intValueMax = static_cast<int>(StorageMode::MODE_DISK);
    StorageMode storageMode = static_cast<StorageMode>(provider.ConsumeIntegralInRange<int>(intValueMin, intValueMax));
    bool readOnly = provider.ConsumeBool();
    const int min = 0;
    const int max = 100;
    std::vector<uint8_t> encryptKey(provider.ConsumeIntegralInRange<size_t>(min, max));
    std::string journalMode = provider.ConsumeRandomLengthString();
    std::string syncMode = provider.ConsumeRandomLengthString();
    std::string databaseFileType = provider.ConsumeRandomLengthString();
    SecurityLevel securityLevel = static_cast<SecurityLevel>(
        provider.ConsumeIntegralInRange<int>(static_cast<int>(SecurityLevel::S1), static_cast<int>(SecurityLevel::S4)));
    bool isCreateNecessary = provider.ConsumeBool();
    bool autoCheck = provider.ConsumeBool();
    const int journalSizeMin = 1;
    const int journalSizeMax = 1024 * 1024;
    int journalSize = provider.ConsumeIntegralInRange<int>(journalSizeMin, journalSizeMax);
    const int pageSizeMin = 1;
    const int pageSizeMax = 1024 * 1024;
    int pageSize = provider.ConsumeIntegralInRange<int>(pageSizeMin, pageSizeMax);

    RdbStoreConfig config(path, storageMode, readOnly, encryptKey, journalMode, syncMode, databaseFileType,
        securityLevel, isCreateNecessary, autoCheck, journalSize, pageSize);

    // Fuzzing individual methods
    OHOS::FuzzSetPath(provider, config);
    OHOS::FuzzSetJournalMode(provider, config);
    OHOS::FuzzSetReadOnly(provider, config);
    OHOS::FuzzSetStorageMode(provider, config);
    OHOS::FuzzSetDatabaseFileType(provider, config);
    OHOS::FuzzSetSecurityLevel(provider, config);
    OHOS::FuzzSetCreateNecessary(provider, config);
    OHOS::FuzzSetTokenizer(provider, config);
    OHOS::FuzzSetEncryptKey(provider, config);
    OHOS::FuzzSetEncryptAlgo(provider, config);
    OHOS::FuzzSetJournalSize(provider, config);
    OHOS::FuzzSetPageSize(provider, config);
    OHOS::FuzzSetScalarFunction(provider, config);
    return 0;
}

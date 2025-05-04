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
#include "relationalstorecapi_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include <cstdlib>

#include "grd_api_manager.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"

using namespace OHOS::NativeRdb;
using namespace OHOS::RdbNdk;

// Helper function to create an OH_Rdb_Config structure with random data
OH_Rdb_Config *CreateRandomConfig(FuzzedDataProvider &provider)
{
    OH_Rdb_Config *config = new OH_Rdb_Config();
    config->selfSize = sizeof(OH_Rdb_Config);
    config->dataBaseDir = strdup(provider.ConsumeRandomLengthString().c_str());
    config->storeName = strdup(provider.ConsumeRandomLengthString().c_str());
    config->bundleName = strdup(provider.ConsumeRandomLengthString().c_str());
    config->moduleName = strdup(provider.ConsumeRandomLengthString().c_str());
    config->isEncrypt = provider.ConsumeBool();
    config->securityLevel = static_cast<int>(provider.ConsumeEnum<OH_Rdb_SecurityLevel>());
    config->area = static_cast<int>(provider.ConsumeEnum<Rdb_SecurityArea>());
    return config;
}

void ReleaseConfig(OH_Rdb_Config *config)
{
    if (config == nullptr) {
        return;
    }
    if (config->dataBaseDir != nullptr) {
        free(static_cast<void *>(const_cast<char *>(config->dataBaseDir)));
    }
    if (config->storeName != nullptr) {
        free(static_cast<void *>(const_cast<char *>(config->storeName)));
    }
    if (config->bundleName != nullptr) {
        free(static_cast<void *>(const_cast<char *>(config->bundleName)));
    }
    if (config->moduleName != nullptr) {
        free(static_cast<void *>(const_cast<char *>(config->moduleName)));
    }
    delete config;
    config = nullptr;
}

// Helper function to create an OH_Rdb_ConfigV2 structure with random data
OH_Rdb_ConfigV2 *CreateRandomConfigV2(FuzzedDataProvider &provider)
{
    OH_Rdb_ConfigV2 *configV2 = OH_Rdb_CreateConfig();
    std::string databaseDir = provider.ConsumeRandomLengthString();
    OH_Rdb_SetDatabaseDir(configV2, databaseDir.c_str());
    std::string storeName = provider.ConsumeRandomLengthString();
    OH_Rdb_SetStoreName(configV2, storeName.c_str());
    std::string bundleName = provider.ConsumeRandomLengthString();
    OH_Rdb_SetBundleName(configV2, bundleName.c_str());
    std::string bmoduleName = provider.ConsumeRandomLengthString();
    OH_Rdb_SetModuleName(configV2, bmoduleName.c_str());
    bool isEncrypted = provider.ConsumeBool();
    OH_Rdb_SetEncrypted(configV2, isEncrypted);
    int securityLevel = provider.ConsumeIntegral<int>();
    OH_Rdb_SetSecurityLevel(configV2, securityLevel);
    int area = provider.ConsumeIntegral<int>();
    OH_Rdb_SetArea(configV2, area);
    int dbType = provider.ConsumeIntegral<int>();
    OH_Rdb_SetDbType(configV2, dbType);

    Rdb_Tokenizer tokenizer = provider.ConsumeEnum<Rdb_Tokenizer>();
    bool isSupported = false;
    OH_Rdb_IsTokenizerSupported(tokenizer, &isSupported);
    if (isSupported) {
    }
    {
        Rdb_Tokenizer tokenizer = provider.ConsumeEnum<Rdb_Tokenizer>();
        OH_Rdb_SetTokenizer(configV2, tokenizer);
    }
    bool isPersistent = provider.ConsumeBool();
    OH_Rdb_SetPersistent(configV2, isPersistent);
    return configV2;
}

// Helper function to create an OH_Predicates structure with random data
OH_Predicates *CreateRandomPredicates(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString();
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return nullptr;
    }

    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    {
        std::string value = provider.ConsumeRandomLengthString();
        valueObject->putText(valueObject, value.c_str());
    }

    {
        std::string value = provider.ConsumeRandomLengthString();
        predicates->equalTo(predicates, value.c_str(), valueObject);
    }

    return predicates;
}

// Helper function to create an OH_VBucket structure with random data
OH_VBucket *CreateRandomVBucket(FuzzedDataProvider &provider)
{
    OH_VBucket *vBucket = OH_Rdb_CreateValuesBucket();
    if (vBucket == nullptr) {
        return nullptr;
    }
    const int minLen = 1;
    const int maxLen = 50;
    size_t len = provider.ConsumeIntegralInRange<size_t>(minLen, maxLen);
    for (size_t i = 0; i < len; i++) {
        std::string column = provider.ConsumeRandomLengthString();
        int64_t value = provider.ConsumeIntegral<int64_t>();
        vBucket->putInt64(vBucket, column.c_str(), value);
    }
    return vBucket;
}

// Helper function to create an OH_Rdb_TransOptions structure with random data
OH_RDB_TransOptions *CreateRandomTransOptions(FuzzedDataProvider &provider)
{
    OH_RDB_TransOptions *options = OH_RdbTrans_CreateOptions();
    OH_RDB_TransType type = provider.ConsumeIntegralInRange<OH_RDB_TransType>();
    OH_RdbTransOption_SetType(options, type);
    return options;
}

void OHRdbCreateOrOpenFuzzTest(FuzzedDataProvider &provider)
{
    OH_Rdb_Config *config = CreateRandomConfig(provider);
    int errCode;
    OH_Rdb_Store *store = OH_Rdb_GetOrOpen(config, &errCode);
    if (store != nullptr) {
        // Test OH_Rdb_CloseStore
        OH_Rdb_CloseStore(store);
    }
    ReleaseConfig(config);
}

void OHRdbCreateOrOpenV2FuzzTest(FuzzedDataProvider &provider)
{
    OH_Rdb_ConfigV2 *config = CreateRandomConfigV2(provider);
    int errCode;
    OH_Rdb_Store *store = OH_Rdb_CreateOrOpen(config, &errCode);
    if (store != nullptr) {
        // Test OH_Rdb_CloseStore
        OH_Rdb_CloseStore(store);
    }
}

void OHRdbSetVersionFuzzTest(FuzzedDataProvider &provider)
{
    OH_Rdb_Config *config = CreateRandomConfig(provider);
    int errCode;
    OH_Rdb_Store *store = OH_Rdb_GetOrOpen(config, &errCode);
    if (store != nullptr) {
        int version = provider.ConsumeIntegral<int>();
        OH_Rdb_SetVersion(store, version);
        OH_Rdb_CloseStore(store);
    }
    ReleaseConfig(config);
}

void OHRdbQueryLockedRowFuzzTest(FuzzedDataProvider &provider)
{
    OH_Rdb_Config *config = CreateRandomConfig(provider);
    int errCode;
    OH_Rdb_Store *store = OH_Rdb_GetOrOpen(config, &errCode);
    if (store != nullptr) {
        OH_Predicates *predicates = CreateRandomPredicates(provider);
        if (predicates != nullptr) {
            const int minColumnCount = 1;
            const int maxColumnCount = 50;
            size_t columnCount = provider.ConsumeIntegralInRange<size_t>(minColumnCount, maxColumnCount);
            const char **columnNames = new const char *[columnCount];
            std::vector<std::unique_ptr<char[]>> columnStorage(columnCount);

            for (size_t i = 0; i < columnCount; ++i) {
                std::string columnName = provider.ConsumeRandomLengthString();
                columnStorage[i] = std::make_unique<char[]>(columnName.size() + 1);
                std::copy(columnName.begin(), columnName.end(), columnStorage[i].get());
                columnStorage[i][columnName.size()] = '\0';
                columnNames[i] = columnStorage[i].get();
            }
            OH_Cursor *cursor = OH_Rdb_QueryLockedRow(store, predicates, columnNames, columnCount);
            if (cursor != nullptr) {
                cursor->destroy(cursor);
            }
            predicates->destroy(predicates);
            delete[] columnNames;
        }
        OH_Rdb_CloseStore(store);
    }
    ReleaseConfig(config);
}

void OHRdbUnlockRowFuzzTest(FuzzedDataProvider &provider)
{
    OH_Rdb_Config *config = CreateRandomConfig(provider);
    int errCode;
    OH_Rdb_Store *store = OH_Rdb_GetOrOpen(config, &errCode);
    if (store != nullptr) {
        OH_Predicates *predicates = CreateRandomPredicates(provider);
        if (predicates != nullptr) {
            OH_Rdb_UnlockRow(store, predicates);
            predicates->destroy(predicates);
        }
        OH_Rdb_CloseStore(store);
    }
    ReleaseConfig(config);
}

void OHRdbExecuteQueryV2FuzzTest(FuzzedDataProvider &provider)
{
    OH_Rdb_Config *config = CreateRandomConfig(provider);
    int errCode;
    OH_Rdb_Store *store = OH_Rdb_GetOrOpen(config, &errCode);
    if (store != nullptr) {
        std::string sql = provider.ConsumeRandomLengthString();
        OH_Data_Values *args = nullptr; // Simplified for fuzzing
        OH_Cursor *cursor = OH_Rdb_ExecuteQueryV2(store, sql.c_str(), args);
        if (cursor != nullptr) {
            cursor->destroy(cursor);
        }
        OH_Rdb_CloseStore(store);
    }
    ReleaseConfig(config);
}

void OHRdbBatchInsertFuzzTest(FuzzedDataProvider &provider)
{
    OH_Rdb_Config *config = CreateRandomConfig(provider);
    int errCode;
    OH_Rdb_Store *store = OH_Rdb_GetOrOpen(config, &errCode);
    if (store != nullptr) {
        std::string table = provider.ConsumeRandomLengthString();
        const int minRowCount = 1;
        const int maxRowCount = 5;
        size_t rowCount = provider.ConsumeIntegralInRange<size_t>(minRowCount, maxRowCount);
        OH_Data_VBuckets *list = OH_VBuckets_Create();
        for (size_t i = 0; i < rowCount; i++) {
            OH_VBuckets_PutRow(list, CreateRandomVBucket(provider));
        }
        int64_t changes;
        Rdb_ConflictResolution resolution = provider.ConsumeEnum<Rdb_ConflictResolution>();
        OH_Rdb_BatchInsert(store, table.c_str(), list, resolution, &changes);
        OH_VBuckets_Destroy(list);
        OH_Rdb_CloseStore(store);
    }
    ReleaseConfig(config);
}

void OHRdbUpdateFuzzTest(FuzzedDataProvider &provider)
{
    OH_Rdb_Config *config = CreateRandomConfig(provider);
    int errCode;
    OH_Rdb_Store *store = OH_Rdb_GetOrOpen(config, &errCode);
    if (store != nullptr) {
        OH_VBucket *valuesBucket = CreateRandomVBucket(provider);
        OH_Predicates *predicates = CreateRandomPredicates(provider);
        if (valuesBucket != nullptr && predicates != nullptr) {
            OH_Rdb_Update(store, valuesBucket, predicates);
            predicates->destroy(predicates);
        }
        OH_Rdb_CloseStore(store);
    }
    ReleaseConfig(config);
}

void OHRdbLockRowFuzzTest(FuzzedDataProvider &provider)
{
    OH_Rdb_Config *config = CreateRandomConfig(provider);
    int errCode;
    OH_Rdb_Store *store = OH_Rdb_GetOrOpen(config, &errCode);
    if (store != nullptr) {
        OH_Predicates *predicates = CreateRandomPredicates(provider);
        if (predicates != nullptr) {
            OH_Rdb_LockRow(store, predicates);
            predicates->destroy(predicates);
        }
        OH_Rdb_CloseStore(store);
    }
    ReleaseConfig(config);
}

void OHRdbCreateTransactionFuzzTest(FuzzedDataProvider &provider)
{
    OH_Rdb_Config *config = CreateRandomConfig(provider);
    int errCode;
    OH_Rdb_Store *store = OH_Rdb_GetOrOpen(config, &errCode);
    if (store != nullptr) {
        OH_RDB_TransOptions *options = CreateRandomTransOptions(provider);
        OH_Rdb_Transaction *trans = nullptr;
        OH_Rdb_CreateTransaction(store, options, &trans);
        OH_Rdb_CloseStore(store);
    }
    ReleaseConfig(config);
}

void OHRdbCommitByTrxIdFuzzTest(FuzzedDataProvider &provider)
{
    OH_Rdb_Config *config = CreateRandomConfig(provider);
    int errCode;
    OH_Rdb_Store *store = OH_Rdb_GetOrOpen(config, &errCode);
    if (store != nullptr) {
        int64_t trxId = provider.ConsumeIntegral<int64_t>();
        OH_Rdb_CommitByTrxId(store, trxId);
        OH_Rdb_CloseStore(store);
    }
    ReleaseConfig(config);
}

void OHRdbBackupFuzzTest(FuzzedDataProvider &provider)
{
    OH_Rdb_Config *config = CreateRandomConfig(provider);
    int errCode;
    OH_Rdb_Store *store = OH_Rdb_GetOrOpen(config, &errCode);
    if (store != nullptr) {
        std::string databasePath = provider.ConsumeRandomLengthString();
        OH_Rdb_Backup(store, databasePath.c_str());
        OH_Rdb_CloseStore(store);
    }
    ReleaseConfig(config);
}

void OHRdbUnsubscribeAutoSyncProgressFuzzTest(FuzzedDataProvider &provider)
{
    OH_Rdb_Config *config = CreateRandomConfig(provider);
    int errCode;
    OH_Rdb_Store *store = OH_Rdb_GetOrOpen(config, &errCode);
    if (store != nullptr) {
        Rdb_ProgressObserver *observer = nullptr; // Simplified for fuzzing
        OH_Rdb_UnsubscribeAutoSyncProgress(store, observer);
        OH_Rdb_CloseStore(store);
    }
    ReleaseConfig(config);
}

void OHRdbUnsubscribeFuzzTest(FuzzedDataProvider &provider)
{
    OH_Rdb_Config *config = CreateRandomConfig(provider);
    int errCode;
    OH_Rdb_Store *store = OH_Rdb_GetOrOpen(config, &errCode);
    if (store != nullptr) {
        Rdb_SubscribeType type = provider.ConsumeEnum<Rdb_SubscribeType>();
        Rdb_DataObserver *observer = nullptr; // Simplified for fuzzing
        OH_Rdb_Unsubscribe(store, type, observer);
        OH_Rdb_CloseStore(store);
    }
    ReleaseConfig(config);
}

void OHRdbExecuteV2FuzzTest(FuzzedDataProvider &provider)
{
    OH_Rdb_Config *config = CreateRandomConfig(provider);
    int errCode;
    OH_Rdb_Store *store = OH_Rdb_GetOrOpen(config, &errCode);
    if (store != nullptr) {
        std::string sql = provider.ConsumeRandomLengthString(100);
        OH_Data_Values *values = OH_Values_Create();
        int value = provider.ConsumeIntegral<int>();
        OH_Values_PutInt(values, value);
        OH_Data_Value *result = nullptr;
        OH_Rdb_ExecuteV2(store, sql.c_str(), values, &result);
        if (values != nullptr) {
            OH_Values_Destroy(values);
        }
        OH_Rdb_CloseStore(store);
    }
    ReleaseConfig(config);
}

void OHRdbFindModifyTimeFuzzTest(FuzzedDataProvider &provider)
{
    OH_Rdb_Config *config = CreateRandomConfig(provider);
    int errCode;
    OH_Rdb_Store *store = OH_Rdb_GetOrOpen(config, &errCode);
    if (store != nullptr) {
        std::string tableName = provider.ConsumeRandomLengthString(50);
        std::string columnName = provider.ConsumeRandomLengthString(50);
        OH_VObject *values = OH_Rdb_CreateValueObject();
        if (values != nullptr) {
            OH_Cursor *cursor = OH_Rdb_FindModifyTime(store, tableName.c_str(), columnName.c_str(), values);
            if (cursor != nullptr) {
                cursor->destroy(cursor);
            }
            values->destroy(values);
        }
        OH_Rdb_CloseStore(store);
    }
    ReleaseConfig(config);
}

void RelationalStoreFuzzTest(FuzzedDataProvider &provider)
{
    // Test OH_Rdb_CreateOrOpen
    OHRdbCreateOrOpenFuzzTest(provider);

    // Test OH_Rdb_CreateOrOpenV2
    OHRdbCreateOrOpenV2FuzzTest(provider);

    // Test OH_Rdb_SetVersion
    OHRdbSetVersionFuzzTest(provider);

    // Test OH_Rdb_QueryLockedRow
    OHRdbQueryLockedRowFuzzTest(provider);

    // Test OH_Rdb_UnlockRow
    OHRdbUnlockRowFuzzTest(provider);

    // Test OH_Rdb_ExecuteQueryV2
    OHRdbExecuteQueryV2FuzzTest(provider);

    // Test OH_Rdb_BatchInsert
    OHRdbBatchInsertFuzzTest(provider);

    // Test OH_Rdb_Update
    OHRdbUpdateFuzzTest(provider);

    // Test OH_Rdb_LockRow
    OHRdbLockRowFuzzTest(provider);

    // Test OH_Rdb_CreateTransaction
    OHRdbCreateTransactionFuzzTest(provider);

    // Test OH_Rdb_CommitByTrxId
    OHRdbCommitByTrxIdFuzzTest(provider);

    // Test OH_Rdb_Backup
    OHRdbBackupFuzzTest(provider);

    // Test OH_Rdb_UnsubscribeAutoSyncProgress
    OHRdbUnsubscribeAutoSyncProgressFuzzTest(provider);

    // Test OH_Rdb_Unsubscribe
    OHRdbUnsubscribeFuzzTest(provider);

    // Test OH_Rdb_ExecuteV2
    OHRdbExecuteV2FuzzTest(provider);

    // Test OH_Rdb_FindModifyTime
    OHRdbFindModifyTimeFuzzTest(provider);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    RelationalStoreFuzzTest(provider);
    return 0;
}

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

#include "grd_api_manager.h"
#include "oh_rdb_transaction.h"
#include "oh_value_object.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"
#include "ohrdbtransaction_fuzzer.h"
#include <iostream>

using namespace OHOS::NativeRdb;
using namespace OHOS::RdbNdk;

#define STRING_SIZE_MAX 15

// Helper function to create an OH_Rdb_Config structure with random data
OH_Rdb_Config *CreateRandomConfig(FuzzedDataProvider &provider)
{
    OH_Rdb_Config *config = new OH_Rdb_Config();
    config->selfSize = sizeof(OH_Rdb_Config);
    config->dataBaseDir = strdup(provider.ConsumeRandomLengthString(STRING_SIZE_MAX).c_str());
    config->storeName = strdup(provider.ConsumeRandomLengthString(STRING_SIZE_MAX).c_str());
    config->bundleName = strdup(provider.ConsumeRandomLengthString(STRING_SIZE_MAX).c_str());
    config->moduleName = strdup(provider.ConsumeRandomLengthString(STRING_SIZE_MAX).c_str());
    config->isEncrypt = provider.ConsumeBool();
    config->securityLevel = provider.ConsumeIntegralInRange<int>(S1, S4);
    config->area = provider.ConsumeIntegralInRange<int>(RDB_SECURITY_AREA_EL1, RDB_SECURITY_AREA_EL5);
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

OH_RDB_TransOptions *CreateRandomTransOptions(FuzzedDataProvider &provider)
{
    OH_RDB_TransOptions *options = OH_RdbTrans_CreateOptions();
    if (options == nullptr) {
        return nullptr;
    }
    OH_RDB_TransType type =
        static_cast<OH_RDB_TransType>(provider.ConsumeIntegralInRange<int>(RDB_TRANS_DEFERRED, RDB_TRANS_BUTT));
    OH_RdbTransOption_SetType(options, type);
    return options;
}

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
        std::string column = provider.ConsumeRandomLengthString(STRING_SIZE_MAX);
        int64_t value = provider.ConsumeIntegral<int64_t>();
        vBucket->putInt64(vBucket, column.c_str(), value);
    }
    return vBucket;
}

std::vector<OH_VBucket*> g_randomVBuckets;
OH_Data_VBuckets *CreateRandomVBuckets(FuzzedDataProvider &provider)
{
    const int minRowCount = 1;
    const int maxRowCount = 5;
    g_randomVBuckets.clear();
    size_t rowCount = provider.ConsumeIntegralInRange<size_t>(minRowCount, maxRowCount);
    OH_Data_VBuckets *list = OH_VBuckets_Create();
    for (size_t i = 0; i < rowCount; i++) {
        OH_VBucket *valueBucket = CreateRandomVBucket(provider);
        g_randomVBuckets.push_back(valueBucket);
        OH_VBuckets_PutRow(list, valueBucket);
    }
    return list;
}

void DeleteCapiValueBuckets(OH_Data_VBuckets *rows)
{
    OH_VBuckets_Destroy(rows);
    for (auto row : g_randomVBuckets) {
        if (row != nullptr) {
            row->destroy(row);
        }
    }
    g_randomVBuckets.clear();
}

OH_VObject *CreateTransVObject(FuzzedDataProvider &provider)
{
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    if (valueObject == nullptr) {
        return nullptr;
    }
    std::string value = provider.ConsumeRandomLengthString(STRING_SIZE_MAX);
    valueObject->putText(valueObject, value.c_str());
    return valueObject;
}

OH_Predicates* GetCapiTransPredicates(FuzzedDataProvider &provider, std::string table)
{
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return nullptr;
    }
    std::string value = provider.ConsumeRandomLengthString(STRING_SIZE_MAX);
    OH_VObject *valueObject = CreateTransVObject(provider);
    if (valueObject == nullptr) {
        predicates->destroy(predicates);
        return nullptr;
    }
    predicates->equalTo(predicates, value.c_str(), valueObject);
    valueObject->destroy(valueObject);
    return predicates;
}

void DeleteCapiTransPredicates(OH_Predicates *predicates)
{
    if (predicates == nullptr) {
        return;
    }
    predicates->destroy(predicates);
}

void TransactionFuzzTest(FuzzedDataProvider &provider)
{
    static bool runEndFlag = false;
    OH_Rdb_Config *config = CreateRandomConfig(provider);
    int errCode;
    static OH_Rdb_Store *store = OH_Rdb_GetOrOpen(config, &errCode);
    OH_RDB_TransOptions *options = CreateRandomTransOptions(provider);
    OH_Rdb_Transaction *trans = nullptr;
    OH_Rdb_CreateTransaction(store, options, &trans);
    OH_RdbTrans_Commit(trans);
    OH_RdbTrans_Rollback(trans);
    std::string table = provider.ConsumeRandomLengthString(STRING_SIZE_MAX);
    int64_t rowId = 0;
    OH_VBucket *valueBucket = CreateRandomVBucket(provider);
    OH_RdbTrans_Insert(trans, table.c_str(), valueBucket, &rowId);
    OH_Data_VBuckets *list = CreateRandomVBuckets(provider);
    std::string batchTable = provider.ConsumeRandomLengthString(STRING_SIZE_MAX);
    int64_t changes;
    Rdb_ConflictResolution resolution = static_cast<Rdb_ConflictResolution>(
        provider.ConsumeIntegralInRange<int>(RDB_CONFLICT_NONE, RDB_CONFLICT_REPLACE));
    OH_RdbTrans_BatchInsert(trans, batchTable.c_str(), list, resolution, &changes);
    OH_RdbTrans_InsertWithConflictResolution(trans, table.c_str(), valueBucket, resolution, &rowId);
    OH_Predicates *predicate = GetCapiTransPredicates(provider, table);
    OH_RdbTrans_UpdateWithConflictResolution(trans, valueBucket, predicate, resolution, &rowId);
    DeleteCapiTransPredicates(predicate);
    DeleteCapiValueBuckets(list);
    ReleaseConfig(config);
    OH_RdbTrans_DestroyOptions(options);
    if (valueBucket != nullptr) {
        valueBucket->destroy(valueBucket);
    }
    OH_RdbTrans_Destroy(trans);
    if (!runEndFlag) {
        runEndFlag = true;
        std::cout << "TransactionFuzzTest end" << std::endl;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Run your code on data
    FuzzedDataProvider provider(data, size);
    TransactionFuzzTest(provider);
    return 0;
}

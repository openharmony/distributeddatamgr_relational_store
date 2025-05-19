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
#include "relationalstore_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "grd_api_manager.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"

using namespace OHOS::NativeRdb;
using namespace OHOS::RdbNdk;

struct OH_Rdb_ConfigV2 *CreateOHRdbConfigV2(FuzzedDataProvider &provider)
{
    struct OH_Rdb_ConfigV2 *configV2 = OH_Rdb_CreateConfig();
    if (configV2 == nullptr) {
        return nullptr;
    }
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

    Rdb_Tokenizer tokenizer =
        static_cast<Rdb_Tokenizer>(provider.ConsumeIntegralInRange<int>(RDB_NONE_TOKENIZER, RDB_CUSTOM_TOKENIZER));
    bool isSupported = false;
    OH_Rdb_IsTokenizerSupported(tokenizer, &isSupported);
    {
        Rdb_Tokenizer tokenizer =
            static_cast<Rdb_Tokenizer>(provider.ConsumeIntegralInRange<int>(RDB_NONE_TOKENIZER, RDB_CUSTOM_TOKENIZER));
        OH_Rdb_SetTokenizer(configV2, tokenizer);
    }
    bool isPersistent = provider.ConsumeBool();
    OH_Rdb_SetPersistent(configV2, isPersistent);
    int typeCount = 0;
    OH_Rdb_GetSupportedDbType(&typeCount);
    return configV2;
}

OH_VObject *CreateOHVObject(FuzzedDataProvider &provider)
{
    OH_VObject *valueObject = OH_Rdb_CreateValueObject();
    if (valueObject == nullptr) {
        return nullptr;
    }
    std::string value = provider.ConsumeRandomLengthString();
    valueObject->putText(valueObject, value.c_str());
    return valueObject;
}

OH_VBucket *CreateOHVBucket(FuzzedDataProvider &provider)
{
    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    if (valueBucket == nullptr) {
        return nullptr;
    }
    {
        std::string key = provider.ConsumeRandomLengthString();
        int64_t value = provider.ConsumeIntegral<int64_t>();
        valueBucket->putInt64(valueBucket, key.c_str(), value);
    }
    {
        std::string key = provider.ConsumeRandomLengthString();
        std::string value = provider.ConsumeRandomLengthString();
        valueBucket->putText(valueBucket, key.c_str(), value.c_str());
    }
    {
        std::string key = provider.ConsumeRandomLengthString();
        float value = provider.ConsumeFloatingPoint<float>();
        valueBucket->putReal(valueBucket, key.c_str(), value);
    }
    {
        std::string key = provider.ConsumeRandomLengthString();
        const int minBlobSize = 1;
        const int maxBlobSize = 50;
        size_t blobSize = provider.ConsumeIntegralInRange<size_t>(minBlobSize, maxBlobSize);
        std::vector<uint8_t> blobData = provider.ConsumeBytes<uint8_t>(blobSize);
        valueBucket->putBlob(valueBucket, key.c_str(), blobData.data(), blobData.size());
    }
    return valueBucket;
}

void RelationalStoreCAPIFuzzTest(FuzzedDataProvider &provider)
{
    struct OH_Rdb_ConfigV2 *configV2 = CreateOHRdbConfigV2(provider);
    if (configV2 == nullptr) {
        return;
    }
    OH_VObject *valueObject = CreateOHVObject(provider);
    if (valueObject == nullptr) {
        return;
    }
    std::string table = provider.ConsumeRandomLengthString();
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return;
    }
    {
        std::string value = provider.ConsumeRandomLengthString();
        predicates->equalTo(predicates, value.c_str(), valueObject);
    }

    OH_VBucket *valueBucket = CreateOHVBucket(provider);
    if (valueBucket == nullptr) {
        return;
    }

    int errCode = 0;
    static OH_Rdb_Store *OHRdbStore = OH_Rdb_CreateOrOpen(configV2, &errCode);
    {
        std::string table = provider.ConsumeRandomLengthString();
        OH_Rdb_Insert(OHRdbStore, table.c_str(), valueBucket);
    }
    OH_Data_VBuckets *list = OH_VBuckets_Create();
    OH_VBuckets_PutRow(list, valueBucket);
    {
        std::string table = provider.ConsumeRandomLengthString();
        Rdb_ConflictResolution resolution = static_cast<Rdb_ConflictResolution>(
            provider.ConsumeIntegralInRange<int>(RDB_CONFLICT_NONE, RDB_CONFLICT_REPLACE));
        int64_t changes = 0;
        OH_Rdb_BatchInsert(OHRdbStore, table.c_str(), list, resolution, &changes);
    }
    OH_Rdb_Update(OHRdbStore, valueBucket, predicates);
    valueBucket->destroy(valueBucket);
    predicates->destroy(predicates);
    valueObject->destroy(valueObject);
    OH_VBuckets_Destroy(list);
    OH_Rdb_CloseStore(OHRdbStore);
    OH_Rdb_DeleteStoreV2(configV2);
    OH_Rdb_DestroyConfig(configV2);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    RelationalStoreCAPIFuzzTest(provider);
    return 0;
}

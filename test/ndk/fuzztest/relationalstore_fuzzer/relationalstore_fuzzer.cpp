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
#include <fstream>
#include <iostream>
#include <sys/stat.h>

#include "grd_api_manager.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"
#include "accesstoken_kit.h"

static constexpr const char *RDB_TEST_PATH = "/data/storage/el2/database/com.ohos.example.distributedndk/entry/";
const std::string RDB_TEST_PATH1 =
    "/data/storage/el2/database/com.ohos.example.distributedndk/entry/rdb/rdb_store_test.db";

using namespace OHOS::NativeRdb;
using namespace OHOS::RdbNdk;
using namespace OHOS::Security::AccessToken;

void CreateAndSetCryptoParam(FuzzedDataProvider &provider, OH_Rdb_ConfigV2 *config)
{
    if (config == nullptr) {
        return;
    }
    OH_Rdb_CryptoParam *param = OH_Rdb_CreateCryptoParam();
    int32_t length = provider.ConsumeIntegral<int32_t>();
    std::vector<uint8_t> key = provider.ConsumeBytes<uint8_t>(length);
    int64_t iterator = provider.ConsumeIntegral<int32_t>();
    int32_t algo = provider.ConsumeIntegral<int32_t>();
    int64_t size = provider.ConsumeIntegral<int32_t>();

    OH_Crypto_SetEncryptionKey(param, key.data(), key.size());
    OH_Crypto_SetIteration(param, iterator);
    OH_Crypto_SetEncryptionAlgo(param, algo);
    OH_Crypto_SetHmacAlgo(param, algo);
    OH_Crypto_SetKdfAlgo(param, algo);
    OH_Crypto_SetCryptoPageSize(param, size);
    OH_Rdb_SetCryptoParam(config, param);
    if (param != nullptr) {
        OH_Rdb_DestroyCryptoParam(param);
    }
}

void TestCorruptedHandler(void *context, OH_Rdb_ConfigV2 *config, OH_Rdb_Store *store)
{
    OH_Rdb_DeleteStoreV2(config);
}

constexpr int RDB_CONFIG_PLUGINS_MAX = 16;
void CreateAndSetPlugins(FuzzedDataProvider &provider, OH_Rdb_ConfigV2 *config)
{
    uint32_t count = provider.ConsumeIntegralInRange(0, RDB_CONFIG_PLUGINS_MAX);
    std::vector<std::string> plugins;
    for (uint32_t i = 0; i < count; i++) {
        plugins.push_back(provider.ConsumeRandomLengthString());
    }
    const char *arr[RDB_CONFIG_PLUGINS_MAX] = {nullptr};
    for (size_t i = 0; i < count; ++i) {
        arr[i] = plugins[i].c_str();
    }
    OH_Rdb_SetPlugins(config, arr, count);
}

void AppendApi20ConfigV2(FuzzedDataProvider &provider, struct OH_Rdb_ConfigV2 *configV2)
{
    if (configV2 == nullptr) {
        return;
    }
    bool readOnly = provider.ConsumeBool();
    OH_Rdb_SetReadOnly(configV2, readOnly);
    std::string customDir = provider.ConsumeRandomLengthString();
    OH_Rdb_SetCustomDir(configV2, customDir.c_str());
    CreateAndSetPlugins(provider, configV2);
    CreateAndSetCryptoParam(provider, configV2);
}

void DestroyDb(const std::string &filePath)
{
    const char *message = "hello";
    const size_t messageLength = 5;
    const size_t seekPosition = 64;
    std::ofstream fsDb(filePath, std::ios_base::binary | std::ios_base::out);
    fsDb.seekp(seekPosition);
    fsDb.write(message, messageLength);
    fsDb.close();
}

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
        table = provider.ConsumeRandomLengthString();
        OH_Rdb_Insert(OHRdbStore, table.c_str(), valueBucket);
    }
    OH_Data_VBuckets *list = OH_VBuckets_Create();
    OH_VBuckets_PutRow(list, valueBucket);
    {
        table = provider.ConsumeRandomLengthString();
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

void RelationalConfigV2Capi20FuzzTest(FuzzedDataProvider &provider)
{
    static bool runEndFlag = false;
    struct OH_Rdb_ConfigV2 *configV2 = CreateOHRdbConfigV2(provider);
    if (configV2 == nullptr) {
        return;
    }
    AppendApi20ConfigV2(provider, configV2);
    OH_Rdb_DestroyConfig(configV2);
    if (!runEndFlag) {
        runEndFlag = true;
        std::cout << "RelationalConfigV2Capi20FuzzTest end" << std::endl;
    }
}

OH_Rdb_ConfigV2* g_normalConfig = nullptr;
void MockHap(void)
{
    HapInfoParams info = {
        .userID = 100,
        .bundleName = "com.example.distributed",
        .instIndex = 0,
        .appIDDesc = "com.example.distributed"
    };
    PermissionDef infoManagerTestPermDef = {
        .permissionName = "ohos.permission.test",
        .bundleName = "com.example.distributed",
        .grantMode = 1,
        .availableLevel = APL_NORMAL,
        .label = "label",
        .labelId = 1,
        .description = "open the door",
        .descriptionId = 1
    };
    PermissionStateFull infoManagerTestState = {
        .permissionName = "ohos.permission.test",
        .isGeneral = true,
        .resDeviceID = { "local" },
        .grantStatus = { PermissionState::PERMISSION_GRANTED },
        .grantFlags = { 1 }
    };
    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = { infoManagerTestPermDef },
        .permStateList = { infoManagerTestState }
    };
    AccessTokenKit::AllocHapToken(info, policy);
}

OH_Rdb_Store *GetFuzzerNormalStore()
{
    MockHap();
    // 0770 is permission
    mkdir(RDB_TEST_PATH, 0770);
    g_normalConfig = OH_Rdb_CreateConfig();
    OH_Rdb_SetDatabaseDir(g_normalConfig, RDB_TEST_PATH);
    OH_Rdb_SetStoreName(g_normalConfig, "rdb_store_test.db");
    OH_Rdb_SetBundleName(g_normalConfig, "com.ohos.example.distributedndk");
    OH_Rdb_SetEncrypted(g_normalConfig, false);
    OH_Rdb_SetSecurityLevel(g_normalConfig, OH_Rdb_SecurityLevel::S1);
    OH_Rdb_SetArea(g_normalConfig, RDB_SECURITY_AREA_EL1);
    int errCode = 0;
    OH_Rdb_Store *store = OH_Rdb_CreateOrOpen(g_normalConfig, &errCode);
    return store;
}

void DeleteFuzzerNormalStroe(OH_Rdb_Store *store)
{
    if (store != nullptr) {
        delete store;
    }
    OH_Rdb_DeleteStoreV2(g_normalConfig);
    OH_Rdb_DestroyConfig(g_normalConfig);
    g_normalConfig = nullptr;
}


void InitFuzzerNormalStore(OH_Rdb_Store *store)
{
    if (store == nullptr) {
        return;
    }
    char createTableSql[] = "CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    OH_Rdb_Execute(store, createTableSql);
}

OH_VBucket* GetFuzzerNormalValuesBucket()
{
    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 1);
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    // 12800 stub number
    valueBucket->putInt64(valueBucket, "data2", 12800);
    // 100.1 stub number
    valueBucket->putReal(valueBucket, "data3", 100.1);
    valueBucket->putText(valueBucket, "data5", "ABCDEFG");
    return valueBucket;
}

void DeleteFuzzerNormalValuesBucket(OH_VBucket *valueBucket)
{
    if (valueBucket == nullptr) {
        return;
    }
    valueBucket->destroy(valueBucket);
}

OH_Predicates* GetCapi20Predicates(FuzzedDataProvider &provider, std::string table)
{
    OH_Predicates *predicates = OH_Rdb_CreatePredicates(table.c_str());
    if (predicates == nullptr) {
        return nullptr;
    }
    std::string value = provider.ConsumeRandomLengthString();
    OH_VObject *valueObject = CreateOHVObject(provider);
    if (valueObject == nullptr) {
        predicates->destroy(predicates);
        return nullptr;
    }
    predicates->equalTo(predicates, value.c_str(), valueObject);
    valueObject->destroy(valueObject);
    return predicates;
}

void DeleteCapi20Predicates(OH_Predicates *predicates)
{
    if (predicates != nullptr) {
        return;
    }
    predicates->destroy(predicates);
}


void RelationalStoreCapi20FuzzTest(FuzzedDataProvider &provider)
{
    static bool runEndFlag = false;
    int64_t rowId;
    std::string table = "test";
    Rdb_ConflictResolution resolution = static_cast<Rdb_ConflictResolution>(
        provider.ConsumeIntegralInRange<int>(RDB_CONFLICT_NONE, RDB_CONFLICT_REPLACE));

    OH_Rdb_Store *store = GetFuzzerNormalStore();
    OH_VBucket *valueBucket = GetFuzzerNormalValuesBucket();
    OH_Predicates *predicates = GetCapi20Predicates(provider, table);
    do {
        if (store == nullptr || valueBucket == nullptr || predicates == nullptr) {
            break;
        }
        OH_Rdb_InsertWithConflictResolution(store, table.c_str(), valueBucket, resolution, &rowId);
        OH_Rdb_UpdateWithConflictResolution(store, valueBucket, predicates, resolution, &rowId);
        if (!runEndFlag) {
            runEndFlag = true;
            std::cout << "RelationalStoreCapi20FuzzTest end" << std::endl;
        }
    } while (0);

    DeleteCapi20Predicates(predicates);
    DeleteFuzzerNormalValuesBucket(valueBucket);
    DeleteFuzzerNormalStroe(store);
}

void RelationalStoreAttatchFuzzTest(FuzzedDataProvider &provider)
{
    static bool runEndFlag = false;
    OH_Rdb_Store *store = GetFuzzerNormalStore();
    OH_Rdb_ConfigV2 *attachConfig = OH_Rdb_CreateConfig();
    int64_t waitTime = provider.ConsumeIntegral<int32_t>();
    do {
        if (store == nullptr || attachConfig == nullptr) {
            break;
        }
        OH_Rdb_SetDatabaseDir(attachConfig, RDB_TEST_PATH);
        OH_Rdb_SetStoreName(attachConfig, "rdb_attach_store_test.db");
        OH_Rdb_SetBundleName(attachConfig, "com.ohos.example.distributedndk");
        OH_Rdb_SetEncrypted(attachConfig, false);
        OH_Rdb_SetSecurityLevel(attachConfig, OH_Rdb_SecurityLevel::S1);
        OH_Rdb_SetArea(attachConfig, RDB_SECURITY_AREA_EL1);

        size_t attachedNumber = 0;
        OH_Rdb_Attach(store, attachConfig, "attach_test", waitTime, &attachedNumber);
        OH_Rdb_Detach(store, "attach_test", waitTime, &attachedNumber);
        if (!runEndFlag) {
            runEndFlag = true;
            std::cout << "RelationalStoreAttatchFuzzTest end" << std::endl;
        }
    } while (0);

    OH_Rdb_DestroyConfig(attachConfig);
    DeleteFuzzerNormalStroe(store);
}

void RelationalStoreCorruptedHandlerFuzzTest(FuzzedDataProvider &provider)
{
    OH_Rdb_ConfigV2 *configV2 = CreateOHRdbConfigV2(provider);
    if (configV2 == nullptr) {
        return;
    }
    OH_Rdb_SetDatabaseDir(configV2, RDB_TEST_PATH);
    OH_Rdb_SetStoreName(configV2, "rdb_store_test.db");
    OH_Rdb_SetBundleName(configV2, "com.ohos.example.distributedndk");
    void *context = nullptr;
    Rdb_CorruptedHandler handler = TestCorruptedHandler;
    auto ret = OH_Rdb_RegisterCorruptedHandler(configV2, context, handler);
    if (ret != RDB_OK) {
        return;
    }
    int errCode = 0;
    OH_Rdb_Store *store = OH_Rdb_CreateOrOpen(configV2, &errCode);
    if (store == nullptr) {
        return;
    }
    OH_Rdb_CloseStore(store);
    DestroyDb(RDB_TEST_PATH1);
    int errCode2 = OH_Rdb_ErrCode::RDB_OK;
    auto store2 = OH_Rdb_CreateOrOpen(configV2, &errCode2);
    store2 = OH_Rdb_CreateOrOpen(configV2, &errCode2);
    OH_Rdb_UnregisterCorruptedHandler(configV2, context, handler);
    OH_Rdb_CloseStore(store2);
    OH_Rdb_DeleteStoreV2(configV2);
    OH_Rdb_DestroyConfig(configV2);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);

    RelationalStoreCAPIFuzzTest(provider);

    // Test OH_Rdb_SetCryptoParam
    RelationalConfigV2Capi20FuzzTest(provider);

    // Test OH_Rdb_InsertWithConflictResolution and OH_Rdb_UpdateWithConflictResolution
    RelationalStoreCapi20FuzzTest(provider);

    // Test OH_Rdb_Attach and OH_Rdb_Detach
    RelationalStoreAttatchFuzzTest(provider);

    RelationalStoreCorruptedHandlerFuzzTest(provider);
    return 0;
}

/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "rdbrekeyvector_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"
#include "rdb_store_config.h"

using namespace OHOS;
using namespace OHOS::NativeRdb;

static const int STRING_MAX_LENGTH = 15;
static const int MIN_KEY_SIZE = 0;
static const int MAX_KEY_SIZE = 100;

namespace OHOS {

class RekeyVectorOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override
    {
        auto res = store.Execute("CREATE TABLE IF NOT EXISTS test "
                                 "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                 "name TEXT NOT NULL, age INTEGER, salary REAL)");
        return res.first;
    }
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override
    {
        return E_OK;
    }
};

static std::vector<uint8_t> ConsumeEncryptKey(FuzzedDataProvider &provider)
{
    size_t keyLen = provider.ConsumeIntegralInRange<size_t>(MIN_KEY_SIZE, MAX_KEY_SIZE);
    return provider.ConsumeBytes<uint8_t>(keyLen);
}

void RdbRekeyVectorWithKeyFuzz(FuzzedDataProvider &provider)
{
    std::string dbPath = "/data/test/rekeyVectorFuzz_" +
        provider.ConsumeRandomLengthString(STRING_MAX_LENGTH) + ".db";
    RdbStoreConfig config(dbPath);
    config.SetIsVector(true);
    config.SetEncryptStatus(true);
    config.SetBundleName("com.example.fuzz_rekey_vector");

    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptKey_ = ConsumeEncryptKey(provider);
    config.SetCryptoParam(cryptoParam);

    RekeyVectorOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    if (store == nullptr || errCode != E_OK) {
        RdbHelper::DeleteRdbStore(config);
        return;
    }

    store->Execute("INSERT INTO test VALUES(1, 'fuzztest', 20, 50.5)", {});

    RdbStoreConfig::CryptoParam newCryptoParam;
    newCryptoParam.encryptKey_ = ConsumeEncryptKey(provider);
    newCryptoParam.isVectorRekey = true;
    store->Rekey(newCryptoParam);

    store = nullptr;
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(config);
}

void RdbRekeyVectorEmptyKeyFuzz(FuzzedDataProvider &provider)
{
    std::string dbPath = "/data/test/rekeyVectorEmptyFuzz_" +
        provider.ConsumeRandomLengthString(STRING_MAX_LENGTH) + ".db";
    RdbStoreConfig config(dbPath);
    config.SetIsVector(true);
    config.SetEncryptStatus(true);
    config.SetBundleName("com.example.fuzz_rekey_vector");

    RekeyVectorOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    if (store == nullptr || errCode != E_OK) {
        RdbHelper::DeleteRdbStore(config);
        return;
    }

    RdbStoreConfig::CryptoParam emptyCryptoParam;
    emptyCryptoParam.isVectorRekey = true;
    store->Rekey(emptyCryptoParam);

    store = nullptr;
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(config);
}

void RdbRekeyVectorIsVectorFlagFuzz(FuzzedDataProvider &provider)
{
    std::string dbPath = "/data/test/rekeyVectorFlagFuzz_" +
        provider.ConsumeRandomLengthString(STRING_MAX_LENGTH) + ".db";
    RdbStoreConfig config(dbPath);
    config.SetIsVector(true);
    config.SetEncryptStatus(true);
    config.SetBundleName("com.example.fuzz_rekey_vector");

    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptKey_ = ConsumeEncryptKey(provider);
    config.SetCryptoParam(cryptoParam);

    RekeyVectorOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    if (store == nullptr || errCode != E_OK) {
        RdbHelper::DeleteRdbStore(config);
        return;
    }

    RdbStoreConfig::CryptoParam newCryptoParam;
    newCryptoParam.encryptKey_ = ConsumeEncryptKey(provider);
    newCryptoParam.isVectorRekey = provider.ConsumeBool();
    store->Rekey(newCryptoParam);

    store = nullptr;
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(config);
}

void RdbRekeyVectorConfigFuzz(FuzzedDataProvider &provider)
{
    std::string dbPath = "/data/test/rekeyVectorCfgFuzz_" +
        provider.ConsumeRandomLengthString(STRING_MAX_LENGTH) + ".db";
    RdbStoreConfig config(dbPath);
    config.SetIsVector(provider.ConsumeBool());
    config.SetEncryptStatus(provider.ConsumeBool());
    config.SetReadOnly(provider.ConsumeBool());
    config.SetBundleName("com.example.fuzz_rekey_vector");

    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptKey_ = ConsumeEncryptKey(provider);
    config.SetCryptoParam(cryptoParam);

    RekeyVectorOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    if (store == nullptr || errCode != E_OK) {
        RdbHelper::DeleteRdbStore(config);
        return;
    }

    RdbStoreConfig::CryptoParam newCryptoParam;
    newCryptoParam.encryptKey_ = ConsumeEncryptKey(provider);
    newCryptoParam.iterNum = provider.ConsumeIntegral<int32_t>();
    newCryptoParam.isVectorRekey = provider.ConsumeBool();
    store->Rekey(newCryptoParam);

    store = nullptr;
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(config);
}

void RdbRekeyVectorConsecutiveFuzz(FuzzedDataProvider &provider)
{
    std::string dbPath = "/data/test/rekeyVectorConsecFuzz_" +
        provider.ConsumeRandomLengthString(STRING_MAX_LENGTH) + ".db";
    RdbStoreConfig config(dbPath);
    config.SetIsVector(true);
    config.SetEncryptStatus(true);
    config.SetBundleName("com.example.fuzz_rekey_vector");

    RdbStoreConfig::CryptoParam cryptoParam;
    cryptoParam.encryptKey_ = ConsumeEncryptKey(provider);
    config.SetCryptoParam(cryptoParam);

    RekeyVectorOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    if (store == nullptr || errCode != E_OK) {
        RdbHelper::DeleteRdbStore(config);
        return;
    }

    store->Execute("INSERT INTO test VALUES(1, 'fuzztest', 20, 50.5)", {});

    int rekeyCount = provider.ConsumeIntegralInRange<int>(1, 5);
    for (int i = 0; i < rekeyCount; i++) {
        RdbStoreConfig::CryptoParam newParam;
        newParam.encryptKey_ = ConsumeEncryptKey(provider);
        newParam.isVectorRekey = true;
        store->Rekey(newParam);
    }

    store = nullptr;
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(config);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::RdbRekeyVectorWithKeyFuzz(provider);
    OHOS::RdbRekeyVectorEmptyKeyFuzz(provider);
    OHOS::RdbRekeyVectorIsVectorFlagFuzz(provider);
    OHOS::RdbRekeyVectorConfigFuzz(provider);
    OHOS::RdbRekeyVectorConsecutiveFuzz(provider);
    return 0;
}

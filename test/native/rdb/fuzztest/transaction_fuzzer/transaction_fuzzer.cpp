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
#include "transaction_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <rdb_helper.h>
#include <rdb_store.h>
#include <rdb_store_config.h>
#include <securec.h>
#include <values_bucket.h>

#include <memory>

#include "connection_pool.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "trans_db.h"

using namespace OHOS;
using namespace OHOS::NativeRdb;
namespace OHOS {

static const std::string RDB_PATH = "/data/test/transactionFuzzTest.db";
static const std::string CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test "
                                             "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                             "name TEXT NOT NULL, age INTEGER, salary REAL, "
                                             "blobType BLOB)";

class TransactionTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

int TransactionTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int TransactionTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void TransactionCommitFailFuzzTest(FuzzedDataProvider &provider)
{
    RdbHelper::DeleteRdbStore(RDB_PATH);
    RdbStoreConfig config(RDB_PATH);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    config.SetReadOnly(false);
    TransactionTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    if (store == nullptr || errCode != E_OK) {
        return;
    }

    store->Execute("DROP TABLE IF EXISTS test1");
    auto res = store->Execute("CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
    if (res.first != E_OK) {
        return;
    }

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    if (transaction == nullptr || ret != E_OK) {
        return;
    }

    Transaction::Row row;
    row.Put("id", provider.ConsumeIntegral<int>());
    row.Put("name", provider.ConsumeRandomLengthString());
    auto result = transaction->Insert("test1", row);
    const int count = 1;
    if (result.first != E_OK || result.second != count) {
        return;
    }

    // Constructing a Commit Failure Scenario
    std::string walFile = RDB_PATH + "-wal";

    // Disabling wal File Operations
    std::string chattrAddiCmd = "chattr +i " + walFile;
    system(chattrAddiCmd.c_str());

    ret = transaction->Commit();
    if (ret == E_OK) {
        return;
    }

    // Enable the wal file operation.
    std::string chattrSubiCmd = "chattr -i " + walFile;
    system(chattrSubiCmd.c_str());

    RdbHelper::DeleteRdbStore(RDB_PATH);
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::TransactionCommitFailFuzzTest(provider);
    return 0;
}

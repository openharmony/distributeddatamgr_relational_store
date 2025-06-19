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
#include "rdb_attach_test_ut2fuzz.h"

#include <fuzzer/FuzzedDataProvider.h>

#include <climits>
#include <string>

#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace OHOS;
using namespace OHOS::NativeRdb;
namespace OHOS {

static const std::string MAIN_DATABASE_NAME = "/data/test/main.db";
static const std::string ATTACHED_DATABASE_NAME = "/data/test/attached.db";
static const std::string ENCRYPT_ATTACHED_DATABASE_NAME = "/data/test/encrypt_attached.db";
static const int BUSY_TIMEOUT = 2;

class MainOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string createTableSql;
};

std::string const MainOpenCallback::createTableSql = "CREATE TABLE IF NOT EXISTS test1(id INTEGER PRIMARY KEY "
                                                        "AUTOINCREMENT, name TEXT NOT NULL)";

int MainOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(createTableSql);
}

int MainOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

class AttachedOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string createTableSql;
};

std::string const AttachedOpenCallback::createTableSql = "CREATE TABLE IF NOT EXISTS test2(id INTEGER PRIMARY KEY "
                                                            "AUTOINCREMENT, name TEXT NOT NULL)";

int AttachedOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(createTableSql);
}

int AttachedOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void SetUpTestCase(void)
{
    RdbStoreConfig attachedConfig(ATTACHED_DATABASE_NAME);
    AttachedOpenCallback attachedHelper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> attachedStore = RdbHelper::GetRdbStore(attachedConfig, 1, attachedHelper, errCode);
}

void TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(MAIN_DATABASE_NAME);
    RdbHelper::DeleteRdbStore(ATTACHED_DATABASE_NAME);
}

void QueryCheck1(std::shared_ptr<RdbStore> &store)
{
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test1");
    int ret = resultSet->GoToNextRow();
    int columnIndex;
    int intVal;
    ret = resultSet->GetColumnIndex("id", columnIndex);
    ret = resultSet->GetInt(columnIndex, intVal);
    std::string strVal;
    ret = resultSet->GetColumnIndex("name", columnIndex);
    ret = resultSet->GetString(columnIndex, strVal);
    resultSet = store->QuerySql("SELECT * FROM test2");
    ret = resultSet->GoToNextRow();
    ret = resultSet->GetColumnIndex("id", columnIndex);
    ret = resultSet->GetInt(columnIndex, intVal);
    ret = resultSet->GetColumnIndex("name", columnIndex);
    ret = resultSet->GetString(columnIndex, strVal);
}

void QueryCheck2(std::shared_ptr<RdbStore> &store)
{
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test1");
    int ret = resultSet->GoToNextRow();
    int columnIndex;
    int intVal;
    ret = resultSet->GetColumnIndex("id", columnIndex);
    ret = resultSet->GetInt(columnIndex, intVal);
    std::string strVal;
    ret = resultSet->GetColumnIndex("name", columnIndex);
    ret = resultSet->GetString(columnIndex, strVal);
    resultSet = store->QuerySql("SELECT * FROM test2");
}

void RdbAttachTestRdbStoreAttach001(FuzzedDataProvider &fdp)
{
    int errCode = E_OK;
    AttachedOpenCallback attachedHelper;
    RdbStoreConfig encryptAttachedConfig(ENCRYPT_ATTACHED_DATABASE_NAME);
    encryptAttachedConfig.SetEncryptStatus(fdp.ConsumeBool());
    std::shared_ptr<RdbStore> encryptAttachedStore =
        RdbHelper::GetRdbStore(encryptAttachedConfig, 1, attachedHelper, errCode);
    if (encryptAttachedStore == NULL) {
        return;
    }
    encryptAttachedStore = nullptr;
    const std::string attachedName = "attached";
    RdbStoreConfig config(MAIN_DATABASE_NAME);
    MainOpenCallback helper;

    std::shared_ptr<RdbStore> store1 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    if (store1 == NULL) {
        return;
    }

    store1->Attach(encryptAttachedConfig, attachedName, BUSY_TIMEOUT);

    int64_t id;
    ValuesBucket values;
    values.PutInt(fdp.ConsumeRandomLengthString(), fdp.ConsumeIntegral<int>());
    values.PutString(fdp.ConsumeRandomLengthString(), fdp.ConsumeRandomLengthString());
    store1->Insert(id, fdp.ConsumeRandomLengthString(), values);

    QueryCheck1(store1);

    store1->Detach(attachedName);

    QueryCheck2(store1);
    RdbHelper::DeleteRdbStore(ENCRYPT_ATTACHED_DATABASE_NAME);
}

void RdbAttachTestRdbStoreAttach002(FuzzedDataProvider &fdp)
{
    const std::string attachedName = "attached";
    RdbStoreConfig config(fdp.ConsumeRandomLengthString());
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    MainOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> mainMemDb = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    if (mainMemDb == NULL) {
        return;
    }

    RdbStoreConfig attachedConfig(fdp.ConsumeRandomLengthString());
    std::shared_ptr<RdbStore> walDb = RdbHelper::GetRdbStore(attachedConfig, 1, helper, errCode);
    if (walDb == NULL) {
        return;
    }

    std::string sql = fdp.ConsumeRandomLengthString();
    auto code = walDb->ExecuteSql(sql);

    mainMemDb->Attach(attachedConfig, attachedName, BUSY_TIMEOUT);

    ValueObject val;
    std::tie(code, val) =
        mainMemDb->Execute(fdp.ConsumeRandomLengthString(), { fdp.ConsumeIntegral<int32_t>(), "memDbName" });
    auto result = mainMemDb->QuerySql(fdp.ConsumeRandomLengthString());

    int index = fdp.ConsumeIntegral<int32_t>();
    result->GetColumnIndex(fdp.ConsumeRandomLengthString(), index);
    std::string name;
    result->GetString(index, name);
    result->Close();
    mainMemDb->Detach(attachedName);
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::RdbAttachTestRdbStoreAttach001(fdp);
    OHOS::RdbAttachTestRdbStoreAttach002(fdp);
    return 0;
}

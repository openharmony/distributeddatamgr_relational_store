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
#include "rdb_delete_test_ut2fuzz.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <unistd.h>

#include <climits>
#include <fstream>
#include <string>
#include <vector>

#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace OHOS;
using namespace OHOS::NativeRdb;
namespace OHOS {

static const std::string DATABASE_NAME = "/data/test/delete_test.db";
std::shared_ptr<RdbStore> store_;
std::shared_ptr<RdbStore> memDBStore_;

struct RowData {
    int id;
    std::string name;
    int age;
    double salary;
    std::vector<uint8_t> blobType;
    AssetValue asset;
    std::vector<AssetValue> assets;
};

class DeleteTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};
constexpr const char *CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test"
                                          "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                          "name TEXT NOT NULL, age INTEGER, salary "
                                          "REAL, blobType BLOB)";
int DeleteTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int DeleteTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

ValuesBucket SetRowData(const RowData &rowData)
{
    ValuesBucket value;
    value.PutInt("id", rowData.id);
    value.PutString("name", rowData.name);
    value.PutInt("age", rowData.age);
    value.PutDouble("salary", rowData.salary);
    value.PutBlob("blobType", rowData.blobType);
    return value;
}

void SetUpTestCase(void)
{
    int errCode = E_OK;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
    RdbStoreConfig config(DATABASE_NAME);
    DeleteTestOpenCallback helper;
    store_ = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    store_->ExecuteSql("DELETE FROM test");

    config.SetStorageMode(StorageMode::MODE_MEMORY);
    memDBStore_ = RdbHelper::GetRdbStore(config, 1, helper, errCode);
}

void TearDownTestCase(void)
{
    RdbStoreConfig config(DATABASE_NAME);
    RdbHelper::DeleteRdbStore(config);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    RdbHelper::DeleteRdbStore(config);
}

void RdbDeleteTestRdbStoreDelete001(FuzzedDataProvider &fdp)
{
    SetUpTestCase();
    std::shared_ptr<RdbStore> store = store_;
    if (store == NULL) {
        return;
    }

    int64_t id;
    int deletedRows;

    const RowData rowData[3] = { { 1, "zhangsan", 18, 100.5, std::vector<uint8_t>{ 1, 2, 3 } },
        { 2, "lisi", 19, 200.5, std::vector<uint8_t>{ 4, 5, 6 } },
        { 3, "wangyjing", 20, 300.5, std::vector<uint8_t>{ 7, 8, 9 } } };

    const int indexZero = 0;
    store->Insert(id, fdp.ConsumeRandomLengthString(), SetRowData(rowData[indexZero]));

    const int indexOne = 1;
    store->Insert(id, fdp.ConsumeRandomLengthString(), SetRowData(rowData[indexOne]));

    const int indexTwo = 2;
    store->Insert(id, fdp.ConsumeRandomLengthString(), SetRowData(rowData[indexTwo]));

    store->Delete(deletedRows, fdp.ConsumeRandomLengthString(), fdp.ConsumeRandomLengthString());

    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test WHERE id = ?", std::vector<std::string>{ "1" });

    resultSet->GoToNextRow();

    resultSet->Close();

    resultSet = store->QuerySql("SELECT * FROM test WHERE id = ?", std::vector<std::string>{ "2" });

    resultSet->GoToFirstRow();

    resultSet->GoToNextRow();

    resultSet->Close();

    resultSet = store->QuerySql("SELECT * FROM test WHERE id = 3", std::vector<std::string>());

    resultSet->GoToFirstRow();

    resultSet->GoToNextRow();

    resultSet->Close();
    TearDownTestCase();
}

void RdbDeleteTestRdbStoreDelete002(FuzzedDataProvider &fdp)
{
    SetUpTestCase();
    std::shared_ptr<RdbStore> store = store_;
    if (store == NULL) {
        return;
    }

    int64_t id;
    ValuesBucket values;
    int deletedRows;

    values.PutInt(fdp.ConsumeRandomLengthString(), fdp.ConsumeIntegral<int32_t>());
    values.PutString(fdp.ConsumeRandomLengthString(), std::string(fdp.ConsumeRandomLengthString()));
    values.PutInt(fdp.ConsumeRandomLengthString(), fdp.ConsumeIntegral<int32_t>());
    values.PutDouble(fdp.ConsumeRandomLengthString(), fdp.ConsumeFloatingPoint<double>());
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    store->Insert(id, fdp.ConsumeRandomLengthString(), values);

    values.Clear();
    values.PutInt(fdp.ConsumeRandomLengthString(), fdp.ConsumeIntegral<int32_t>());
    values.PutString(fdp.ConsumeRandomLengthString(), std::string(fdp.ConsumeRandomLengthString()));
    values.PutInt(fdp.ConsumeRandomLengthString(), fdp.ConsumeIntegral<int32_t>());
    values.PutDouble(fdp.ConsumeRandomLengthString(), fdp.ConsumeFloatingPoint<double>());
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    store->Insert(id, fdp.ConsumeRandomLengthString(), values);

    values.Clear();
    values.PutInt(fdp.ConsumeRandomLengthString(), fdp.ConsumeIntegral<int32_t>());
    values.PutString(fdp.ConsumeRandomLengthString(), std::string(fdp.ConsumeRandomLengthString()));
    values.PutInt(fdp.ConsumeRandomLengthString(), fdp.ConsumeIntegral<int32_t>());
    values.PutDouble(fdp.ConsumeRandomLengthString(), fdp.ConsumeFloatingPoint<double>());
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    store->Insert(id, fdp.ConsumeRandomLengthString(), values);

    store->Delete(deletedRows, fdp.ConsumeRandomLengthString());

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    if (resultSet == NULL) {
        return;
    }
    resultSet->GoToNextRow();
    resultSet->Close();
    TearDownTestCase();
}

void RdbDeleteTestRdbStoreDelete003(FuzzedDataProvider &fdp)
{
    SetUpTestCase();
    std::shared_ptr<RdbStore> store = store_;
    if (store == NULL) {
        return;
    }

    int64_t id;
    ValuesBucket values;
    int deletedRows;

    values.PutInt(fdp.ConsumeRandomLengthString(), fdp.ConsumeIntegral<int32_t>());
    values.PutString(fdp.ConsumeRandomLengthString(), std::string(fdp.ConsumeRandomLengthString()));
    values.PutInt(fdp.ConsumeRandomLengthString(), fdp.ConsumeIntegral<int32_t>());
    values.PutDouble(fdp.ConsumeRandomLengthString(), fdp.ConsumeFloatingPoint<double>());
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    store->Insert(id, fdp.ConsumeRandomLengthString(), values);

    store->Delete(deletedRows, "", "id = ?", std::vector<std::string>{ "1" });

    store->Delete(deletedRows, "wrongTable", "id = ?", std::vector<std::string>{ "1" });

    store->Delete(deletedRows, "test", "wrong sql id = ?", std::vector<std::string>{ "1" });

    store->Delete(deletedRows, "test", "id = 1", std::vector<std::string>());
    TearDownTestCase();
}

} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::RdbDeleteTestRdbStoreDelete001(fdp);
    OHOS::RdbDeleteTestRdbStoreDelete002(fdp);
    OHOS::RdbDeleteTestRdbStoreDelete003(fdp);
    return 0;
}

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
#include "rdb_double_write_test_ut2fuzz.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <string>

#include "file_ex.h"
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "sqlite_utils.h"
#include "sys/types.h"

using namespace OHOS;
using namespace OHOS::NativeRdb;
namespace OHOS {

static const std::string DATABASE_NAME = "/data/test/dual_write_test.db";
static const std::string SLAVE_DATABASE_NAME = "/data/test/dual_write_test_slave.db";
std::shared_ptr<RdbStore> store = nullptr;
std::shared_ptr<RdbStore> slaveStore = nullptr;
std::shared_ptr<RdbStore> store3 = nullptr;

class DoubleWriteTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string createTableTest;
};

const std::string DoubleWriteTestOpenCallback::createTableTest =
    std::string("CREATE TABLE IF NOT EXISTS test ") + std::string("(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                  "name TEXT NOT NULL, age INTEGER, salary "
                                                                  "REAL, blobType BLOB)");

int DoubleWriteTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(createTableTest);
}

int DoubleWriteTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void SetUpTestCase(void)
{
}

void TearDownTestCase(void)
{
    store = nullptr;
    slaveStore = nullptr;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
}

void InitDb()
{
    int errCode = E_OK;
    RdbStoreConfig config(DATABASE_NAME);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    DoubleWriteTestOpenCallback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);

    RdbStoreConfig slaveConfig(SLAVE_DATABASE_NAME);
    DoubleWriteTestOpenCallback slaveHelper;
    slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    store->ExecuteSql("DELETE FROM test");
    slaveStore->ExecuteSql("DELETE FROM test");
}

void CheckAge(std::shared_ptr<ResultSet> &resultSet)
{
    int columnIndex;
    int intVal;
    ColumnType columnType;
    int ret = resultSet->GetColumnIndex("age", columnIndex);
    ret = resultSet->GetColumnType(columnIndex, columnType);

    ret = resultSet->GetInt(columnIndex, intVal);
}

void CheckSalary(std::shared_ptr<ResultSet> &resultSet)
{
    int columnIndex;
    double dVal;
    ColumnType columnType;
    int ret = resultSet->GetColumnIndex("salary", columnIndex);

    ret = resultSet->GetColumnType(columnIndex, columnType);

    ret = resultSet->GetDouble(columnIndex, dVal);
}

void CheckBlob(std::shared_ptr<ResultSet> &resultSet)
{
    int columnIndex;
    std::vector<uint8_t> blob;
    ColumnType columnType;
    int ret = resultSet->GetColumnIndex("blobType", columnIndex);

    ret = resultSet->GetColumnType(columnIndex, columnType);

    ret = resultSet->GetBlob(columnIndex, blob);
}

void CheckNumber(
    std::shared_ptr<RdbStore> &store, int num, int errCode, const std::string &tableName)
{
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM " + tableName);
    int countNum;
    resultSet->GetRowCount(countNum);
}

void CheckResultSet(std::shared_ptr<RdbStore> &store)
{
    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test WHERE name = ?", std::vector<std::string>{ "zhangsan" });

    int columnIndex;
    int intVal;
    std::string strVal;
    ColumnType columnType;
    int position;
    int ret = resultSet->GetRowIndex(position);

    ret = resultSet->GetColumnType(0, columnType);

    ret = resultSet->GoToFirstRow();

    ret = resultSet->GetColumnIndex("id", columnIndex);

    ret = resultSet->GetColumnType(columnIndex, columnType);

    ret = resultSet->GetInt(columnIndex, intVal);

    ret = resultSet->GetColumnIndex("name", columnIndex);

    ret = resultSet->GetColumnType(columnIndex, columnType);

    ret = resultSet->GetString(columnIndex, strVal);

    CheckAge(resultSet);
    CheckSalary(resultSet);
    CheckBlob(resultSet);

    ret = resultSet->GoToNextRow();

    ret = resultSet->GetColumnType(columnIndex, columnType);

    ret = resultSet->Close();
}

void RdbDoubleWriteTestRdbStoreDoubleWrite001(FuzzedDataProvider &fdp)
{
    InitDb();
    int64_t id;
    ValuesBucket values;

    values.PutInt(fdp.ConsumeRandomLengthString(), fdp.ConsumeIntegral<int32_t>());
    values.PutString(fdp.ConsumeRandomLengthString(), std::string(fdp.ConsumeRandomLengthString()));
    values.PutInt(fdp.ConsumeRandomLengthString(), fdp.ConsumeIntegral<int32_t>());
    values.PutDouble(fdp.ConsumeRandomLengthString(), fdp.ConsumeFloatingPoint<double>());
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);

    values.Clear();
    values.PutInt(fdp.ConsumeRandomLengthString(), fdp.ConsumeIntegral<int32_t>());
    values.PutString(fdp.ConsumeRandomLengthString(), std::string(fdp.ConsumeRandomLengthString()));
    values.PutInt(fdp.ConsumeRandomLengthString(), fdp.ConsumeIntegral<int32_t>());
    values.PutDouble(fdp.ConsumeRandomLengthString(), fdp.ConsumeFloatingPoint<double>());
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Insert(id, "test", values);

    values.Clear();
    values.PutInt(fdp.ConsumeRandomLengthString(), fdp.ConsumeIntegral<int32_t>());
    values.PutString(fdp.ConsumeRandomLengthString(), std::string(fdp.ConsumeRandomLengthString()));
    values.PutInt(fdp.ConsumeRandomLengthString(), fdp.ConsumeIntegral<int64_t>());
    values.PutDouble(fdp.ConsumeRandomLengthString(), fdp.ConsumeFloatingPoint<float>());
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Insert(id, "test", values);

    CheckResultSet(slaveStore);
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::RdbDoubleWriteTestRdbStoreDoubleWrite001(fdp);
    return 0;
}

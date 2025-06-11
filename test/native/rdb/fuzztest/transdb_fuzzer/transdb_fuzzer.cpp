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
#include "transdb_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <rdb_helper.h>
#include <rdb_store.h>
#include <rdb_store_config.h>
#include <securec.h>
#include <values_bucket.h>

#include <memory>

#include "connection_pool.h"
#include "trans_db.h"

using namespace OHOS;
using namespace OHOS::NativeRdb;
namespace OHOS {

static constexpr const char *CREATE_TABLE = "CREATE TABLE IF NOT EXISTS TEST (id INT PRIMARY KEY, name TEXT, "
                                            "extend BLOB, code REAL, years UNLIMITED INT, attachment ASSET, "
                                            "attachments ASSETS)";
static constexpr const char *DROP_TABLE = "DROP TABLE IF EXISTS TEST";
static constexpr const char *TABLE_NAME = "TEST";
static const int MIN_ROWS_SIZE = 1;
static const int MAX_ROWS_SIZE = 50;

void FillDataToValuesBucket(FuzzedDataProvider &provider, ValuesBucket &value)
{
    std::string valName = provider.ConsumeRandomLengthString();
    int valAge = provider.ConsumeIntegral<int>();
    double valSalary = provider.ConsumeFloatingPoint<double>();

    value.PutString("name", valName);
    value.PutInt("age", valAge);
    value.PutDouble("salary", valSalary);
}

void FillDataToValuesBuckets(FuzzedDataProvider &provider, ValuesBuckets &values)
{
    uint32_t loopTimes = provider.ConsumeIntegralInRange<uint32_t>(MIN_ROWS_SIZE, MAX_ROWS_SIZE);
    for (uint32_t i = 0; i < loopTimes; i++) {
        ValuesBucket value;
        FillDataToValuesBucket(provider, value);
        values.Put(value);
    }
}

void TransDbExecuteFuzzTest(std::shared_ptr<RdbStore> transDB, FuzzedDataProvider &provider)
{
    if (transDB == nullptr) {
        return;
    }
    transDB->Execute(DROP_TABLE);
    transDB->Execute(CREATE_TABLE);
    std::string sql = provider.ConsumeRandomLengthString();
    transDB->Execute(sql);
}

ConflictResolution GetConflictResolution(FuzzedDataProvider &provider)
{
    int min = static_cast<int>(ConflictResolution::ON_CONFLICT_NONE);
    int max = static_cast<int>(ConflictResolution::ON_CONFLICT_REPLACE);
    int enumInt = provider.ConsumeIntegralInRange<int>(min, max);
    ConflictResolution resolution = static_cast<ConflictResolution>(enumInt);
    return resolution;
}

void TransDbInsertFuzzTest(std::shared_ptr<RdbStore> transDB, FuzzedDataProvider &provider)
{
    if (transDB == nullptr) {
        return;
    }
    ValuesBucket value;
    FillDataToValuesBucket(provider, value);

    {
        ConflictResolution resolution = GetConflictResolution(provider);
        transDB->Insert(TABLE_NAME, value, resolution);
    }

    ValuesBuckets rows;
    FillDataToValuesBuckets(provider, rows);
    transDB->BatchInsert(TABLE_NAME, rows);

    {
        ConflictResolution resolution = GetConflictResolution(provider);
        transDB->BatchInsert(TABLE_NAME, rows, resolution);
    }
}

void TransDbFuzzTest(FuzzedDataProvider &provider)
{
    std::string path = provider.ConsumeRandomLengthString();
    RdbStoreConfig config(path);
    config.SetHaMode(provider.ConsumeIntegral<int32_t>());
    int errCode = 0;
    std::shared_ptr<ConnectionPool> connPool = ConnectionPool::Create(config, errCode);
    if (connPool == nullptr) {
        return;
    }
    auto [err, conn] = connPool->CreateTransConn();
    if (err != E_OK || conn == nullptr) {
        return;
    }
    std::shared_ptr<RdbStore> transDB = std::make_shared<TransDB>(conn, config.GetName());
    if (transDB == nullptr) {
        return;
    }
    TransDbExecuteFuzzTest(transDB, provider);
    TransDbInsertFuzzTest(transDB, provider);
}

} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::TransDbFuzzTest(provider);
    return 0;
}

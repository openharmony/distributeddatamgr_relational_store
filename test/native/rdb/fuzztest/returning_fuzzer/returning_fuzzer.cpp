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
#include <iostream>
#include "rdb_errno.h"
#define LOG_TAG "RETURNING_FUZZER"
#include "returning_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <rdb_helper.h>
#include <rdb_store.h>
#include <rdb_store_config.h>
#include <securec.h>
#include <values_bucket.h>

#include <cstdint>
#include <memory>

#include "abs_predicates.h"
#include "abs_rdb_predicates.h"
#include "connection_pool.h"
#include "logger.h"
#include "trans_db.h"
#include "value_object.h"
#include "values_buckets.h"

using namespace OHOS;
using namespace OHOS::NativeRdb;
using namespace OHOS::Rdb;

namespace OHOS {

static const int MIN_BLOB_SIZE = 1;
static const int MAX_BLOB_SIZE = 20;
static const int STRING_MAX_LENGTH = 15;
static const std::string TABLE_NAME = "test";
static const std::string DATABASE_NAME = "/data/test/returningFuzz.db";
static const std::string CREATE_TABLE_SQL =
    "CREATE TABLE IF NOT EXISTS test "
    "(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB)";

class ReturningFuzzTest {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);

    static std::shared_ptr<RdbStore> store_;
};

class RdbTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

std::shared_ptr<RdbStore> ReturningFuzzTest::store_ = nullptr;

int RdbTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_SQL);
}

int RdbTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void ReturningFuzzTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    RdbStoreConfig config(DATABASE_NAME);
    config.SetSecurityLevel(SecurityLevel::S3);
    config.SetBundleName("com.example.returningfuzz");
    RdbTestOpenCallback helper;
    ReturningFuzzTest::store_ = RdbHelper::GetRdbStore(config, 1, helper, errCode);

    if (store_ == nullptr || errCode != E_OK) {
        return;
    }
}

void ReturningFuzzTest::TearDownTestCase(void)
{
    if (RdbHelper::DeleteRdbStore(DATABASE_NAME) != E_OK) {
        return;
    }
}

std::vector<std::string> GetColumns(FuzzedDataProvider &provider, int max = 10, int min = 1)
{
    std::vector<std::string> columns;
    int colCount = provider.ConsumeIntegralInRange<int>(min, max);
    for (int i = 0; i < colCount; i++) {
        columns.push_back(provider.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    }
    return columns;
}

ValuesBucket MakeRandomBucket(FuzzedDataProvider &provider)
{
    ValuesBucket bucket;
    size_t strLength = provider.ConsumeIntegralInRange<size_t>(1, 16);
    int fieldCount = provider.ConsumeIntegralInRange<int>(1, 5);
    for (int i = 0; i < fieldCount; ++i) {
        std::string key = provider.ConsumeRandomLengthString(strLength);
        int type = provider.ConsumeIntegralInRange<int>(0, 2);
        if (type == 0) {
            bucket.Put(key, provider.ConsumeIntegral<int>());
        } else if (type == 1) {
            bucket.Put(key, provider.ConsumeRandomLengthString(strLength));
        } else {
            int blobSize = provider.ConsumeIntegralInRange<size_t>(MIN_BLOB_SIZE, MAX_BLOB_SIZE);
            std::vector<uint8_t> blob =
                provider.ConsumeBytes<uint8_t>(provider.ConsumeIntegralInRange<size_t>(0, blobSize));
            bucket.PutBlob(key, blob);
        }
    }
    return bucket;
}

Transaction::TransactionType GetRandomTransactionType(FuzzedDataProvider &provider)
{
    return provider.PickValueInArray({
        Transaction::DEFERRED,
        Transaction::IMMEDIATE,
        Transaction::EXCLUSIVE
    });
}

ConflictResolution GetRandomConflictResolution(FuzzedDataProvider &provider)
{
    return provider.PickValueInArray({
        ConflictResolution::ON_CONFLICT_NONE,
        ConflictResolution::ON_CONFLICT_ROLLBACK,
        ConflictResolution::ON_CONFLICT_ABORT,
        ConflictResolution::ON_CONFLICT_REPLACE,
        ConflictResolution::ON_CONFLICT_IGNORE,
        ConflictResolution::ON_CONFLICT_FAIL
    });
}

void BatchInsertReturningFuzz(FuzzedDataProvider &provider, std::shared_ptr<RdbStore> store)
{
    std::string valName = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int valAge = provider.ConsumeIntegral<int>();
    double valSalary = provider.ConsumeFloatingPoint<double>();

    ValuesBuckets rows;
    ValuesBucket value;
    value.PutString("name", valName);
    value.PutInt("age", valAge);
    value.PutDouble("salary", valSalary);
    rows.Put(value);

    size_t blobSize = provider.ConsumeIntegralInRange<size_t>(MIN_BLOB_SIZE, MAX_BLOB_SIZE);
    std::vector<uint8_t> blobData = provider.ConsumeBytes<uint8_t>(blobSize);
    value.PutBlob("blobType", blobData);

    auto resolution = GetRandomConflictResolution(provider);

    auto columns = GetColumns(provider);
    auto [codeReturning, result] = store->BatchInsert(TABLE_NAME, rows, columns, resolution);

    auto [ret, trans] = store->CreateTransaction(GetRandomTransactionType(provider));

    if (ret != E_OK || trans == nullptr) {
        LOG_ERROR("Failed to create transaction, error code: %{public}d", ret);
        return;
    }
    
    trans->BatchInsert(TABLE_NAME, rows, columns, resolution);

    trans->Commit();
}

void UpdateReturningFuzz(FuzzedDataProvider &provider, std::shared_ptr<RdbStore> store)
{
    std::string valName = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int valAge = provider.ConsumeIntegral<int>();
    double valSalary = provider.ConsumeFloatingPoint<double>();

    ValuesBucket values;
    values.PutString("name", valName);
    values.PutInt("age", valAge);
    values.PutDouble("salary", valSalary);

    size_t blobSize = provider.ConsumeIntegralInRange<size_t>(MIN_BLOB_SIZE, MAX_BLOB_SIZE);
    std::vector<uint8_t> blobData = provider.ConsumeBytes<uint8_t>(blobSize);
    values.PutBlob("blobType", blobData);

    AbsRdbPredicates predicates(TABLE_NAME);
    predicates.EqualTo("name", ValueObject(provider.ConsumeRandomLengthString(STRING_MAX_LENGTH)));
    auto returningFields = GetColumns(provider);

    store->Update(values, predicates, returningFields);

    auto [ret, trans] = store->CreateTransaction(GetRandomTransactionType(provider));

    if (ret != E_OK || trans == nullptr) {
        LOG_ERROR("Failed to create transaction, error code: %{public}d", ret);
        return;
    }

    AbsRdbPredicates predicates2(TABLE_NAME);
    predicates2.EqualTo("name", ValueObject(provider.ConsumeRandomLengthString(STRING_MAX_LENGTH)));
    auto returningFields2 = GetColumns(provider);
    
    trans->Update(values, predicates2, returningFields2);
    trans->Commit();
}

void DeleteReturningFuzz(FuzzedDataProvider &provider, std::shared_ptr<RdbStore> store)
{
    AbsRdbPredicates predicates(TABLE_NAME);
    predicates.EqualTo("name", ValueObject(provider.ConsumeRandomLengthString(STRING_MAX_LENGTH)));
    auto returningFields = GetColumns(provider);

    store->Delete(predicates, returningFields);

    auto [ret, trans] = store->CreateTransaction(GetRandomTransactionType(provider));

    if (ret != E_OK || trans == nullptr) {
        LOG_ERROR("Failed to create transaction, error code: %{public}d", ret);
        return;
    }
    AbsRdbPredicates predicates2(TABLE_NAME);
    predicates2.EqualTo("name", ValueObject(provider.ConsumeRandomLengthString(STRING_MAX_LENGTH)));
    auto returningFields2 = GetColumns(provider);
    trans->Delete(predicates2, returningFields2);
    trans->Rollback();
}

void ExecuteExtReturningFuzz(FuzzedDataProvider &provider, std::shared_ptr<RdbStore> store)
{
    std::string sql = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);

    std::vector<ValueObject> bindArgs;
    bindArgs.push_back(ValueObject(provider.ConsumeIntegral<int>()));
    bindArgs.push_back(ValueObject(provider.ConsumeRandomLengthString(STRING_MAX_LENGTH)));
    bindArgs.push_back(ValueObject(provider.ConsumeIntegral<int>()));
    bindArgs.push_back(ValueObject(provider.ConsumeFloatingPoint<double>()));

    size_t blobSize = provider.ConsumeIntegralInRange<size_t>(MIN_BLOB_SIZE, MAX_BLOB_SIZE);
    std::vector<uint8_t> blobData = provider.ConsumeBytes<uint8_t>(blobSize);
    bindArgs.push_back(ValueObject(blobData));

    auto returning = provider.PickValueInArray<std::string>({
        "id",
        "name",
        "age",
        "salary",
    });

    store->ExecuteExt("INSERT INTO test(id, name, age, salary) VALUES (?, ?, ?, ?) returning " + returning, bindArgs);
    store->ExecuteExt("UPDATE test set name = ? where name = ? RETURNING " + returning, bindArgs);
    store->ExecuteExt("DELETE FROM test where name = ? RETURNING " + returning, bindArgs);

    auto [ret, trans] = store->CreateTransaction(GetRandomTransactionType(provider));

    if (ret != E_OK || trans == nullptr) {
        LOG_ERROR("Failed to create transaction, error code: %{public}d", ret);
        return;
    }

    trans->ExecuteExt("INSERT INTO test(id, name, age, salary) VALUES (?, ?, ?, ?) returning " + returning, bindArgs);
    trans->ExecuteExt("UPDATE test set name = ? where name = ? RETURNING " + returning, bindArgs);
    trans->ExecuteExt("DELETE FROM test where name = ? RETURNING " + returning, bindArgs);
    trans->Rollback();
}

void ValuesBucketFuzz(FuzzedDataProvider &provider)
{
    int rowCount = provider.ConsumeIntegralInRange<int>(0, 10);
    std::vector<ValuesBucket> buckets;
    for (int i = 0; i < rowCount; ++i) {
        buckets.push_back(MakeRandomBucket(provider));
    }

    ValuesBuckets vb1;
    ValuesBuckets vb2(buckets);
    ValuesBuckets vb3(std::move(buckets));

    for (int i = 0; i < rowCount; ++i) {
        vb1.Put(MakeRandomBucket(provider));
    }

    vb1.RowSize();
    std::string field = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    vb1.GetFieldsAndValues();
    int32_t size = static_cast<int32_t>(provider.ConsumeIntegral<uint8_t>());
    vb1.Reserve(size);
    vb1.Clear();
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::ReturningFuzzTest::SetUpTestCase();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::BatchInsertReturningFuzz(provider, ReturningFuzzTest::store_);
    OHOS::UpdateReturningFuzz(provider, ReturningFuzzTest::store_);
    OHOS::DeleteReturningFuzz(provider, ReturningFuzzTest::store_);
    OHOS::ExecuteExtReturningFuzz(provider, ReturningFuzzTest::store_);
    OHOS::ValuesBucketFuzz(provider);
    return 0;
}

/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "rdbstore_fuzzer.h"

#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"

using namespace OHOS;
using namespace OHOS::NativeRdb;

namespace OHOS {
class RdbStoreFuzzTest {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);

    static bool InsertData(std::shared_ptr<RdbStore> store, const uint8_t *data, size_t size);
    static bool BatchInsertData(std::shared_ptr<RdbStore> store, const uint8_t *data, size_t size);

    static std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store_;
};
std::shared_ptr<RdbStore> RdbStoreFuzzTest::store_ = nullptr;
std::string RdbStoreFuzzTest::DATABASE_NAME = "/data/test/rdbStoreFuzz.db";

class RdbTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};
const std::string RdbTestOpenCallback::CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test "
                                                           "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                           "name TEXT NOT NULL, age INTEGER, salary REAL, "
                                                           "blobType BLOB)";

int RdbTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int RdbTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbStoreFuzzTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreFuzzTest::DATABASE_NAME);
    RdbTestOpenCallback helper;
    RdbStoreFuzzTest::store_ = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    if (store_ == nullptr || errCode != E_OK) {
        return;
    }
}

void RdbStoreFuzzTest::TearDownTestCase(void)
{
    if (RdbHelper::DeleteRdbStore(RdbStoreFuzzTest::DATABASE_NAME) != E_OK) {
        return;
    }
}

bool RdbStoreFuzzTest::InsertData(std::shared_ptr<RdbStore> store, const uint8_t *data, size_t size)
{
    if (data == nullptr || store == nullptr) {
        return false;
    }

    int64_t id;
    ValuesBucket values;

    std::string tableName(data, data + size);
    std::string valName(data, data + size);
    int valAge = static_cast<int>(size);
    double valSalary = static_cast<double>(size);

    values.PutString("name", valName);
    values.PutInt("age", valAge);
    values.PutDouble("salary", valSalary);
    values.PutBlob("blobType", std::vector<uint8_t>(data, data + size));

    return store->Insert(id, tableName, values);
}

bool RdbInsertFuzz(const uint8_t *data, size_t size)
{
    if (data == nullptr || RdbStoreFuzzTest::store_ == nullptr) {
        return false;
    }
    bool result = true;
    if (!RdbStoreFuzzTest::InsertData(RdbStoreFuzzTest::store_, data, size)) {
        result = false;
    }

    RdbStoreFuzzTest::store_->ExecuteSql("DELETE FROM test");
    return result;
}

bool RdbStoreFuzzTest::BatchInsertData(std::shared_ptr<RdbStore> store, const uint8_t *data, size_t size)
{
    if (data == nullptr || store == nullptr) {
        return false;
    }

    ValuesBuckets rows;
    std::string tableName(data, data + size);
    std::string valName(data, data + size);
    int valAge = static_cast<int>(size);
    double valSalary = static_cast<double>(size);
    ValuesBucket value;
    value.PutString("name", valName);
    value.PutInt("age", valAge);
    value.PutDouble("salary", valSalary);
    value.PutBlob("blobType", std::vector<uint8_t>(data, data + size));
    for (auto i = 0; i < static_cast<uint32_t>(data[0]); i++) {
        rows.Put(value);
    }
    auto [code, num] = store->BatchInsertWithConflictResolution(tableName, rows, ConflictResolution::ON_CONFLICT_NONE);
    return code == E_OK;
}

bool RdbBatchInsertFuzz(const uint8_t *data, size_t size)
{
    if (data == nullptr || RdbStoreFuzzTest::store_ == nullptr) {
        return false;
    }
    bool result = true;
    if (!RdbStoreFuzzTest::BatchInsertData(RdbStoreFuzzTest::store_, data, size)) {
        result = false;
    }

    RdbStoreFuzzTest::store_->ExecuteSql("DELETE FROM test");
    return result;
}

bool RdbDeleteFuzz(const uint8_t *data, size_t size)
{
    if (data == nullptr || RdbStoreFuzzTest::store_ == nullptr) {
        return false;
    }
    bool result = true;
    int errCode = RdbStoreFuzzTest::InsertData(RdbStoreFuzzTest::store_, data, size);
    if (errCode != E_OK) {
        result = false;
    }

    int deletedRows;
    std::string tableName(data, data + size);
    std::string whereClause(data, data + size);
    errCode = RdbStoreFuzzTest::store_->Delete(deletedRows, tableName, whereClause);
    if (errCode != E_OK) {
        result = false;
    }

    RdbStoreFuzzTest::store_->ExecuteSql("DELETE FROM test");
    return result;
}

bool RdbUpdateFuzz(const uint8_t *data, size_t size)
{
    if (data == nullptr || RdbStoreFuzzTest::store_ == nullptr) {
        return false;
    }
    bool result = true;
    int errCode = RdbStoreFuzzTest::InsertData(RdbStoreFuzzTest::store_, data, size);
    if (errCode != E_OK) {
        result = false;
    }

    int changedRows;
    ValuesBucket values;
    std::string valName(data, data + size);
    int valAge = static_cast<int>(*data);
    double valSalary = static_cast<double>(*data);
    std::string whereClause(data, data + size);
    std::string tableName(data, data + size);

    values.PutString("name", valName);
    values.PutInt("age", valAge);
    values.PutDouble("salary", valSalary);
    values.PutBlob("blobType", std::vector<uint8_t>(data, data + size));

    errCode = RdbStoreFuzzTest::store_->Update(
        changedRows, tableName, values, whereClause, std::vector<std::string>{ valName });
    if (errCode != E_OK) {
        result = false;
    }
    RdbStoreFuzzTest::store_->ExecuteSql("DELETE FROM test");
    return result;
}

int RdbDoLockRowFuzz(const uint8_t *data, size_t size, bool isLock)
{
    if (data == nullptr || RdbStoreFuzzTest::store_ == nullptr) {
        return false;
    }
    bool result = true;
    int errCode = RdbStoreFuzzTest::InsertData(RdbStoreFuzzTest::store_, data, size);
    if (errCode != E_OK) {
        result = false;
    }

    std::string tableName(data, data + size);
    std::string valName(data, data + size);
    AbsRdbPredicates predicates(tableName);
    predicates.EqualTo("name", ValueObject(valName));
    errCode = RdbStoreFuzzTest::store_->ModifyLockStatus(predicates, isLock);
    if (errCode != E_OK) {
        result = false;
    }

    RdbStoreFuzzTest::store_->ExecuteSql("DELETE FROM test");
    return result;
}

bool RdbLockRowFuzz(const uint8_t *data, size_t size)
{
    return RdbDoLockRowFuzz(data, size, true);
}

bool RdbUnlockRowFuzz(const uint8_t *data, size_t size)
{
    return RdbDoLockRowFuzz(data, size, false);
}

void RdbSetLockedRowPredicates(AbsRdbPredicates &predicates)
{
    predicates.Clear();
    predicates.BeginWrap();
    predicates.EqualTo(AbsRdbPredicates::LOCK_STATUS, AbsRdbPredicates::LOCKED);
    predicates.Or();
    predicates.EqualTo(AbsRdbPredicates::LOCK_STATUS, AbsRdbPredicates::LOCK_CHANGED);
    predicates.EndWrap();
}

void RdbQueryLockedRowFuzz1(const uint8_t *data, size_t size)
{
    if (data == nullptr || RdbStoreFuzzTest::store_ == nullptr) {
        return;
    }
    int errCode = RdbStoreFuzzTest::InsertData(RdbStoreFuzzTest::store_, data, size);
    if (errCode != E_OK) {
        return;
    }

    std::string tableName(data, data + size);
    std::string valName(data, data + size);
    std::string vectorElem(data, data + size);
    AbsRdbPredicates predicates(tableName);
    RdbSetLockedRowPredicates(predicates);
    predicates.EqualTo("name", ValueObject(valName));
    RdbStoreFuzzTest::store_->QueryByStep(predicates, { vectorElem });

    RdbSetLockedRowPredicates(predicates);
    predicates.NotEqualTo("name", ValueObject(valName));
    RdbStoreFuzzTest::store_->QueryByStep(predicates, { vectorElem });

    RdbSetLockedRowPredicates(predicates);
    predicates.Contains("name", valName);
    RdbStoreFuzzTest::store_->QueryByStep(predicates, { vectorElem });

    RdbSetLockedRowPredicates(predicates);
    predicates.BeginsWith("name", valName);
    RdbStoreFuzzTest::store_->QueryByStep(predicates, { vectorElem });

    RdbSetLockedRowPredicates(predicates);
    predicates.EndsWith("name", valName);
    RdbStoreFuzzTest::store_->QueryByStep(predicates, { vectorElem });

    RdbSetLockedRowPredicates(predicates);
    predicates.Like("name", valName);
    RdbStoreFuzzTest::store_->QueryByStep(predicates, { vectorElem });

    RdbSetLockedRowPredicates(predicates);
    predicates.Glob("name", valName);
    RdbStoreFuzzTest::store_->QueryByStep(predicates, { vectorElem });
    RdbStoreFuzzTest::store_->ExecuteSql("DELETE FROM test");
}

void RdbQueryLockedRowFuzz2(const uint8_t *data, size_t size)
{
    if (data == nullptr || RdbStoreFuzzTest::store_ == nullptr) {
        return;
    }
    int errCode = RdbStoreFuzzTest::InsertData(RdbStoreFuzzTest::store_, data, size);
    if (errCode != E_OK) {
        return;
    }

    std::string tableName(data, data + size);
    std::string valName(data, data + size);
    ValueObject valAge(std::string(data, data + size));
    ValueObject valAgeChange(std::string(data, data + size));
    std::vector<std::string> bindaArgs({ std::string(data, data + size) });
    std::vector<ValueObject> vectorElem({ std::string(data, data + size) });
    AbsRdbPredicates predicates(tableName);
    RdbSetLockedRowPredicates(predicates);
    predicates.Between("age", valAge, valAgeChange);
    RdbStoreFuzzTest::store_->QueryByStep(predicates, bindaArgs);

    RdbSetLockedRowPredicates(predicates);
    predicates.NotBetween("age", valAge, valAgeChange);
    RdbStoreFuzzTest::store_->QueryByStep(predicates, bindaArgs);

    RdbSetLockedRowPredicates(predicates);
    predicates.GreaterThan("age", valAge);
    RdbStoreFuzzTest::store_->QueryByStep(predicates, bindaArgs);

    RdbSetLockedRowPredicates(predicates);
    predicates.LessThan("age", valAgeChange);
    RdbStoreFuzzTest::store_->QueryByStep(predicates, bindaArgs);

    RdbSetLockedRowPredicates(predicates);
    predicates.GreaterThanOrEqualTo("age", valAge);
    RdbStoreFuzzTest::store_->QueryByStep(predicates, bindaArgs);

    RdbSetLockedRowPredicates(predicates);
    predicates.LessThanOrEqualTo("age", valAgeChange);
    RdbStoreFuzzTest::store_->QueryByStep(predicates, bindaArgs);

    RdbSetLockedRowPredicates(predicates);
    predicates.In("name", vectorElem);
    RdbStoreFuzzTest::store_->QueryByStep(predicates, bindaArgs);

    RdbSetLockedRowPredicates(predicates);
    predicates.NotIn("name", vectorElem);
    RdbStoreFuzzTest::store_->QueryByStep(predicates, bindaArgs);
    RdbStoreFuzzTest::store_->ExecuteSql("DELETE FROM test");
}

void RdbQueryFuzz1(const uint8_t *data, size_t size)
{
    if (data == nullptr || RdbStoreFuzzTest::store_ == nullptr) {
        return;
    }
    int errCode = RdbStoreFuzzTest::InsertData(RdbStoreFuzzTest::store_, data, size);
    if (errCode != E_OK) {
        return;
    }

    std::string tableName(data, data + size);
    std::string valName(data, data + size);
    std::string vectorElem(data, data + size);
    AbsRdbPredicates predicates(tableName);

    predicates.EqualTo("name", ValueObject(valName));
    RdbStoreFuzzTest::store_->Query(predicates, { vectorElem });

    predicates.Clear();
    predicates.NotEqualTo("name", ValueObject(valName));
    RdbStoreFuzzTest::store_->Query(predicates, { vectorElem });

    predicates.Clear();
    predicates.Contains("name", valName);
    RdbStoreFuzzTest::store_->Query(predicates, { vectorElem });

    predicates.Clear();
    predicates.BeginsWith("name", valName);
    RdbStoreFuzzTest::store_->Query(predicates, { vectorElem });

    predicates.Clear();
    predicates.EndsWith("name", valName);
    RdbStoreFuzzTest::store_->Query(predicates, { vectorElem });

    predicates.Clear();
    predicates.Like("name", valName);
    RdbStoreFuzzTest::store_->Query(predicates, { vectorElem });

    predicates.Clear();
    predicates.NotLike("name", valName);
    RdbStoreFuzzTest::store_->Query(predicates, { vectorElem });

    predicates.Clear();
    predicates.NotContains("name", valName);
    RdbStoreFuzzTest::store_->Query(predicates, { vectorElem });

    predicates.Clear();
    predicates.Glob("name", valName);
    RdbStoreFuzzTest::store_->Query(predicates, { vectorElem });
    RdbStoreFuzzTest::store_->ExecuteSql("DELETE FROM test");
}

void RdbQueryFuzz2(const uint8_t *data, size_t size)
{
    if (data == nullptr || RdbStoreFuzzTest::store_ == nullptr) {
        return;
    }
    int errCode = RdbStoreFuzzTest::InsertData(RdbStoreFuzzTest::store_, data, size);
    if (errCode != E_OK) {
        return;
    }

    std::string tableName(data, data + size);
    std::string valName(data, data + size);
    ValueObject valAge(std::string(data, data + size));
    ValueObject valAgeChange(std::string(data, data + size));
    std::vector<std::string> bindaArgs({ std::string(data, data + size) });
    std::vector<ValueObject> vectorElem({ std::string(data, data + size) });

    AbsRdbPredicates predicates(tableName);

    predicates.Clear();
    predicates.Between("age", valAge, valAgeChange);
    RdbStoreFuzzTest::store_->Query(predicates, bindaArgs);

    predicates.Clear();
    predicates.NotBetween("age", valAge, valAgeChange);
    RdbStoreFuzzTest::store_->Query(predicates, bindaArgs);

    predicates.Clear();
    predicates.GreaterThan("age", valAge);
    RdbStoreFuzzTest::store_->Query(predicates, bindaArgs);

    predicates.Clear();
    predicates.LessThan("age", valAgeChange);
    RdbStoreFuzzTest::store_->Query(predicates, bindaArgs);

    predicates.Clear();
    predicates.GreaterThanOrEqualTo("age", valAge);
    RdbStoreFuzzTest::store_->Query(predicates, bindaArgs);

    predicates.Clear();
    predicates.LessThanOrEqualTo("age", valAgeChange);
    RdbStoreFuzzTest::store_->Query(predicates, bindaArgs);

    predicates.Clear();
    predicates.In("name", vectorElem);
    RdbStoreFuzzTest::store_->Query(predicates, bindaArgs);

    predicates.Clear();
    predicates.NotIn("name", vectorElem);
    RdbStoreFuzzTest::store_->Query(predicates, bindaArgs);
    RdbStoreFuzzTest::store_->ExecuteSql("DELETE FROM test");
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::RdbStoreFuzzTest::SetUpTestCase();
    OHOS::RdbInsertFuzz(data, size);
    OHOS::RdbDeleteFuzz(data, size);
    OHOS::RdbUpdateFuzz(data, size);
    OHOS::RdbQueryFuzz1(data, size);
    OHOS::RdbQueryFuzz2(data, size);
    OHOS::RdbLockRowFuzz(data, size);
    OHOS::RdbUnlockRowFuzz(data, size);
    OHOS::RdbQueryLockedRowFuzz1(data, size);
    OHOS::RdbQueryLockedRowFuzz2(data, size);
    OHOS::RdbStoreFuzzTest::TearDownTestCase();
    return 0;
}
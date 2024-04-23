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

#include "rdb_store.h"
#include "rdb_helper.h"
#include "rdb_errno.h"
#include "rdb_open_callback.h"
#include "rdbstore_fuzzer.h"

using namespace OHOS;
using namespace OHOS::NativeRdb;

namespace OHOS {
class RdbStoreFuzzTest {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);

    static bool InsertData(std::shared_ptr<RdbStore> &store, const uint8_t *data, size_t size);

    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store_;
};
std::shared_ptr<RdbStore> RdbStoreFuzzTest::store_ = nullptr;
const std::string RdbStoreFuzzTest::DATABASE_NAME = "/data/test/rdbStoreFuzz.db";

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
    RdbStoreConfig config(DATABASE_NAME);
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

bool RdbStoreFuzzTest::InsertData(std::shared_ptr<RdbStore> &store, const uint8_t *data, size_t size)
{
    if (data == nullptr) {
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
    values.PutBlob("blobType", std::vector<uint8_t> (data, data + size));

    return store->Insert(id, tableName, values);
}

bool RdbInsertFuzz(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return false;
    }

    std::shared_ptr<RdbStore> &store = RdbStoreFuzzTest::store_;
    bool result = true;

    int errCode = RdbStoreFuzzTest::InsertData(store, data, size);
    if (errCode != E_OK) {
        result = false;
    }

    store->ExecuteSql("DELETE FROM test");
    return result;
}

bool RdbDeleteFuzz(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return false;
    }

    std::shared_ptr<RdbStore> &store = RdbStoreFuzzTest::store_;

    bool result = true;
    int errCode = RdbStoreFuzzTest::InsertData(store, data, size);
    if (errCode != E_OK) {
        result = false;
    }

    int deletedRows;
    std::string tableName(data, data + size);
    std::string whereClause(data, data + size);
    errCode = store->Delete(deletedRows, tableName, whereClause);
    if (errCode != E_OK) {
        result = false;
    }

    store->ExecuteSql("DELETE FROM test");
    return result;
}

bool RdbUpdateFuzz(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return false;
    }

    std::shared_ptr<RdbStore> &store = RdbStoreFuzzTest::store_;
    bool result = true;

    int errCode = RdbStoreFuzzTest::InsertData(store, data, size);
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
    values.PutBlob("blobType", std::vector<uint8_t> (data, data + size));

    errCode = store->Update(changedRows, tableName, values, whereClause,
        std::vector<std::string> { valName });
    if (errCode != E_OK) {
        result = false;
    }
    store->ExecuteSql("DELETE FROM test");
    return result;
}

int RdbDoLockRowFuzz(const uint8_t *data, size_t size, bool isLock)
{
    if (data == nullptr) {
        return false;
    }

    std::shared_ptr<RdbStore> &store = RdbStoreFuzzTest::store_;

    bool result = true;
    int errCode = RdbStoreFuzzTest::InsertData(store, data, size);
    if (errCode != E_OK) {
        result = false;
    }

    std::string tableName(data, data + size);
    std::string valName(data, data + size);
    AbsRdbPredicates predicates(tableName);
    predicates.EqualTo("name", ValueObject(valName));
    errCode = store->ModifyLockStatus(predicates, isLock);
    if (errCode != E_OK) {
        result = false;
    }

    store->ExecuteSql("DELETE FROM test");
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
    if (data == nullptr) {
        return;
    }

    std::shared_ptr<RdbStore> &store = RdbStoreFuzzTest::store_;
    int errCode = RdbStoreFuzzTest::InsertData(store, data, size);
    if (errCode != E_OK) {
        return;
    }

    std::string tableName(data, data + size);
    std::string valName(data, data + size);
    std::string vectorElem(data, data + size);
    AbsRdbPredicates predicates(tableName);
    RdbSetLockedRowPredicates(predicates);
    predicates.EqualTo("name", ValueObject(valName));
    store->QueryByStep(predicates, { vectorElem });

    RdbSetLockedRowPredicates(predicates);
    predicates.NotEqualTo("name", ValueObject(valName));
    store->QueryByStep(predicates, { vectorElem });

    RdbSetLockedRowPredicates(predicates);
    predicates.Contains("name", valName);
    store->QueryByStep(predicates, { vectorElem });

    RdbSetLockedRowPredicates(predicates);
    predicates.BeginsWith("name", valName);
    store->QueryByStep(predicates, { vectorElem });

    RdbSetLockedRowPredicates(predicates);
    predicates.EndsWith("name", valName);
    store->QueryByStep(predicates, { vectorElem });

    RdbSetLockedRowPredicates(predicates);
    predicates.Like("name", valName);
    store->QueryByStep(predicates, { vectorElem });

    RdbSetLockedRowPredicates(predicates);
    predicates.Glob("name", valName);
    store->QueryByStep(predicates, { vectorElem });
    store->ExecuteSql("DELETE FROM test");
}

void RdbQueryLockedRowFuzz2(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return;
    }

    std::shared_ptr<RdbStore> &store = RdbStoreFuzzTest::store_;
    int errCode = RdbStoreFuzzTest::InsertData(store, data, size);
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
    store->QueryByStep(predicates, bindaArgs);

    RdbSetLockedRowPredicates(predicates);
    predicates.NotBetween("age", valAge, valAgeChange);
    store->QueryByStep(predicates, bindaArgs);

    RdbSetLockedRowPredicates(predicates);
    predicates.GreaterThan("age", valAge);
    store->QueryByStep(predicates, bindaArgs);

    RdbSetLockedRowPredicates(predicates);
    predicates.LessThan("age", valAgeChange);
    store->QueryByStep(predicates, bindaArgs);

    RdbSetLockedRowPredicates(predicates);
    predicates.GreaterThanOrEqualTo("age", valAge);
    store->QueryByStep(predicates, bindaArgs);

    RdbSetLockedRowPredicates(predicates);
    predicates.LessThanOrEqualTo("age", valAgeChange);
    store->QueryByStep(predicates, bindaArgs);

    RdbSetLockedRowPredicates(predicates);
    predicates.In("name", vectorElem);
    store->QueryByStep(predicates, bindaArgs);

    RdbSetLockedRowPredicates(predicates);
    predicates.NotIn("name", vectorElem);
    store->QueryByStep(predicates, bindaArgs);
    store->ExecuteSql("DELETE FROM test");
}

void RdbQueryFuzz1(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return;
    }

    std::shared_ptr<RdbStore> &store = RdbStoreFuzzTest::store_;

    int errCode = RdbStoreFuzzTest::InsertData(store, data, size);
    if (errCode != E_OK) {
        return;
    }

    std::string tableName(data, data + size);
    std::string valName(data, data + size);
    std::string vectorElem(data, data + size);
    AbsRdbPredicates predicates(tableName);

    predicates.EqualTo("name", ValueObject(valName));
    store->Query(predicates, {vectorElem});

    predicates.Clear();
    predicates.NotEqualTo("name", ValueObject(valName));
    store->Query(predicates, {vectorElem});

    predicates.Clear();
    predicates.Contains("name", valName);
    store->Query(predicates, {vectorElem});

    predicates.Clear();
    predicates.BeginsWith("name", valName);
    store->Query(predicates, {vectorElem});

    predicates.Clear();
    predicates.EndsWith("name", valName);
    store->Query(predicates, {vectorElem});

    predicates.Clear();
    predicates.Like("name", valName);
    store->Query(predicates, {vectorElem});

    predicates.Clear();
    predicates.NotLike("name", valName);
    store->Query(predicates, {vectorElem});

    predicates.Clear();
    predicates.NotContains("name", valName);
    store->Query(predicates, {vectorElem});

    predicates.Clear();
    predicates.Glob("name", valName);
    store->Query(predicates, {vectorElem});
    store->ExecuteSql("DELETE FROM test");
}

void RdbQueryFuzz2(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return;
    }

    std::shared_ptr<RdbStore> &store = RdbStoreFuzzTest::store_;

    int errCode = RdbStoreFuzzTest::InsertData(store, data, size);
    if (errCode != E_OK) {
        return;
    }

    std::string tableName(data, data + size);
    std::string valName(data, data + size);
    ValueObject valAge(std::string(data, data + size));
    ValueObject valAgeChange(std::string(data, data + size));
    std::vector<std::string> bindaArgs({std::string(data, data + size)});
    std::vector<ValueObject> vectorElem({std::string(data, data + size)});

    AbsRdbPredicates predicates(tableName);

    predicates.Clear();
    predicates.Between("age", valAge, valAgeChange);
    store->Query(predicates, bindaArgs);

    predicates.Clear();
    predicates.NotBetween("age", valAge, valAgeChange);
    store->Query(predicates, bindaArgs);

    predicates.Clear();
    predicates.GreaterThan("age", valAge);
    store->Query(predicates, bindaArgs);

    predicates.Clear();
    predicates.LessThan("age", valAgeChange);
    store->Query(predicates, bindaArgs);

    predicates.Clear();
    predicates.GreaterThanOrEqualTo("age", valAge);
    store->Query(predicates, bindaArgs);

    predicates.Clear();
    predicates.LessThanOrEqualTo("age", valAgeChange);
    store->Query(predicates, bindaArgs);

    predicates.Clear();
    predicates.In("name", vectorElem);
    store->Query(predicates, bindaArgs);

    predicates.Clear();
    predicates.NotIn("name", vectorElem);
    store->Query(predicates, bindaArgs);
    store->ExecuteSql("DELETE FROM test");
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
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
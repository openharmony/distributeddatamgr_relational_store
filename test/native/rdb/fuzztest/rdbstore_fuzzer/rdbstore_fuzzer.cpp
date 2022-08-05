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
/* change value */
constexpr int ageChange = 2;
constexpr double salaryChange = 100;
constexpr double salaryChanges = 200;

class RdbStoreFuzzTest {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);

    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store_;
};
std::shared_ptr<RdbStore> RdbStoreFuzzTest::store_ = nullptr;
const std::string RdbStoreFuzzTest::DATABASE_NAME = "/data/test/rdbstore_test.db";

class RdbTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &rdbStore) override;
    int OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

const std::string RdbTestOpenCallback::CREATE_TABLE_TEST = std::string("CREATE TABLE IF NOT EXISTS test ")
                                                              + std::string("(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                            "name TEXT NOT NULL, age INTEGER, salary "
                                                                            "REAL, blobType BLOB)");

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
}

void RdbStoreFuzzTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(RdbStoreFuzzTest::DATABASE_NAME);
}

bool RdbInsertFuzz(const uint8_t *data, size_t size)
{
    std::shared_ptr<RdbStore> &store = RdbStoreFuzzTest::store_;
    bool result = true;
    int64_t id;
    ValuesBucket values;
    std::string valName(data, data + size);
    int valAge = static_cast<int>(size);
    double valSalary = static_cast<double>(size);
    values.PutString("name", valName + "test1");
    values.PutInt("age", valAge);
    values.PutDouble("salary", valSalary);
    values.PutBlob("blobType", std::vector<uint8_t> {*data});
    int errCode = store->Insert(id, "test", values);
    if (errCode != E_OK) {
        result = false;
    }
    values.Clear();
    values.PutString("name", valName + "test2");
    values.PutInt("age", valAge + 1);
    values.PutDouble("salary", valSalary + salaryChange);
    values.PutBlob("blobType", std::vector<uint8_t> {*data, *data + 1});
    store->Insert(id, "test", values);
    if (errCode != E_OK) {
        result = false;
    }
    store->ExecuteSql("DELETE FROM test");
    return result;
}

bool RdbDeleteFuzz(const uint8_t *data, size_t size)
{
    std::shared_ptr<RdbStore> &store = RdbStoreFuzzTest::store_;
    bool result = true;
    int64_t id;
    int deletedRows;

    ValuesBucket values;
    std::string valName(data, data + size);
    int valAge = static_cast<int>(size);
    double valSalary = static_cast<double>(size);
    values.PutString("name", valName + "test1");
    values.PutInt("age", valAge);
    values.PutDouble("salary", valSalary);
    values.PutBlob("blobType", std::vector<uint8_t> {*data});
    store->Insert(id, "test", values);

    values.Clear();
    values.PutString("name", valName + "test2");
    values.PutInt("age", valAge + 1);
    values.PutDouble("salary", valSalary + salaryChange);
    values.PutBlob("blobType", std::vector<uint8_t> {*data, *data + 1});
    store->Insert(id, "test", values);
    int errCode = store->Delete(deletedRows, "test", "id = 1");
    if (errCode != E_OK) {
        result = false;
    }
    store->ExecuteSql("DELETE FROM test");
    return result;
}

bool RdbUpdateFuzz(const uint8_t *data, size_t size)
{
    std::shared_ptr<RdbStore> &store = RdbStoreFuzzTest::store_;
    bool result = true;
    int64_t id;
    int changedRows;

    ValuesBucket values;
    std::string valName(data, data + size);
    int valAge = static_cast<int>(size);
    double valSalary = static_cast<double>(size);
    values.PutString("name", valName + "test1");
    values.PutInt("age", valAge);
    values.PutDouble("salary", valSalary);
    values.PutBlob("blobType", std::vector<uint8_t> {*data});
    store->Insert(id, "test", values);

    values.Clear();
    values.PutString("name", valName + "test2");
    values.PutInt("age", valAge + 1);
    values.PutDouble("salary", valSalary + salaryChange);
    values.PutBlob("blobType", std::vector<uint8_t> {*data, *data + 1});
    int errCode = store->Update(changedRows, "test", values, "name = ?",
        std::vector<std::string> { valName + "test1" });
    if (errCode != E_OK) {
        result = false;
    }
    store->ExecuteSql("DELETE FROM test");
    return result;
}

void DBInsert(std::string &valName, int &valAge, double &valSalary,
    std::shared_ptr<RdbStore> &store, const uint8_t *data)
{
    int64_t id;
    ValuesBucket values;
    values.PutString("name", valName + "test1");
    values.PutInt("age", valAge);
    values.PutDouble("salary", valSalary);
    values.PutBlob("blobType", std::vector<uint8_t> {*data});
    store->Insert(id, "test", values);

    values.Clear();
    values.PutString("name", valName + "test2");
    values.PutInt("age", valAge + 1);
    values.PutDouble("salary", valSalary + salaryChange);
    values.PutBlob("blobType", std::vector<uint8_t> {*data, *data + 1});
    store->Insert(id, "test", values);

    values.Clear();
    values.PutString("name", valName + "test3");
    values.PutInt("age", valAge + ageChange);
    values.PutDouble("salary", valSalary + salaryChanges);
    values.PutBlob("blobType", std::vector<uint8_t> {*data, *data + 1});
    store->Insert(id, "test", values);

    values.Clear();
    values.PutString("name", valName + "test4");
    values.PutInt("age", valAge + ageChange);
    values.PutDouble("salary", valSalary + salaryChanges);
    values.PutBlob("blobType", std::vector<uint8_t> {*data, *data + 1});
    store->Insert(id, "test", values);
}

void RdbQueryFuzz1(const uint8_t *data, size_t size)
{
    std::string valName(data, data + size);
    int valAge = static_cast<int>(size);
    double valSalary = static_cast<double>(size);
    std::shared_ptr<RdbStore> &store = RdbStoreFuzzTest::store_;
    AbsRdbPredicates predicates("test");
    std::vector<std::string> columns;
    columns.push_back("id");
    columns.push_back("name");
    columns.push_back("age");
    columns.push_back("salary");
    columns.push_back("blobType");
    DBInsert(valName, valAge, valSalary, store, data);

    predicates.EqualTo("name", valName + "test1");
    store->Query(predicates, columns);

    predicates.Clear();
    predicates.NotEqualTo("name", valName + "test1");
    store->Query(predicates, columns);

    predicates.Clear();
    predicates.Contains("name", valName + "test1");
    store->Query(predicates, columns);

    predicates.Clear();
    predicates.BeginsWith("name", valName + "test1");
    store->Query(predicates, columns);

    predicates.Clear();
    predicates.EndsWith("name", valName + "test1");
    store->Query(predicates, columns);

    predicates.Clear();
    predicates.Like("name", valName + "test1");
    store->Query(predicates, columns);

    predicates.Clear();
    predicates.Glob("name", valName + "?est1");
    store->Query(predicates, columns);
    store->ExecuteSql("DELETE FROM test");
}

void RdbQueryFuzz2(const uint8_t *data, size_t size)
{
    std::string valName(data, data + size);
    int valAge = static_cast<int>(size);
    double valSalary = static_cast<double>(size);
    std::shared_ptr<RdbStore> &store = RdbStoreFuzzTest::store_;
    AbsRdbPredicates predicates("test");
    std::vector<std::string> columns;
    columns.push_back("id");
    columns.push_back("name");
    columns.push_back("age");
    columns.push_back("salary");
    columns.push_back("blobType");
    DBInsert(valName, valAge, valSalary, store, data);

    predicates.Clear();
    predicates.Between("age", std::to_string(valAge), std::to_string(valAge + ageChange));
    store->Query(predicates, columns);

    predicates.Clear();
    predicates.NotBetween("age", std::to_string(valAge), std::to_string(valAge + 1));
    store->Query(predicates, columns);

    predicates.Clear();
    predicates.GreaterThan("age", std::to_string(valAge));
    store->Query(predicates, columns);

    predicates.Clear();
    predicates.LessThan("age", std::to_string(valAge + ageChange));
    store->Query(predicates, columns);

    predicates.Clear();
    predicates.GreaterThanOrEqualTo("age", std::to_string(valAge));
    store->Query(predicates, columns);

    predicates.Clear();
    predicates.LessThanOrEqualTo("age", std::to_string(valAge + ageChange));
    store->Query(predicates, columns);

    std::vector<std::string> agrsIn = {std::to_string(INT_MAX)};
    predicates.Clear();
    predicates.In("name", agrsIn);
    store->Query(predicates, columns);

    predicates.Clear();
    std::vector<std::string> agrsNotin = {std::to_string(INT_MAX), std::to_string(INT_MIN)};
    predicates.NotIn("name", agrsNotin);
    store->Query(predicates, columns);
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
    OHOS::RdbStoreFuzzTest::TearDownTestCase();
    return 0;
}


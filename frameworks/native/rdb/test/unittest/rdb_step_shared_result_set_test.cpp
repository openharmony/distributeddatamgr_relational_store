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

#include <gtest/gtest.h>

#include <string>

#include "common.h"
#include "datashare_abstract_result_set.h"
#include "datashare_block_writer_impl.h"
#include "datashare_predicates.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;

class RdbStepSharedResultSetTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();

    void GenerateDefaultTable();

    void GenerateDefaultEmptyTable();

    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;
    static const int E_SQLITE_ERROR;
    static const int E_INVALID_COLUMN_TYPE;
    static const size_t DEFAULT_BLOCK_SIZE;
};

const std::string RdbStepSharedResultSetTest::DATABASE_NAME = RDB_TEST_PATH + "stepResultSet_test.db";
const int RdbStepSharedResultSetTest::E_SQLITE_ERROR = -1;          // errno SQLITE_ERROR
const int RdbStepSharedResultSetTest::E_INVALID_COLUMN_TYPE = 1009; // errno SQLITE_NULL
const size_t RdbStepSharedResultSetTest::DEFAULT_BLOCK_SIZE = 2 * 1024 * 1024;
std::shared_ptr<RdbStore> RdbStepSharedResultSetTest::store = nullptr;

class RdbStepSharedResultSetOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &rdbStore) override;

    int OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion) override;

    static const std::string CREATE_TABLE_TEST;
};

int RdbStepSharedResultSetOpenCallback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int RdbStepSharedResultSetOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbStepSharedResultSetTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStepSharedResultSetTest::DATABASE_NAME);
    RdbStepSharedResultSetOpenCallback helper;
    RdbStepSharedResultSetTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbStepSharedResultSetTest::store, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void RdbStepSharedResultSetTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(RdbStepSharedResultSetTest::DATABASE_NAME);
}

void RdbStepSharedResultSetTest::SetUp(void)
{
    store->ExecuteSql("DELETE FROM test");
}

void RdbStepSharedResultSetTest::TearDown(void)
{
    RdbHelper::ClearCache();
}

void RdbStepSharedResultSetTest::GenerateDefaultTable()
{
    std::string createTableSql = std::string("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, ") +
                                 std::string("data2 INTEGER, data3 FLOAT, data4 BLOB);");
    store->ExecuteSql(createTableSql);

    std::string insertSql = "INSERT INTO test (data1, data2, data3, data4) VALUES (?, ?, ?, ?);";

    /* insert first entry data */
    uint8_t uValue = 66;
    std::vector<uint8_t> typeBlob;
    typeBlob.push_back(uValue);
    store->ExecuteSql(insertSql, std::vector<ValueObject> {
        ValueObject(std::string("hello")), ValueObject((int)10),
        ValueObject((double)1.0), ValueObject((std::vector<uint8_t>)typeBlob)
    });

    /* insert second entry data */
    typeBlob.clear();
    store->ExecuteSql(insertSql, std::vector<ValueObject> {
        ValueObject(std::string("2")), ValueObject((int)-5), ValueObject((double)2.5),
        ValueObject() // set double value 2.5
    });

    /* insert third entry data */
    store->ExecuteSql(insertSql, std::vector<ValueObject> {
        ValueObject(std::string("hello world")), ValueObject((int)3),
        ValueObject((double)1.8), ValueObject() // set int value 3, double 1.8
    });

    /* insert four entry data */
    store->ExecuteSql(insertSql, std::vector<ValueObject> {
        ValueObject(std::string("new world")), ValueObject((int)5),
        ValueObject((double)5.8), ValueObject() // set int value 5, double 5.8
    });
}

void RdbStepSharedResultSetTest::GenerateDefaultEmptyTable()
{
    std::string createTableSql = std::string("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, ") +
                                 std::string("data2 INTEGER, data3 FLOAT, data4 BLOB);");
    store->ExecuteSql(createTableSql);
}

/* *
 * @tc.name: RdbStore_StepSharedResultSet_001
 * @tc.desc: test StepSharedResultSet
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepSharedResultSetTest, RdbStore_StepSharedResultSet_001, TestSize.Level1)
{
    GenerateDefaultTable();

    std::shared_ptr<OHOS::DataShare::DataShareAbstractResultSet> resultSet = store->DataShareQueryByStep(
        "SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    int rowCount;
    resultSet.get()->GetRowCount(rowCount);
    LOG_INFO("result row count:  %{public}d", rowCount);
    EXPECT_NE(rowCount, 0);

    std::vector<std::string> columns;
    resultSet.get()->GetAllColumnOrKeyName(columns);

    LOG_INFO("result column name:  %{public}s", columns[1].c_str());
}

/* *
 * @tc.name: RdbStore_StepSharedResultSet_002
 * @tc.desc: normal testcase of StepSharedResultSet
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepSharedResultSetTest, RdbStore_StepSharedResultSet_002, TestSize.Level1)
{
    GenerateDefaultTable();

    std::string table = "test";
    OHOS::DataShare::DataSharePredicates predicates = OHOS::DataShare::DataSharePredicates(table);
    std::string value = "hello";
    predicates.EqualTo("data1", value);
    std::vector<std::string> columns;
    std::shared_ptr<OHOS::DataShare::DataShareAbstractResultSet> allDataTypes =
        store->Query(predicates, columns);
    int rowCount;
    allDataTypes.get()->GetRowCount(rowCount);

    EXPECT_EQ(rowCount, 1);
}

/* *
 * @tc.name: RdbStore_StepSharedResultSet_003
 * @tc.desc: normal testcase of StepSharedResultSet
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepSharedResultSetTest, RdbStore_StepSharedResultSet_003, TestSize.Level1)
{
    GenerateDefaultTable();

    std::string table = "test";
    OHOS::DataShare::DataSharePredicates predicates = OHOS::DataShare::DataSharePredicates(table);
    predicates.GreaterThan("data2", -5);
    std::vector<std::string> columns;
    std::shared_ptr<OHOS::DataShare::DataShareAbstractResultSet> allDataTypes =
        store->Query(predicates, columns);
    int rowCount;
    allDataTypes.get()->GetRowCount(rowCount);
    EXPECT_EQ(rowCount, 3);

    std::shared_ptr<DataShareBlockWriterImpl> blockWriter =
        std::make_shared<OHOS::DataShare::DataShareBlockWriterImpl>("DataShareTest", DEFAULT_BLOCK_SIZE);
    allDataTypes.get()->OnGo(0, 0, blockWriter);
    uint32_t rowNum = 3;
    EXPECT_EQ(blockWriter->GetRowNum(), rowNum);
    OHOS::AppDataFwk::SharedBlock::CellUnit *cellUnit =
        blockWriter->GetBlock()->GetCellUnit((uint32_t)1, (uint32_t)2);
    int tempValue = (int)cellUnit->cell.longValue;
    LOG_ERROR("StepSharedResultSet:: tempValue: %{public}d.", tempValue);
    EXPECT_EQ(tempValue, 3);
}

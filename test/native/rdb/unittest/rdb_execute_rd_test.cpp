/*

Copyright (c) 2024 Huawei Device Co., Ltd.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include <gtest/gtest.h>

#include <random>
#include <string>

#include "common.h"
#include "grd_api_manager.h"
#include "rd_utils.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbExecuteRdTest : public testing::TestWithParam<bool> {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string databaseName;
    static std::shared_ptr<RdbStore> store;
    static const std::string restoreDatabaseName;
    static const std::string backupDatabaseName;
};

INSTANTIATE_TEST_CASE_P(, RdbExecuteRdTest, testing::Values(false, true));

const std::string RdbExecuteRdTest::databaseName = RDB_TEST_PATH + "execute_test.db";
const std::string RdbExecuteRdTest::restoreDatabaseName = RDB_TEST_PATH + "execute_test_restore.db";
const std::string RdbExecuteRdTest::backupDatabaseName = RDB_TEST_PATH + "execute_test_backup.db";
std::shared_ptr<RdbStore> RdbExecuteRdTest::store = nullptr;

class ExecuteTestOpenRdCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

int ExecuteTestOpenRdCallback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int ExecuteTestOpenRdCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbExecuteRdTest::SetUpTestCase(void)
{
}

void RdbExecuteRdTest::TearDownTestCase(void)
{
}

void RdbExecuteRdTest::SetUp(void)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    int errCode = E_OK;
    RdbHelper::DeleteRdbStore(RdbExecuteRdTest::databaseName);
    RdbStoreConfig config(RdbExecuteRdTest::databaseName);
    config.SetIsVector(true);
    config.SetEncryptStatus(GetParam());
    int num = 300;
    config.SetNcandidates(num);
    ExecuteTestOpenRdCallback helper;
    RdbExecuteRdTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbExecuteRdTest::store, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void RdbExecuteRdTest::TearDown(void)
{
    RdbExecuteRdTest::store = nullptr;
    RdbHelper::DeleteRdbStore(RdbExecuteRdTest::databaseName);
}

// 随机数生成器
std::random_device g_rd; // 用于获取随机种子
std::mt19937 g_gen(g_rd()); // 以随机设备作为种子的Mersenne Twister生成器
std::uniform_real_distribution<> dis(-1.0, 1.0); // 定义一个均匀分布的实数范围

/**
@tc.name: RdbStore_Execute_001
@tc.desc: test RdbStore Execute in vector mode
@tc.type: FUNC
*/
HWTEST_P(RdbExecuteRdTest, RdbStore_Execute_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteRdTest::store;

    int64_t id = 0;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });

    values.Clear();
    values.PutInt("id", 2);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 19);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });

    values.Clear();
    values.PutInt("id", 3);
    values.PutString("name", std::string("wangyjing"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    std::vector bindArgs = std::vector{ ValueObject(std::string("18")), ValueObject(std ::string("20")) };

    std::string sqlDelNoBind = "DELETE FROM test WHERE age = 19";
    std::string sqlSelect = "SELECT * FROM test WHERE age = ? OR age = ?";
    std::string sqlDelete = "DELETE FROM test WHERE age = ? OR age = ?";
    EXPECT_EQ(store->ExecuteSql(sqlDelete.c_str(), bindArgs), E_NOT_SUPPORT);
    EXPECT_EQ(store->ExecuteSql(sqlDelNoBind.c_str()), E_NOT_SUPPORT);

    int64_t count = 0;
    EXPECT_EQ(store->ExecuteAndGetLong(count, "SELECT COUNT() FROM test where age = 19"), E_NOT_SUPPORT);
    EXPECT_EQ(store->ExecuteAndGetLong(count, "SELECT COUNT() FROM test"), E_NOT_SUPPORT);
    EXPECT_EQ(store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test"), E_NOT_SUPPORT);
    EXPECT_EQ(store->Insert(id, "test", values), E_NOT_SUPPORT);
}

/**
@tc.name: RdbStore_Execute_002
@tc.desc: test RdbStore Execute in vector mode
@tc.type: FUNC
*/
HWTEST_P(RdbExecuteRdTest, RdbStore_Execute_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteRdTest::store;
    std::pair<int, uint64_t> res1 = {};
    std::pair<int, uint64_t> res2 = {};
    res1 = store->BeginTrans();
    EXPECT_EQ(res1.first, E_OK);
    EXPECT_NE(res1.second, 0);
    res2 = store->BeginTrans();
    EXPECT_EQ(res2.first, E_OK);
    EXPECT_NE(res2.second, 0);
    EXPECT_EQ(store->RollBack(res1.second), E_OK);
    EXPECT_EQ(store->Commit(res2.second), E_OK);
}

/**
@tc.name: RdbStore_Execute_003
@tc.desc: test RdbStore Execute in vector mode. Repeatly require trx.
@tc.type: FUNC
*/
HWTEST_P(RdbExecuteRdTest, RdbStore_Execute_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteRdTest::store;
    std::vector<std::pair<int, uint64_t>> results = {};
    for (uint32_t i = 0; i < 100; i++) { // Get 100 trxs
        std::pair<int, uint64_t> res = {};
        res = store->BeginTrans();
        EXPECT_TRUE((res.first == E_OK) || (res.first == E_DATABASE_BUSY));
        results.push_back(res);
    }
    for (uint32_t i = 0; i < 100; i++) { // Commit 100 trxs
        if (results[i].first == E_OK) {
            EXPECT_EQ(store->RollBack(results[i].second), E_OK);
        }
    }
}

/**
@tc.name: RdbStore_Execute_004
@tc.desc: test RdbStore Execute in vector mode
@tc.type: FUNC
*/
HWTEST_P(RdbExecuteRdTest, RdbStore_Execute_004, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteRdTest::store;
    std::string sqlCreateTable = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, repr floatvector(8));";
    std::string sqlInsert = "INSERT INTO test VALUES(1, '[1.2, 0.3, 3.2, 1.6, 2.5, 3.1, 0.8, 0.4]');";
    std::string sqlQuery = "SELECT id FROM test order by repr <-> '[1.1, 0.3, 2.2, 6.6, 1.5, 3.1, 0.6, 0.2]' limit 3;";

    std::pair<int32_t, ValueObject> res = {};
    res = store->Execute(sqlCreateTable.c_str(), {}, 0);
    EXPECT_EQ(res.first, E_OK);

    std::pair<int, uint64_t> res1 = {};
    res1 = store->BeginTrans();
    EXPECT_EQ(res1.first, E_OK);
    EXPECT_NE(res1.second, 0);

    res = store->Execute(sqlInsert.c_str(), {}, res1.second);
    EXPECT_EQ(res.first, E_OK);
    EXPECT_EQ(store->Commit(res1.second), E_OK);
    res = store->Execute("DROP TABLE test;", {}, 0);
    EXPECT_EQ(res.first, E_OK);
}

/**
@tc.name: RdbStore_Execute_005
@tc.desc: test RdbStore Execute in vector mode
@tc.type: FUNC
*/
HWTEST_P(RdbExecuteRdTest, RdbStore_Execute_005, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteRdTest::store;
    std::string sqlCreateTable = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, repr floatvector(8));";
    std::string sqlInsert = "INSERT INTO test VALUES(1, '[1.2, 0.3, 3.2, 1.6, 2.5, 3.1, 0.8, 0.4]');";
    std::string sqlQuery = "SELECT id FROM test order by repr <-> '[1.1, 0.3, 2.2, 6.6, 1.5, 3.1, 0.6, 0.2]' limit 3;";

    std::pair<int32_t, ValueObject> res = {};
    res = store->Execute(sqlCreateTable.c_str(), {});
    EXPECT_EQ(res.first, E_OK);
    res = store->Execute(sqlInsert.c_str(), {});
    EXPECT_EQ(res.first, E_OK);
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep(sqlQuery.c_str(), std::vector<ValueObject>());
    EXPECT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GoToNextRow(), E_OK);
    std::vector<std::string> colNames = {};
    resultSet->GetAllColumnNames(colNames);
    EXPECT_EQ(colNames.size(), 1);
    int columnIndex = 0;
    int intVal = 0;
    resultSet->GetColumnIndex("id", columnIndex);
    resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(columnIndex, 0);
    EXPECT_EQ(intVal, 1);
    EXPECT_EQ(E_OK, resultSet->Close());
    res = store->Execute("DROP TABLE test;");
    EXPECT_EQ(E_OK, res.first);
}

/**
@tc.name: RdbStore_Execute_006
@tc.desc: test RdbStore Execute in vector mode
@tc.type: FUNC
*/
HWTEST_P(RdbExecuteRdTest, RdbStore_Execute_006, TestSize.Level1)
{
    std::string sqlCreateTable = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, repr floatvector(8));";
    std::string sqlInsert = "INSERT INTO test VALUES(1, '[1.2, 0.3, 3.2, 1.6, 2.5, 3.1, 0.8, 0.4]');";
    std::string sqlBeginTrans = "begin;";

    std::string dbPath = "/data/test/execute_test1.db";
    std::string configStr =
    "{\"pageSize\":8, \"crcCheckEnable\":0, \"redoFlushByTrx\":1, \"bufferPoolSize\":10240,"
    "\"sharedModeEnable\":1, \"metaInfoBak\":1, \"maxConnNum\":500, \"ignoreMetaDataCorruption\":1 }";

    GRD_DB *db2 = nullptr;
    GRD_DB *db4 = nullptr;
    EXPECT_EQ(RdUtils::RdDbOpen(dbPath.c_str(), configStr.c_str(), GRD_DB_OPEN_CREATE, &db2), E_OK);
    EXPECT_EQ(RdUtils::RdDbOpen(dbPath.c_str(), configStr.c_str(), GRD_DB_OPEN_CREATE, &db4), E_OK);

    GRD_SqlStmt *stmt = nullptr;
    EXPECT_EQ(RdUtils::RdSqlPrepare(db2, sqlCreateTable.c_str(), sqlCreateTable.size(), &stmt, nullptr), E_OK);
    EXPECT_EQ(RdUtils::RdSqlStep(stmt), E_OK);
    EXPECT_EQ(RdUtils::RdSqlFinalize(stmt), E_OK);

    stmt = nullptr;
    EXPECT_EQ(RdUtils::RdSqlPrepare(db4, sqlBeginTrans.c_str(), sqlBeginTrans.size(), &stmt, nullptr), E_OK);
    EXPECT_EQ(RdUtils::RdSqlStep(stmt), E_OK);
    EXPECT_EQ(RdUtils::RdSqlFinalize(stmt), E_OK);

    stmt = nullptr;
    EXPECT_EQ(RdUtils::RdSqlPrepare(db4, sqlInsert.c_str(), sqlInsert.size(), &stmt, nullptr), E_OK);
    EXPECT_EQ(RdUtils::RdSqlStep(stmt), E_OK);
    EXPECT_EQ(RdUtils::RdSqlFinalize(stmt), E_OK);
    EXPECT_EQ(RdUtils::RdDbClose(db2, 0), E_OK);
    EXPECT_EQ(RdUtils::RdDbClose(db4, 0), E_OK);
}

std::string GetRandVector(uint32_t maxElementNum, uint16_t dim)
{
    if (maxElementNum == 0) {
        return "";
    }
    unsigned int randomNumberSeed = time(nullptr);
    std::string res = "[";
    for (uint16_t i = 0; i < dim; i++) {
        uint32_t intPart = (rand_r(&randomNumberSeed) % maxElementNum);
        intPart += 1;
        uint32_t tenths = (rand_r(&randomNumberSeed) % 10); // 10是用来限制小数点后的数字不能超过10
        res += std::to_string(intPart);
        res += ".";
        res += std::to_string(tenths);
        res += ", ";
    }
    res.pop_back();
    res.pop_back();
    res += "]";
    return res;
}

constexpr uint32_t MAX_INT_PART = 10;
constexpr uint16_t LARGE_ANN_INDEX_DIM = 8;
std::shared_ptr<ResultSet> CreateIdxAndSelect(std::string &sqlSelect)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteRdTest::store;

    std::string sqlCreateTable =
        "CREATE TABLE test(id int primary key, repr floatvector(" + std::to_string(LARGE_ANN_INDEX_DIM) + "));";
    std::string sqlCreateIndex = "CREATE INDEX diskann_l2_idx ON test USING GSIVFFLAT(repr L2);";

    std::pair<int32_t, ValueObject> res = {};
    res = store->Execute(sqlCreateTable.c_str(), {});
    EXPECT_EQ(res.first, E_OK);
    res = store->Execute(sqlCreateIndex.c_str(), {});
    EXPECT_EQ(res.first, E_OK);
    for (uint16_t i = 0; i < 10; i++) { // iterate 10 times to insert 10 data
        std::string sqlInsert = "INSERT INTO test VALUES(1000000" + std::to_string(i) + ", '" +
                                GetRandVector(MAX_INT_PART, LARGE_ANN_INDEX_DIM) + "');";
        res = store->Execute(sqlInsert.c_str(), {});
        EXPECT_EQ(res.first, E_OK);
    }
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep(sqlSelect.c_str(), std::vector<ValueObject>());
    EXPECT_NE(resultSet, nullptr);

    bool isStarted = false;
    bool isAtFirstRow = false;
    EXPECT_EQ(E_OK, resultSet->IsStarted(isStarted));
    EXPECT_EQ(E_OK, resultSet->IsAtFirstRow(isAtFirstRow));
    EXPECT_EQ(false, isStarted);
    EXPECT_EQ(false, isAtFirstRow);

    EXPECT_EQ(E_OK, resultSet->GoToNextRow());
    EXPECT_EQ(E_OK, resultSet->IsStarted(isStarted));
    EXPECT_EQ(E_OK, resultSet->IsAtFirstRow(isAtFirstRow));
    EXPECT_EQ(true, isStarted);
    EXPECT_EQ(true, isAtFirstRow);

    std::vector<std::string> colNames = {};
    resultSet->GetAllColumnNames(colNames);
    EXPECT_EQ(colNames.size(), 2); // Expect 2 columns
    return resultSet;
}

/**
@tc.name: RdbStore_Execute_007
@tc.desc: test RdbStore Execute in vector mode
@tc.type: FUNC
*/
constexpr uint16_t SELECT_RES_NUM = 3;
HWTEST_P(RdbExecuteRdTest, RdbStore_Execute_007, TestSize.Level1)
{
    std::string sqlSelect = "SELECT * FROM test ORDER BY repr <-> '" +
                            GetRandVector(MAX_INT_PART, LARGE_ANN_INDEX_DIM) + "' LIMIT " +
                            std::to_string(SELECT_RES_NUM) + ";";
    std::shared_ptr<ResultSet> resultSet = CreateIdxAndSelect(sqlSelect);
    int columnIndex = 0;
    size_t vectSize = 0;
    ValueObject::FloatVector vecs = {};
    EXPECT_EQ(E_OK, resultSet->GetColumnIndex("repr", columnIndex));
    EXPECT_EQ(columnIndex, 1);

    ColumnType colType = ColumnType::TYPE_NULL;
    EXPECT_EQ(E_OK, resultSet->GetColumnType(columnIndex, colType));
    EXPECT_EQ(ColumnType::TYPE_FLOAT32_ARRAY, colType);

    EXPECT_EQ(E_OK, resultSet->GetFloat32Array(columnIndex, vecs));
    EXPECT_EQ(E_OK, resultSet->GetSize(columnIndex, vectSize));
    EXPECT_EQ(vecs.size(), LARGE_ANN_INDEX_DIM);
    EXPECT_EQ(sizeof(float) * LARGE_ANN_INDEX_DIM, vectSize);

    int idVal = 0;
    EXPECT_EQ(E_OK, resultSet->GetColumnIndex("id", columnIndex));
    EXPECT_EQ(E_OK, resultSet->GetInt(columnIndex, idVal));

    int ret = E_OK;
    int resCnt = 0;
    vecs.clear();
    while ((ret = resultSet->GoToNextRow() == E_OK)) {
        EXPECT_EQ(E_OK, resultSet->GetColumnIndex("repr", columnIndex));
        EXPECT_EQ(1, columnIndex); // 1是向量的列

        resultSet->GetColumnType(columnIndex, colType);
        EXPECT_EQ(colType, ColumnType::TYPE_FLOAT32_ARRAY);

        EXPECT_EQ(E_COLUMN_OUT_RANGE, resultSet->GetColumnType(100, colType)); // 100是一个不存在的col, 所以预期返回NULL

        EXPECT_EQ(E_OK, resultSet->GetFloat32Array(columnIndex, vecs));
        EXPECT_EQ(E_OK, resultSet->GetSize(columnIndex, vectSize));
        EXPECT_EQ(vecs.size(), LARGE_ANN_INDEX_DIM);
        EXPECT_EQ(sizeof(float) * LARGE_ANN_INDEX_DIM, vectSize);
        resCnt++;
    }
    EXPECT_EQ(SELECT_RES_NUM - 1, resCnt);
    EXPECT_EQ(E_OK, resultSet->Close());
    std::pair<int32_t, ValueObject> res = RdbExecuteRdTest::store->Execute("DROP TABLE test;");
    EXPECT_EQ(E_OK, res.first);
}

/**
@tc.name: RdbStore_Execute_008
@tc.desc: test RdbStore Execute in vector mode
@tc.type: FUNC
*/
HWTEST_P(RdbExecuteRdTest, RdbStore_Execute_008, TestSize.Level1)
{
    std::string sqlSelect = "SELECT * FROM test;";
    std::shared_ptr<ResultSet> resultSet = CreateIdxAndSelect(sqlSelect);
    int columnIndex = 0;
    size_t vectSize = 0;
    ValueObject::FloatVector vecs = {};
    EXPECT_EQ(E_OK, resultSet->GetColumnIndex("repr", columnIndex));
    EXPECT_EQ(columnIndex, 1);

    ColumnType colType = ColumnType::TYPE_NULL;
    EXPECT_EQ(E_OK, resultSet->GetColumnType(columnIndex, colType));
    EXPECT_EQ(ColumnType::TYPE_FLOAT32_ARRAY, colType);

    int idVal = 0;
    EXPECT_EQ(E_OK, resultSet->GetColumnIndex("id", columnIndex));
    EXPECT_EQ(E_OK, resultSet->GetInt(columnIndex, idVal));

    int ret = E_OK;
    int resCnt = 1;
    vecs.clear();
    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());
    while ((ret = resultSet->GoToNextRow() == E_OK)) {
        EXPECT_EQ(E_OK, resultSet->GetColumnIndex("repr", columnIndex));
        EXPECT_EQ(1, columnIndex); // 1是向量的列， columnIndex期望是1

        resultSet->GetColumnType(columnIndex, colType);
        EXPECT_EQ(colType, ColumnType::TYPE_FLOAT32_ARRAY);

        EXPECT_EQ(E_OK, resultSet->GetFloat32Array(columnIndex, vecs));
        EXPECT_EQ(E_OK, resultSet->GetSize(columnIndex, vectSize));
        EXPECT_EQ(vecs.size(), LARGE_ANN_INDEX_DIM);
        EXPECT_EQ(sizeof(float) * LARGE_ANN_INDEX_DIM, vectSize);
        resCnt++;
    }
    EXPECT_EQ(10, resCnt); // 期待resCnt是10
    EXPECT_EQ(E_OK, resultSet->Close());
    std::pair<int32_t, ValueObject> res = RdbExecuteRdTest::store->Execute("DROP TABLE test;");
    EXPECT_EQ(E_OK, res.first);
}

/**
@tc.name: RdbStore_Execute_009
@tc.desc: test RdbStore Execute in vector mode
@tc.type: FUNC
*/
constexpr uint32_t EXPEC_INSERT_CNT_FOR = 10;
HWTEST_P(RdbExecuteRdTest, RdbStore_Execute_009, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteRdTest::store;

    std::string sqlCreateTable =
        "CREATE TABLE test(id int primary key, repr floatvector(" + std::to_string(LARGE_ANN_INDEX_DIM) + "));";
    std::string sqlCreateIndex = "CREATE INDEX diskann_l2_idx ON test USING GSIVFFLAT(repr L2);";
    std::string sqlSelect = "SELECT * FROM test;";

    std::pair<int32_t, ValueObject> res = {};
    res = store->Execute(sqlCreateTable.c_str(), {});
    EXPECT_EQ(res.first, E_OK);

    std::pair<int32_t, int64_t> trx = {};
    trx = store->BeginTrans();
    EXPECT_EQ(trx.first, E_OK);

    for (uint16_t i = 0; i < EXPEC_INSERT_CNT_FOR; i++) {
        std::string sqlInsert = "INSERT INTO test VALUES(1000000" + std::to_string(i) + ", '" +
                                GetRandVector(MAX_INT_PART, LARGE_ANN_INDEX_DIM) + "');";
        res = store->Execute(sqlInsert.c_str(), {}, trx.second);
        EXPECT_EQ(res.first, E_OK);
    }
    EXPECT_EQ(E_OK, store->Commit(trx.second));

    res = store->Execute(sqlCreateIndex.c_str(), {});
    EXPECT_EQ(res.first, E_OK);

    std::shared_ptr<ResultSet> resultSet = store->QueryByStep(sqlSelect.c_str(), std::vector<ValueObject>());
    EXPECT_NE(resultSet, nullptr);

    int32_t resCnt = 0;
    while (resultSet->GoToNextRow() == E_OK) {
        resCnt++;
    }
    EXPECT_EQ(EXPEC_INSERT_CNT_FOR, resCnt);
}

/**
@tc.name: RdbStore_Execute_010
@tc.desc: test RdbStore Execute in vector mode
@tc.type: FUNC
*/
HWTEST_P(RdbExecuteRdTest, RdbStore_Execute_010, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteRdTest::store;

    std::string sqlCreateTable =
        "CREATE TABLE test(id int primary key, repr floatvector(" + std::to_string(LARGE_ANN_INDEX_DIM) + "));";
    std::string sqlCreateIndex = "CREATE INDEX diskann_l2_idx ON test USING GSIVFFLAT(repr L2);";
    std::string sqlSelect = "SELECT * FROM test;";

    std::pair<int32_t, ValueObject> res = {};
    res = store->Execute(sqlCreateTable.c_str(), {});
    EXPECT_EQ(res.first, E_OK);

    for (uint16_t i = 0; i < 10; i++) {
        std::string sqlInsert = "INSERT INTO test VALUES(1000000" + std::to_string(i) + ", '" +
                                GetRandVector(MAX_INT_PART, LARGE_ANN_INDEX_DIM) + "');";
        res = store->Execute(sqlInsert.c_str(), {}, 0);
        EXPECT_EQ(res.first, E_OK);
    }

    std::pair<int32_t, int64_t> trx = {};
    trx = store->BeginTrans();
    EXPECT_EQ(trx.first, E_OK);
    EXPECT_NE(trx.second, 0);

    for (uint16_t i = 0; i < 10; i++) {
        std::string sqlDelete = "DELETE FROM test WHERE id = 1000000" + std::to_string(i) + ";";
        res = store->Execute(sqlDelete.c_str(), {}, trx.second);
        EXPECT_EQ(res.first, E_OK);
    }

    EXPECT_EQ(E_OK, store->Commit(trx.second));

    std::shared_ptr<ResultSet> resultSet = store->QueryByStep(sqlSelect.c_str(), std::vector<ValueObject>());
    EXPECT_NE(resultSet, nullptr);
    EXPECT_EQ(E_ROW_OUT_RANGE, resultSet->GoToNextRow());
}

/**
@tc.name: RdbStore_Execute_011
@tc.desc: test RdbStore Execute in vector mode
@tc.type: FUNC
*/
HWTEST_P(RdbExecuteRdTest, RdbStore_Execute_011, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteRdTest::store;

    std::string sqlCreateTable = "CREATE TABLE test(id int primary key, day int, repr floatvector(" +
                                 std::to_string(LARGE_ANN_INDEX_DIM) + "));";
    std::string sqlCreateIndex = "CREATE INDEX diskann_l2_idx ON test USING GSIVFFLAT(repr L2);";
    std::string sqlSelect = "SELECT * FROM test;";

    std::pair<int32_t, ValueObject> res = {};
    res = store->Execute(sqlCreateTable.c_str(), {});
    EXPECT_EQ(res.first, E_OK);

    for (uint16_t i = 0; i < 10; i++) {
        std::string sqlInsert = "INSERT INTO test VALUES(1000000" + std::to_string(i) + ", 0, '" +
                                GetRandVector(MAX_INT_PART, LARGE_ANN_INDEX_DIM) + "');";
        res = store->Execute(sqlInsert.c_str(), {}, 0);
        EXPECT_EQ(res.first, E_OK);
    }

    std::pair<int32_t, int64_t> trx = {};
    trx = store->BeginTrans();
    EXPECT_EQ(trx.first, E_OK);
    EXPECT_NE(trx.second, 0);

    for (uint16_t i = 0; i < 10; i++) {
        std::string sqlDelete = "UPDATE test SET day = 1 WHERE id = 1000000" + std::to_string(i) + ";";
        res = store->Execute(sqlDelete.c_str(), {}, trx.second);
        EXPECT_EQ(res.first, E_OK);
    }

    EXPECT_EQ(E_OK, store->Commit(trx.second));
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep(sqlSelect.c_str(), std::vector<ValueObject>());
    EXPECT_NE(resultSet, nullptr);

    uint32_t resCnt = 0;
    int64_t intVal = 0;
    int columnIndex = 0;
    ColumnType colType = ColumnType::TYPE_NULL;

    while (resultSet->GoToNextRow() == E_OK) {
        std::vector<std::string> colNames = {};
        resultSet->GetAllColumnNames(colNames);
        EXPECT_STREQ("id", colNames[0].c_str());
        EXPECT_STREQ("day", colNames[1].c_str());
        EXPECT_STREQ("repr", colNames[2].c_str());

        EXPECT_EQ(E_OK, resultSet->GetColumnIndex("day", columnIndex));
        EXPECT_EQ(1, columnIndex); // 1是day的列

        EXPECT_EQ(E_OK, resultSet->GetColumnType(columnIndex, colType));
        EXPECT_EQ(colType, ColumnType::TYPE_INTEGER);

        EXPECT_EQ(
            E_COLUMN_OUT_RANGE, resultSet->GetColumnType(100, colType)); // 100是一个不存在的col, 所以预期返回错误码
        EXPECT_EQ(colType, ColumnType::TYPE_INTEGER);                    // 值不会被更新

        EXPECT_EQ(E_OK, resultSet->GetLong(columnIndex, intVal));
        EXPECT_EQ(1, intVal);

        resCnt++;
    }
}

/**
@tc.name: RdbStore_Execute_012
@tc.desc: test RdbStore Execute in vector mode
@tc.type: FUNC
*/
HWTEST_P(RdbExecuteRdTest, RdbStore_Execute_012, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteRdTest::store;

    std::string sqlCreateTable =
        "CREATE TABLE test(id int primary key, repr floatvector(" + std::to_string(LARGE_ANN_INDEX_DIM) + "));";
    std::string sqlCreateIndex = "CREATE INDEX diskann_l2_idx ON test USING GSIVFFLAT(repr L2);";
    std::string sqlSelect = "SELECT * FROM test;";

    std::pair<int32_t, ValueObject> res = {};
    res = store->Execute(sqlCreateTable.c_str(), {});
    EXPECT_EQ(res.first, E_OK);

    std::pair<int32_t, int64_t> trx = {};
    trx = store->BeginTrans();
    EXPECT_EQ(trx.first, E_OK);

    for (uint16_t i = 0; i < EXPEC_INSERT_CNT_FOR; i++) {
        std::string sqlInsert = "INSERT INTO test VALUES(1000000" + std::to_string(i) + ", '" +
                                GetRandVector(MAX_INT_PART, LARGE_ANN_INDEX_DIM) + "');";
        res = store->Execute(sqlInsert.c_str(), {}, trx.second);
        EXPECT_EQ(res.first, E_OK);
    }
    EXPECT_EQ(E_OK, store->RollBack(trx.second));

    res = store->Execute(sqlCreateIndex.c_str(), {});
    EXPECT_EQ(res.first, E_OK);

    std::shared_ptr<ResultSet> resultSet = store->QueryByStep(sqlSelect.c_str(), std::vector<ValueObject>());
    EXPECT_NE(resultSet, nullptr);

    int32_t resCnt = 0;
    while (resultSet->GoToNextRow() == E_OK) {
        resCnt++;
    }
    EXPECT_EQ(0, resCnt);
}

/**
@tc.name: RdbStore_Execute_013
@tc.desc: test RdbStore Execute in vector mode
@tc.type: FUNC
*/
HWTEST_P(RdbExecuteRdTest, RdbStore_Execute_013, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteRdTest::store;

    std::string sqlCreateTable =
        "CREATE TABLE test(id int primary key, repr floatvector(" + std::to_string(LARGE_ANN_INDEX_DIM) + "));";
    std::string sqlCreateIndex = "CREATE INDEX diskann_l2_idx ON test USING GSIVFFLAT(repr L2);";
    std::string sqlSelect = "SELECT * FROM test;";

    std::pair<int32_t, ValueObject> res = {};
    res = store->Execute(sqlCreateTable.c_str(), {});
    EXPECT_EQ(res.first, E_OK);

    std::pair<int32_t, int64_t> trx = {};
    trx = store->BeginTrans();
    EXPECT_EQ(trx.first, E_OK);

    for (uint16_t i = 0; i < EXPEC_INSERT_CNT_FOR; i++) {
        std::string sqlInsert = "INSERT INTO test VALUES(1000000" + std::to_string(i) + ", '" +
                                GetRandVector(MAX_INT_PART, LARGE_ANN_INDEX_DIM) + "');";
        res = store->Execute(sqlInsert.c_str(), {}, trx.second);
        EXPECT_EQ(res.first, E_OK);
    }
    EXPECT_EQ(E_OK, store->RollBack(trx.second));

    res = store->Execute(sqlCreateIndex.c_str(), {});
    EXPECT_EQ(res.first, E_OK);

    std::shared_ptr<ResultSet> resultSet = store->QueryByStep(sqlSelect.c_str(), std::vector<ValueObject>());
    EXPECT_NE(resultSet, nullptr);

    int32_t resCnt = 0;
    while (resultSet->GoToNextRow() == E_OK) {
        resCnt++;
    }
    EXPECT_EQ(0, resCnt);
}

/**
@tc.name: RdbStore_Execute_014
@tc.desc: test RdbStore Execute update in transaction
@tc.type: FUNC
*/
HWTEST_P(RdbExecuteRdTest, RdbStore_Execute_014, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteRdTest::store;

    std::string sqlCreateTable = "CREATE TABLE test(id int primary key, age int, repr floatvector(" +
                                 std::to_string(LARGE_ANN_INDEX_DIM) + "));";
    std::string sqlCreateIndex = "CREATE INDEX diskann_l2_idx ON test USING GSIVFFLAT(repr L2);";
    std::string sqlSelect = "SELECT * FROM test;";

    std::pair<int32_t, ValueObject> res = {};
    res = store->Execute(sqlCreateTable.c_str(), {});
    EXPECT_EQ(res.first, E_OK);

    for (uint16_t i = 0; i < 10; i++) {
        std::string sqlInsert = "INSERT INTO test VALUES(1000000" + std::to_string(i) + ", " + std::to_string(i) +
                                ", '" + GetRandVector(MAX_INT_PART, LARGE_ANN_INDEX_DIM) + "');";
        res = store->Execute(sqlInsert.c_str(), {}, 0);
        EXPECT_EQ(res.first, E_OK);
    }

    std::pair<int32_t, int64_t> trx = {};
    trx = store->BeginTrans();
    EXPECT_EQ(trx.first, E_OK);
    EXPECT_NE(trx.second, 0);

    for (uint16_t i = 0; i < 10; i++) {
        std::string sqlUpdate = "UPDATE test SET age = 1 WHERE id = 1000000" + std::to_string(i) + ";";
        res = store->Execute(sqlUpdate.c_str(), {}, trx.second);
        EXPECT_EQ(res.first, E_OK);
    }

    EXPECT_EQ(E_OK, store->Commit(trx.second));
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep(sqlSelect.c_str(), std::vector<ValueObject>());
    int columnIndex = 0;
    while (resultSet->GoToNextRow() == E_OK) {
        std::vector<std::string> colNames = {};
        resultSet->GetAllColumnNames(colNames);
        EXPECT_STREQ("id", colNames[0].c_str());
        EXPECT_STREQ("age", colNames[1].c_str());
        EXPECT_STREQ("repr", colNames[2].c_str());

        EXPECT_EQ(E_OK, resultSet->GetColumnIndex("age", columnIndex));
        EXPECT_EQ(1, columnIndex); // 1是age的列
        int result;
        EXPECT_EQ(E_OK, resultSet->GetInt(columnIndex, result));
        EXPECT_EQ(result, 1);
    }
}

/**
@tc.name: RdbStore_Execute_014
@tc.desc: test RdbStore Execute Repeatly Get Transaction
@tc.type: FUNC
*/
HWTEST_P(RdbExecuteRdTest, RdbStore_Execute_015, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteRdTest::store;

    std::string sqlCreateTable = "CREATE TABLE test2 (id INTEGER PRIMARY KEY, repr INTEGER);";
    std::string sqlSelect = "SELECT * FROM test2;";

    std::pair<int32_t, ValueObject> res = {};
    res = store->Execute(sqlCreateTable.c_str(), {});
    EXPECT_EQ(res.first, E_OK);

    for (uint32_t i = 0; i < 10; i++) {
        std::pair<int32_t, int64_t> trx = {};
        trx = store->BeginTrans();
        EXPECT_EQ(trx.first, E_OK);
        std::string sqlInsert = "INSERT INTO test2 VALUES(" + std::to_string(i) + ", 1);";
        res = store->Execute(sqlInsert.c_str(), {}, trx.second);
        EXPECT_EQ(res.first, E_OK);
        EXPECT_EQ(E_OK, store->Commit(trx.second));
    }

    std::shared_ptr<ResultSet> resultSet = store->QueryByStep(sqlSelect.c_str(), std::vector<ValueObject>());
    EXPECT_NE(resultSet, nullptr);

    int32_t resCnt = 0;
    while (resultSet->GoToNextRow() == E_OK) {
        int rowIdx = 0;
        resultSet->GetRowIndex(rowIdx);
        EXPECT_EQ(resCnt, rowIdx);
        resCnt++;
    }
    EXPECT_EQ(10, resCnt);
}

/**
@tc.name: RdbStore_Execute_016
@tc.desc: test RdbStore Execute Repeatly Get Transaction
@tc.type: FUNC
*/
HWTEST_P(RdbExecuteRdTest, RdbStore_Execute_016, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteRdTest::store;
    std::string sqlCreateTable = "CREATE TABLE IF NOT EXISTS test1 (docId Text, str Text, repr floatvector(4));";
    std::string sqlCreateIdx = "CREATE INDEX test_idx ON test1 USING GSIVFFLAT(repr L2);";
    std::string sqlSelect = "SELECT * FROM test1 ORDER BY repr <-> '[1.0, 2.0, 3.0, 4.0]' LIMIT 2;";

    std::pair<int32_t, ValueObject> res = store->Execute(sqlCreateTable.c_str(), {});
    EXPECT_EQ(res.first, E_OK);
    res = store->Execute(sqlCreateIdx.c_str(), {});
    EXPECT_EQ(res.first, E_OK);

    std::vector<std::vector<float>> vectorSamples = { { 1.0, 2.0, 3.0, 4.0 }, { 10, 20, 30, 40 },
        { 100, 200, 300, 400 } };

    for (uint32_t i = 0; i < vectorSamples.size(); i++) {
        std::pair<int32_t, int64_t> trx = {};
        trx = store->BeginTrans();
        EXPECT_EQ(trx.first, E_OK);
        std::string sqlInsert = "insert into test1 values('" + std::to_string(i) + "', ?, ?);";
        ValueObject floatObj = ValueObject(vectorSamples[i]);
        ValueObject::FloatVector vector = {};
        EXPECT_EQ(floatObj.GetVecs(vector), E_OK);
        EXPECT_EQ(vectorSamples[i].size(), vector.size());
        for (size_t j = 0; j < vector.size(); j++) {
            EXPECT_FLOAT_EQ(vectorSamples[i][j], vector[j]);
        }

        res = store->Execute(sqlInsert.c_str(), { ValueObject(std::string("textVal")), floatObj }, trx.second);
        EXPECT_EQ(res.first, E_OK);
        EXPECT_EQ(E_OK, store->Commit(trx.second));
    }

    std::shared_ptr<ResultSet> resultSet = store->QueryByStep(sqlSelect.c_str(), std::vector<ValueObject>());
    EXPECT_NE(resultSet, nullptr);

    int32_t resCnt = 0;
    while (resultSet->GoToNextRow() == E_OK) {
        std::string primaryStrVal = "";
        std::string textStrVal = "";
        ValueObject::FloatVector floatVector = {};
        resultSet->GetString(0, primaryStrVal);     // 0 is the index of primary String column in select projection
        resultSet->GetString(1, textStrVal);        // 1 is the index of TEXT column in select projection
        resultSet->GetFloat32Array(2, floatVector); // 2 is the index of vector column in select projection
        EXPECT_STREQ(std::to_string(resCnt).c_str(), primaryStrVal.c_str());
        EXPECT_STREQ("textVal", textStrVal.c_str());
        EXPECT_EQ(vectorSamples[resCnt].size(), floatVector.size());
        for (size_t i = 0; i < floatVector.size(); i++) {
            EXPECT_FLOAT_EQ(vectorSamples[resCnt][i], floatVector[i]);
        }
        resCnt++;
    }
    EXPECT_EQ(2, resCnt); // Expect 2 result due to limit 2
}

/**
@tc.name: RdbStore_Execute_017
@tc.desc: test RdbStore Execute Getting or Setting version
@tc.type: FUNC
*/
HWTEST_P(RdbExecuteRdTest, RdbStore_Execute_017, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteRdTest::store;
    int versionToGet = 0;
    int versionToSet = 1;
    EXPECT_EQ(E_OK, store->SetVersion(versionToSet));
    EXPECT_EQ(E_OK, store->GetVersion(versionToGet));
    EXPECT_EQ(versionToGet, versionToSet);

    std::string sqlPragmaSetVersion = "PRAGMA user_version = 3";
    std::pair<int32_t, ValueObject> res = {};
    res = store->Execute(sqlPragmaSetVersion.c_str(), {}, 0);
    EXPECT_EQ(res.first, E_OK);
    EXPECT_EQ(E_OK, store->GetVersion(versionToGet));
    EXPECT_EQ(versionToGet, 3); // 3 is set by sql

    sqlPragmaSetVersion = "PRAGMA user_version = 4;";
    res = store->Execute(sqlPragmaSetVersion.c_str(), {}, 0);
    EXPECT_EQ(res.first, E_OK);
    EXPECT_EQ(E_OK, store->GetVersion(versionToGet));
    EXPECT_EQ(versionToGet, 4); // 4 is set by sql

    sqlPragmaSetVersion = "PRAGMA user_version = 35678";
    res = store->Execute(sqlPragmaSetVersion.c_str(), {}, 0);
    EXPECT_EQ(res.first, E_OK);
    EXPECT_EQ(E_OK, store->GetVersion(versionToGet));
    EXPECT_EQ(versionToGet, 35678); // 35678 is set by sql

    sqlPragmaSetVersion = "PRAGMA user_version = asdfds";
    res = store->Execute(sqlPragmaSetVersion.c_str(), {}, 0);
    EXPECT_EQ(res.first, E_INCORRECT_SQL);

    sqlPragmaSetVersion = "PRAGMA user_version = ;";
    res = store->Execute(sqlPragmaSetVersion.c_str(), {}, 0);
    EXPECT_EQ(res.first, E_INCORRECT_SQL);

    sqlPragmaSetVersion = "PRAGMA user_version = 456   ";
    res = store->Execute(sqlPragmaSetVersion.c_str(), {}, 0);
    EXPECT_EQ(res.first, E_OK);
    EXPECT_EQ(E_OK, store->GetVersion(versionToGet));
    EXPECT_EQ(versionToGet, 456); // 456 is set by sql

    sqlPragmaSetVersion = "PRAGMA user_version = 456  1231 ";
    res = store->Execute(sqlPragmaSetVersion.c_str(), {}, 0);
    EXPECT_EQ(res.first, E_INCORRECT_SQL);

    sqlPragmaSetVersion = "PRAGMA user_version = 456  1asdf231 ";
    res = store->Execute(sqlPragmaSetVersion.c_str(), {}, 0);
    EXPECT_EQ(res.first, E_INCORRECT_SQL);
}

/**
@tc.name: RdbStore_Execute_018
@tc.desc: test RdbStore create encrypted db from non-encrypted db
@tc.type: FUNC
*/
HWTEST_P(RdbExecuteRdTest, RdbStore_Execute_018, TestSize.Level1)
{
    RdbExecuteRdTest::store = nullptr;
    bool isOriginDbEncrypt = GetParam();

    RdbStoreConfig config(RdbExecuteRdTest::databaseName);
    config.SetIsVector(true);
    config.SetEncryptStatus(!isOriginDbEncrypt);
    ExecuteTestOpenRdCallback helper;
    int errCode = E_OK;
    RdbExecuteRdTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    // open encrypted-db in un-encrypted mode is not allowed
    // open un-encrypted db in encrypted-db is allowed
    EXPECT_TRUE((isOriginDbEncrypt && RdbExecuteRdTest::store == nullptr) ||
                (!isOriginDbEncrypt && RdbExecuteRdTest::store != nullptr));
    if (!isOriginDbEncrypt) {
        RdbExecuteRdTest::store = nullptr;
        config.SetEncryptStatus(false); // open encrypted-db update from un-encrypt in un-encrypted mode is not allowed
        RdbExecuteRdTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
        EXPECT_EQ(store, nullptr);
    }
}

/**
 * @tc.name: RdbStore_Execute_019
 * @tc.desc: test RdbStore Execute in vector mode
 * @tc.type: FUNC
 */
HWTEST_P(RdbExecuteRdTest, RdbStore_Execute_019, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteRdTest::store;
    const char *sqlCreateTable = "CREATE TABLE vecTable(inode int primary key, embedding floatvector(4));";
    auto res = store->Execute(sqlCreateTable);
    EXPECT_EQ(E_OK, res.first);

    const char *sqlCreateIndex = "CREATE INDEX diskann_cos_idx ON vecTable USING GSDISKANN(embedding COSINE);";
    res = store->Execute(sqlCreateIndex);
    EXPECT_EQ(E_OK, res.first);

    std::string sqlInsert = "INSERT INTO vecTable VALUES(1, '[1,2,-3,4]'), (2, '[2,2,-3,4]'), (3, '[3,2,3,4]'), (4, "
                            "'[4,2,3,4]'), (5, '[5,2,-3,4]')";
    for (int i = 6; i <= 1000; i++) {
        std::string tmpStr = ", (" + std::to_string(i) + ", '[" + std::to_string(dis(g_gen)) + "," +
                         std::to_string(dis(g_gen)) + "," + std::to_string(dis(g_gen)) + "," +
                         std::to_string(dis(g_gen)) + "]')";
        sqlInsert.append(tmpStr);
    }
    sqlInsert.append(";");
    res = store->Execute(sqlInsert);
    EXPECT_EQ(E_OK, res.first);

    const char *sqlSelect = "SELECT inode, embedding, embedding<=>'[1,1,1,1]' AS score FROM vecTable ORDER BY "
                            "embedding<=>'[1,1,1,1]' LIMIT 501;";
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep(sqlSelect, std::vector<ValueObject>());
    EXPECT_NE(resultSet, nullptr);
    int count = 0;
    resultSet->GetRowCount(count);
    EXPECT_EQ(count, 299);
    const char *sqlDelete = "DELETE FROM vecTable";
    res = store->Execute(sqlDelete);
    EXPECT_EQ(E_OK, res.first);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_001
 * @tc.desc: backup and restore
 * @tc.type: FUNC
 */
HWTEST_P(RdbExecuteRdTest, Rdb_BackupRestoreTest_001, TestSize.Level2)
{
    //create new db instance
    int errCode = E_OK;
    RdbStoreConfig config(RdbExecuteRdTest::restoreDatabaseName);
    config.SetIsVector(true);
    config.SetSecurityLevel(SecurityLevel::S4);
    config.SetEncryptStatus(GetParam());
    if (GetParam()) { // check if encrypt
        config.SetHaMode(HAMode::MAIN_REPLICA);
    }
    config.SetAllowRebuild(true);
    ExecuteTestOpenRdCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store, nullptr);

    std::string sqlCreateTable = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, repr floatvector(8));";
    std::string sqlInsert = "INSERT INTO test VALUES(1, '[1.2, 0.3, 3.2, 1.6, 2.5, 3.1, 0.8, 0.4]');";
    std::string sqlQuery = "SELECT id FROM test order by repr <-> '[1.1, 0.3, 2.2, 6.6, 1.5, 3.1, 0.6, 0.2]' limit 3;";

    std::pair<int32_t, ValueObject> res = {};
    res = store->Execute(sqlCreateTable.c_str(), {});
    EXPECT_EQ(res.first, E_OK);
    res = store->Execute(sqlInsert.c_str(), {});
    EXPECT_EQ(res.first, E_OK);

    std::vector<uint8_t> encryptKey;
    if (GetParam()) {
        encryptKey = config.GetEncryptKey();
    }

    int ret = store->Backup(RdbExecuteRdTest::backupDatabaseName, encryptKey);
    EXPECT_EQ(ret, E_OK);

    res = store->Execute("delete from test where id = 1;");
    EXPECT_EQ(E_OK, res.first);

    ret = store->Restore(RdbExecuteRdTest::backupDatabaseName, encryptKey);
    EXPECT_EQ(ret, E_OK);

    std::shared_ptr<ResultSet> resultSet = store->QueryByStep(sqlQuery.c_str(), std::vector<ValueObject>());

    //check the result
    EXPECT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GoToNextRow(), E_OK);
    std::vector<std::string> colNames = {};
    resultSet->GetAllColumnNames(colNames);
    EXPECT_EQ(colNames.size(), 1);
    int columnIndex = 0;
    int intVal = 0;
    resultSet->GetColumnIndex("id", columnIndex);
    resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(columnIndex, 0);
    EXPECT_EQ(intVal, 1);
    EXPECT_EQ(E_OK, resultSet->Close());
    res = store->Execute("DROP TABLE test;");
    EXPECT_EQ(E_OK, res.first);

    RdbHelper::DeleteRdbStore(RdbExecuteRdTest::restoreDatabaseName);
    RdbHelper::DeleteRdbStore(RdbExecuteRdTest::backupDatabaseName);
}
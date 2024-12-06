/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbStepResultSetGetRowTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;
};

const std::string RdbStepResultSetGetRowTest::DATABASE_NAME = RDB_TEST_PATH + "stepResultSet_getRow_test.db";
std::shared_ptr<RdbStore> RdbStepResultSetGetRowTest::store = nullptr;

class RdbStepResultSetGetOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

int RdbStepResultSetGetOpenCallback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int RdbStepResultSetGetOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbStepResultSetGetRowTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
    RdbStoreConfig config(RdbStepResultSetGetRowTest::DATABASE_NAME);
    RdbStepResultSetGetOpenCallback helper;
    RdbStepResultSetGetRowTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbStepResultSetGetRowTest::store, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void RdbStepResultSetGetRowTest::TearDownTestCase(void)
{
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(RdbStepResultSetGetRowTest::DATABASE_NAME);
}

void RdbStepResultSetGetRowTest::SetUp(void)
{
    store->ExecuteSql("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, "
                      "data2 INTEGER, data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
}

void RdbStepResultSetGetRowTest::TearDown(void)
{
    store->ExecuteSql("DROP TABLE IF EXISTS test");
}

/* *
 * @tc.name: RdbStore_StepResultSet_GetRow_001
 * @tc.desc: test StepResultSet GetRow
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetGetRowTest, RdbStore_StepResultSet_GetRow_001, TestSize.Level1)
{
    int64_t rowId;
    ValuesBucket valuesBucket;
    valuesBucket.PutInt("id", ValueObject(1));
    int errorCode = RdbStepResultSetGetRowTest::store->Insert(rowId, "test", valuesBucket);
    EXPECT_EQ(E_OK, errorCode);
    EXPECT_EQ(1, rowId);

    std::shared_ptr<ResultSet> resultSet = RdbStepResultSetGetRowTest::store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());

    int iRet = E_ERROR;
    RowEntity rowEntity;
    iRet = resultSet->GetRow(rowEntity);
    EXPECT_EQ(E_OK, iRet);

    int idValue = rowEntity.Get("id");
    EXPECT_EQ(1, idValue);

    int idValueByIndex = rowEntity.Get(0);
    EXPECT_EQ(1, idValueByIndex);

    std::map<std::string, ValueObject> rowEntityTmp = rowEntity.Get();
    ValueObject valueObjectTmp = rowEntityTmp["id"];
    int id;
    valueObjectTmp.GetInt(id);
    EXPECT_EQ(1, id);

    std::map<std::string, ValueObject> rowEntityTmp2 = rowEntity.Steal();
    ValueObject valueObjectTmp2 = rowEntityTmp2["id"];
    id = 0;
    valueObjectTmp2.GetInt(id);
    EXPECT_EQ(1, id);
    rowEntityTmp = rowEntity.Get();
    EXPECT_EQ(0, rowEntityTmp.size());

    resultSet->Close();
}

/* *
 * @tc.name: RdbStore_StepResultSet_GetRow_002
 * @tc.desc: test StepResultSet GetRow
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetGetRowTest, RdbStore_StepResultSet_GetRow_002, TestSize.Level1)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutNull("data1");
    valuesBucket.PutNull("data2");
    valuesBucket.PutNull("data3");
    valuesBucket.PutNull("data4");
    valuesBucket.PutNull("data5");
    int64_t rowId;
    int errorCode = RdbStepResultSetGetRowTest::store->Insert(rowId, "test", valuesBucket);
    EXPECT_EQ(E_OK, errorCode);
    EXPECT_EQ(1, rowId);

    std::shared_ptr<ResultSet> resultSet = RdbStepResultSetGetRowTest::store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());

    int iRet = E_ERROR;
    RowEntity rowEntity;
    iRet = resultSet->GetRow(rowEntity);
    EXPECT_EQ(E_OK, iRet);

    int idValue = rowEntity.Get("id");
    EXPECT_EQ(1, idValue);

    int idValueByIndex = rowEntity.Get(0);
    EXPECT_EQ(1, idValueByIndex);

    resultSet->Close();
}

/* *
 * @tc.name: RdbStore_StepResultSet_GetRow_003
 * @tc.desc: test StepResultSet GetRow
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetGetRowTest, RdbStore_StepResultSet_GetRow_003, TestSize.Level1)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutString("data1", "olleh");
    valuesBucket.PutInt("data2", 20);
    valuesBucket.PutDouble("data3", 2.0);
    valuesBucket.PutBlob("data4", { 4, 3, 2, 1 });
    valuesBucket.PutBool("data5", true);
    int64_t rowId;
    int errorCode = RdbStepResultSetGetRowTest::store->Insert(rowId, "test", valuesBucket);
    EXPECT_EQ(E_OK, errorCode);
    EXPECT_EQ(1, rowId);

    std::shared_ptr<ResultSet> resultSet = RdbStepResultSetGetRowTest::store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());

    int iRet = E_ERROR;
    RowEntity rowEntity;
    iRet = resultSet->GetRow(rowEntity);
    EXPECT_EQ(E_OK, iRet);

    int idValue = rowEntity.Get("id");
    std::string data1Value = rowEntity.Get("data1");
    int data2Value = rowEntity.Get("data2");
    double data3Value = rowEntity.Get("data3");
    std::vector<uint8_t> data4Value = rowEntity.Get("data4");
    int data5Value = rowEntity.Get("data5");
    EXPECT_EQ(1, idValue);
    EXPECT_EQ("olleh", data1Value);
    EXPECT_EQ(20, data2Value);
    EXPECT_EQ(2.0, data3Value);
    EXPECT_EQ(1, data4Value[3]);
    EXPECT_EQ(1, data5Value);

    int idValueByIndex = rowEntity.Get(0);
    std::string data1ValueByIndex = rowEntity.Get(1);
    int data2ValueByIndex = rowEntity.Get(2);
    double data3ValueByIndex = rowEntity.Get(3);
    std::vector<uint8_t> data4ValueByIndex = rowEntity.Get(4);
    int data5ValueByIndex = rowEntity.Get(5);
    EXPECT_EQ(1, idValueByIndex);
    EXPECT_EQ("olleh", data1ValueByIndex);
    EXPECT_EQ(20, data2ValueByIndex);
    EXPECT_EQ(2.0, data3ValueByIndex);
    EXPECT_EQ(1, data4ValueByIndex[3]);
    EXPECT_EQ(1, data5ValueByIndex);

    resultSet->Close();
}

/* *
 * @tc.name: RdbStore_StepResultSet_GetRow_004
 * @tc.desc: test StepResultSet GetRow
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetGetRowTest, RdbStore_StepResultSet_GetRow_004, TestSize.Level1)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutString("data1", "");
    valuesBucket.PutInt("data2", 10);
    valuesBucket.PutDouble("data3", 1.0);
    valuesBucket.PutBlob("data4", { 1, 2, 3, 4 });
    valuesBucket.PutBool("data5", true);
    int64_t rowId;
    int errorCode = RdbStepResultSetGetRowTest::store->Insert(rowId, "test", valuesBucket);
    EXPECT_EQ(E_OK, errorCode);
    EXPECT_EQ(1, rowId);

    std::shared_ptr<ResultSet> resultSet =
        RdbStepResultSetGetRowTest::store->QueryByStep("SELECT data1, data2 FROM test");
    EXPECT_NE(resultSet, nullptr);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());

    int iRet = E_ERROR;
    RowEntity rowEntity;
    iRet = resultSet->GetRow(rowEntity);
    EXPECT_EQ(E_OK, iRet);

    std::string data1Value = rowEntity.Get("data1");
    EXPECT_EQ("", data1Value);

    std::string data1ValueByIndex = rowEntity.Get(0);
    EXPECT_EQ("", data1ValueByIndex);

    resultSet->Close();
}

/* *
 * @tc.name: RdbStore_StepResultSet_GetRow_005
 * @tc.desc: Abnormal testCase of GetRow for rowEntity, if params of Get() is invalid
 * @tc.type: FUNC
 */
HWTEST_F(RdbStepResultSetGetRowTest, RdbStore_StepResultSet_GetRow_005, TestSize.Level2)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutString("data1", "keep");
    valuesBucket.PutInt("data2", 10);

    int64_t rowId;
    EXPECT_EQ(E_OK, RdbStepResultSetGetRowTest::store->Insert(rowId, "test", valuesBucket));
    EXPECT_EQ(1, rowId);

    std::shared_ptr<ResultSet> resultSet =
        RdbStepResultSetGetRowTest::store->QueryByStep("SELECT data1, data2 FROM test");
    EXPECT_NE(nullptr, resultSet);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());

    RowEntity rowEntity;
    EXPECT_EQ(E_OK, resultSet->GetRow(rowEntity));

    EXPECT_EQ(ValueObjectType::TYPE_NULL, rowEntity.Get("data3").GetType());
    EXPECT_EQ(ValueObjectType::TYPE_NULL, rowEntity.Get(-1).GetType());
    EXPECT_EQ(ValueObjectType::TYPE_NULL, rowEntity.Get(2).GetType());

    resultSet->Close();
}

/* *
 * @tc.name: RdbStore_StepResultSet_GetRow_006
 * @tc.desc: Abnormal testCase of GetRow for rowEntity, if close resultSet before GetRow
 * @tc.type: FUNC
 */
HWTEST_F(RdbStepResultSetGetRowTest, RdbStore_StepResultSet_GetRow_006, TestSize.Level2)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutString("data1", "keep");
    valuesBucket.PutInt("data2", 10);

    int64_t rowId;
    EXPECT_EQ(E_OK, RdbStepResultSetGetRowTest::store->Insert(rowId, "test", valuesBucket));
    EXPECT_EQ(1, rowId);

    std::shared_ptr<ResultSet> resultSet =
        RdbStepResultSetGetRowTest::store->QueryByStep("SELECT data1, data2 FROM test");
    EXPECT_NE(nullptr, resultSet);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());

    EXPECT_EQ(E_OK, resultSet->Close());

    RowEntity rowEntity;
    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GetRow(rowEntity));
}

/* *
 * @tc.name: RdbStore_StepResultSet_GetRows_001
 * @tc.desc: test StepResultSet GetRows(maxCount, position): maxCount < resultSet.length
 * @tc.type: FUNC
 */
HWTEST_F(RdbStepResultSetGetRowTest, RdbStore_StepResultSet_GetRows_001, TestSize.Level1)
{
    std::vector<OHOS::NativeRdb::ValuesBucket> valueBuckets;
    OHOS::NativeRdb::ValuesBucket value;
    value.PutInt("data2", 30);
    value.PutDouble("data3", 0.6);
    value.PutBool("data5", false);
    for (int i = 1; i <= 17; i++) {
        int64_t rowId;
        int errCode = RdbStepResultSetGetRowTest::store->Insert(rowId, "test", value);
        EXPECT_EQ(E_OK, errCode);
        EXPECT_EQ(i, rowId);
    }
    OHOS::NativeRdb::ValuesBucket value1;
    value.PutString("data1", "ETO");
    value.PutInt("data2", 6);
    value.PutBlob("data4", {4, 3, 2, 1});
    value.PutBool("data5", true);
    int64_t rowId;
    int errCode = RdbStepResultSetGetRowTest::store->Insert(rowId, "test", value);
    EXPECT_EQ(E_OK, errCode);
    EXPECT_EQ(18, rowId);
    std::shared_ptr<ResultSet> resultSet =
        RdbStepResultSetGetRowTest::store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(nullptr, resultSet);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());

    uint32_t maxCount = 5;
    uint32_t position = 0;
    std::vector<RowEntity> rows;
    std::tie(errCode, rows) = resultSet->GetRows(maxCount, position);
    EXPECT_EQ(E_OK, errCode);
    EXPECT_EQ(maxCount, rows.size());
    EXPECT_EQ(5, position);
    EXPECT_EQ(30, rows[0].Get("data2"));
    EXPECT_EQ(false, rows[2].Get(5));
    EXPECT_EQ(ValueObjectType::TYPE_NULL, rows[4].Get(1).GetType());

    int cnt = 0;
    position += maxCount;
    while (rows.size() == maxCount) {
        cnt++;
        std::tie(errCode, rows) = resultSet->GetRows(maxCount, position);
        position += rows.size();
    }
    EXPECT_EQ(3, cnt);
    EXPECT_EQ(18, position);
    EXPECT_EQ(E_ROW_OUT_RANGE, errCode);
    EXPECT_EQ(3, rows.size());
    EXPECT_EQ(0.6, rows[0].Get(3));
    EXPECT_EQ(30, rows[1].Get("data2"));
    EXPECT_EQ("ETO", rows[2].Get(1));
    EXPECT_EQ(6, rows[2].Get("data2"));
    std::vector<uint8_t> data4ValueByIndex = rows[2].Get(4);
    EXPECT_EQ(4, data4ValueByIndex[0]);
    EXPECT_EQ(true, rows[2].Get(5));

    resultSet->Close();
}

/* *
 * @tc.name: RdbStore_StepResultSet_GetRows_002
 * @tc.desc: test StepResultSet GetRows(maxCount, position): maxCount > resultSet.length
 * @tc.type: FUNC
 */
HWTEST_F(RdbStepResultSetGetRowTest, RdbStore_StepResultSet_GetRows_002, TestSize.Level1)
{
    std::vector<OHOS::NativeRdb::ValuesBucket> valueBuckets;
    OHOS::NativeRdb::ValuesBucket value;
    value.PutInt("data2", 30);
    value.PutDouble("data3", 0.6);
    value.PutBool("data5", false);
    for (int i = 1; i <= 7; i++) {
        int64_t rowId;
        int errCode = RdbStepResultSetGetRowTest::store->Insert(rowId, "test", value);
        EXPECT_EQ(E_OK, errCode);
        EXPECT_EQ(i, rowId);
    }
    OHOS::NativeRdb::ValuesBucket value1;
    value.PutString("data1", "ETO");
    value.PutInt("data2", 6);
    value.PutBlob("data4", {4, 3, 2, 1});
    value.PutBool("data5", true);
    int64_t rowId;
    int errCode = RdbStepResultSetGetRowTest::store->Insert(rowId, "test", value);
    EXPECT_EQ(E_OK, errCode);
    EXPECT_EQ(8, rowId);
    std::shared_ptr<ResultSet> resultSet =
        RdbStepResultSetGetRowTest::store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(nullptr, resultSet);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());

    uint32_t maxCount = 10;
    uint32_t position = 1;
    std::vector<RowEntity> rows;
    std::tie(errCode, rows) = resultSet->GetRows(maxCount, position);
    EXPECT_EQ(E_ROW_OUT_RANGE, errCode);
    EXPECT_EQ(7, rows.size());
    EXPECT_EQ(2, rows[0].Get("id"));
    EXPECT_EQ(false, rows[2].Get(5));
    EXPECT_EQ(ValueObjectType::TYPE_NULL, rows[4].Get(1).GetType());
    EXPECT_EQ("ETO", rows[6].Get(1));
    EXPECT_EQ(ValueObjectType::TYPE_NULL, rows[6].Get(3).GetType());
    EXPECT_EQ(6, rows[6].Get(2));
    EXPECT_EQ(true, rows[6].Get(5));

    resultSet->Close();
}

/* *
 * @tc.name: RdbStore_StepResultSet_GetRows_003
 * @tc.desc: test StepResultSet GetRows(maxCount, position): position > resultSet.length
 * @tc.type: FUNC
 */
HWTEST_F(RdbStepResultSetGetRowTest, RdbStore_StepResultSet_GetRows_003, TestSize.Level1)
{
    std::vector<OHOS::NativeRdb::ValuesBucket> valueBuckets;
    OHOS::NativeRdb::ValuesBucket value;
    value.PutInt("data2", 30);
    value.PutDouble("data3", 0.6);
    value.PutBool("data5", false);
    for (int i = 1; i <= 7; i++) {
        int64_t rowId;
        int errCode = RdbStepResultSetGetRowTest::store->Insert(rowId, "test", value);
        EXPECT_EQ(E_OK, errCode);
        EXPECT_EQ(i, rowId);
    }
    OHOS::NativeRdb::ValuesBucket value1;
    value.PutString("data1", "ETO");
    value.PutInt("data2", 6);
    value.PutBlob("data4", {4, 3, 2, 1});
    value.PutBool("data5", true);
    int64_t rowId;
    int errCode = RdbStepResultSetGetRowTest::store->Insert(rowId, "test", value);
    EXPECT_EQ(E_OK, errCode);
    EXPECT_EQ(8, rowId);
    std::shared_ptr<ResultSet> resultSet =
        RdbStepResultSetGetRowTest::store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(nullptr, resultSet);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());

    uint32_t maxCount = 5;
    uint32_t position = 10;
    std::vector<RowEntity> rows;
    std::tie(errCode, rows) = resultSet->GetRows(maxCount, position);
    EXPECT_EQ(E_ROW_OUT_RANGE, errCode);
    EXPECT_EQ(0, rows.size());

    resultSet->Close();
}

/* *
 * @tc.name: RdbStore_StepResultSet_GetRows_004
 * @tc.desc: Abnormal testCase of GetRows for rowEntity, if close resultSet before GetRows
 * @tc.type: FUNC
 */
HWTEST_F(RdbStepResultSetGetRowTest, RdbStore_StepResultSet_GetRows_004, TestSize.Level1)
{
    std::vector<OHOS::NativeRdb::ValuesBucket> valueBuckets;
    OHOS::NativeRdb::ValuesBucket value;
    value.PutInt("data2", 30);
    value.PutDouble("data3", 0.6);
    value.PutBool("data5", false);
    for (int i = 1; i <= 7; i++) {
        int64_t rowId;
        int errCode = RdbStepResultSetGetRowTest::store->Insert(rowId, "test", value);
        EXPECT_EQ(E_OK, errCode);
        EXPECT_EQ(i, rowId);
    }
    OHOS::NativeRdb::ValuesBucket value1;
    value.PutString("data1", "ETO");
    value.PutInt("data2", 6);
    value.PutBlob("data4", {4, 3, 2, 1});
    value.PutBool("data5", true);
    int64_t rowId;
    int errCode = RdbStepResultSetGetRowTest::store->Insert(rowId, "test", value);
    EXPECT_EQ(E_OK, errCode);
    EXPECT_EQ(8, rowId);
    std::shared_ptr<ResultSet> resultSet =
        RdbStepResultSetGetRowTest::store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(nullptr, resultSet);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());
    
    resultSet->Close();
    uint32_t maxCount = 5;
    uint32_t position = 1;
    std::vector<RowEntity> rows;
    std::tie(errCode, rows) = resultSet->GetRows(maxCount, position);
    EXPECT_EQ(E_ALREADY_CLOSED, errCode);
    EXPECT_EQ(0, rows.size());
}

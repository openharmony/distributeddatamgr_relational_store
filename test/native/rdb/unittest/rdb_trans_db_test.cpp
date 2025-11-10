/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <map>
#include <string>

#include "common.h"
#include "connection_pool.h"
#include "rdb_errno.h"
#include "rdb_predicates.h"
#include "sqlite_sql_builder.h"
#include "trans_db.h"
using namespace testing::ext;
using namespace OHOS::NativeRdb;
namespace Test {
class RdbTransDBTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    static constexpr const char *CREATE_TABLE = "CREATE TABLE IF NOT EXISTS TEST (id INT PRIMARY KEY, name TEXT, "
                                                "extend BLOB, code REAL, years UNLIMITED INT, attachment ASSET, "
                                                "attachments ASSETS)";
    static constexpr const char *DROP_TABLE = "DROP TABLE IF EXISTS TEST";
    static constexpr const char *TABLE_NAME = "TEST";
    static std::shared_ptr<ConnectionPool> connPool_;
    static RdbStoreConfig config_;
    static ValuesBucket row_;
    std::shared_ptr<RdbStore> transDB_;
    std::shared_ptr<Connection> conn_;
};
std::shared_ptr<ConnectionPool> RdbTransDBTest::connPool_ = nullptr;
RdbStoreConfig RdbTransDBTest::config_(RDB_TEST_PATH + "transDb_test.db");
ValuesBucket RdbTransDBTest::row_(std::map<std::string, ValueObject>{
    { "id", ValueObject(1) },
    { "name", ValueObject("xiaoming") },
    { "extend", ValueObject(std::vector<uint8_t>(100, 128)) },
    { "code", ValueObject(3.1415926) },
    { "years", ValueObject(BigInteger(0, { 128, 225 })) },
    { "attachment", ValueObject(AssetValue{ .id = "119", .name = "picture1", .hash = "111" }) },
    { "attachments", ValueObject(ValueObject::Assets{
                         AssetValue{ .id = "120", .name = "picture2", .hash = "112" },
                         AssetValue{ .id = "121", .name = "picture3", .hash = "113" },
                         AssetValue{ .id = "122", .name = "picture4", .hash = "114" },
                         AssetValue{ .id = "123", .name = "picture5", .hash = "115" }
                     })
    }
});

void RdbTransDBTest::SetUpTestCase(void)
{
    config_.SetBundleName("arkdata_test");
    config_.SetSecurityLevel(OHOS::NativeRdb::SecurityLevel::S1);
    Connection::Delete(config_);
    int32_t errCode = E_OK;
    std::shared_ptr<RdbStoreConfig> configHolder = std::make_shared<RdbStoreConfig>(config_);
    connPool_ = ConnectionPool::Create(*configHolder, configHolder, errCode);
    EXPECT_TRUE(connPool_ != nullptr);
}

void RdbTransDBTest::TearDownTestCase(void)
{
    connPool_ = nullptr;
    Connection::Delete(config_);
}

void RdbTransDBTest::SetUp()
{
    auto [errCode, conn] = connPool_->CreateTransConn();
    ASSERT_NE(conn, nullptr);
    ASSERT_EQ(errCode, E_OK);
    transDB_ = std::make_shared<TransDB>(conn, config_.GetName());
    ASSERT_NE(transDB_, nullptr);
    auto [err, object] = transDB_->Execute(DROP_TABLE);
    ASSERT_EQ(err, E_OK);
    std::tie(err, object) = transDB_->Execute(CREATE_TABLE);
    ASSERT_EQ(err, E_OK);
    conn_ = conn;
}

void RdbTransDBTest::TearDown()
{
    transDB_ = nullptr;
    conn_ = nullptr;
}

/* *
 * @tc.name: ALREADY_CLOSED_001
 * @tc.desc: closed db
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, ALREADY_CLOSED_001, TestSize.Level1)
{
    conn_ = nullptr;
    ValuesBucket row = row_;
    int32_t changed = 0;
    auto [errCode, rowId] = transDB_->Insert(TABLE_NAME, row);
    ASSERT_EQ(errCode, E_ALREADY_CLOSED);
    std::tie(errCode, changed) = transDB_->Update(TABLE_NAME, row);
    ASSERT_EQ(errCode, E_ALREADY_CLOSED);
    errCode = transDB_->Delete(changed, TABLE_NAME);
    ASSERT_EQ(errCode, E_ALREADY_CLOSED);
    auto resultSet = transDB_->QueryByStep("select * from TEST");
    ASSERT_NE(resultSet, nullptr);
    errCode = resultSet->GoToNextRow();
    ASSERT_EQ(errCode, E_ALREADY_CLOSED);
    resultSet = transDB_->QuerySql("select * from TEST");
    ASSERT_NE(resultSet, nullptr);
    errCode = resultSet->GoToNextRow();
    ASSERT_EQ(errCode, E_ALREADY_CLOSED);
}

/* *
 * @tc.name: ALREADY_CLOSED_002
 * @tc.desc: closed db
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, ALREADY_CLOSED_002, TestSize.Level1)
{
    ValuesBucket row = row_;
    int32_t changed = 0;
    auto [errCode, rowId] = transDB_->Insert(TABLE_NAME, row);
    ASSERT_EQ(errCode, E_OK);
    auto resultSet = transDB_->QueryByStep("select * from TEST");
    ASSERT_NE(resultSet, nullptr);
    errCode = resultSet->GoToNextRow();
    ASSERT_EQ(errCode, E_OK);
    conn_ = nullptr;
    resultSet->Close();
    errCode = transDB_->Delete(changed, TABLE_NAME);
    ASSERT_EQ(errCode, E_ALREADY_CLOSED);
    errCode = resultSet->GoToNextRow();
    ASSERT_EQ(errCode, E_ALREADY_CLOSED);
}

/* *
 * @tc.name: Insert_NEW_001
 * @tc.desc: insert into test(...) values(?)
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Insert_NEW_001, TestSize.Level1)
{
    ValuesBucket row = row_;
    auto [errCode, rowId] = transDB_->Insert(TABLE_NAME, row);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(rowId, 1);
    auto resultSet = transDB_->QueryByStep("select * from TEST");
    ASSERT_NE(resultSet, nullptr);
    errCode = resultSet->GoToNextRow();
    ASSERT_EQ(errCode, E_OK);
    RowEntity rowEntity;
    errCode = resultSet->GetRow(rowEntity);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_TRUE(row.values_ == rowEntity.Get());
}

/* *
 * @tc.name: Insert_NEW_002
 * @tc.desc: insert or replace into test(...) values(?)
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Insert_NEW_002, TestSize.Level1)
{
    ValuesBucket row = row_;
    auto [errCode, rowId] = transDB_->Insert(TABLE_NAME, row);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(rowId, 1);
    row.Put("name", "xiaohua");
    std::tie(errCode, rowId) = transDB_->Insert(TABLE_NAME, row, ConflictResolution::ON_CONFLICT_REPLACE);
    ASSERT_EQ(errCode, E_INVALID_ARGS);
    row.Put("attachments", ValueObject());
    std::tie(errCode, rowId) = transDB_->Insert(TABLE_NAME, row, ConflictResolution::ON_CONFLICT_REPLACE);
    ASSERT_EQ(errCode, E_OK);
    auto resultSet = transDB_->QueryByStep("select * from TEST");
    ASSERT_NE(resultSet, nullptr);
    errCode = resultSet->GoToNextRow();
    ASSERT_EQ(errCode, E_OK);
    RowEntity rowEntity;
    errCode = resultSet->GetRow(rowEntity);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_TRUE(row.values_ == rowEntity.Get());
}

/* *
 * @tc.name: Insert_NEW_003
 * @tc.desc: insert or ignore into test(...) values(?)
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Insert_NEW_003, TestSize.Level1)
{
    ValuesBucket row = row_;
    auto [errCode, rowId] = transDB_->Insert(TABLE_NAME, row);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(rowId, 1);
    row.Put("name", "xiaohua");
    std::tie(errCode, rowId) = transDB_->Insert(TABLE_NAME, row, ConflictResolution::ON_CONFLICT_IGNORE);
    ASSERT_EQ(errCode, E_OK);
    auto resultSet = transDB_->QueryByStep("select * from TEST");
    ASSERT_NE(resultSet, nullptr);
    errCode = resultSet->GoToNextRow();
    ASSERT_EQ(errCode, E_OK);
    RowEntity rowEntity;
    errCode = resultSet->GetRow(rowEntity);
    ASSERT_EQ(errCode, E_OK);
    row = row_;
    SqliteSqlBuilder::UpdateAssetStatus(row.values_["attachment"], AssetValue::STATUS_INSERT);
    SqliteSqlBuilder::UpdateAssetStatus(row.values_["attachments"], AssetValue::STATUS_INSERT);
    ASSERT_TRUE(row.values_ == rowEntity.Get());
}

/* *
 * @tc.name: Insert_NEW_003
 * @tc.desc: insert or fail into test(...) values(?)
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Insert_NEW_004, TestSize.Level1)
{
    ValuesBucket row = row_;
    auto [errCode, rowId] = transDB_->Insert(TABLE_NAME, row);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(rowId, 1);
    row.Put("name", "xiaohua");
    std::tie(errCode, rowId) = transDB_->Insert(TABLE_NAME, row, ConflictResolution::ON_CONFLICT_FAIL);
    ASSERT_EQ(errCode, E_SQLITE_CONSTRAINT);
    auto resultSet = transDB_->QueryByStep("select * from TEST");
    ASSERT_NE(resultSet, nullptr);
    errCode = resultSet->GoToNextRow();
    ASSERT_EQ(errCode, E_OK);
    RowEntity rowEntity;
    errCode = resultSet->GetRow(rowEntity);
    ASSERT_EQ(errCode, E_OK);
    row = row_;
    SqliteSqlBuilder::UpdateAssetStatus(row.values_["attachment"], AssetValue::STATUS_INSERT);
    SqliteSqlBuilder::UpdateAssetStatus(row.values_["attachments"], AssetValue::STATUS_INSERT);
    ASSERT_TRUE(row.values_ == rowEntity.Get());
}

/* *
 * @tc.name: Insert_NEW_003
 * @tc.desc: insert or abort into test(...) values(?)
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Insert_NEW_005, TestSize.Level1)
{
    ValuesBucket row = row_;
    auto [errCode, rowId] = transDB_->Insert(TABLE_NAME, row);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(rowId, 1);
    row.Put("name", "xiaohua");
    std::tie(errCode, rowId) = transDB_->Insert(TABLE_NAME, row, ConflictResolution::ON_CONFLICT_ABORT);
    ASSERT_EQ(errCode, E_SQLITE_CONSTRAINT);
    auto resultSet = transDB_->QueryByStep("select * from TEST");
    ASSERT_NE(resultSet, nullptr);
    errCode = resultSet->GoToNextRow();
    ASSERT_EQ(errCode, E_OK);
    RowEntity rowEntity;
    errCode = resultSet->GetRow(rowEntity);
    ASSERT_EQ(errCode, E_OK);
    row = row_;
    SqliteSqlBuilder::UpdateAssetStatus(row.values_["attachment"], AssetValue::STATUS_INSERT);
    SqliteSqlBuilder::UpdateAssetStatus(row.values_["attachments"], AssetValue::STATUS_INSERT);
    ASSERT_TRUE(row.values_ == rowEntity.Get());
}

/* *
 * @tc.name: Insert_NEW_006
 * @tc.desc: insert or rollback into test(...) values(?)
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Insert_NEW_006, TestSize.Level1)
{
    ValuesBucket row = row_;
    auto [errCode, rowId] = transDB_->Insert(TABLE_NAME, row);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(rowId, 1);
    row.Put("name", "xiaohua");
    std::tie(errCode, rowId) = transDB_->Insert(TABLE_NAME, row, ConflictResolution::ON_CONFLICT_ROLLBACK);
    ASSERT_EQ(errCode, E_SQLITE_CONSTRAINT);
    auto resultSet = transDB_->QueryByStep("select * from TEST");
    ASSERT_NE(resultSet, nullptr);
    errCode = resultSet->GoToNextRow();
    ASSERT_EQ(errCode, E_OK);
    RowEntity rowEntity;
    errCode = resultSet->GetRow(rowEntity);
    ASSERT_EQ(errCode, E_OK);
    row = row_;
    SqliteSqlBuilder::UpdateAssetStatus(row.values_["attachment"], AssetValue::STATUS_INSERT);
    SqliteSqlBuilder::UpdateAssetStatus(row.values_["attachments"], AssetValue::STATUS_INSERT);
    ASSERT_TRUE(row.values_ == rowEntity.Get());
}

/* *
 * @tc.name: Insert_001
 * @tc.desc: insert into test(...) values(?)
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Insert_001, TestSize.Level1)
{
    int64_t rowId = -1;
    ValuesBucket row = row_;
    auto errCode = transDB_->Insert(rowId, TABLE_NAME, row);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(rowId, 1);
    auto resultSet = transDB_->QueryByStep("select * from TEST");
    ASSERT_NE(resultSet, nullptr);
    errCode = resultSet->GoToNextRow();
    ASSERT_EQ(errCode, E_OK);
    RowEntity rowEntity;
    errCode = resultSet->GetRow(rowEntity);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_TRUE(row.values_ == rowEntity.Get());
}

/* *
 * @tc.name: Insert_002
 * @tc.desc: insert into test(...) values(?)
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Insert_002, TestSize.Level1)
{
    int64_t rowId = -1;
    ValuesBucket row = row_;
    auto errCode = transDB_->Insert(rowId, TABLE_NAME, row);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(rowId, 1);
    errCode = transDB_->Insert(rowId, TABLE_NAME, row);
    ASSERT_EQ(errCode, E_SQLITE_CONSTRAINT);
}

/* *
 * @tc.name: InsertWithConflictResolution_001
 * @tc.desc: insert or replace into test(...) values(?)
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, InsertWithConflictResolution_001, TestSize.Level1)
{
    ValuesBucket row = row_;
    auto [errCode, rowId] = transDB_->Insert(TABLE_NAME, row);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(rowId, 1);
    row.Put("name", "xiaohua");
    errCode = transDB_->InsertWithConflictResolution(rowId, TABLE_NAME, row, ConflictResolution::ON_CONFLICT_REPLACE);
    ASSERT_EQ(errCode, E_INVALID_ARGS);
    row.Put("attachments", ValueObject());
    errCode = transDB_->InsertWithConflictResolution(rowId, TABLE_NAME, row, ConflictResolution::ON_CONFLICT_REPLACE);
    ASSERT_EQ(errCode, E_OK);
    auto resultSet = transDB_->QueryByStep("select * from TEST");
    ASSERT_NE(resultSet, nullptr);
    errCode = resultSet->GoToNextRow();
    ASSERT_EQ(errCode, E_OK);
    RowEntity rowEntity;
    errCode = resultSet->GetRow(rowEntity);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_TRUE(row.values_ == rowEntity.Get());
}

/* *
 * @tc.name: Replace_001
 * @tc.desc: insert or replace into test(...) values(?)
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Replace_001, TestSize.Level1)
{
    ValuesBucket row = row_;
    auto [errCode, rowId] = transDB_->Insert(TABLE_NAME, row);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(rowId, 1);
    row.Put("name", "xiaohua");
    errCode = transDB_->Replace(rowId, TABLE_NAME, row);
    ASSERT_EQ(errCode, E_INVALID_ARGS);
    row.Put("attachments", ValueObject());
    errCode = transDB_->Replace(rowId, TABLE_NAME, row);
    ASSERT_EQ(errCode, E_OK);
    auto resultSet = transDB_->QueryByStep("select * from TEST");
    ASSERT_NE(resultSet, nullptr);
    errCode = resultSet->GoToNextRow();
    ASSERT_EQ(errCode, E_OK);
    RowEntity rowEntity;
    errCode = resultSet->GetRow(rowEntity);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_TRUE(row.values_ == rowEntity.Get());
}

/* *
 * @tc.name: BatchInsert
 * @tc.desc: insert Normal ValuesBucket to db
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, BatchInsert_001, TestSize.Level1)
{
    int64_t changedNum = -1;
    std::vector<ValuesBucket> rows;
    for (int i = 0; i < 20; i++) {
        ValuesBucket row = row_;
        row.Put("id", i);
        row.Put("name", "xiaoming_" + std::to_string(i));
        row.Put("years", BigInteger(i % 2, { 128, 225 }));
        rows.push_back(std::move(row));
    }
    auto errCode = transDB_->BatchInsert(changedNum, TABLE_NAME, rows);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(changedNum, 20);
    auto resultSet = transDB_->QueryByStep("select * from TEST order by id");
    ASSERT_NE(resultSet, nullptr);
    size_t index = 0;
    while (resultSet->GoToNextRow() == E_OK && index < rows.size()) {
        RowEntity rowEntity;
        errCode = resultSet->GetRow(rowEntity);
        ASSERT_EQ(errCode, E_OK);
        auto row = rowEntity.Steal();
        SqliteSqlBuilder::UpdateAssetStatus(rows[index].values_["attachment"], AssetValue::STATUS_INSERT);
        SqliteSqlBuilder::UpdateAssetStatus(rows[index].values_["attachments"], AssetValue::STATUS_INSERT);
        ASSERT_TRUE(rows[index].values_ == row);
        index++;
    }
    int32_t rowCount = 0;
    errCode = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(rowCount, rows.size());
}

/* *
 * @tc.name: BatchInsert
 * @tc.desc: insert RefRows to db
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, BatchInsert_002, TestSize.Level1)
{
    ValuesBuckets rows;
    for (int i = 0; i < 20; i++) {
        ValuesBucket row = row_;
        row.Put("id", i);
        row.Put("name", "xiaoming_" + std::to_string(i));
        row.Put("years", BigInteger(i % 2, { 128, 225 }));
        rows.Put(row);
    }
    auto [errCode, changedNum] = transDB_->BatchInsert(TABLE_NAME, rows);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(changedNum, 20);
    auto resultSet = transDB_->QueryByStep("select * from TEST order by id");
    ASSERT_NE(resultSet, nullptr);
    size_t index = 0;
    while (resultSet->GoToNextRow() == E_OK) {
        RowEntity rowEntity;
        errCode = resultSet->GetRow(rowEntity);
        ASSERT_EQ(errCode, E_OK);
        auto row = rowEntity.Steal();
        for (auto &[key, value] : row) {
            auto [ret, val] = rows.Get(index, ValuesBuckets::FieldType(key));
            ASSERT_EQ(ret, E_OK);
            ASSERT_TRUE(val.get() == value);
        }
        index++;
    }
    int32_t rowCount = 0;
    errCode = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(rows.RowSize(), size_t(rowCount));
}

/* *
 * @tc.name: Update_001
 * @tc.desc: update test set(id=?,...)
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Update_001, TestSize.Level1)
{
    ValuesBucket row = row_;
    int32_t changed = -1;
    auto [errCode, rowId] = transDB_->Insert(TABLE_NAME, row);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(rowId, 1);
    row.Put("name", "xiaohua");
    row.Put(
        "attachment", ValueObject(AssetValue{ .id = "119", .name = "picture1", .hash = "111", .path = "/data/test" }));
    std::tie(errCode, changed) = transDB_->Update(TABLE_NAME, row);
    ASSERT_EQ(errCode, E_OK);
    auto resultSet = transDB_->QueryByStep("select * from TEST");
    ASSERT_NE(resultSet, nullptr);
    errCode = resultSet->GoToNextRow();
    ASSERT_EQ(errCode, E_OK);
    RowEntity rowEntity;
    errCode = resultSet->GetRow(rowEntity);
    ASSERT_EQ(errCode, E_OK);
    SqliteSqlBuilder::UpdateAssetStatus(row.values_["attachment"], AssetValue::STATUS_UPDATE);
    ASSERT_TRUE(row.values_ == rowEntity.Get());
}

/* *
 * @tc.name: Update_002
 * @tc.desc: update test set(id=?,...) where id > ? and  id < ?
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Update_002, TestSize.Level1)
{
    int64_t changedNum = -1;
    std::vector<ValuesBucket> rows;
    for (int i = 0; i < 20; i++) {
        ValuesBucket row = row_;
        row.Put("id", i);
        row.Put("name", "xiaoming_" + std::to_string(i));
        row.Put("years", BigInteger(i % 2, { 128, 225 }));
        rows.push_back(std::move(row));
    }
    auto errCode = transDB_->BatchInsert(changedNum, TABLE_NAME, rows);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(changedNum, 20);
    auto updateRow = row_;
    updateRow.values_.erase("id");
    updateRow.Put(
        "attachment", ValueObject(AssetValue{ .id = "119", .name = "picture1", .hash = "111", .path = "/data/test" }));
    int32_t updatedNum = -1;
    std::tie(errCode, updatedNum) = transDB_->Update(TABLE_NAME, updateRow, "id > ? and  id < ?", { 0, 10 });
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(updatedNum, 9);
    auto resultSet = transDB_->QueryByStep("select * from TEST where id > ? and  id < ? order by id", { 0, 10 });
    ASSERT_NE(resultSet, nullptr);
    SqliteSqlBuilder::UpdateAssetStatus(updateRow.values_["attachment"], AssetValue::STATUS_UPDATE);
    SqliteSqlBuilder::UpdateAssetStatus(updateRow.values_["attachments"], AssetValue::STATUS_INSERT);
    size_t index = 0;
    while (resultSet->GoToNextRow() == E_OK) {
        RowEntity rowEntity;
        errCode = resultSet->GetRow(rowEntity);
        ASSERT_EQ(errCode, E_OK);
        auto row = rowEntity.Steal();
        row.erase("id");
        ASSERT_TRUE(updateRow.values_ == row);
        index++;
    }
    ASSERT_EQ(index, 9);
}

/* *
 * @tc.name: Update_003
 * @tc.desc: update test set(id=?,...) where id > ? and  id < ?
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Update_003, TestSize.Level1)
{
    int64_t changedNum = -1;
    std::vector<ValuesBucket> rows;
    for (int i = 0; i < 20; i++) {
        ValuesBucket row = row_;
        row.Put("id", i);
        row.Put("name", "xiaoming_" + std::to_string(i));
        row.Put("years", BigInteger(i % 2, { 128, 225 }));
        rows.push_back(std::move(row));
    }
    auto errCode = transDB_->BatchInsert(changedNum, TABLE_NAME, rows);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(changedNum, 20);
    auto updateRow = row_;
    updateRow.values_.erase("id");
    updateRow.Put(
        "attachment", ValueObject(AssetValue{ .id = "119", .name = "picture1", .hash = "111", .path = "/data/test" }));
    int32_t updatedNum = -1;
    std::tie(errCode, updatedNum) = transDB_->Update(
        TABLE_NAME, updateRow, "id > ? and  id < ?", { 0, 10 }, ConflictResolution::ON_CONFLICT_ROLLBACK);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(updatedNum, 9);
    auto resultSet = transDB_->QueryByStep("select * from TEST where id > ? and  id < ? order by id", { 0, 10 });
    ASSERT_NE(resultSet, nullptr);
    SqliteSqlBuilder::UpdateAssetStatus(updateRow.values_["attachment"], AssetValue::STATUS_UPDATE);
    SqliteSqlBuilder::UpdateAssetStatus(updateRow.values_["attachments"], AssetValue::STATUS_INSERT);
    size_t index = 0;
    while (resultSet->GoToNextRow() == E_OK) {
        RowEntity rowEntity;
        errCode = resultSet->GetRow(rowEntity);
        ASSERT_EQ(errCode, E_OK);
        auto row = rowEntity.Steal();
        row.erase("id");
        ASSERT_TRUE(updateRow.values_ == row);
        index++;
    }
    ASSERT_EQ(index, 9);
}

/* *
 * @tc.name: Update_004
 * @tc.desc: update test set(id=?,...)
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Update_004, TestSize.Level1)
{
    ValuesBucket row = row_;
    int32_t changed = -1;
    auto [errCode, rowId] = transDB_->Insert(TABLE_NAME, row);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(rowId, 1);
    row.Put("name", "xiaohua");
    row.Put(
        "attachment", ValueObject(AssetValue{ .id = "119", .name = "picture1", .hash = "111", .path = "/data/test" }));
    errCode = transDB_->Update(changed, TABLE_NAME, row);
    ASSERT_EQ(errCode, E_OK);
    auto resultSet = transDB_->QueryByStep("select * from TEST");
    ASSERT_NE(resultSet, nullptr);
    errCode = resultSet->GoToNextRow();
    ASSERT_EQ(errCode, E_OK);
    RowEntity rowEntity;
    errCode = resultSet->GetRow(rowEntity);
    ASSERT_EQ(errCode, E_OK);
    SqliteSqlBuilder::UpdateAssetStatus(row.values_["attachment"], AssetValue::STATUS_UPDATE);
    ASSERT_TRUE(row.values_ == rowEntity.Get());
}

/* *
 * @tc.name: Update_005
 * @tc.desc: update test set(id=?,...) where id > ? and  id < ?
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Update_005, TestSize.Level1)
{
    int64_t changedNum = -1;
    std::vector<ValuesBucket> rows;
    for (int i = 0; i < 20; i++) {
        ValuesBucket row = row_;
        row.Put("id", i);
        row.Put("name", "xiaoming_" + std::to_string(i));
        row.Put("years", BigInteger(i % 2, { 128, 225 }));
        rows.push_back(std::move(row));
    }
    auto errCode = transDB_->BatchInsert(changedNum, TABLE_NAME, rows);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(changedNum, 20);
    auto updateRow = row_;
    updateRow.values_.erase("id");
    updateRow.Put(
        "attachment", ValueObject(AssetValue{ .id = "119", .name = "picture1", .hash = "111", .path = "/data/test" }));
    int32_t updatedNum = -1;
    RdbPredicates rdbPredicates(TABLE_NAME);
    rdbPredicates.GreaterThan("id", 0);
    rdbPredicates.And();
    rdbPredicates.LessThan("id", 10);
    errCode = transDB_->Update(updatedNum, updateRow, rdbPredicates);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(updatedNum, 9);
    auto resultSet = transDB_->QueryByStep(rdbPredicates);
    ASSERT_NE(resultSet, nullptr);
    SqliteSqlBuilder::UpdateAssetStatus(updateRow.values_["attachment"], AssetValue::STATUS_UPDATE);
    SqliteSqlBuilder::UpdateAssetStatus(updateRow.values_["attachments"], AssetValue::STATUS_INSERT);
    size_t index = 0;
    while (resultSet->GoToNextRow() == E_OK) {
        RowEntity rowEntity;
        errCode = resultSet->GetRow(rowEntity);
        ASSERT_EQ(errCode, E_OK);
        auto row = rowEntity.Steal();
        row.erase("id");
        ASSERT_TRUE(updateRow.values_ == row);
        index++;
    }
    ASSERT_EQ(index, 9);
}

/* *
 * @tc.name: UpdateWithConflictResolution_001
 * @tc.desc: update test set(id=?,...) where id > ? and  id < ?
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, UpdateWithConflictResolution_001, TestSize.Level1)
{
    int64_t changedNum = -1;
    std::vector<ValuesBucket> rows;
    for (int i = 0; i < 20; i++) {
        ValuesBucket row = row_;
        row.Put("id", i);
        row.Put("name", "xiaoming_" + std::to_string(i));
        row.Put("years", BigInteger(i % 2, { 128, 225 }));
        rows.push_back(std::move(row));
    }
    auto errCode = transDB_->BatchInsert(changedNum, TABLE_NAME, rows);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(changedNum, 20);
    auto updateRow = row_;
    updateRow.values_.erase("id");
    updateRow.Put(
        "attachment", ValueObject(AssetValue{ .id = "119", .name = "picture1", .hash = "111", .path = "/data/test" }));
    int32_t updatedNum = -1;
    errCode =
        transDB_->UpdateWithConflictResolution(updatedNum, TABLE_NAME, updateRow, "id > ? and  id < ?", { 0, 10 });
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(updatedNum, 9);
    auto resultSet = transDB_->QueryByStep("select * from TEST where id > ? and  id < ? order by id", { 0, 10 });
    ASSERT_NE(resultSet, nullptr);
    SqliteSqlBuilder::UpdateAssetStatus(updateRow.values_["attachment"], AssetValue::STATUS_UPDATE);
    SqliteSqlBuilder::UpdateAssetStatus(updateRow.values_["attachments"], AssetValue::STATUS_INSERT);
    size_t index = 0;
    while (resultSet->GoToNextRow() == E_OK) {
        RowEntity rowEntity;
        errCode = resultSet->GetRow(rowEntity);
        ASSERT_EQ(errCode, E_OK);
        auto row = rowEntity.Steal();
        row.erase("id");
        ASSERT_TRUE(updateRow.values_ == row);
        index++;
    }
    ASSERT_EQ(index, 9);
}

/* *
 * @tc.name: Delete_001
 * @tc.desc: delete from test where id > ? and  id < ?
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Delete_001, TestSize.Level1)
{
    int64_t changedNum = -1;
    std::vector<ValuesBucket> rows;
    for (int i = 0; i < 20; i++) {
        ValuesBucket row = row_;
        row.Put("id", i);
        row.Put("name", "xiaoming_" + std::to_string(i));
        row.Put("years", BigInteger(i % 2, { 128, 225 }));
        rows.push_back(std::move(row));
    }
    auto errCode = transDB_->BatchInsert(changedNum, TABLE_NAME, rows);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(changedNum, 20);
    int32_t deleteNum = -1;
    RdbPredicates rdbPredicates(TABLE_NAME);
    rdbPredicates.GreaterThan("id", 0);
    rdbPredicates.And();
    rdbPredicates.LessThan("id", 10);
    errCode = transDB_->Delete(deleteNum, rdbPredicates);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(deleteNum, 9);
    auto resultSet = transDB_->QueryByStep(rdbPredicates);
    ASSERT_NE(resultSet, nullptr);
    int32_t count = -1;
    errCode = resultSet->GetRowCount(count);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(count, 0);
}

/* *
 * @tc.name: Delete_002
 * @tc.desc: delete from test where id > ? and  id < ?
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Delete_002, TestSize.Level1)
{
    int64_t changedNum = -1;
    std::vector<ValuesBucket> rows;
    for (int i = 0; i < 20; i++) {
        ValuesBucket row = row_;
        row.Put("id", i);
        row.Put("name", "xiaoming_" + std::to_string(i));
        row.Put("years", BigInteger(i % 2, { 128, 225 }));
        rows.push_back(std::move(row));
    }
    auto errCode = transDB_->BatchInsert(changedNum, TABLE_NAME, rows);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(changedNum, 20);
    int32_t deleteNum = -1;
    errCode = transDB_->Delete(deleteNum, TABLE_NAME, "id > ? and  id < ?", { 0, 10 });
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(deleteNum, 9);
    auto resultSet = transDB_->QueryByStep("select * from TEST where id > ? and  id < ? order by id", { 0, 10 });
    ASSERT_NE(resultSet, nullptr);
    int32_t count = -1;
    errCode = resultSet->GetRowCount(count);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(count, 0);
}

/* *
 * @tc.name: QueryByStep_001
 * @tc.desc: select id, name, yeas from test where id > ? and  id < ? order by id asc
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, QueryByStep_001, TestSize.Level1)
{
    int64_t changedNum = -1;
    std::vector<ValuesBucket> rows;
    for (int i = 0; i < 20; i++) {
        ValuesBucket row = row_;
        row.Put("id", i);
        row.Put("name", "xiaoming_" + std::to_string(i));
        row.Put("years", BigInteger(i % 2, { 128, 225 }));
        rows.push_back(std::move(row));
    }
    auto errCode = transDB_->BatchInsert(changedNum, TABLE_NAME, rows);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(changedNum, 20);
    RdbPredicates rdbPredicates(TABLE_NAME);
    rdbPredicates.GreaterThan("id", 0);
    rdbPredicates.And();
    rdbPredicates.LessThan("id", 10);
    rdbPredicates.OrderByAsc("id");
    auto resultSet = transDB_->QueryByStep(rdbPredicates, { "id", "name", "years" });
    ASSERT_NE(resultSet, nullptr);
    int64_t index = 1;
    while (resultSet->GoToNextRow() == E_OK) {
        RowEntity rowEntity;
        errCode = resultSet->GetRow(rowEntity);
        ASSERT_EQ(errCode, E_OK);
        auto row = rowEntity.Steal();
        ASSERT_TRUE(row.size() == 3);
        ASSERT_TRUE(row["id"] == ValueObject(index));
        ASSERT_TRUE(row["name"] == ValueObject("xiaoming_" + std::to_string(index)));
        ASSERT_TRUE(row["years"] == ValueObject(BigInteger(index % 2, { 128, 225 })));
        index++;
    }
    int32_t count = -1;
    errCode = resultSet->GetRowCount(count);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(count, 9);
}

/* *
 * @tc.name: Query_001
 * @tc.desc: select id, name, yeas from test where id > ? and  id < ? order by id asc
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Query_001, TestSize.Level1)
{
    int64_t changedNum = -1;
    std::vector<ValuesBucket> rows;
    for (int i = 0; i < 20; i++) {
        ValuesBucket row = row_;
        row.Put("id", i);
        row.Put("name", "xiaoming_" + std::to_string(i));
        row.Put("years", BigInteger(i % 2, { 128, 225 }));
        rows.push_back(std::move(row));
    }
    auto errCode = transDB_->BatchInsert(changedNum, TABLE_NAME, rows);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(changedNum, 20);
    RdbPredicates rdbPredicates(TABLE_NAME);
    rdbPredicates.GreaterThan("id", 0);
    rdbPredicates.And();
    rdbPredicates.LessThan("id", 10);
    rdbPredicates.OrderByAsc("id");
    auto resultSet = transDB_->Query(rdbPredicates, { "id", "name", "years" });
    ASSERT_NE(resultSet, nullptr);
    int64_t index = 1;
    while (resultSet->GoToNextRow() == E_OK) {
        RowEntity rowEntity;
        errCode = resultSet->GetRow(rowEntity);
        ASSERT_EQ(errCode, E_OK);
        auto row = rowEntity.Steal();
        ASSERT_TRUE(row.size() == 3);
        ASSERT_TRUE(row["id"] == ValueObject(index));
        ASSERT_TRUE(row["name"] == ValueObject("xiaoming_" + std::to_string(index)));
        ASSERT_TRUE(row["years"] == ValueObject(BigInteger(index % 2, { 128, 225 })));
        index++;
    }
    int32_t count = -1;
    errCode = resultSet->GetRowCount(count);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(count, 9);
}

/* *
 * @tc.name: QuerySql_001
 * @tc.desc: select * from test where id > ? and  id < ? order by id asc
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, QuerySql_001, TestSize.Level1)
{
    int64_t changedNum = -1;
    std::vector<ValuesBucket> rows;
    for (int i = 0; i < 20; i++) {
        ValuesBucket row = row_;
        row.Put("id", i);
        row.Put("name", "xiaoming_" + std::to_string(i));
        row.Put("years", BigInteger(i % 2, { 128, 225 }));
        rows.push_back(std::move(row));
    }
    auto errCode = transDB_->BatchInsert(changedNum, TABLE_NAME, rows);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(changedNum, 20);
    auto resultSet = transDB_->QuerySql("select * from TEST where id > ? and  id < ? order by id", { 0, 10 });
    ASSERT_NE(resultSet, nullptr);
    int64_t index = 1;
    while (resultSet->GoToNextRow() == E_OK) {
        RowEntity rowEntity;
        errCode = resultSet->GetRow(rowEntity);
        ASSERT_EQ(errCode, E_OK);
        auto row = rowEntity.Steal();
        ASSERT_TRUE(row["id"] == ValueObject(index));
        ASSERT_TRUE(row["name"] == ValueObject("xiaoming_" + std::to_string(index)));
        ASSERT_TRUE(row["years"] == ValueObject(BigInteger(index % 2, { 128, 225 })));
        index++;
    }
    int32_t count = -1;
    errCode = resultSet->GetRowCount(count);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(count, 9);
}

/* *
 * @tc.name: Execute_001
 * @tc.desc: PRAGMA user_version
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Execute_PRAGMA_001, TestSize.Level1)
{
    auto [errCode, value] = transDB_->Execute("PRAGMA user_version=100");
    ASSERT_EQ(errCode, E_OK);
    std::tie(errCode, value) = transDB_->Execute("PRAGMA user_version");
    ASSERT_EQ(errCode, E_OK);
    ASSERT_TRUE(value == ValueObject(100));
}

/* *
 * @tc.name: Execute_DDL_001
 * @tc.desc: PRAGMA user_version
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Execute_DDL_001, TestSize.Level1)
{
    auto [errCode, value] = transDB_->Execute("PRAGMA schema_version");
    ASSERT_EQ(errCode, E_OK);
    ASSERT_NE(value, ValueObject());
    auto oldVer = value;
    std::tie(errCode, value) = transDB_->Execute("CREATE TABLE IF NOT EXISTS TEST1 (id INT PRIMARY KEY, name TEXT)");
    ASSERT_EQ(errCode, E_OK);
    ASSERT_TRUE(value == ValueObject());
    std::tie(errCode, value) = transDB_->Execute("DROP TABLE IF EXISTS TEST1");
    ASSERT_EQ(errCode, E_OK);
    ASSERT_TRUE(value == ValueObject());
    std::tie(errCode, value) = transDB_->Execute("PRAGMA schema_version");
    ASSERT_EQ(errCode, E_OK);
    ASSERT_FALSE(value == ValueObject());
    ASSERT_FALSE(value == oldVer);
}

/* *
 * @tc.name: Execute_Insert_001
 * @tc.desc: INSERT INTO TEST(id, name) VALUES(?,?)
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Execute_Insert_001, TestSize.Level1)
{
    auto [errCode, value] = transDB_->Execute("INSERT INTO TEST(id, name) VALUES (?,?)", { 100, "xiaohong" });
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(value, ValueObject(1));
    auto resultSet = transDB_->QueryByStep("select * from TEST where id == ?", RdbStore::Values{ 100 });
    ASSERT_NE(resultSet, nullptr);
    errCode = resultSet->GoToNextRow();
    ASSERT_EQ(errCode, E_OK);
    RowEntity rowEntity;
    errCode = resultSet->GetRow(rowEntity);
    ASSERT_EQ(errCode, E_OK);
    auto row = rowEntity.Steal();
    ASSERT_TRUE(row["id"] == ValueObject(100));
    ASSERT_TRUE(row["name"] == ValueObject("xiaohong"));
    ASSERT_TRUE(row["years"] == ValueObject());
    int32_t count = -1;
    errCode = resultSet->GetRowCount(count);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(count, 1);
}

/* *
 * @tc.name: Execute_Insert_002
 * @tc.desc: INSERT OR IGNORE INTO TEST(id, name) VALUES(?,?)
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Execute_Insert_002, TestSize.Level1)
{
    auto [errCode, value] = transDB_->Execute("INSERT INTO TEST(id, name) VALUES (?,?)", { 100, "xiaohong" });
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(value, ValueObject(1));
    std::tie(errCode, value) =
        transDB_->Execute("INSERT OR IGNORE INTO TEST(id, name) VALUES (?,?)", { 100, "xiaoming" });
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(value, ValueObject(-1));
    auto resultSet = transDB_->QueryByStep("select * from TEST where id == ?", RdbStore::Values{ 100 });
    ASSERT_NE(resultSet, nullptr);
    errCode = resultSet->GoToNextRow();
    ASSERT_EQ(errCode, E_OK);
    RowEntity rowEntity;
    errCode = resultSet->GetRow(rowEntity);
    ASSERT_EQ(errCode, E_OK);
    auto row = rowEntity.Steal();
    ASSERT_TRUE(row["id"] == ValueObject(100));
    ASSERT_TRUE(row["name"] == ValueObject("xiaohong"));
    int32_t count = -1;
    errCode = resultSet->GetRowCount(count);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(count, 1);
}

/* *
 * @tc.name: Execute_Update_001
 * @tc.desc: UPDATE TEST SET id=?, name=?
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Execute_Update_001, TestSize.Level1)
{
    auto [errCode, value] = transDB_->Execute("INSERT INTO TEST(id, name) VALUES (?,?)", { 100, "xiaohong" });
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(value, ValueObject(1));
    std::tie(errCode, value) = transDB_->Execute("UPDATE TEST SET id=?, name=?", { 100, "xiaoming" });
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(value, ValueObject(1));
    auto resultSet = transDB_->QueryByStep("select * from TEST where id == ?", RdbStore::Values{ 100 });
    ASSERT_NE(resultSet, nullptr);
    errCode = resultSet->GoToNextRow();
    ASSERT_EQ(errCode, E_OK);
    RowEntity rowEntity;
    errCode = resultSet->GetRow(rowEntity);
    ASSERT_EQ(errCode, E_OK);
    auto row = rowEntity.Steal();
    ASSERT_TRUE(row["id"] == ValueObject(100));
    ASSERT_TRUE(row["name"] == ValueObject("xiaoming"));
    int32_t count = -1;
    errCode = resultSet->GetRowCount(count);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(count, 1);
}

/* *
 * @tc.name: Execute_Transaction_001
 * @tc.desc: UPDATE TEST SET(id=?, name=?)
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Execute_Transaction_001, TestSize.Level1)
{
    auto [errCode, value] = transDB_->Execute("BEGIN");
    ASSERT_EQ(errCode, E_OK);
    ASSERT_TRUE(value == ValueObject());
    std::tie(errCode, value) = transDB_->Execute("INSERT INTO TEST(id, name) VALUES (?,?)", { 100, "xiaohong" });
    ASSERT_EQ(errCode, E_OK);
    ASSERT_TRUE(value == ValueObject(1));
    auto resultSet = transDB_->QueryByStep("select * from TEST where id == ?", RdbStore::Values{ 100 });
    ASSERT_NE(resultSet, nullptr);
    int32_t count = -1;
    errCode = resultSet->GetRowCount(count);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(count, 1);
    std::tie(errCode, value) = transDB_->Execute("ROLLBACK");
    ASSERT_EQ(errCode, E_OK);
    resultSet = transDB_->QueryByStep("select * from TEST where id == ?", RdbStore::Values{ 100 });
    ASSERT_NE(resultSet, nullptr);
    count = -1;
    errCode = resultSet->GetRowCount(count);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(count, 0);
}

/* *
 * @tc.name: Execute_Transaction_002
 * @tc.desc: BEGIN, COMMIT, ROLLBACK
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Execute_Transaction_002, TestSize.Level1)
{
    auto [errCode, value] = transDB_->Execute("BEGIN");
    ASSERT_EQ(errCode, E_OK);
    ASSERT_TRUE(value == ValueObject());
    std::tie(errCode, value) = transDB_->Execute("INSERT INTO TEST(id, name) VALUES (?,?)", { 100, "xiaohong" });
    ASSERT_EQ(errCode, E_OK);
    ASSERT_TRUE(value == ValueObject(1));
    std::tie(errCode, value) = transDB_->Execute("COMMIT");
    auto resultSet = transDB_->QueryByStep("select * from TEST where id == ?", RdbStore::Values{ 100 });
    ASSERT_NE(resultSet, nullptr);
    int32_t count = -1;
    errCode = resultSet->GetRowCount(count);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(count, 1);
    std::tie(errCode, value) = transDB_->Execute("ROLLBACK");
    resultSet = transDB_->QueryByStep("select * from TEST where id == ?", RdbStore::Values{ 100 });
    ASSERT_NE(resultSet, nullptr);
    count = -1;
    errCode = resultSet->GetRowCount(count);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(count, 1);
}

/* *
 * @tc.name: Execute_INVALID_001
 * @tc.desc: attach detach select and etc.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, Execute_INVALID_001, TestSize.Level1)
{
    auto [errCode, value] = transDB_->Execute(" ATTACH DATABASE ? AS ? ", { "/data/test/a.db", "a" });
    ASSERT_EQ(errCode, E_INVALID_ARGS);
    std::tie(errCode, value) = transDB_->Execute(" DETACH DATABASE ?", { "/data/test/a.db" });
    ASSERT_EQ(errCode, E_INVALID_ARGS);
    std::tie(errCode, value) = transDB_->Execute(" select * from TEST where id == ?", RdbStore::Values{ 100 });
    ASSERT_EQ(errCode, E_INVALID_ARGS);
}

/* *
 * @tc.name: QueryByStep_ThreadSafe_001
 * @tc.desc: multi-thread use resultSet and closed etc.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, QueryByStep_ThreadSafe_001, TestSize.Level1)
{
    ValuesBucket row = row_;
    auto [errCode, rowId] = transDB_->Insert(TABLE_NAME, row);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(rowId, 1);
    auto resultSet = transDB_->QueryByStep("select * from TEST");
    ASSERT_NE(resultSet, nullptr);
    errCode = resultSet->GoToNextRow();
    ASSERT_EQ(errCode, E_OK);
    std::shared_ptr<std::thread> threads[4];
    for (int i = 0; i < 4; ++i) {
        threads[i] = std::make_shared<std::thread>([resultSet]() {
            RowEntity rowEntity;
            while (resultSet->GetRow(rowEntity) != E_ALREADY_CLOSED) {
            };
        });
    }
    usleep(200);
    resultSet->Close();
    for (int i = 0; i < 4; ++i) {
        if (threads[i] == nullptr) {
            continue;
        }
        threads[i]->join();
        threads[i] = nullptr;
    }
}

/* *
 * @tc.name: ExecuteForLastInsertRowId_001
 * @tc.desc: INSERT OR IGNORE INTO TEST(id, name) VALUES(?,?)
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, ExecuteForLastInsertRowId_001, TestSize.Level1)
{
    int64_t rowId = 0;
    auto errCode =
        transDB_->ExecuteForLastInsertedRowId(rowId, "INSERT INTO TEST(id, name) VALUES (?,?)", { 100, "xiaohong" });
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(rowId, 1);
    errCode = transDB_->ExecuteForLastInsertedRowId(
        rowId, "INSERT OR IGNORE INTO TEST(id, name) VALUES (?,?)", { 100, "xiaoming" });
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(rowId, -1);
    auto resultSet = transDB_->QueryByStep("select * from TEST where id == ?", RdbStore::Values{ 100 });
    ASSERT_NE(resultSet, nullptr);
    errCode = resultSet->GoToNextRow();
    ASSERT_EQ(errCode, E_OK);
    RowEntity rowEntity;
    errCode = resultSet->GetRow(rowEntity);
    ASSERT_EQ(errCode, E_OK);
    auto row = rowEntity.Steal();
    ASSERT_TRUE(row["id"] == ValueObject(100));
    ASSERT_TRUE(row["name"] == ValueObject("xiaohong"));
    int32_t count = -1;
    errCode = resultSet->GetRowCount(count);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(count, 1);
}

/* *
 * @tc.name: ExecuteForChangedRowCount_001
 * @tc.desc: UPDATE TEST SET id=?, name=?
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransDBTest, ExecuteForChangedRowCount_001, TestSize.Level1)
{
    auto [errCode, value] = transDB_->Execute("INSERT INTO TEST(id, name) VALUES (?,?)", { 100, "xiaohong" });
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(value, ValueObject(1));
    int64_t changedRow = 0;
    errCode = transDB_->ExecuteForChangedRowCount(changedRow, "UPDATE TEST SET id=?, name=?", { 100, "xiaoming" });
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(changedRow, 1);
    auto resultSet = transDB_->QueryByStep("select * from TEST where id == ?", RdbStore::Values{ 100 });
    ASSERT_NE(resultSet, nullptr);
    errCode = resultSet->GoToNextRow();
    ASSERT_EQ(errCode, E_OK);
    RowEntity rowEntity;
    errCode = resultSet->GetRow(rowEntity);
    ASSERT_EQ(errCode, E_OK);
    auto row = rowEntity.Steal();
    ASSERT_TRUE(row["id"] == ValueObject(100));
    ASSERT_TRUE(row["name"] == ValueObject("xiaoming"));
    int32_t count = -1;
    errCode = resultSet->GetRowCount(count);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(count, 1);
}
} // namespace Test

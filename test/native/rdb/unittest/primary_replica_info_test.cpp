/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#define LOG_TAG "PrimaryReplicaInfoTest"
#include "primary_replica_info.h"
#include "rdb_store_impl.h"
#include "sqlite_connection.h"

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include "common.h"
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "sqlite_global_config.h"
#include "sqlite_utils.h"
#include "values_bucket.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

// RAII scope guard for extra test resources
struct ScopeGuard {
    std::function<void()> func;
    explicit ScopeGuard(std::function<void()> f) : func(std::move(f)) {}
    ~ScopeGuard() { if (func) func(); }
    ScopeGuard(const ScopeGuard &) = delete;
    ScopeGuard &operator=(const ScopeGuard &) = delete;
};

class PrimaryReplicaInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::string dbName;
    std::string slaveDbName;
protected:
    std::shared_ptr<RdbStore> store_;
};

class PrimaryReplicaInfoCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override
    {
        return store.ExecuteSql("CREATE TABLE IF NOT EXISTS test "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, age INTEGER)");
    }
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override
    {
        return E_OK;
    }
};

void PrimaryReplicaInfoTest::SetUpTestCase(void)
{
    SqliteGlobalConfig::InitSqliteGlobalConfig();
}

void PrimaryReplicaInfoTest::TearDownTestCase(void) {}

void PrimaryReplicaInfoTest::SetUp()
{
    auto *info = testing::UnitTest::GetInstance()->current_test_info();
    std::string testTag = std::string(info->test_suite_name()) + "_" + info->name();
    dbName = RDB_TEST_PATH + testTag + ".db";
    slaveDbName = RDB_TEST_PATH + testTag + "_slave.db";
    RdbHelper::DeleteRdbStore(dbName);
    RdbHelper::DeleteRdbStore(slaveDbName);
    RdbStoreConfig config(dbName);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    PrimaryReplicaInfoCallback helper;
    int errCode = E_OK;
    store_ = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store_, nullptr);
    ASSERT_EQ(errCode, E_OK);
}

void PrimaryReplicaInfoTest::TearDown()
{
    store_ = nullptr;
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(dbName);
    RdbHelper::DeleteRdbStore(slaveDbName);
}

static void InsertRows(std::shared_ptr<RdbStore> &store, int start, int count)
{
    for (int i = 0; i < count; i++) {
        ValuesBucket values;
        values.PutInt("id", start + i);
        values.PutString("name", "row" + std::to_string(start + i));
        values.PutInt("age", 20 + i);
        int64_t rowId = 0;
        int ret = store->Insert(rowId, "test", values);
        EXPECT_EQ(ret, E_OK);
    }
}

/**
 * @tc.name: PrimaryReplicaInfo_TypeExistence_001
 * @tc.desc: AC-6.4: Verify all new types can be default-constructed with correct defaults.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, TypeExistence_001, TestSize.Level1)
{
    PrimaryAndReplicaInfo info{};
    EXPECT_EQ(info.primaryInfo.dbInfo.size, 0);
    EXPECT_EQ(info.primaryInfo.dbInfo.ctime, 0);
    EXPECT_EQ(info.primaryInfo.dbInfo.mtime, 0);
    EXPECT_EQ(info.primaryInfo.walInfo.size, 0);
    EXPECT_EQ(info.primaryInfo.userVersion, 0);
    EXPECT_TRUE(info.primaryInfo.tables.empty());
    EXPECT_EQ(info.binlogInfo.exist, false);
    EXPECT_EQ(info.binlogInfo.fileCount, 0u);
    EXPECT_EQ(info.binlogInfo.totalSize, 0);
    EXPECT_EQ(info.binlogInfo.lastModifyTime, 0);
    // Per-item status fields default to E_OK (R-02)
    EXPECT_EQ(info.primaryInfo.dbInfo.errCode, E_OK);
    EXPECT_EQ(info.primaryInfo.dbInfo.sizeErr, E_OK);
    EXPECT_EQ(info.primaryInfo.walInfo.errCode, E_OK);
    EXPECT_EQ(info.primaryInfo.walInfo.sizeErr, E_OK);
    EXPECT_EQ(info.primaryInfo.checkpointErr, E_OK);
    EXPECT_EQ(info.replicaInfo.checkpointErr, E_OK);
    EXPECT_EQ(info.binlogInfo.errCode, E_OK);
    EXPECT_EQ(info.replayErr, E_OK);
    EXPECT_EQ(info.primaryLastModifyTime, 0);
    EXPECT_EQ(info.primaryTimeErr, E_OK);
    EXPECT_EQ(info.replicaLastModifyTime, 0);
    EXPECT_EQ(info.replicaTimeErr, E_OK);

    RdbFileInfo fi{};
    fi.size = 1024;
    fi.mtime = 1234567890;
    EXPECT_EQ(fi.size, 1024);
    EXPECT_EQ(fi.mtime, 1234567890);
    EXPECT_EQ(fi.errCode, E_OK);

    TableInfo ti{};
    ti.count = 42;
    EXPECT_EQ(ti.count, 42);
    EXPECT_EQ(ti.errCode, E_OK);

    RdbBinlogInfo bi{};
    bi.exist = true;
    bi.fileCount = 3;
    bi.totalSize = 4096;
    bi.lastModifyTime = 99999;
    EXPECT_EQ(bi.exist, true);
    EXPECT_EQ(bi.fileCount, 3u);
    EXPECT_EQ(bi.errCode, E_OK);
}

/**
 * @tc.name: PrimaryReplicaInfo_SingleMode_001
 * @tc.desc: AC-5.3: SINGLE ha-mode returns E_NOT_SUPPORT.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, SingleMode_001, TestSize.Level1)
{
    std::string singleDb = RDB_TEST_PATH + "pri_replica_single_test.db";
    RdbHelper::DeleteRdbStore(singleDb);
    ScopeGuard cleanup([&]() {
        RdbHelper::ClearCache();
        RdbHelper::DeleteRdbStore(singleDb);
    });
    RdbStoreConfig config(singleDb);
    config.SetHaMode(HAMode::SINGLE);
    PrimaryReplicaInfoCallback helper;
    int errCode = E_OK;
    auto singleStore = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(singleStore, nullptr);
    ASSERT_EQ(errCode, E_OK);

    auto [ret, info] = singleStore->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_NOT_SUPPORT);
}

/**
 * @tc.name: PrimaryReplicaInfo_StoreClosed_001
 * @tc.desc: AC-5.1: Closed store returns E_ALREADY_CLOSED.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, StoreClosed_001, TestSize.Level1)
{
    std::string closedDb = RDB_TEST_PATH + "pri_replica_closed_test.db";
    RdbHelper::DeleteRdbStore(closedDb);
    ScopeGuard cleanup([&]() {
        RdbHelper::ClearCache();
        RdbHelper::DeleteRdbStore(closedDb);
    });
    RdbStoreConfig config(closedDb);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    PrimaryReplicaInfoCallback helper;
    int errCode = E_OK;
    auto closedStore = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(closedStore, nullptr);

    auto impl = std::static_pointer_cast<RdbStoreImpl>(closedStore);
    impl->Close();

    auto [ret, info] = closedStore->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_ALREADY_CLOSED);
}

/**
 * @tc.name: PrimaryReplicaInfo_EmptyTableName_001
 * @tc.desc: AC-3.2: Empty table name skips count, tables map stays empty.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, EmptyTableName_001, TestSize.Level1)
{
    InsertRows(store_, 1, 2);
    auto [ret, info] = store_->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_OK);
    EXPECT_TRUE(info.primaryInfo.tables.empty());
    EXPECT_TRUE(info.replicaInfo.tables.empty());
}

/**
 * @tc.name: PrimaryReplicaInfo_FileSizes_001
 * @tc.desc: AC-1.1: Primary DB file size matches stat after checkpoint.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, FileSizes_001, TestSize.Level1)
{
    InsertRows(store_, 1, 5);
    auto [ret, info] = store_->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_OK);
    EXPECT_GT(info.primaryInfo.dbInfo.size, 0);
    EXPECT_EQ(info.primaryInfo.dbInfo.errCode, E_OK);
    // WAL file stat should succeed (file exists after writes, may be 0 after checkpoint) (T-03 fix).
    EXPECT_EQ(info.primaryInfo.walInfo.errCode, E_OK);

    struct stat st;
    ASSERT_EQ(stat(dbName.c_str(), &st), 0);
    EXPECT_EQ(info.primaryInfo.dbInfo.size, static_cast<int64_t>(st.st_size));
}

/**
 * @tc.name: PrimaryReplicaInfo_TableCount_001
 * @tc.desc: AC-3.1: Table row count matches inserted rows on primary.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, TableCount_001, TestSize.Level1)
{
    InsertRows(store_, 1, 3);
    auto [ret, info] = store_->GetPrimaryReplicaInfo("test");
    EXPECT_EQ(ret, E_OK);
    auto it = info.primaryInfo.tables.find("test");
    ASSERT_NE(it, info.primaryInfo.tables.end());
    EXPECT_EQ(it->second.count, 3);
}

/**
 * @tc.name: PrimaryReplicaInfo_TimeFields_001
 * @tc.desc: AC-2.1: Time fields are collected and are positive millisecond timestamps.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, TimeFields_001, TestSize.Level1)
{
    InsertRows(store_, 1, 1);
    auto [ret, info] = store_->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_OK);
    EXPECT_GT(info.primaryInfo.dbInfo.mtime, 0);
    EXPECT_GE(info.primaryInfo.dbInfo.ctime, 0);
    EXPECT_GE(info.primaryInfo.dbInfo.atime, 0);
    // Verify summarized time is set and follows max(DB, WAL) rule (T-04 fix).
    EXPECT_GT(info.primaryLastModifyTime, 0);
    EXPECT_EQ(info.primaryLastModifyTime,
        std::max(info.primaryInfo.dbInfo.mtime, info.primaryInfo.walInfo.mtime));
}

/**
 * @tc.name: PrimaryReplicaInfo_BinlogInfo_NoBinlog_001
 * @tc.desc: AC-2.4: When no binlog data files exist, binlogInfo.exist is false.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, BinlogInfo_NoBinlog_001, TestSize.Level1)
{
    auto [ret, info] = store_->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_OK);
    // No binlog writes performed; exist must be false (T-07 fix).
    EXPECT_EQ(info.binlogInfo.exist, false);
    EXPECT_EQ(info.binlogInfo.fileCount, 0u);
    EXPECT_EQ(info.binlogInfo.totalSize, 0);
    EXPECT_EQ(info.binlogInfo.lastModifyTime, 0);
}

/**
 * @tc.name: PrimaryReplicaInfo_UserVersion_001
 * @tc.desc: AC-1.1: user_version is collected from the primary database.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, UserVersion_001, TestSize.Level1)
{
    EXPECT_EQ(store_->ExecuteSql("PRAGMA user_version = 42"), E_OK);
    auto [ret, info] = store_->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_OK);
    // Verify exact user_version value, not just >= 0 (T-07 fix).
    EXPECT_EQ(info.primaryInfo.userVersion, 42);
}

/**
 * @tc.name: PrimaryReplicaInfo_PartialResults_001
 * @tc.desc: AC-5.1: Even when replica is absent, primary fields are valid and ret is E_OK.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, PartialResults_001, TestSize.Level1)
{
    InsertRows(store_, 1, 2);
    auto [ret, info] = store_->GetPrimaryReplicaInfo("test");
    EXPECT_EQ(ret, E_OK);
    // Primary should have valid data.
    EXPECT_GT(info.primaryInfo.dbInfo.size, 0);
    auto it = info.primaryInfo.tables.find("test");
    ASSERT_NE(it, info.primaryInfo.tables.end());
    EXPECT_EQ(it->second.count, 2);
    RdbStoreConfig checkConfig(dbName);
    checkConfig.SetHaMode(HAMode::MAIN_REPLICA);
    int expectedReplayErr = SqliteUtils::IsSupportBinlog(checkConfig) ? E_OK : E_NOT_SUPPORT;
    EXPECT_EQ(info.replayErr, expectedReplayErr);
    EXPECT_EQ(info.primaryInfo.checkpointErr, E_OK);
    EXPECT_EQ(info.primaryInfo.dbInfo.errCode, E_OK);
    EXPECT_EQ(it->second.errCode, E_OK);
    // Summarized time must be populated (R-03).
    EXPECT_EQ(info.primaryLastModifyTime,
        std::max(info.primaryInfo.dbInfo.mtime, info.primaryInfo.walInfo.mtime));
}

/**
 * @tc.name: PrimaryReplicaInfo_InvalidTableName_001
 * @tc.desc: AC-3.4: Invalid table name returns E_INVALID_ARGS with partial results preserved.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, InvalidTableName_001, TestSize.Level1)
{
    InsertRows(store_, 1, 1);
    // Table name with injection attempt must be rejected by IsValidTableName (T-01 fix).
    auto [ret, info] = store_->GetPrimaryReplicaInfo("test; DROP TABLE test");
    EXPECT_EQ(ret, E_INVALID_ARGS);
    // Partial results should still be present.
    EXPECT_GT(info.primaryInfo.dbInfo.size, 0);
    // Original table must still exist with its data (no SQL injection).
    auto [ret2, info2] = store_->GetPrimaryReplicaInfo("test");
    EXPECT_EQ(ret2, E_OK);
    auto it = info2.primaryInfo.tables.find("test");
    ASSERT_NE(it, info2.primaryInfo.tables.end());
    EXPECT_EQ(it->second.count, 1);
}

/**
 * @tc.name: PrimaryReplicaInfo_ReadOnlyDb_001
 * @tc.desc: AC-5.4: Read-only database returns E_NOT_SUPPORT.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, ReadOnlyDb_001, TestSize.Level1)
{
    std::string roDb = RDB_TEST_PATH + "pri_replica_readonly_test.db";
    RdbHelper::DeleteRdbStore(roDb);
    ScopeGuard cleanup([&]() {
        RdbHelper::ClearCache();
        RdbHelper::DeleteRdbStore(roDb);
    });
    // Create the DB first so the file exists before reopening read-only
    {
        RdbStoreConfig createConfig(roDb);
        createConfig.SetHaMode(HAMode::MAIN_REPLICA);
        PrimaryReplicaInfoCallback helper;
        int errCode = E_OK;
        auto store = RdbHelper::GetRdbStore(createConfig, 1, helper, errCode);
        ASSERT_NE(store, nullptr);
        store = nullptr;
        RdbHelper::ClearCache();
    }
    // Reopen as read-only
    RdbStoreConfig config(roDb);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    config.SetReadOnly(true);
    PrimaryReplicaInfoCallback helper;
    int errCode = E_OK;
    auto roStore = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    if (roStore == nullptr) {
        GTEST_SKIP() << "Cannot create read-only MAIN_REPLICA store in this environment";
    }
    auto [ret, info] = roStore->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_NOT_SUPPORT);
}

/**
 * @tc.name: PrimaryReplicaInfo_MemoryDb_001
 * @tc.desc: AC-5.4: A real memory database (StorageMode::MODE_MEMORY) sets isMemoryRdb_=true;
 *           GetPrimaryReplicaInfo returns E_NOT_SUPPORT from the pre-check.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, MemoryDb_001, TestSize.Level1)
{
    std::string memDb = RDB_TEST_PATH + "pri_replica_memory_test.db";
    RdbHelper::DeleteRdbStore(memDb);
    ScopeGuard cleanup([&]() {
        RdbHelper::ClearCache();
        RdbHelper::DeleteRdbStore(memDb);
    });
    RdbStoreConfig config(memDb, StorageMode::MODE_MEMORY);
    PrimaryReplicaInfoCallback helper;
    int errCode = E_OK;
    auto memStore = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(memStore, nullptr);
    ASSERT_EQ(errCode, E_OK);
    auto [ret, info] = memStore->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_NOT_SUPPORT);
}

/**
 * @tc.name: PrimaryReplicaInfo_VectorDb_001
 * @tc.desc: AC-5.4: A real vector database (SetIsVector → DB_VECTOR) is rejected by the pre-check;
 *           GetPrimaryReplicaInfo returns E_NOT_SUPPORT. Skips if the environment cannot create
 *           a vector store (requires ArkData support).
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, VectorDb_001, TestSize.Level1)
{
    std::string vecDb = RDB_TEST_PATH + "pri_replica_vector_test.db";
    RdbHelper::DeleteRdbStore(vecDb);
    ScopeGuard cleanup([&]() {
        RdbHelper::ClearCache();
        RdbHelper::DeleteRdbStore(vecDb);
    });
    RdbStoreConfig config(vecDb);
    config.SetIsVector(true);
    PrimaryReplicaInfoCallback helper;
    int errCode = E_OK;
    auto vecStore = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    if (vecStore == nullptr || errCode != E_OK) {
        GTEST_SKIP() << "Vector DB not supported in this environment (requires ArkData), errCode=" << errCode;
    }
    auto [ret, info] = vecStore->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_NOT_SUPPORT);
}

/**
 * @tc.name: PrimaryReplicaInfo_EmptyTableCount_001
 * @tc.desc: AC-3.1: Table with 0 rows returns count=0 and errCode=E_OK (TC-13).
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, EmptyTableCount_001, TestSize.Level1)
{
    auto [ret, info] = store_->GetPrimaryReplicaInfo("test");
    EXPECT_EQ(ret, E_OK);
    auto it = info.primaryInfo.tables.find("test");
    ASSERT_NE(it, info.primaryInfo.tables.end());
    EXPECT_EQ(it->second.count, 0);
    EXPECT_EQ(it->second.errCode, E_OK);
}

/**
 * @tc.name: PrimaryReplicaInfo_TableNotExist_001
 * @tc.desc: AC-3.3: Non-existent table yields errCode != E_OK, count stays 0 (TC-15).
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, TableNotExist_001, TestSize.Level1)
{
    auto [ret, info] = store_->GetPrimaryReplicaInfo("nonexistent_table");
    EXPECT_EQ(ret, E_OK);
    auto it = info.primaryInfo.tables.find("nonexistent_table");
    ASSERT_NE(it, info.primaryInfo.tables.end());
    EXPECT_NE(it->second.errCode, E_OK);
    EXPECT_EQ(it->second.count, 0);
}

/**
 * @tc.name: PrimaryReplicaInfo_PrimaryTimeRule_001
 * @tc.desc: AC-2.2: primaryLastModifyTime = max(primaryDb.mtime, primaryWal.mtime) (TC-05).
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, PrimaryTimeRule_001, TestSize.Level1)
{
    InsertRows(store_, 1, 3);
    auto [ret, info] = store_->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(info.primaryLastModifyTime,
        std::max(info.primaryInfo.dbInfo.mtime, info.primaryInfo.walInfo.mtime));
    EXPECT_GT(info.primaryLastModifyTime, 0);
}

/**
 * @tc.name: PrimaryReplicaInfo_ReplicaTimeRule_001
 * @tc.desc: AC-2.3/2.4: replicaLastModifyTime follows binlog-priority or max(DB,WAL) fallback (TC-07).
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, ReplicaTimeRule_001, TestSize.Level1)
{
    auto [ret, info] = store_->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_OK);
    int64_t expected = info.binlogInfo.exist
        ? info.binlogInfo.lastModifyTime
        : std::max(info.replicaInfo.dbInfo.mtime, info.replicaInfo.walInfo.mtime);
    EXPECT_EQ(info.replicaLastModifyTime, expected);
}

/**
 * @tc.name: PrimaryReplicaInfo_StatusFieldsDefault_001
 * @tc.desc: AC-5.1: All per-item status fields are E_OK on a successful query.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, StatusFieldsDefault_001, TestSize.Level1)
{
    InsertRows(store_, 1, 2);
    auto [ret, info] = store_->GetPrimaryReplicaInfo("test");
    EXPECT_EQ(ret, E_OK);
    RdbStoreConfig checkConfig(dbName);
    checkConfig.SetHaMode(HAMode::MAIN_REPLICA);
    int expectedReplayErr = SqliteUtils::IsSupportBinlog(checkConfig) ? E_OK : E_NOT_SUPPORT;
    EXPECT_EQ(info.replayErr, expectedReplayErr);
    EXPECT_EQ(info.primaryInfo.checkpointErr, E_OK);
    EXPECT_EQ(info.replicaInfo.checkpointErr, E_OK);
    EXPECT_EQ(info.primaryInfo.dbInfo.errCode, E_OK);
    EXPECT_EQ(info.primaryInfo.walInfo.errCode, E_OK);
    EXPECT_EQ(info.binlogInfo.errCode, E_OK);
    auto it = info.primaryInfo.tables.find("test");
    ASSERT_NE(it, info.primaryInfo.tables.end());
    EXPECT_EQ(it->second.errCode, E_OK);
}

/**
 * @tc.name: PrimaryReplicaInfo_RepeatedQuery_001
 * @tc.desc: AC-5.1: Repeated queries return consistent results (TC-22).
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, RepeatedQuery_001, TestSize.Level1)
{
    InsertRows(store_, 1, 3);
    auto [ret1, info1] = store_->GetPrimaryReplicaInfo("test");
    EXPECT_EQ(ret1, E_OK);
    auto [ret2, info2] = store_->GetPrimaryReplicaInfo("test");
    EXPECT_EQ(ret2, E_OK);
    auto it1 = info1.primaryInfo.tables.find("test");
    auto it2 = info2.primaryInfo.tables.find("test");
    ASSERT_NE(it1, info1.primaryInfo.tables.end());
    ASSERT_NE(it2, info2.primaryInfo.tables.end());
    EXPECT_EQ(it1->second.count, it2->second.count);
    EXPECT_EQ(info1.primaryInfo.userVersion, info2.primaryInfo.userVersion);
    EXPECT_EQ(info1.primaryInfo.dbInfo.size, info2.primaryInfo.dbInfo.size);
}

/**
 * @tc.name: PrimaryReplicaInfo_WalFileStat_001
 * @tc.desc: AC-1.1: Primary WAL file is stat'd successfully with errCode=E_OK (TC-03).
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, WalFileStat_001, TestSize.Level1)
{
    InsertRows(store_, 1, 5);
    auto [ret, info] = store_->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_OK);
    // After checkpoint, WAL may be truncated to 0 bytes, but errCode must be E_OK.
    EXPECT_EQ(info.primaryInfo.walInfo.errCode, E_OK);
    EXPECT_GE(info.primaryInfo.walInfo.size, 0);
    EXPECT_GE(info.primaryInfo.walInfo.mtime, 0);
}

/**
 * @tc.name: PrimaryReplicaInfo_CheckpointStatus_001
 * @tc.desc: AC-5.1: checkpointErr is E_OK on a MAIN_REPLICA writer with slave connection.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, CheckpointStatus_001, TestSize.Level1)
{
    InsertRows(store_, 1, 3);
    auto [ret, info] = store_->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(info.primaryInfo.checkpointErr, E_OK);
    // Replica checkpoint: slaveConnection_ exists in MAIN_REPLICA → executed successfully → E_OK
    EXPECT_EQ(info.replicaInfo.checkpointErr, E_OK);
}

/**
 * @tc.name: PrimaryReplicaInfo_BinlogErrCode_001
 * @tc.desc: AC-2.4: binlogInfo.errCode is E_OK when no binlog directory exists.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, BinlogErrCode_001, TestSize.Level1)
{
    auto [ret, info] = store_->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_OK);
    // No binlog directory: ENOENT is not an error.
    EXPECT_EQ(info.binlogInfo.errCode, E_OK);
    EXPECT_EQ(info.binlogInfo.exist, false);
}

/**
 * @tc.name: PrimaryReplicaInfo_ReplicaWalErrCode_001
 * @tc.desc: AC-1.1: Replica WAL errCode is E_OK when connection exists; replica DB stat from config.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, ReplicaWalErrCode_001, TestSize.Level1)
{
    InsertRows(store_, 1, 2);
    auto [ret, info] = store_->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_OK);
    // With a slave connection, replica WAL should be stat'd successfully
    EXPECT_EQ(info.replicaInfo.walInfo.errCode, E_OK);
    EXPECT_EQ(info.replicaInfo.dbInfo.errCode, E_OK);
}

/**
 * @tc.name: PrimaryReplicaInfo_TimeValidity_001
 * @tc.desc: AC-2.2: primaryLastModifyTime only uses valid (errCode==E_OK) times.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, TimeValidity_001, TestSize.Level1)
{
    InsertRows(store_, 1, 5);
    auto [ret, info] = store_->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_OK);
    // Both DB and WAL stats should succeed, so primaryLastModifyTime = max(db.mtime, wal.mtime)
    EXPECT_EQ(info.primaryInfo.dbInfo.errCode, E_OK);
    EXPECT_EQ(info.primaryInfo.walInfo.errCode, E_OK);
    EXPECT_EQ(info.primaryLastModifyTime,
        std::max(info.primaryInfo.dbInfo.mtime, info.primaryInfo.walInfo.mtime));
    EXPECT_GT(info.primaryLastModifyTime, 0);
}

/**
 * @tc.name: PrimaryReplicaInfo_ReplicaTimeFallback_001
 * @tc.desc: AC-2.3: replicaLastModifyTime falls back to file times when no binlog.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, ReplicaTimeFallback_001, TestSize.Level1)
{
    auto [ret, info] = store_->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_OK);
    // No binlog and scan succeeded: replicaLastModifyTime = max(valid db.mtime, valid wal.mtime)
    if (info.binlogInfo.errCode == E_OK && !info.binlogInfo.exist) {
        int64_t replicaDbMtime =
            (info.replicaInfo.dbInfo.errCode == E_OK) ? info.replicaInfo.dbInfo.mtime : 0;
        int64_t replicaWalMtime =
            (info.replicaInfo.walInfo.errCode == E_OK) ? info.replicaInfo.walInfo.mtime : 0;
        EXPECT_EQ(info.replicaLastModifyTime, std::max(replicaDbMtime, replicaWalMtime));
    }
}

/**
 * @tc.name: PrimaryReplicaInfo_DiagnosticHealthyReplica_001
 * @tc.desc: AC-1.3: A healthy replica remains available after diagnostic query and connection release.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, DiagnosticHealthyReplica_001, TestSize.Level1)
{
    InsertRows(store_, 1, 2);
    // Verify replica DB file exists before diagnostic call
    struct stat stBefore;
    ASSERT_EQ(stat(slaveDbName.c_str(), &stBefore), 0);
    auto [ret, info] = store_->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_OK);
    // Verify replica DB file still exists after diagnostic call + connection release
    struct stat stAfter;
    ASSERT_EQ(stat(slaveDbName.c_str(), &stAfter), 0);
    // Verify replica checkpoint was attempted for this MAIN_REPLICA store.
    EXPECT_NE(info.replicaInfo.checkpointErr, E_NOT_SUPPORT)
        << "Replica checkpoint should execute in MAIN_REPLICA mode";
}

/**
 * @tc.name: PrimaryReplicaInfo_SchemaTableQuoting_001
 * @tc.desc: AC-3.4: schema.table is properly quoted as "schema"."table" in COUNT.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, SchemaTableQuoting_001, TestSize.Level1)
{
    InsertRows(store_, 1, 3);
    // "main.test" splits and quotes as "main"."test" — same table in main schema.
    auto [ret, info] = store_->GetPrimaryReplicaInfo("main.test");
    EXPECT_EQ(ret, E_OK);
    auto it = info.primaryInfo.tables.find("main.test");
    ASSERT_NE(it, info.primaryInfo.tables.end());
    EXPECT_EQ(it->second.count, 3);
    EXPECT_EQ(it->second.errCode, E_OK);
}

/**
 * @tc.name: PrimaryReplicaInfo_ReplicaDbStatFromConfig_001
 * @tc.desc: AC-1.1: Replica DB is stat'd from config path even without a slave connection.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, ReplicaDbStatFromConfig_001, TestSize.Level1)
{
    InsertRows(store_, 1, 2);
    auto [ret, info] = store_->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_OK);
    // In MAIN_REPLICA mode, the slave DB file exists on disk
    EXPECT_EQ(info.replicaInfo.dbInfo.errCode, E_OK);
    EXPECT_GE(info.replicaInfo.dbInfo.size, 0);
}

/**
 * @tc.name: PrimaryReplicaInfo_NoSlaveConnection_001
 * @tc.desc: AC-4.2/4.4: A standalone connection without slaveConnection_ reports partial results —
 *           replica DB stat'd from config path (E_OK), WAL/replay/replica-checkpoint skipped (E_NOT_SUPPORT).
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, NoSlaveConnection_001, TestSize.Level1)
{
    InsertRows(store_, 1, 2);
    // Release the fixture pool so a standalone connection opens without lock conflict.
    store_ = nullptr;
    RdbHelper::ClearCache();

    RdbStoreConfig config(dbName);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    // Read connection (isWrite=false) skips slave creation in InnerCreate → slaveConnection_ is null.
    auto [createErr, conn] = SqliteConnection::Create(config, false);
    ASSERT_EQ(createErr, E_OK) << "Failed to create standalone read connection";
    ASSERT_NE(conn, nullptr);

    auto [ret, info] = conn->GetPrimaryAndReplicaInfo("");

    // Overall E_OK: partial results preserved, no fatal failure.
    EXPECT_EQ(ret, E_OK);

    // Replica DB stat'd from config path — file exists from the fixture pool.
    EXPECT_EQ(info.replicaInfo.dbInfo.errCode, E_OK);

    // WAL path, replay, and replica checkpoint require a slave handle → skipped.
    EXPECT_EQ(info.replicaInfo.walInfo.errCode, E_NOT_SUPPORT);
    EXPECT_EQ(info.replayErr, E_NOT_SUPPORT);
    EXPECT_EQ(info.replicaInfo.checkpointErr, E_NOT_SUPPORT);

    // Primary checkpoint skipped: a read connection is not a writer.
    EXPECT_EQ(info.primaryInfo.checkpointErr, E_NOT_SUPPORT);

    // Diagnostic did not create or remove the replica file.
    EXPECT_EQ(access(slaveDbName.c_str(), F_OK), 0);
}

/**
 * @tc.name: PrimaryReplicaInfo_TimeNotOverwrittenByCheckpoint_001
 * @tc.desc: AC-2.5: mtime collected before checkpoint is not overwritten by post-checkpoint stat.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, TimeNotOverwrittenByCheckpoint_001, TestSize.Level1)
{
    InsertRows(store_, 1, 10);
    // Stat the WAL file before the diagnostic call (pre-checkpoint mtime)
    std::string walPath = dbName + "-wal";
    struct stat stBefore;
    ASSERT_EQ(stat(walPath.c_str(), &stBefore), 0) << "WAL file should exist after inserts";

    auto [ret, info] = store_->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_OK);
    // AC-2.5: The returned WAL mtime must be from the initial collection (before checkpoint),
    // not overwritten by RefreshSizesAfterCheckpoint which only updates size.
    EXPECT_GT(info.primaryInfo.walInfo.mtime, 0);

    int64_t mtimeBeforeMs = static_cast<int64_t>(stBefore.st_mtim.tv_sec) * 1000 +
        stBefore.st_mtim.tv_nsec / 1000000;
    EXPECT_EQ(info.primaryInfo.walInfo.mtime, mtimeBeforeMs);

    EXPECT_EQ(info.primaryInfo.walInfo.sizeErr, E_OK);
    EXPECT_EQ(info.primaryInfo.dbInfo.sizeErr, E_OK);

    // Prove the checkpoint inside the diagnostic actually changed the WAL file time.
    // Without this, the collection-order assertion above could pass even if the
    // implementation collected after checkpoint (no observable difference).
    struct stat stAfter;
    if (stat(walPath.c_str(), &stAfter) != 0) {
        // WAL removed/truncated by checkpoint — file state provably changed.
        return;
    }
    int64_t mtimeAfterMs = static_cast<int64_t>(stAfter.st_mtim.tv_sec) * 1000 +
        stAfter.st_mtim.tv_nsec / 1000000;
    if (mtimeAfterMs == mtimeBeforeMs) {
        GTEST_SKIP() << "WAL mtime unchanged after checkpoint (fs precision or no-op); "
                        "collection-order assertion not independently verifiable";
    }
}

/**
 * @tc.name: PrimaryReplicaInfo_ConcurrentWrite_001
 * @tc.desc: AC-6.1: Concurrent writes during query do not crash or freeze; BUSY is a status not a global error.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, ConcurrentWrite_001, TestSize.Level1)
{
    InsertRows(store_, 1, 5);
    std::atomic<bool> stop{false};
    std::atomic<int> writeCount{0};

    std::mutex mtx;
    std::condition_variable cv;
    bool wroteOnce = false;

    // Writer thread: insert rows; notify after the first successful write so the main
    // thread can start sampling while writes are still in progress (no fixed sleep).
    std::thread writer([&]() {
        for (int i = 100; i < 200 && !stop.load(); i++) {
            ValuesBucket values;
            values.PutInt("id", i);
            values.PutString("name", "concurrent" + std::to_string(i));
            values.PutInt("age", 20 + i);
            int64_t rowId = 0;
            if (store_->Insert(rowId, "test", values) == E_OK) {
                if (writeCount.fetch_add(1) == 0) {
                    {
                        std::lock_guard<std::mutex> lk(mtx);
                        wroteOnce = true;
                    }
                    cv.notify_one();
                }
            }
        }
    });

    // RAII: stop and join the writer regardless of assertion outcomes.
    ScopeGuard joinGuard([&]() {
        stop.store(true);
        writer.join();
    });

    // Wait (bounded) until the writer has completed at least one successful write.
    {
        std::unique_lock<std::mutex> lk(mtx);
        cv.wait_for(lk, std::chrono::seconds(3), [&] { return wroteOnce; });
    }

    // Main thread: call diagnostic while writer is still active.
    auto [ret, info] = store_->GetPrimaryReplicaInfo("test");
    EXPECT_EQ(ret, E_OK);

    EXPECT_GT(writeCount.load(), 0) << "Writer thread should have successfully written rows";

    auto it = info.primaryInfo.tables.find("test");
    ASSERT_NE(it, info.primaryInfo.tables.end());
    EXPECT_GE(it->second.count, 5); // At least the initial 5 rows
    // checkpoint may be BUSY during concurrent writes.
    EXPECT_TRUE(info.primaryInfo.checkpointErr == E_OK ||
        info.primaryInfo.checkpointErr == E_NOT_SUPPORT ||
        info.primaryInfo.checkpointErr == E_SQLITE_BUSY)
        << "checkpointErr=" << info.primaryInfo.checkpointErr;
}

/**
 * @tc.name: PrimaryReplicaInfo_CustomReplicaPath_001
 * @tc.desc: AC-6.3: Custom replicaPath is used for replica DB stat, not the default adjacent path.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, CustomReplicaPath_001, TestSize.Level1)
{
    // AC-6.3: SetReplicaPath takes a directory; slave DB is created inside it
    std::string customDir = RDB_TEST_PATH + "custom_replica_dir";
    mkdir(customDir.c_str(), 0755); // IsValidReplicaPath requires an existing directory

    // Slave DB file name = ExtractFileName(dbName) with .db → _slave.db
    std::string baseName = dbName.substr(dbName.rfind('/') + 1);
    auto dotPos = baseName.rfind(".db");
    std::string slaveName = baseName.substr(0, dotPos) + "_slave.db";
    std::string expectedSlavePath = customDir + "/" + slaveName;

    RdbHelper::DeleteRdbStore(dbName);
    RdbHelper::DeleteRdbStore(expectedSlavePath);

    ScopeGuard cleanup([&]() {
        RdbHelper::ClearCache();
        RdbHelper::DeleteRdbStore(expectedSlavePath);
        RdbHelper::DeleteRdbStore(dbName);
        rmdir(customDir.c_str());
    });

    RdbStoreConfig config(dbName);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    config.SetReplicaPath(customDir);
    PrimaryReplicaInfoCallback helper;
    int errCode = E_OK;
    auto customStore = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    if (customStore == nullptr) {
        GTEST_SKIP() << "Cannot create MAIN_REPLICA store with custom replica path in this environment";
    }
    ASSERT_EQ(errCode, E_OK);

    InsertRows(customStore, 1, 3);
    auto [ret, info] = customStore->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_OK);
    // Replica DB should be stat'd from the custom directory path, not the default adjacent path
    EXPECT_EQ(info.replicaInfo.dbInfo.errCode, E_OK);
    EXPECT_GT(info.replicaInfo.dbInfo.size, 0);

    // Verify the slave DB file exists inside the custom directory
    struct stat st;
    EXPECT_EQ(stat(expectedSlavePath.c_str(), &st), 0);
}

/**
 * @tc.name: PrimaryReplicaInfo_ViewRejection_001
 * @tc.desc: AC-3.3: CountTable rejects views via type check — view errCode != E_OK.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, ViewRejection_001, TestSize.Level1)
{
    InsertRows(store_, 1, 3);
    // Create a view on the test table
    EXPECT_EQ(store_->ExecuteSql("CREATE VIEW IF NOT EXISTS test_view AS SELECT id FROM test"), E_OK);

    // "test_view" passes IsValidTableName but fails type check in CountTable.
    auto [ret, info] = store_->GetPrimaryReplicaInfo("test_view");
    EXPECT_EQ(ret, E_OK); // Overall call succeeds; error stored in table entry
    auto it = info.primaryInfo.tables.find("test_view");
    ASSERT_NE(it, info.primaryInfo.tables.end());
    EXPECT_NE(it->second.errCode, E_OK) << "View should be rejected by type check";

    // Verify regular table still counts correctly
    auto [ret2, info2] = store_->GetPrimaryReplicaInfo("test");
    EXPECT_EQ(ret2, E_OK);
    auto it2 = info2.primaryInfo.tables.find("test");
    ASSERT_NE(it2, info2.primaryInfo.tables.end());
    EXPECT_EQ(it2->second.errCode, E_OK);
    EXPECT_EQ(it2->second.count, 3);

    store_->ExecuteSql("DROP VIEW IF EXISTS test_view");
}

/**
 * @tc.name: PrimaryReplicaInfo_ReplayStatus_001
 * @tc.desc: AC-2.4: replayErr distinguishes skip (E_NOT_SUPPORT) from success/no-binlog (E_OK).
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, ReplayStatus_001, TestSize.Level1)
{
    InsertRows(store_, 1, 2);
    auto [ret, info] = store_->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_OK);
    RdbStoreConfig checkConfig(dbName);
    checkConfig.SetHaMode(HAMode::MAIN_REPLICA);
    int expectedReplayErr = SqliteUtils::IsSupportBinlog(checkConfig) ? E_OK : E_NOT_SUPPORT;
    EXPECT_EQ(info.replayErr, expectedReplayErr)
        << "replayErr=" << info.replayErr << " (should match IsSupportBinlog result)";
}

/**
 * @tc.name: PrimaryReplicaInfo_TimeErrValidity_001
 * @tc.desc: AC-2.2: primaryTimeErr and replicaTimeErr are E_OK when at least one source is valid.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, TimeErrValidity_001, TestSize.Level1)
{
    InsertRows(store_, 1, 5);
    auto [ret, info] = store_->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_OK);
    // Both DB and WAL stats succeed → primaryTimeErr = E_OK
    EXPECT_EQ(info.primaryInfo.dbInfo.errCode, E_OK);
    EXPECT_EQ(info.primaryInfo.walInfo.errCode, E_OK);
    EXPECT_EQ(info.primaryTimeErr, E_OK);
    EXPECT_GT(info.primaryLastModifyTime, 0);
    // Replica has at least one valid time source → replicaTimeErr = E_OK
    EXPECT_EQ(info.replicaTimeErr, E_OK);
}

/**
 * @tc.name: PrimaryReplicaInfo_SizeErrValidity_001
 * @tc.desc: AC-1.2: sizeErr is E_OK when post-checkpoint size refresh succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(PrimaryReplicaInfoTest, SizeErrValidity_001, TestSize.Level1)
{
    InsertRows(store_, 1, 3);
    auto [ret, info] = store_->GetPrimaryReplicaInfo("");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(info.primaryInfo.dbInfo.sizeErr, E_OK);
    EXPECT_EQ(info.primaryInfo.walInfo.sizeErr, E_OK);
    EXPECT_EQ(info.replicaInfo.dbInfo.sizeErr, E_OK);
    EXPECT_EQ(info.replicaInfo.walInfo.sizeErr, E_OK);
}

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

#include "connection.h"

#include <gtest/gtest.h>

#include <climits>
#include <string>

#include "common.h"
#include "grd_type_export.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "sqlite_connection.h"
#include "sqlite_global_config.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace Test {
class ConnectionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void){};
    void TearDown(void){};
    static const std::string rdbStorePath;
};

const std::string ConnectionTest::rdbStorePath = RDB_TEST_PATH + "connection_ut_test.db";

class ConnectionTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

int ConnectionTestOpenCallback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int ConnectionTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void ConnectionTest::SetUpTestCase(void)
{
}

void ConnectionTest::TearDownTestCase(void)
{
}

/**
 * @tc.name: Connection_Test_001
 * @tc.desc: Normal testCase of sqlite_utils for IsSpecial, if sqlType is special
 * @tc.type: FUNC
 */
HWTEST_F(ConnectionTest, Connection_Test_001, TestSize.Level1)
{
    SqliteGlobalConfig::InitSqliteGlobalConfig();
    RdbStoreConfig config(rdbStorePath);
    config.SetDBType(OHOS::NativeRdb::DBType::DB_BUTT);
    auto [errCode, connection] = Connection::Create(config, true);
    EXPECT_EQ(errCode, E_INVALID_ARGS);
    EXPECT_EQ(connection, nullptr);

    config.SetDBType(OHOS::NativeRdb::DBType::DB_SQLITE);
    auto [errCode1, connection1] = Connection::Create(config, true);
    EXPECT_EQ(errCode1, E_OK);
    EXPECT_NE(connection1, nullptr);
}

/**
 * @tc.name: Connection_Test_002
 * @tc.desc: Normal testCase of sqlite_utils for IsSpecial, if sqlType is special
 * @tc.type: FUNC
 */
HWTEST_F(ConnectionTest, Connection_Test_002, TestSize.Level1)
{
    RdbStoreConfig config(rdbStorePath);
    config.SetDBType(OHOS::NativeRdb::DBType::DB_BUTT);
    int ret = Connection::Repair(config);
    EXPECT_EQ(ret, E_INVALID_ARGS);

    config.SetDBType(OHOS::NativeRdb::DBType::DB_SQLITE);
    ret = Connection::Repair(config);
    EXPECT_EQ(ret, E_NOT_SUPPORT);
}

/**
 * @tc.name: SetEncryptAgo_Test_001
 * @tc.desc: The test case is to test whether the param is available.
 * @tc.type: FUNC
 */
HWTEST_F(ConnectionTest, SetEncryptAgo_Test_001, TestSize.Level2)
{
    int errCode;
    RdbStoreConfig config(rdbStorePath);
    auto conn = std::make_shared<SqliteConnection>(config, true);
    config.SetIter(-1);
    errCode = conn->SetEncryptAgo(config);
    EXPECT_EQ(errCode, E_INVALID_ARGS);
}

/**
 * @tc.name: ResetKey_Test_001
 * @tc.desc: The test case is to test whether ResetKey is a write connection.
 * @tc.type: FUNC
 */
HWTEST_F(ConnectionTest, ReSetKey_Test_001, TestSize.Level2)
{
    int errCode;
    RdbStoreConfig config(rdbStorePath);
    auto conn = std::make_shared<SqliteConnection>(config, false);
    errCode = conn->ResetKey(config);
    EXPECT_EQ(errCode, E_OK);
}

/**
 * @tc.name: SetEncrypt_Test_001
 * @tc.desc: The test case is to test whether SetEncrypt is a memory RDB.
 * @tc.type: FUNC
 */
HWTEST_F(ConnectionTest, SetEncrypt_Test_001, TestSize.Level2)
{
    int errCode;
    RdbStoreConfig config(rdbStorePath);
    auto conn = std::make_shared<SqliteConnection>(config, true);
    config.SetEncryptStatus(true);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    errCode = conn->SetEncrypt(config);
    EXPECT_EQ(errCode, E_NOT_SUPPORT);
}

/**
 * @tc.name: RegDefaultFunctions_Test_001
 * @tc.desc: The testCase of RegDefaultFunctions.
 * @tc.type: FUNC
 */
HWTEST_F(ConnectionTest, RegDefaultFunctions_Test_001, TestSize.Level2)
{
    int errCode;
    RdbStoreConfig config(rdbStorePath);
    auto conn = std::make_shared<SqliteConnection>(config, true);
    errCode = conn->RegDefaultFunctions(nullptr);
    EXPECT_EQ(errCode, SQLITE_OK);
}

/**
 * @tc.name: SetTokenizer_Test_001
 * @tc.desc: The testCase of SetTokenizer.
 * @tc.type: FUNC
 */
HWTEST_F(ConnectionTest, SetTokenizer_Test_001, TestSize.Level2)
{
    int errCode;
    RdbStoreConfig config(rdbStorePath);
    auto conn = std::make_shared<SqliteConnection>(config, true);
    config.SetTokenizer(TOKENIZER_END);
    errCode = conn->SetTokenizer(config);
    EXPECT_EQ(errCode, E_INVALID_ARGS);
}

/**
 * @tc.name: Backup_Test_001
 * @tc.desc: The testCase of Backup.
 * @tc.type: FUNC
 */
HWTEST_F(ConnectionTest, Backup_Test_001, TestSize.Level2)
{
    int errCode;
    RdbStoreConfig config(rdbStorePath);
    auto conn = std::make_shared<SqliteConnection>(config, true);
    std::shared_ptr<SlaveStatus> slaveStatus = std::make_shared<SlaveStatus>(SlaveStatus::BACKING_UP);
    errCode = conn->Backup("test", { 1, 2, 3 }, true, slaveStatus);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(*slaveStatus, BACKING_UP);
}

/**
 * @tc.name: ExchangeVerify_Test_001
 * @tc.desc: The testCase of ExchangeVerify.
 * @tc.type: FUNC
 */
HWTEST_F(ConnectionTest, ExchangeVerify_Test_001, TestSize.Level2)
{
    int errCode;
    RdbStoreConfig config(rdbStorePath);
    auto conn = std::make_shared<SqliteConnection>(config, true);
    errCode = conn->ExchangeVerify(false);
    EXPECT_EQ(errCode, E_ALREADY_CLOSED);
}

/**
 * @tc.name: VeritySlaveIntegrity_Test_001
 * @tc.desc: The testCase of VeritySlaveIntegrity.
 * @tc.type: FUNC
 */
HWTEST_F(ConnectionTest, VeritySlaveIntegrity_Test_001, TestSize.Level2)
{
    int errCode;
    RdbStoreConfig config(rdbStorePath);
    auto conn = std::make_shared<SqliteConnection>(config, true);
    errCode = conn->VeritySlaveIntegrity();
    EXPECT_EQ(errCode, E_ALREADY_CLOSED);
}

/**
 * @tc.name: IsDbVersionBelowSlave_Test_001
 * @tc.desc: The testCase of IsDbVersionBelowSlave.
 * @tc.type: FUNC
 */
HWTEST_F(ConnectionTest, IsDbVersionBelowSlave_Test_001, TestSize.Level2)
{
    RdbStoreConfig config(rdbStorePath);
    auto conn = std::make_shared<SqliteConnection>(config, true);
    bool res = conn->IsDbVersionBelowSlave();
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: CheckReplicaIntegrity_Test_001
 * @tc.desc: The testCase of CheckReplicaIntegrity.
 * @tc.type: FUNC
 */
HWTEST_F(ConnectionTest, CheckReplicaIntegrity_Test_001, TestSize.Level2)
{
    RdbStoreConfig config(rdbStorePath);
    config.SetDBType(OHOS::NativeRdb::DBType::DB_BUTT);
    EXPECT_EQ(Connection::CheckReplicaIntegrity(config), E_INVALID_ARGS);

    config.SetDBType(OHOS::NativeRdb::DBType::DB_VECTOR);
    EXPECT_EQ(Connection::CheckReplicaIntegrity(config), E_NOT_SUPPORT);
}

/**
 * @tc.name: CheckReplicaIntegrity_Test_002
 * @tc.desc: The testCase of CheckReplicaIntegrity.
 * @tc.type: FUNC
 */
HWTEST_F(ConnectionTest, CheckReplicaIntegrity_Test_002, TestSize.Level2)
{
    RdbHelper::DeleteRdbStore(rdbStorePath);
    RdbStoreConfig config(rdbStorePath);
    config.SetDBType(OHOS::NativeRdb::DBType::DB_SQLITE);
    config.SetHaMode(HAMode::SINGLE);
    EXPECT_EQ(Connection::CheckReplicaIntegrity(config), E_NOT_SUPPORT);
    RdbHelper::DeleteRdbStore(rdbStorePath);
}

static int32_t MockReplicaChecker(const RdbStoreConfig &config)
{
    return E_OK;
}

/**
 * @tc.name: RegisterReplicaChecker_Test_001
 * @tc.desc: The testCase of RegisterReplicaChecker.
 * @tc.type: FUNC
 */
HWTEST_F(ConnectionTest, RegisterReplicaChecker_Test_001, TestSize.Level2)
{
    EXPECT_EQ(Connection::RegisterReplicaChecker(OHOS::NativeRdb::DBType::DB_BUTT, nullptr), E_INVALID_ARGS);
    EXPECT_EQ(Connection::RegisterReplicaChecker(OHOS::NativeRdb::DBType::DB_VECTOR, MockReplicaChecker), E_OK);
    EXPECT_EQ(Connection::RegisterReplicaChecker(OHOS::NativeRdb::DBType::DB_VECTOR, MockReplicaChecker), E_OK);
    EXPECT_EQ(Connection::RegisterReplicaChecker(OHOS::NativeRdb::DBType::DB_SQLITE, MockReplicaChecker), E_OK);
    EXPECT_EQ(Connection::RegisterReplicaChecker(OHOS::NativeRdb::DBType::DB_SQLITE, MockReplicaChecker), E_OK);
}
} // namespace Test
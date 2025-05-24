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

#include "rdb_store_impl.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "common.h"
#include "connection_mock.h"
#include "dataobs_mgr_client_mock.h"
#include "delay_notify.h"
#include "grd_api_manager.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_manager_impl_mock.h"
#include "rdb_open_callback.h"
#include "rdb_service_mock.h"
#include "rdb_sql_statistic.h"
#include "rdb_store_config.h"
#include "rdb_types.h"
#include "statement_mock.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedRdb;
using namespace OHOS::AAFwk;
using CheckOnChangeFunc = std::function<void(RdbStoreObserver::ChangeInfo &changeInfo)>;
using ValueObjects = std::vector<ValueObject>;
class SubObserver : public RdbStoreObserver {
public:
    virtual ~SubObserver()
    {
    }
    void OnChange(const std::vector<std::string> &devices){};
    void OnChange(const Origin &origin, const PrimaryFields &fields, RdbStoreObserver::ChangeInfo &&changeInfo){};
    void OnChange(){};
    void RegisterCallback(const CheckOnChangeFunc &callback);
    uint32_t count = 0;

private:
    CheckOnChangeFunc checkOnChangeFunc_;
};
class RdbStoreImplConditionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static std::shared_ptr<SubObserver> observer_;
    static const std::string DATABASE_NAME;
    static const std::string DATABASE_BACKUP_NAME;
    static const std::string DEFAULT_DATABASE_NAME;
    static inline std::shared_ptr<MockRdbManagerImpl> mockRdbManagerImpl = nullptr;
    static inline std::shared_ptr<MockDataObsMgrClient> mockDataObsMgrClient = nullptr;
    static inline std::shared_ptr<MockStatement> mockStatement = nullptr;
    static inline std::shared_ptr<MockConnection> mockConnection = nullptr;

protected:
    std::shared_ptr<RdbStore> store_;
};

const std::string RdbStoreImplConditionTest::DATABASE_NAME = RDB_TEST_PATH + "rdb_store_impl_condition_test.db";
const std::string RdbStoreImplConditionTest::DATABASE_BACKUP_NAME =
    RDB_TEST_PATH + "rdb_store_impl_condition_test_backup.db";
const std::string RdbStoreImplConditionTest::DEFAULT_DATABASE_NAME = RDB_TEST_PATH + "default_condition_test.db";

std::shared_ptr<SubObserver> RdbStoreImplConditionTest::observer_ = nullptr;

class RdbStoreImplConditionTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

const std::string RdbStoreImplConditionTestOpenCallback::CREATE_TABLE_TEST =
    std::string("CREATE TABLE IF NOT EXISTS employee ") + std::string("(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                      "name TEXT NOT NULL, age INTEGER, salary "
                                                                      "REAL, blobType BLOB)");

int RdbStoreImplConditionTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int RdbStoreImplConditionTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbStoreImplConditionTest::SetUpTestCase(void)
{
    if (observer_ == nullptr) {
        observer_ = std::make_shared<SubObserver>();
    }
    mockRdbManagerImpl = std::make_shared<MockRdbManagerImpl>();
    BRdbManagerImpl::rdbManagerImpl = mockRdbManagerImpl;
    mockDataObsMgrClient = std::make_shared<MockDataObsMgrClient>();
    IDataObsMgrClient::dataObsMgrClient = mockDataObsMgrClient;
    mockStatement = std::make_shared<MockStatement>();
    mockConnection = std::make_shared<MockConnection>();
}

void RdbStoreImplConditionTest::TearDownTestCase(void)
{
    mockRdbManagerImpl = nullptr;
    BRdbManagerImpl::rdbManagerImpl = nullptr;
    mockDataObsMgrClient = nullptr;
    IDataObsMgrClient::dataObsMgrClient = nullptr;
    mockStatement = nullptr;
    mockConnection = nullptr;
}

void RdbStoreImplConditionTest::SetUp(void)
{
    int errCode;
    RdbStoreConfig config(RdbStoreImplConditionTest::DEFAULT_DATABASE_NAME);
    RdbStoreImplConditionTestOpenCallback helper;
    store_ = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    EXPECT_NE(store_, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void RdbStoreImplConditionTest::TearDown(void)
{
    store_ = nullptr;
    RdbHelper::ClearCache();
    int errCode = RdbHelper::DeleteRdbStore(DEFAULT_DATABASE_NAME);
    EXPECT_EQ(E_OK, errCode);
    errCode = RdbHelper::DeleteRdbStore(DATABASE_NAME);
    EXPECT_EQ(E_OK, errCode);
}

/* *
 * @tc.name: Rdb_RemoteQueryTest_003
 * @tc.desc: Abnormal testCase for RemoteQuery
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, Rdb_RemoteQueryTest_003, TestSize.Level2)
{
    int errCode = E_OK;
    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", 1);

    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetName("RdbStore_impl_test.db");
    config.SetBundleName("com.example.distributed.rdb");
    config.SetDBType(DB_SQLITE);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    RdbStoreImplConditionTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    EXPECT_EQ(E_OK, errCode);

    // GetRdbService succeeded if configuration file has already been configured
    auto ret = store->RemoteQuery("", predicates, {}, errCode);
    ASSERT_EQ(nullptr, ret);

    store = nullptr;
    RdbHelper::DeleteRdbStore(RdbStoreImplConditionTest::DATABASE_NAME);
}

/* *
 * @tc.name: Rdb_RemoteQueryTest_005
 * @tc.desc: Abnormal testCase for RemoteQuery
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, Rdb_RemoteQueryTest_005, TestSize.Level2)
{
    auto mockRdbService = std::make_shared<MockRdbService>();
    EXPECT_CALL(*mockRdbManagerImpl, GetRdbService(_))
        .WillRepeatedly(Return(std::make_pair(E_NOT_SUPPORT, mockRdbService)));
    int errCode = E_OK;
    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", 1);

    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetName("RdbStore_impl_test.db");
    config.SetBundleName("com.example.distributed.rdb");
    config.SetDBType(DB_SQLITE);
    config.SetStorageMode(StorageMode::MODE_DISK);
    RdbStoreImplConditionTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(nullptr, store);
    EXPECT_EQ(E_OK, errCode);
    // GetRdbService succeeded if configuration file has already been configured
    auto ret = store->RemoteQuery("", predicates, {}, errCode);
    ASSERT_EQ(nullptr, ret);

    store = nullptr;
    RdbHelper::DeleteRdbStore(RdbStoreImplConditionTest::DATABASE_NAME);
}

/* *
 * @tc.name: NotifyDataChangeTest_005
 * @tc.desc: Abnormal testCase for NotifyDataChange
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, NotifyDataChangeTest_005, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetDBType(DB_SQLITE);
    config.SetRegisterInfo(RegisterType::CLIENT_OBSERVER, true);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    storeImpl->NotifyDataChange();
    EXPECT_EQ(storeImpl->config_.GetRegisterInfo(RegisterType::CLIENT_OBSERVER), true);
}

/* *
 * @tc.name: NotifyDataChangeTest_006
 * @tc.desc: Abnormal testCase for NotifyDataChange
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, NotifyDataChangeTest_006, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(true);
    config.SetDBType(DB_SQLITE);
    config.SetRegisterInfo(RegisterType::CLIENT_OBSERVER, true);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    storeImpl->NotifyDataChange();
    EXPECT_EQ(storeImpl->config_.GetRegisterInfo(RegisterType::CLIENT_OBSERVER), true);
}

/* *
 * @tc.name: NotifyDataChangeTest_007
 * @tc.desc: Abnormal testCase for NotifyDataChange
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, NotifyDataChangeTest_007, TestSize.Level2)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(true);
    config.SetDBType(DB_VECTOR);
    config.SetRegisterInfo(RegisterType::CLIENT_OBSERVER, true);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    storeImpl->NotifyDataChange();
    EXPECT_EQ(storeImpl->config_.GetRegisterInfo(RegisterType::CLIENT_OBSERVER), true);
}

/* *
 * @tc.name: NotifyDataChangeTest_009
 * @tc.desc: Abnormal testCase for NotifyDataChange
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, NotifyDataChangeTest_009, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(true);
    config.SetDBType(DB_SQLITE);
    config.SetRegisterInfo(RegisterType::OBSERVER_END, true);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    storeImpl->NotifyDataChange();
    EXPECT_EQ(storeImpl->config_.GetRegisterInfo(RegisterType::CLIENT_OBSERVER), true);
}

/* *
 * @tc.name: ObtainDistributedTableNameTest_003
 * @tc.desc: Abnormal testCase for ObtainDistributedTableName
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, ObtainDistributedTableNameTest_003, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetDBType(DB_SQLITE);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    RdbStoreImplConditionTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    auto tableName = store->ObtainDistributedTableName("123", "test", errCode);
    EXPECT_EQ(tableName, "");
}

/* *
 * @tc.name: GetUriTest_001
 * @tc.desc: Abnormal testCase for GetUri
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, GetUriTest_001, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetDataGroupId("123");
    auto storeImlp = std::make_shared<RdbStoreImpl>(config);
    auto uri = storeImlp->GetUri("test");
    EXPECT_EQ(uri.ToString(), "rdb://123//data/test/rdb_store_impl_condition_test.db/test");
}

/* *
 * @tc.name: Rdb_QuerySharingResourceTest_004
 * @tc.desc: QuerySharingResource testCase
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, Rdb_QuerySharingResourceTest_004, TestSize.Level2)
{
    auto mockRdbService = std::make_shared<MockRdbService>();
    EXPECT_CALL(*mockRdbManagerImpl, GetRdbService(_)).WillRepeatedly(Return(std::make_pair(E_OK, mockRdbService)));
    EXPECT_CALL(*mockRdbService, QuerySharingResource(_, _, _)).WillOnce(Return(std::make_pair(E_ERROR, nullptr)));
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetName("RdbStore_impl_test.db");
    config.SetBundleName("com.example.distributed.rdb");
    RdbStoreImplConditionTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", 1);

    auto ret = store->QuerySharingResource(predicates, {});
    EXPECT_EQ(E_ERROR, ret.first);
    EXPECT_EQ(nullptr, ret.second);
}

/* *
 * @tc.name: Rdb_QuerySharingResourceTest_005
 * @tc.desc: QuerySharingResource testCase
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, Rdb_QuerySharingResourceTest_005, TestSize.Level2)
{
    auto mockRdbService = std::make_shared<MockRdbService>();
    EXPECT_CALL(*mockRdbManagerImpl, GetRdbService(_)).WillRepeatedly(Return(std::make_pair(E_OK, mockRdbService)));
    EXPECT_CALL(*mockRdbService, QuerySharingResource(_, _, _)).WillOnce(Return(std::make_pair(E_OK, nullptr)));
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetName("RdbStore_impl_test.db");
    config.SetBundleName("com.example.distributed.rdb");
    RdbStoreImplConditionTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", 1);

    auto ret = store->QuerySharingResource(predicates, {});
    EXPECT_EQ(E_OK, ret.first);
    EXPECT_EQ(nullptr, ret.second);
}

/* *
 * @tc.name: CleanDirtyDataTest_002
 * @tc.desc: Abnormal testCase for CleanDirtyData
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, Abnormal_CleanDirtyDataTest_002, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetDBType(DB_SQLITE);
    config.SetStorageMode(StorageMode::MODE_DISK);
    RdbStoreImplConditionTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(nullptr, store);
    EXPECT_EQ(E_OK, errCode);
    std::string table = "";
    uint64_t cursor = UINT64_MAX;
    errCode = store->CleanDirtyData(table, cursor);
    EXPECT_EQ(E_INVALID_ARGS, errCode);
}

/* *
 * @tc.name: CleanDirtyDataTest_003
 * @tc.desc: Abnormal testCase for CleanDirtyData
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, Abnormal_CleanDirtyDataTest_003, TestSize.Level2)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(true);
    config.SetDBType(DB_VECTOR);
    config.SetStorageMode(StorageMode::MODE_DISK);
    RdbStoreImplConditionTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(nullptr, store);
    EXPECT_EQ(E_OK, errCode);
    std::string table = "";
    uint64_t cursor = UINT64_MAX;
    errCode = store->CleanDirtyData(table, cursor);
    EXPECT_EQ(E_NOT_SUPPORT, errCode);
}

/* *
 * @tc.name: CleanDirtyDataTest_006
 * @tc.desc: Abnormal testCase for CleanDirtyData
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, Abnormal_CleanDirtyDataTest_006, TestSize.Level2)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetDBType(DB_VECTOR);
    config.SetStorageMode(StorageMode::MODE_DISK);
    RdbStoreImplConditionTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(nullptr, store);
    EXPECT_EQ(E_OK, errCode);
    std::string table = "";
    uint64_t cursor = UINT64_MAX;
    errCode = store->CleanDirtyData(table, cursor);
    EXPECT_EQ(E_NOT_SUPPORT, errCode);
}

/* *
 * @tc.name: CleanDirtyDataTest_007
 * @tc.desc: Abnormal testCase for CleanDirtyData
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, Abnormal_CleanDirtyDataTest_007, TestSize.Level2)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(true);
    config.SetDBType(DB_VECTOR);
    config.SetStorageMode(StorageMode::MODE_DISK);
    RdbStoreImplConditionTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(nullptr, store);
    EXPECT_EQ(E_OK, errCode);
    std::string table = "";
    uint64_t cursor = UINT64_MAX;
    errCode = store->CleanDirtyData(table, cursor);
    EXPECT_EQ(E_NOT_SUPPORT, errCode);
}

/* *
 * @tc.name: CleanDirtyDataTest_009
 * @tc.desc: Abnormal testCase for CleanDirtyData
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, Abnormal_CleanDirtyDataTest_009, TestSize.Level2)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetDBType(DB_VECTOR);
    config.SetStorageMode(StorageMode::MODE_DISK);
    RdbStoreImplConditionTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(nullptr, store);
    EXPECT_EQ(E_OK, errCode);
    std::string table = "";
    uint64_t cursor = UINT64_MAX;
    errCode = store->CleanDirtyData(table, cursor);
    EXPECT_EQ(E_NOT_SUPPORT, errCode);
}

/* *
 * @tc.name: CleanDirtyDataTest_010
 * @tc.desc: Abnormal testCase for CleanDirtyData
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, Abnormal_CleanDirtyDataTest_010, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetDBType(DB_SQLITE);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    RdbStoreImplConditionTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(nullptr, store);
    EXPECT_EQ(E_OK, errCode);
    std::string table = "";
    uint64_t cursor = UINT64_MAX;
    errCode = store->CleanDirtyData(table, cursor);
    EXPECT_EQ(E_NOT_SUPPORT, errCode);
}

/**
 * @tc.name: RdbStoreSubscribeRemote_001
 * @tc.desc: RdbStoreSubscribe
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, RdbStoreSubscribeRemote_001, TestSize.Level2)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetDBType(DB_VECTOR);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    ASSERT_NE(observer_, nullptr) << "observer is null";
    auto status = store->Subscribe({ SubscribeMode::REMOTE, "observer" }, observer_);
    EXPECT_EQ(status, E_NOT_SUPPORT);
    status = store->UnSubscribe({ SubscribeMode::REMOTE, "observer" }, observer_);
    EXPECT_EQ(status, E_NOT_SUPPORT);
}

/**
 * @tc.name: RdbStoreSubscribeRemote_002
 * @tc.desc: RdbStoreSubscribe
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, RdbStoreSubscribeRemote_002, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetDBType(DB_SQLITE);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    ASSERT_NE(observer_, nullptr) << "observer is null";
    auto status = store->Subscribe({ SubscribeMode::REMOTE, "observer" }, observer_);
    EXPECT_EQ(status, E_NOT_SUPPORT);
    status = store->UnSubscribe({ SubscribeMode::REMOTE, "observer" }, observer_);
    EXPECT_EQ(status, E_NOT_SUPPORT);
}

/**
 * @tc.name: SetKnowledgeSchema
 * @tc.desc: RdbStoreSubscribe
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, SetKnowledgeSchema, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetKnowledgeProcessing(true);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    EXPECT_EQ(storeImpl->config_, config);
    storeImpl->Close();
}

/**
 * @tc.name: SetDistributedTables_Test_001
 * @tc.desc: Abnormal testCase of SetDistributedTables
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, SetDistributedTables_Test_001, TestSize.Level2)
{
    auto mockRdbService = std::make_shared<MockRdbService>();
    EXPECT_CALL(*mockRdbManagerImpl, GetRdbService(_)).WillRepeatedly(Return(std::make_pair(E_OK, mockRdbService)));
    EXPECT_CALL(*mockRdbService, SetDistributedTables(_, _, _, _, _)).WillOnce(Return(E_OK));
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_SQLITE);
    config.SetRegisterInfo(RegisterType::STORE_OBSERVER, true);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    std::vector<std::string> tables;
    OHOS::DistributedRdb::DistributedConfig distributedConfig;

    tables.push_back("employee");
    errCode = store->SetDistributedTables(tables, DISTRIBUTED_DEVICE, distributedConfig);
    EXPECT_EQ(E_OK, errCode);
}

/**
 * @tc.name: RdbStore_Distributed_Test_002
 * @tc.desc: Abnormal testCase of SetDistributedTables
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, SetDistributedTables_Test_002, TestSize.Level2)
{
    auto mockRdbService = std::make_shared<MockRdbService>();
    EXPECT_CALL(*mockRdbManagerImpl, GetRdbService(_)).WillRepeatedly(Return(std::make_pair(E_OK, mockRdbService)));
    EXPECT_CALL(*mockRdbService, SetDistributedTables(_, _, _, _, _)).WillOnce(Return(E_OK));
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_SQLITE);
    config.SetRegisterInfo(RegisterType::CLIENT_OBSERVER, true);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    std::vector<std::string> tables;
    OHOS::DistributedRdb::DistributedConfig distributedConfig;

    tables.push_back("employee");
    errCode = store->SetDistributedTables(tables, DISTRIBUTED_DEVICE, distributedConfig);
    EXPECT_EQ(E_OK, errCode);
}

/**
 * @tc.name: SetDistributedTables_Test_003
 * @tc.desc: Abnormal testCase of SetDistributedTables
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, SetDistributedTables_Test_003, TestSize.Level2)
{
    auto mockRdbService = std::make_shared<MockRdbService>();
    EXPECT_CALL(*mockRdbManagerImpl, GetRdbService(_)).WillRepeatedly(Return(std::make_pair(E_OK, mockRdbService)));
    EXPECT_CALL(*mockRdbService, SetDistributedTables(_, _, _, _, _)).WillOnce(Return(E_OK));
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_SQLITE);
    config.SetRegisterInfo(RegisterType::CLIENT_OBSERVER, true);
    config.SetAllowRebuild(true);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    std::vector<std::string> tables;
    OHOS::DistributedRdb::DistributedConfig distributedConfig;
    distributedConfig.enableCloud = true;
    distributedConfig.autoSync = true;
    tables.push_back("employee");
    errCode = store->SetDistributedTables(tables, DISTRIBUTED_CLOUD, distributedConfig);
    EXPECT_EQ(E_OK, errCode);
}

/**
 * @tc.name: SetDistributedTables_Test_004
 * @tc.desc: Abnormal testCase of SetDistributedTables
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, SetDistributedTables_Test_004, TestSize.Level2)
{
    auto mockRdbService = std::make_shared<MockRdbService>();
    EXPECT_CALL(*mockRdbManagerImpl, GetRdbService(_)).WillRepeatedly(Return(std::make_pair(E_OK, mockRdbService)));
    EXPECT_CALL(*mockRdbService, SetDistributedTables(_, _, _, _, _)).WillOnce(Return(E_OK));
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_SQLITE);
    config.SetRegisterInfo(RegisterType::CLIENT_OBSERVER, true);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    std::vector<std::string> tables;
    OHOS::DistributedRdb::DistributedConfig distributedConfig;
    distributedConfig.enableCloud = true;
    distributedConfig.autoSync = true;
    tables.push_back("employee");
    errCode = store->SetDistributedTables(tables, DISTRIBUTED_CLOUD, distributedConfig);
    EXPECT_EQ(E_OK, errCode);
}

/**
 * @tc.name: SetDistributedTables_Test_005
 * @tc.desc: Abnormal testCase of SetDistributedTables
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, SetDistributedTables_Test_005, TestSize.Level2)
{
    auto mockRdbService = std::make_shared<MockRdbService>();
    EXPECT_CALL(*mockRdbManagerImpl, GetRdbService(_)).WillRepeatedly(Return(std::make_pair(E_OK, mockRdbService)));
    EXPECT_CALL(*mockRdbService, SetDistributedTables(_, _, _, _, _)).WillOnce(Return(E_OK));
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_SQLITE);
    config.SetRegisterInfo(RegisterType::STORE_OBSERVER, true);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    std::vector<std::string> tables;
    OHOS::DistributedRdb::DistributedConfig distributedConfig;
    distributedConfig.enableCloud = true;
    distributedConfig.autoSync = false;
    tables.push_back("employee");
    errCode = store->SetDistributedTables(tables, DISTRIBUTED_CLOUD, distributedConfig);
    EXPECT_EQ(E_OK, errCode);
}

/**
 * @tc.name: SetDistributedTables_Test_006
 * @tc.desc: Abnormal testCase of SetDistributedTables
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, SetDistributedTables_Test_006, TestSize.Level2)
{
    auto mockRdbService = std::make_shared<MockRdbService>();
    EXPECT_CALL(*mockRdbManagerImpl, GetRdbService(_)).WillRepeatedly(Return(std::make_pair(E_OK, mockRdbService)));
    EXPECT_CALL(*mockRdbService, SetDistributedTables(_, _, _, _, _)).WillOnce(Return(E_OK));
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_SQLITE);
    config.SetRegisterInfo(RegisterType::STORE_OBSERVER, true);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    std::vector<std::string> tables;
    OHOS::DistributedRdb::DistributedConfig distributedConfig;
    distributedConfig.enableCloud = false;
    distributedConfig.autoSync = false;
    tables.push_back("employee");
    errCode = store->SetDistributedTables(tables, DISTRIBUTED_CLOUD, distributedConfig);
    EXPECT_EQ(E_OK, errCode);
}

/**
 * @tc.name: SetDistributedTables_Test_007
 * @tc.desc: Abnormal testCase of SetDistributedTables
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, SetDistributedTables_Test_007, TestSize.Level2)
{
    auto mockRdbService = std::make_shared<MockRdbService>();
    EXPECT_CALL(*mockRdbManagerImpl, GetRdbService(_)).WillRepeatedly(Return(std::make_pair(E_OK, mockRdbService)));
    EXPECT_CALL(*mockRdbService, SetDistributedTables(_, _, _, _, _)).WillOnce(Return(E_OK));
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_SQLITE);
    config.SetRegisterInfo(RegisterType::STORE_OBSERVER, true);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    std::vector<std::string> tables;
    OHOS::DistributedRdb::DistributedConfig distributedConfig;
    distributedConfig.enableCloud = false;
    distributedConfig.autoSync = true;
    tables.push_back("employee");
    errCode = store->SetDistributedTables(tables, DISTRIBUTED_CLOUD, distributedConfig);
    EXPECT_EQ(E_OK, errCode);
}

/**
 * @tc.name: Notify_Test_001
 * @tc.desc: Abnormal testCase of Notify
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, Notify_Test_001, TestSize.Level2)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_VECTOR);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    std::string event = "test";
    auto res = store->Notify(event);
    EXPECT_EQ(E_NOT_SUPPORT, res);
}

/**
 * @tc.name: Notify_Test_002
 * @tc.desc: Abnormal testCase of Notify
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, Notify_Test_002, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    config.SetDBType(DB_SQLITE);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    std::string event = "test";
    auto res = store->Notify(event);
    EXPECT_EQ(E_OK, res);
}

/**
 * @tc.name: Notify_Test_003
 * @tc.desc: Abnormal testCase of Notify
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, Notify_Test_003, TestSize.Level2)
{
    EXPECT_CALL(*mockDataObsMgrClient, GetInstance()).WillOnce(Return(nullptr));
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_SQLITE);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    std::string event = "test";
    auto res = store->Notify(event);
    EXPECT_EQ(E_GET_DATAOBSMGRCLIENT_FAIL, res);
}

/**
 * @tc.name: Notify_Test_004
 * @tc.desc: Abnormal testCase of Notify
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, Notify_Test_004, TestSize.Level2)
{
    //mock client->NotifyChange(GetUri(event))
    auto dataObsMgrClient = std::make_shared<DataObsMgrClient>();
    EXPECT_CALL(*mockDataObsMgrClient, GetInstance()).WillOnce(Return(dataObsMgrClient));
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_SQLITE);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    std::string event = "test";
    auto res = store->Notify(event);
    EXPECT_EQ(E_OK, res);
}

/**
 * @tc.name: SetSearchable_Test_001
 * @tc.desc: Abnormal testCase of SetSearchable
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, SetSearchable_Test_001, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    config.SetDBType(DB_SQLITE);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    auto res = store->SetSearchable(true);
    EXPECT_EQ(E_NOT_SUPPORT, res);
}

/**
 * @tc.name: SetSearchable_Test_002
 * @tc.desc: Abnormal testCase of SetSearchable
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, SetSearchable_Test_002, TestSize.Level2)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_VECTOR);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    auto res = store->SetSearchable(true);
    EXPECT_EQ(E_NOT_SUPPORT, res);
}

/**
 * @tc.name: RegisterAutoSyncCallback_Test_001
 * @tc.desc: Abnormal testCase of RegisterAutoSyncCallback
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, RegisterAutoSyncCallback_Test_001, TestSize.Level2)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_VECTOR);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    std::shared_ptr<DetailProgressObserver> observer;
    auto res = store->RegisterAutoSyncCallback(observer);
    EXPECT_EQ(E_NOT_SUPPORT, res);
}

/**
 * @tc.name: RegisterAutoSyncCallback_Test_002
 * @tc.desc: Abnormal testCase of RegisterAutoSyncCallback
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, RegisterAutoSyncCallback_Test_002, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    config.SetDBType(DB_SQLITE);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    std::shared_ptr<DetailProgressObserver> observer;
    auto res = store->RegisterAutoSyncCallback(observer);
    EXPECT_EQ(E_NOT_SUPPORT, res);
}

/**
 * @tc.name: RegisterAutoSyncCallback_Test_003
 * @tc.desc: Abnormal testCase of RegisterAutoSyncCallback
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, RegisterAutoSyncCallback_Test_003, TestSize.Level2)
{
    EXPECT_CALL(*mockRdbManagerImpl, GetRdbService(_)).WillRepeatedly(Return(std::make_pair(E_ERROR, nullptr)));
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_SQLITE);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    std::shared_ptr<DetailProgressObserver> observer;
    auto res = store->RegisterAutoSyncCallback(observer);
    EXPECT_EQ(E_ERROR, res);
}

/**
 * @tc.name: UnregisterAutoSyncCallback_Test_001
 * @tc.desc: Abnormal testCase of UnregisterAutoSyncCallback
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, UnregisterAutoSyncCallback_Test_001, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    config.SetDBType(DB_SQLITE);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    std::shared_ptr<DetailProgressObserver> observer;
    auto res = store->UnregisterAutoSyncCallback(observer);
    EXPECT_EQ(E_NOT_SUPPORT, res);
}

/**
 * @tc.name: UnregisterAutoSyncCallback_Test_002
 * @tc.desc: Abnormal testCase of UnregisterAutoSyncCallback
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, UnregisterAutoSyncCallback_Test_002, TestSize.Level2)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_VECTOR);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    std::shared_ptr<DetailProgressObserver> observer;
    auto res = store->UnregisterAutoSyncCallback(observer);
    EXPECT_EQ(E_NOT_SUPPORT, res);
}

/**
 * @tc.name: UnregisterAutoSyncCallback_Test_003
 * @tc.desc: Abnormal testCase of UnregisterAutoSyncCallback
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, UnregisterAutoSyncCallback_Test_003, TestSize.Level2)
{
    EXPECT_CALL(*mockRdbManagerImpl, GetRdbService(_)).WillRepeatedly(Return(std::make_pair(E_ERROR, nullptr)));
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_SQLITE);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    std::shared_ptr<DetailProgressObserver> observer;
    auto res = store->UnregisterAutoSyncCallback(observer);
    EXPECT_EQ(E_ERROR, res);
}

/**
 * @tc.name: RegisterDataChangeCallback_Test_001
 * @tc.desc: Abnormal testCase of RegisterDataChangeCallback
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, RegisterDataChangeCallback_Test_001, TestSize.Level2)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    int errCode;
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_VECTOR);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config, errCode);
    storeImpl->connectionPool_ = nullptr;
    auto res = storeImpl->RegisterDataChangeCallback();
    EXPECT_EQ(E_ALREADY_CLOSED, res);
}

/**
 * @tc.name: ModifyLockStatus_Test_001
 * @tc.desc: Abnormal testCase of ModifyLockStatus
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, ModifyLockStatusk_Test_001, TestSize.Level2)
{
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    store = nullptr;
    store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_SQLITE);
    config.SetReadOnly(true);
    AbsRdbPredicates predicates("");
    auto res = store->ModifyLockStatus(predicates, false);
    EXPECT_EQ(E_EMPTY_TABLE_NAME, res);
}

/**
 * @tc.name: ModifyLockStatus_Test_002
 * @tc.desc: Abnormal testCase of ModifyLockStatus
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, ModifyLockStatusk_Test_002, TestSize.Level2)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_VECTOR);
    config.SetReadOnly(true);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    AbsRdbPredicates predicates("");
    auto res = store->ModifyLockStatus(predicates, false);
    EXPECT_EQ(E_NOT_SUPPORT, res);
}

/**
 * @tc.name: ModifyLockStatus_Test_003
 * @tc.desc: Abnormal testCase of ModifyLockStatus
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, ModifyLockStatusk_Test_003, TestSize.Level2)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_VECTOR);
    config.SetReadOnly(false);
    config.SetIsVector(true);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    AbsRdbPredicates predicates("");
    auto res = store->ModifyLockStatus(predicates, false);
    EXPECT_EQ(E_NOT_SUPPORT, res);
}

/**
 * @tc.name: ModifyLockStatus_Test_004
 * @tc.desc: Abnormal testCase of ModifyLockStatus
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, ModifyLockStatusk_Test_004, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    config.SetDBType(DB_SQLITE);
    config.SetReadOnly(false);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    AbsRdbPredicates predicates("");
    auto res = store->ModifyLockStatus(predicates, false);
    EXPECT_EQ(E_NOT_SUPPORT, res);
}

/**
 * @tc.name: ModifyLockStatus_Test_005
 * @tc.desc: Abnormal testCase of ModifyLockStatus
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, ModifyLockStatusk_Test_005, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_SQLITE);
    config.SetReadOnly(false);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    AbsRdbPredicates predicates("");
    auto res = store->ModifyLockStatus(predicates, false);
    EXPECT_EQ(E_EMPTY_TABLE_NAME, res);
}

/**
 * @tc.name: ModifyLockStatus_Test_006
 * @tc.desc: Abnormal testCase of ModifyLockStatus
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, ModifyLockStatusk_Test_006, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_SQLITE);
    config.SetReadOnly(false);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    AbsRdbPredicates predicates("test");
    auto res = store->ModifyLockStatus(predicates, false);
    EXPECT_EQ(E_NO_ROW_IN_QUERY, res);
}

/**
 * @tc.name: ModifyLockStatus_Test_007
 * @tc.desc: Abnormal testCase of ModifyLockStatus
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, ModifyLockStatusk_Test_007, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_SQLITE);
    config.SetReadOnly(false);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    AbsRdbPredicates predicates("test");
    auto res = store->ModifyLockStatus(predicates, false);
    EXPECT_EQ(E_NO_ROW_IN_QUERY, res);
}

/**
 * @tc.name: LockCloudContainer_Test_001
 * @tc.desc: Abnormal testCase of LockCloudContainer
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, LockCloudContainer_Test_001, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    config.SetDBType(DB_SQLITE);
    config.SetReadOnly(false);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    auto res1 = store->LockCloudContainer();
    EXPECT_EQ(E_NOT_SUPPORT, res1.first);
    auto res2 = store->UnlockCloudContainer();
    EXPECT_EQ(E_NOT_SUPPORT, res2);
}

/**
 * @tc.name: LockCloudContainer_Test_002
 * @tc.desc: Abnormal testCase of LockCloudContainer
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, LockCloudContainer_Test_002, TestSize.Level2)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_VECTOR);
    config.SetReadOnly(false);
    config.SetIsVector(true);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    auto res1 = store->LockCloudContainer();
    EXPECT_EQ(E_NOT_SUPPORT, res1.first);
    auto res2 = store->UnlockCloudContainer();
    EXPECT_EQ(E_NOT_SUPPORT, res2);
}

/**
 * @tc.name: LockCloudContainer_Test_003
 * @tc.desc: Abnormal testCase of LockCloudContainer
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, LockCloudContainer_Test_003, TestSize.Level2)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_VECTOR);
    config.SetReadOnly(true);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    auto res1 = store->LockCloudContainer();
    EXPECT_EQ(E_NOT_SUPPORT, res1.first);
    auto res2 = store->UnlockCloudContainer();
    EXPECT_EQ(E_NOT_SUPPORT, res2);
}

/**
 * @tc.name: LockCloudContainer_Test_004
 * @tc.desc: Abnormal testCase of LockCloudContainer
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, LockCloudContainer_Test_004, TestSize.Level2)
{
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    store = nullptr;
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_SQLITE);
    config.SetReadOnly(true);
    store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    auto res1 = store->LockCloudContainer();
    EXPECT_EQ(E_NOT_SUPPORT, res1.first);
    auto res2 = store->UnlockCloudContainer();
    EXPECT_EQ(E_NOT_SUPPORT, res2);
}

/**
 * @tc.name: LockCloudContainer_Test_005
 * @tc.desc: Abnormal testCase of LockCloudContainer
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, LockCloudContainer_Test_005, TestSize.Level2)
{
    EXPECT_CALL(*mockRdbManagerImpl, GetRdbService(_)).WillRepeatedly(Return(std::make_pair(E_NOT_SUPPORT, nullptr)));
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_SQLITE);
    config.SetReadOnly(false);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    auto res1 = store->LockCloudContainer();
    EXPECT_EQ(E_NOT_SUPPORT, res1.first);
    auto res2 = store->UnlockCloudContainer();
    EXPECT_EQ(E_NOT_SUPPORT, res2);
}

/**
 * @tc.name: Vector_Test_001
 * @tc.desc: Abnormal testCase of VectorDB
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, Vector_Test_001, TestSize.Level2)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetDBType(DB_VECTOR);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    const std::string sql;
    const ValueObjects bindArgs;
    auto res1 = store->QuerySql(sql, bindArgs);
    ASSERT_EQ(nullptr, res1);
    const AbsRdbPredicates predicates("test");
    int64_t outValue;
    std::string valueString;
    auto res2 = store->Count(outValue, predicates);
    EXPECT_EQ(E_NOT_SUPPORT, res2);
    auto res3 = store->ExecuteAndGetString(valueString, sql, bindArgs);
    EXPECT_EQ(E_NOT_SUPPORT, res3);
}

/**
 * @tc.name: ExecuteForChangedRowCount_Test_001
 * @tc.desc: Abnormal testCase of ExecuteForChangedRowCount
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, ExecuteForChangedRowCount_Test_001, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    store = nullptr;
    config.SetDBType(DB_SQLITE);
    config.SetReadOnly(true);
    store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    int64_t outValue;
    const std::string sql;
    const ValueObjects bindArgs;
    auto res = store->ExecuteForChangedRowCount(outValue, sql, bindArgs);
    EXPECT_EQ(E_NOT_SUPPORT, res);
}

/**
 * @tc.name: ExecuteForChangedRowCount_Test_002
 * @tc.desc: Abnormal testCase of ExecuteForChangedRowCount
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, ExecuteForChangedRowCount_Test_002, TestSize.Level2)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetDBType(DB_VECTOR);
    config.SetReadOnly(true);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    int64_t outValue;
    const std::string sql;
    const ValueObjects bindArgs;
    auto res = store->ExecuteForChangedRowCount(outValue, sql, bindArgs);
    EXPECT_EQ(E_NOT_SUPPORT, res);
}

/**
 * @tc.name: ExecuteForChangedRowCount_Test_003
 * @tc.desc: Abnormal testCase of ExecuteForChangedRowCount
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, ExecuteForChangedRowCount_Test_003, TestSize.Level2)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetDBType(DB_VECTOR);
    config.SetReadOnly(false);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    int64_t outValue;
    const std::string sql;
    const ValueObjects bindArgs;
    auto res = store->ExecuteForChangedRowCount(outValue, sql, bindArgs);
    EXPECT_EQ(E_NOT_SUPPORT, res);
}

/**
 * @tc.name: SetDefaultEncryptSql_Test_001
 * @tc.desc: Abnormal testCase of SetDefaultEncryptSql
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, SetDefaultEncryptSql_Test_001, TestSize.Level2)
{
    EXPECT_CALL(*mockStatement, Prepare(_)).WillOnce(Return(E_ERROR));
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    const std::string sql = "SELECT * FROM employee";
    auto res = storeImpl->SetDefaultEncryptSql(mockStatement, sql, config);
    EXPECT_EQ(E_ERROR, res);
}

/**
 * @tc.name: SetDefaultEncryptSql_Test_002
 * @tc.desc: Abnormal testCase of SetDefaultEncryptSql
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, SetDefaultEncryptSql_Test_002, TestSize.Level2)
{
    std::vector<ValueObject> args;
    EXPECT_CALL(*mockStatement, Prepare(_)).WillOnce(Return(E_OK));
    EXPECT_CALL(*mockStatement, Execute(args)).WillOnce(Return(E_SQLITE_BUSY));
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    const std::string sql = "SELECT * FROM employee";
    auto res = storeImpl->SetDefaultEncryptSql(mockStatement, sql, config);
    EXPECT_EQ(E_SQLITE_BUSY, res);
}

/**
 * @tc.name: SetDefaultEncryptAlgo_Test_001
 * @tc.desc: Abnormal testCase of SetDefaultEncryptAlgo
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, SetDefaultEncryptAlgo_Test_001, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    auto res = storeImpl->SetDefaultEncryptAlgo(nullptr, config);
    EXPECT_EQ(E_DATABASE_BUSY, res);
}

/**
 * @tc.name: SetDefaultEncryptAlgo_Test_002
 * @tc.desc: Abnormal testCase of SetDefaultEncryptAlgo
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, SetDefaultEncryptAlgo_Test_002, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    RdbStoreConfig::CryptoParam cryptoParam;
    config.SetCryptoParam(cryptoParam);
    config.SetIter(-1);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    auto res = storeImpl->SetDefaultEncryptAlgo(mockConnection, config);
    EXPECT_EQ(E_INVALID_ARGS, res);
}

/**
 * @tc.name: SetDefaultEncryptAlgo_Test_003
 * @tc.desc: Abnormal testCase of SetDefaultEncryptAlgo
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, SetDefaultEncryptAlgo_Test_003, TestSize.Level2)
{
    EXPECT_CALL(*mockConnection, CreateStatement(_, _)).WillOnce(Return(std::make_pair(E_OK, mockStatement)));
    EXPECT_CALL(*mockStatement, Prepare(_)).WillOnce(Return(E_ERROR));
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    RdbStoreConfig::CryptoParam cryptoParam;
    config.SetCryptoParam(cryptoParam);
    config.SetIter(1);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    auto res = storeImpl->SetDefaultEncryptAlgo(mockConnection, config);
    EXPECT_EQ(E_ERROR, res);
}

/**
 * @tc.name: SetDefaultEncryptAlgo_Test_004
 * @tc.desc: Abnormal testCase of SetDefaultEncryptAlgo
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, SetDefaultEncryptAlgo_Test_004, TestSize.Level2)
{
    EXPECT_CALL(*mockConnection, CreateStatement(_, _)).WillOnce(Return(std::make_pair(E_OK, mockStatement)));
    std::vector<ValueObject> args;
    EXPECT_CALL(*mockStatement, Prepare(_)).WillOnce(Return(E_OK)).WillOnce(Return(E_ERROR));
    EXPECT_CALL(*mockStatement, Execute(args)).WillOnce(Return(E_OK));
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    RdbStoreConfig::CryptoParam cryptoParam;
    config.SetCryptoParam(cryptoParam);
    config.SetIter(1);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    auto res = storeImpl->SetDefaultEncryptAlgo(mockConnection, config);
    EXPECT_EQ(E_ERROR, res);
}

/**
 * @tc.name: SetDefaultEncryptAlgo_Test_005
 * @tc.desc: Abnormal testCase of SetDefaultEncryptAlgo
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, SetDefaultEncryptAlgo_Test_005, TestSize.Level2)
{
    EXPECT_CALL(*mockConnection, CreateStatement(_, _)).WillOnce(Return(std::make_pair(E_OK, mockStatement)));
    std::vector<ValueObject> args;
    EXPECT_CALL(*mockStatement, Prepare(_)).WillOnce(Return(E_OK)).WillOnce(Return(E_OK)).WillOnce(Return(E_ERROR));
    EXPECT_CALL(*mockStatement, Execute(args)).WillOnce(Return(E_OK)).WillOnce(Return(E_OK));
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    RdbStoreConfig::CryptoParam cryptoParam;
    config.SetCryptoParam(cryptoParam);
    config.SetIter(1);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    auto res = storeImpl->SetDefaultEncryptAlgo(mockConnection, config);
    EXPECT_EQ(E_ERROR, res);
}

/**
 * @tc.name: SetDefaultEncryptAlgo_Test_006
 * @tc.desc: Abnormal testCase of SetDefaultEncryptAlgo
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, SetDefaultEncryptAlgo_Test_006, TestSize.Level2)
{
    EXPECT_CALL(*mockConnection, CreateStatement(_, _)).WillOnce(Return(std::make_pair(E_OK, mockStatement)));
    std::vector<ValueObject> args;
    EXPECT_CALL(*mockStatement, Prepare(_))
        .WillOnce(Return(E_OK))
        .WillOnce(Return(E_OK))
        .WillOnce(Return(E_OK))
        .WillOnce(Return(E_ERROR));
    EXPECT_CALL(*mockStatement, Execute(args)).WillOnce(Return(E_OK)).WillOnce(Return(E_OK)).WillOnce(Return(E_OK));
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    RdbStoreConfig::CryptoParam cryptoParam;
    config.SetCryptoParam(cryptoParam);
    config.SetIter(1);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    auto res = storeImpl->SetDefaultEncryptAlgo(mockConnection, config);
    EXPECT_EQ(E_ERROR, res);
}

/**
 * @tc.name: Backup_Test_001
 * @tc.desc: Abnormal testCase of Backup
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, Backup_Test_001, TestSize.Level2)
{
    auto mockRdbService = std::make_shared<MockRdbService>();
    EXPECT_CALL(*mockRdbManagerImpl, GetRdbService(_)).WillRepeatedly(Return(std::make_pair(E_OK, mockRdbService)));
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetReadOnly(false);
    config.SetHaMode(HAMode::SINGLE);
    config.SetIter(1);
    config.SetEncryptStatus(true);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    std::vector<uint8_t> encryptKey;
    auto res = store->Backup(RdbStoreImplConditionTest::DATABASE_BACKUP_NAME, encryptKey);
    EXPECT_EQ(E_OK, res);
}

/**
 * @tc.name: Backup_Test_002
 * @tc.desc: Abnormal testCase of Backup
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, Backup_Test_002, TestSize.Level2)
{
    std::vector<ValueObject> args;
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetReadOnly(false);
    config.SetHaMode(HAMode::SINGLE);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    std::vector<uint8_t> encryptKey;
    auto res = store->Backup(RdbStoreImplConditionTest::DATABASE_BACKUP_NAME, encryptKey);
    EXPECT_EQ(E_OK, res);
}

/**
 * @tc.name: Attach_Test_001
 * @tc.desc: Abnormal testCase of Attach
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, Attach_Test_001, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetEncryptStatus(true);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    RdbStoreConfig config1(RdbStoreImplConditionTest::DATABASE_NAME);
    config1.SetReadOnly(false);
    config1.SetDBType(DB_SQLITE);
    config1.SetHaMode(HAMode::SINGLE);
    config1.SetStorageMode(StorageMode::MODE_DISK);
    config1.SetEncryptStatus(false);
    auto res = store->Attach(config1, "test", 0);
    EXPECT_EQ(E_NOT_SUPPORT, res.first);
}

/**
 * @tc.name: ExecuteByTrxId_Test_001
 * @tc.desc: Abnormal testCase of ExecuteByTrxId
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, ExecuteByTrxId_Test_001, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetIsVector(true);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    std::vector<ValueObject> bindArgs;
    auto res = storeImpl->ExecuteByTrxId("sql", 0, false);
    EXPECT_EQ(E_INVALID_ARGS, res);
}

/**
 * @tc.name: ExecuteByTrxId_Test_002
 * @tc.desc: Abnormal testCase of ExecuteByTrxId
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, ExecuteByTrxId_Test_002, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetIsVector(true);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    std::vector<ValueObject> bindArgs;
    auto res = storeImpl->ExecuteByTrxId("sql", 1, false);
    EXPECT_EQ(E_INVALID_ARGS, res);
}

/**
 * @tc.name: Restore_Test_001
 * @tc.desc: Abnormal testCase of Restore
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, Restore_Test_001, TestSize.Level2)
{
    std::vector<uint8_t> newKey;
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(true);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    auto res = storeImpl->Restore("test.db", newKey);
    EXPECT_EQ(E_NOT_SUPPORT, res);
}

/**
 * @tc.name: Restore_Test_002
 * @tc.desc: Abnormal testCase of Restore
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, Restore_Test_002, TestSize.Level2)
{
    std::vector<uint8_t> newKey;
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(false);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    auto res = storeImpl->Restore("test.db", newKey);
    EXPECT_EQ(E_NOT_SUPPORT, res);
}

/**
 * @tc.name: Restore_Test_003
 * @tc.desc: Abnormal testCase of Restore
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, Restore_Test_003, TestSize.Level2)
{
    std::vector<uint8_t> newKey;
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetReadOnly(true);
    config.SetStorageMode(StorageMode::MODE_DISK);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    auto res = storeImpl->Restore("test.db", newKey);
    EXPECT_EQ(E_NOT_SUPPORT, res);
}

/**
 * @tc.name: GetStatement_Test_001
 * @tc.desc: Abnormal testCase of GetStatement
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, GetStatement_Test_001, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    const std::string sql = "ATTACH DATABASE 'database.db';";
    auto res = storeImpl->GetStatement(sql, nullptr);
    EXPECT_EQ(E_DATABASE_BUSY, res.first);
}

/**
 * @tc.name: InterruptBackup_Test_001
 * @tc.desc: Abnormal testCase of InterruptBackup
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, InterruptBackup_Test_001, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetHaMode(HAMode::SINGLE);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    auto res = storeImpl->InterruptBackup();
    EXPECT_EQ(E_NOT_SUPPORT, res);
}

/**
 * @tc.name: InterruptBackup_Test_002
 * @tc.desc: Abnormal testCase of InterruptBackup
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, InterruptBackup_Test_002, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    storeImpl->slaveStatus_ = DB_NOT_EXITS;
    auto res = storeImpl->InterruptBackup();
    EXPECT_EQ(E_CANCEL, res);
}

/**
 * @tc.name: InterruptBackup_Test_003
 * @tc.desc: Abnormal testCase of InterruptBackup
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, InterruptBackup_Test_003, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    storeImpl->slaveStatus_ = BACKING_UP;
    auto res = storeImpl->InterruptBackup();
    EXPECT_EQ(E_OK, res);
}

/**
 * @tc.name: GetBackupStatus_Test_001
 * @tc.desc: Abnormal testCase of GetBackupStatus
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, GetBackupStatus_Test_001, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetHaMode(HAMode::SINGLE);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    auto res = storeImpl->GetBackupStatus();
    EXPECT_EQ(UNDEFINED, res);
}

/**
 * @tc.name: GetBackupStatus_Test_002
 * @tc.desc: Abnormal testCase of GetBackupStatus
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, GetBackupStatus_Test_002, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    auto storeImpl = std::make_shared<RdbStoreImpl>(config);
    storeImpl->slaveStatus_ = BACKING_UP;
    auto res = storeImpl->GetBackupStatus();
    EXPECT_EQ(BACKING_UP, res);
}

/**
 * @tc.name: CleanDirtyLog_Test_001
 * @tc.desc: Abnormal testCase of CleanDirtyLog
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, CleanDirtyLog_Test_001, TestSize.Level2)
{
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    config.SetDBType(DB_SQLITE);
    config.SetReadOnly(false);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    uint64_t cursor = 0;
    auto res = store->CleanDirtyLog("test", cursor);
    EXPECT_EQ(E_NOT_SUPPORT, res);
}

/**
 * @tc.name: CleanDirtyLog_Test_002
 * @tc.desc: Abnormal testCase of CleanDirtyLog
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, CleanDirtyLog_Test_002, TestSize.Level2)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_VECTOR);
    config.SetReadOnly(false);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    uint64_t cursor = 0;
    auto res = store->CleanDirtyLog("test", cursor);
    EXPECT_EQ(E_NOT_SUPPORT, res);
}

/**
 * @tc.name: CleanDirtyLog_Test_004
 * @tc.desc: Abnormal testCase of CleanDirtyLog
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, CleanDirtyLog_Test_004, TestSize.Level2)
{
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode;
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    store = nullptr;
    config.SetStorageMode(StorageMode::MODE_DISK);
    config.SetDBType(DB_SQLITE);
    config.SetReadOnly(true);
    store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    uint64_t cursor = 0;
    auto res = store->CleanDirtyLog("test", cursor);
    EXPECT_EQ(E_NOT_SUPPORT, res);
}

/**
 * @tc.name: CloudTables::Change_Test_001
 * @tc.desc: Abnormal testCase of CloudTables::Change
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreImplConditionTest, CloudTables_Change_Test_001, TestSize.Level2)
{
    auto cloudTables = std::make_shared<RdbStoreImpl::CloudTables>();
    std::string table = "";
    auto res = cloudTables->Change(table);
    EXPECT_EQ(false, res);
    cloudTables->AddTables({ "test1" });
    std::string table1 = "test";
    res = cloudTables->Change(table1);
    EXPECT_EQ(false, res);
    cloudTables->AddTables({ "test" });
    std::string table2 = "test";
    res = cloudTables->Change(table2);
    EXPECT_EQ(true, res);
    res = cloudTables->Change(table);
    EXPECT_EQ(false, res);
}
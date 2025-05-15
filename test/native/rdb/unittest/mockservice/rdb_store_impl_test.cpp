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
#include "grd_api_manager.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_manager_impl_mock.h"
#include "rdb_open_callback.h"
#include "rdb_service_mock.h"
#include "rdb_sql_statistic.h"
#include "rdb_store_config.h"
#include "rdb_types.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedRdb;
using CheckOnChangeFunc = std::function<void(RdbStoreObserver::ChangeInfo &changeInfo)>;
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
    static const std::string DEFAULT_DATABASE_NAME;
    static inline std::shared_ptr<MockRdbManagerImpl> mockRdbManagerImpl = nullptr;

protected:
    std::shared_ptr<RdbStore> store_;
};

const std::string RdbStoreImplConditionTest::DATABASE_NAME = RDB_TEST_PATH + "rdb_store_impl_condition_test.db";
const std::string RdbStoreImplConditionTest::DEFAULT_DATABASE_NAME = RDB_TEST_PATH + "default_condition_test.db";

std::shared_ptr<SubObserver> RdbStoreImplConditionTest::observer_ = nullptr;

class RdbStoreImplConditionTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

int RdbStoreImplConditionTestOpenCallback::OnCreate(RdbStore &store)
{
    return E_OK;
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
}

void RdbStoreImplConditionTest::TearDownTestCase(void)
{
    mockRdbManagerImpl = nullptr;
    BRdbManagerImpl::rdbManagerImpl = nullptr;
}

void RdbStoreImplConditionTest::SetUp(void)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
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
    RdbStoreConfig config(RdbStoreImplConditionTest::DATABASE_NAME);
    config.SetDBType(DB_VECTOR);
    RdbStoreImplConditionTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 0, helper, errCode);
    ASSERT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->Subscribe({ SubscribeMode::REMOTE, "observer" }, observer_.get());
    EXPECT_EQ(status, E_NOT_SUPPORT);
    status = store->UnSubscribe({ SubscribeMode::REMOTE, "observer" }, observer_.get());
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
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->Subscribe({ SubscribeMode::REMOTE, "observer" }, observer_.get());
    EXPECT_EQ(status, E_NOT_SUPPORT);
    status = store->UnSubscribe({ SubscribeMode::REMOTE, "observer" }, observer_.get());
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
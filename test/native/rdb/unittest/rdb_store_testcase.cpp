/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <memory>

#include "iremote_object.h"
#include "iremote_proxy.h"
#include "itypes_util.h"
#include "kvstore_interface_code.h"
#include "message_option.h"
#include "message_parcel.h"
#include "rdb_manager_impl.h"
#include "rdb_service.h"
#include "rdb_service_proxy.h"
#include "rdb_syncer_param.h"
#include "system_ability_manager.h"
#include "system_ability_manager_client.h"

using namespace OHOS::DistributedRdb;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedRdb::RelationalStore;

namespace OHOS {
namespace DistributedRdb {
class RdbManagerImplTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
    }
    static void TearDownTestCase()
    {
    }
    void SetUp() override
    {
        // 设置模拟对象
        systemAbilityManager_ = std::make_shared<SystemAbilityManager>();
        distributedDataMgr_ = std::make_shared<RdbStoreDataServiceProxy>(nullptr);
        remoteObject_ = std::make_shared<IRemoteObject>();
        rdbServiceProxy_ = std::make_shared<RdbServiceProxy>(remoteObject_);
        rdbService_ = std::make_shared<RdbService>(rdbServiceProxy_);
    }
    void TearDown() override
    {
    }
    static std::string RemoveSuffix(const std::string &name);
    static std::chrono::system_clock::time_point GetKeyFileDate(const std::string &dbName);
    static bool ChangeKeyFileDate(const std::string &dbName, int rep);
    static bool SaveNewKey(const std::string &dbName);
    static RdbStoreConfig GetRdbConfig(const std::string &name_);
    static RdbStoreConfig GetRdbNotRekeyConfig(const std::string &name_);
    static void InsertData(std::shared_ptr<RdbStore> &rdbStore);
    static void CheckQueryData(std::shared_ptr<RdbStore> &rdbStore);

    std::shared_ptr<SystemAbilityManager> systemAbilityManager_;
    std::shared_ptr<RdbStoreDataServiceProxy> distributedDataMgr_;
    std::shared_ptr<IRemoteObject> remoteObject_;
    std::shared_ptr<RdbServiceProxy> rdbServiceProxy_;
    std::shared_ptr<RdbService> rdbService_;
    static const std::string encryptedDatabaseName;
    static const std::string encryptedDatabasePath;
    static const std::string encryptedDatabaseKeyDir;
    static const std::string encryptedDatabaseMockName;
    static const std::string encryptedDatabaseMockPath;
};
void RdbStorePredicateJoinTest::InsertUserDates()
{
    int64_t id_;
    ValuesBucket value;

    value.PutInt("userId", 1);
    value.PutString("firstName", std::string("Zhang"));
    value.PutString("lastName", std::string("San"));
    value.PutInt("age_", 1);
    value.PutDouble("balance", 1);
    rdbStore->Insert(id_, "user", value);

    value.Clear();
    value.PutInt("userId", 1);
    value.PutString("firstName", std::string("Li"));
    value.PutString("lastName", std::string("Si"));
    value.PutInt("age_", 1);
    value.PutDouble("balance", 1);
    rdbStore->Insert(id_, "user", value);

    value.Clear();
    value.PutInt("userId", 1);
    value.PutString("firstName", std::string("Wang"));
    value.PutString("lastName", std::string("Wu"));
    value.PutInt("age_", 1);
    value.PutDouble("balance", 1);
    rdbStore->Insert(id_, "user", value);

    value.Clear();
    value.PutInt("userId", 1);
    value.PutString("firstName", std::string("Sun"));
    value.PutString("lastName", std::string("Liu"));
    value.PutInt("age_", 1);
    value.PutDouble("balance", 1);
    rdbStore->Insert(id_, "user", value);

    value.Clear();
    value.PutInt("userId", 1);
    value.PutString("firstName", std::string("Ma"));
    value.PutString("lastName", std::string("Qi"));
    value.PutInt("age_", 1);
    value.PutDouble("balance", 1);
    rdbStore->Insert(id_, "user", value);
}

void RdbStorePredicateJoinTest::InsertBookDates()
{
    int64_t id_;
    ValuesBucket value;

    value.PutInt("id_", 1);
    value.PutString("name_", std::string("SanGuo"));
    value.PutInt("userId", 1);
    rdbStore->Insert(id_, "book", value);

    value.Clear();
    value.PutInt("id_", 1);
    value.PutString("name_", std::string("XiYouJi"));
    value.PutInt("userId", 1);
    rdbStore->Insert(id_, "book", value);

    value.Clear();
    value.PutInt("id_", 1);
    value.PutString("name_", std::string("ShuiHuZhuan"));
    value.PutInt("userId", 1);
    rdbStore->Insert(id_, "book", value);
}
const std::string RdbRekeyTest::encryptedDatabaseName = "encrypted.db";
const std::string RdbRekeyTest::encryptedDatabasePath = RDB_TEST_PATH + encryptedDatabaseName;
const std::string RdbRekeyTest::encryptedDatabaseKeyDir = RDB_TEST_PATH + "key/";
const std::string RdbRekeyTest::encryptedDatabaseMockName = "encrypted_mock.db";
const std::string RdbRekeyTest::encryptedDatabaseMockPath = RDB_TEST_PATH + encryptedDatabaseMockName;

HWTEST_F(RdbManagerImplTest, GetRdbService_EmptyBundleName_ReturnsInvalidArgs, TestSize.Level1)
{
    RdbSyncerParam param;
    param.bundleName_ = "";
    RdbManagerImpl &manager = RdbManagerImpl::GetInstance();
    auto [errorCode, service] = manager.GetRdbService(param);
    EXPECT_EQ(errorCode, E_INVALID_ARGS);
    EXPECT_EQ(service, nullptr);
}

HWTEST_F(RdbManagerImplTest, GetRdbService_ExistingRdbService_ReturnsOk, TestSize.Level1)
{
    RdbSyncerParam param;
    param.bundleName_ = "testBundle";
    RdbManagerImpl &manager = RdbManagerImpl::GetInstance();
    manager.rdbService_ = rdbService_;
    auto [errorCode, service] = manager.GetRdbService(param);
    EXPECT_EQ(errorCode, E_OK);
    EXPECT_EQ(service, rdbService_);
}

HWTEST_F(RdbManagerImplTest, GetRdbService_FailedToGetDistributedDataManager_ReturnsServiceNotFound, TestSize.Level1)
{
    RdbSyncerParam param;
    param.bundleName_ = "testBundle";
    RdbManagerImpl &manager = RdbManagerImpl::GetInstance();
    manager.distributedDataMgr_ = nullptr;
    auto [errorCode, service] = manager.GetRdbService(param);
    EXPECT_EQ(errorCode, E_SERVICE_NOT_FOUND);
    EXPECT_EQ(service, nullptr);
}

HWTEST_F(RdbManagerImplTest, GetRdbService_RemoteObjectNotProxy_ReturnsNotSupport, TestSize.Level1)
{
    RdbSyncerParam param;
    param.bundleName_ = "testBundle";
    RdbManagerImpl &manager = RdbManagerImpl::GetInstance();
    manager.distributedDataMgr_ = distributedDataMgr_;
    EXPECT_CALL(*remoteObject_, IsProxyObject()).WillOnce(testing::Return(false));
    auto [errorCode, service] = manager.GetRdbService(param);
    EXPECT_EQ(errorCode, E_NOT_SUPPORT);
    EXPECT_EQ(service, nullptr);
}

HWTEST_F(RdbManagerImplTest, GetRdbService_FailedToInitNotifier_ReturnsError, TestSize.Level1)
{
    RdbSyncerParam param;
    param.bundleName_ = "testBundle";
    RdbManagerImpl &manager = RdbManagerImpl::GetInstance();
    manager.distributedDataMgr_ = distributedDataMgr_;
    EXPECT_CALL(*remoteObject_, IsProxyObject()).WillOnce(testing::Return(true));
    EXPECT_CALL(*rdbServiceProxy_, InitNotifier(testing::_)).WillOnce(testing::Return(E_ERROR));
    auto [errorCode, service] = manager.GetRdbService(param);
    EXPECT_EQ(errorCode, E_ERROR);
    EXPECT_EQ(service, nullptr);
}

HWTEST_F(RdbManagerImplTest, GetRdbService_Success_ReturnsOk, TestSize.Level1)
{
    RdbSyncerParam param;
    param.bundleName_ = "testBundle";
    RdbManagerImpl &manager = RdbManagerImpl::GetInstance();
    manager.distributedDataMgr_ = distributedDataMgr_;
    EXPECT_CALL(*remoteObject_, IsProxyObject()).WillOnce(testing::Return(true));
    EXPECT_CALL(*rdbServiceProxy_, InitNotifier(testing::_)).WillOnce(testing::Return(RDB_OK));
    auto [errorCode, service] = manager.GetRdbService(param);
    EXPECT_EQ(errorCode, E_OK);
    EXPECT_EQ(service, rdbService_);
}

HWTEST_F(RdbManagerImplTest, GetRdbStore_ValidConfig_ReturnsStore, TestSize.Level1)
{
    RdbStoreConfig storesConfig("test.db");
    RdbOpenCallback openCallback;
    int errorCode = E_OK;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(storesConfig, 1, openCallback, errorCode);
    EXPECT_TRUE(rdbStore != nullptr);
    EXPECT_EQ(errorCode, E_OK);
}

HWTEST_F(RdbManagerImplTest, ClearCache_CacheCleared, TestSize.Level1)
{
    RdbHelper::ClearCache();
    // 验证缓存是否被清除的逻辑
}

HWTEST_F(RdbManagerImplTest, DeleteRdbStore_ValidFileName_DeletesSuccessfully, TestSize.Level1)
{
    std::string fileName = "test.db";
    int result = RdbHelper::DeleteRdbStore(fileName);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(RdbManagerImplTest, DeleteRdbStore_InvalidFileName_ReturnsError, TestSize.Level1)
{
    std::string fileName = "";
    int result = RdbHelper::DeleteRdbStore(fileName);
    EXPECT_EQ(result, E_INVALID_FILE_PATH);
}

HWTEST_F(RdbManagerImplTest, DeleteRdbStore_ValidConfig_DeletesSuccessfully, TestSize.Level1)
{
    RdbStoreConfig storesConfig("test.db");
    int result = RdbHelper::DeleteRdbStore(storesConfig);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(RdbManagerImplTest, DeleteRdbStore_InvalidConfig_ReturnsError, TestSize.Level1)
{
    RdbStoreConfig storesConfig("");
    int result = RdbHelper::DeleteRdbStore(storesConfig);
    EXPECT_EQ(result, E_INVALID_FILE_PATH);
}

HWTEST_F(RdbManagerImplTest, EqualTo_ValidFieldAndValue_ShouldAddToWhereClause, TestSize.Level1)
{
    predicates->EqualTo("name_", ValueObject("Alice"));
    EXPECT_EQ(predicates->GetWhereClause(), "name_ = ? ");
    EXPECT_EQ(predicates->GetWhereArgs(), std::vector<std::string>{ "Alice" });
}

HWTEST_F(RdbManagerImplTest, EqualTo_EmptyField_ShouldNotAddToWhereClause, TestSize.Level1)
{
    predicates->EqualTo("", ValueObject("Alice"));
    EXPECT_EQ(predicates->GetWhereClause(), "");
    EXPECT_EQ(predicates->GetWhereArgs(), std::vector<std::string>{});
}

HWTEST_F(RdbManagerImplTest, EqualTo_SpecificField_ShouldSetHasSpecificField, TestSize.Level1)
{
    predicates->EqualTo("specific_field", ValueObject("value"));
    EXPECT_TRUE(predicates->HasSpecificField());
}

HWTEST_F(RdbManagerImplTest, EqualTo_OriginField_ShouldAdjustFieldAndValue, TestSize.Level1)
{
    predicates->EqualTo(DistributedRdb::Field::ORIGIN_FIELD, ValueObject(1.0));
    EXPECT_EQ(predicates->GetWhereClause(), "(origin & 0x02 = 0x0)");
    EXPECT_EQ(predicates->GetWhereArgs(), std::vector<std::string>{});
}

HWTEST_F(RdbManagerImplTest, EqualTo_WithAndCondition_ShouldAddAndToWhereClause, TestSize.Level1)
{
    predicates->EqualTo("name_", ValueObject("Alice"));
    predicates->EqualTo("age_", ValueObject(1));
    EXPECT_EQ(predicates->GetWhereClause(), "name_ = ? AND age_ = ? ");
    EXPECT_EQ(predicates->GetWhereArgs(), std::vector<std::string>{ "Alice", "1" });
}

HWTEST_F(RdbManagerImplTest, Constructor_SingleTableName_InitializesCorrectly, TestSize.Level1)
{
    AbsRdbPredicates predicates("testTable");
    EXPECT_EQ(predicates.GetTableName(), "testTable");
}

HWTEST_F(RdbManagerImplTest, Constructor_EmptyTableName_InitializesEmpty, TestSize.Level1)
{
    AbsRdbPredicates predicates("");
    EXPECT_EQ(predicates.GetTableName(), "");
}

HWTEST_F(RdbManagerImplTest, Constructor_TableNameList_InitializesCorrectly, TestSize.Level1)
{
    std::vector<std::string> tables = { "table1", "table2" };
    AbsRdbPredicates predicates(tables);
    EXPECT_EQ(predicates.GetTableName(), "table1");
}

HWTEST_F(RdbManagerImplTest, Constructor_EmptyTableNameList_InitializesEmpty, TestSize.Level1)
{
    std::vector<std::string> tables;
    AbsRdbPredicates predicates(tables);
    EXPECT_EQ(predicates.GetTableName(), "");
}

HWTEST_F(RdbManagerImplTest, Clear_ResetsPredicates, TestSize.Level1)
{
    AbsRdbPredicates predicates("testTable");
    predicates.EqualTo("field", ValueObject("value"));
    predicates.Clear();
    EXPECT_TRUE(predicates.GetWhereArgs().empty());
}

HWTEST_F(RdbManagerImplTest, InitialParam_ResetsJoinParameters, TestSize.Level1)
{
    AbsRdbPredicates predicates("testTable");
    predicates.SetJoinTypes({ "INNER JOIN" });
    predicates.InitialParam();
    EXPECT_TRUE(predicates.GetJoinTypes().empty());
}

HWTEST_F(RdbManagerImplTest, GetAndSetMethods_CorrectlySetAndRetrieveValues, TestSize.Level1)
{
    AbsRdbPredicates predicates("testTable");
    predicates.SetJoinTypes({ "INNER JOIN" });
    predicates.SetJoinTableNames({ "table1", "table2" });
    predicates.SetJoinConditions({ "condition1", "condition2" });
    predicates.SetJoinCount(1);

    EXPECT_EQ(predicates.GetJoinTypes(), std::vector<std::string>{ "INNER JOIN" });
    EXPECT_EQ(predicates.GetJoinTableNames(), std::vector<std::string>{ "table1", "table2" });
    EXPECT_EQ(predicates.GetJoinConditions(), std::vector<std::string>{ "condition1", "condition2" });
    EXPECT_EQ(predicates.GetJoinCount(), 1);
}

HWTEST_F(RdbManagerImplTest, PredicateBuilderMethods_CorrectlyBuildPredicates, TestSize.Level1)
{
    AbsRdbPredicates predicates("testTable");
    predicates.EqualTo("field1", ValueObject("value1"))
        .NotEqualTo("field2", ValueObject("value2"))
        .And()
        .Or()
        .OrderByAsc("field3")
        .OrderByDesc("field4")
        .BeginWrap()
        .EndWrap()
        .In("field5", { "value5", "value6" })
        .Contains("field6", "value7")
        .NotContains("field7", "value8")
        .BeginsWith("field8", "value9")
        .EndsWith("field9", "value10")
        .IsNull("field10")
        .IsNotNull("field11")
        .Like("field12", "value13")
        .NotLike("field13", "value14")
        .Glob("field14", "value15")
        .Distinct()
        .IndexedBy("index1")
        .NotIn("field15", { "value16", "value17" });
}
HWTEST_F(RdbTransactionTest, RdbStore_Transaction_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &rdbStore = RdbTransactionTest::rdbStore;

    int64_t id_;
    int val = rdbStore->BeginTransaction();
    EXPECT_EQ(val, E_OK);

    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Commit();
    EXPECT_EQ(val, E_OK);

    int64_t count;
    val = rdbStore->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(count, 1);

    int xrows;
    val = rdbStore->Delete(xrows, "test");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(xrows, 1);
}

/**
 * @tc.name_: RdbStore_Transaction_002
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionTest, RdbStore_Transaction_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &rdbStore = RdbTransactionTest::rdbStore;

    int64_t id_;
    int val = rdbStore->BeginTransaction();
    EXPECT_EQ(val, E_OK);

    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Commit();
    EXPECT_EQ(val, E_OK);

    int64_t count;
    val = rdbStore->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(count, 1);

    std::shared_ptr<result> result = rdbStore->QuerySql("SELECT * FROM table");
    EXPECT_NE(result, nullptr);
    val = result->GoToNextRow();
    EXPECT_EQ(val, E_OK);
    val = result->Close();
    EXPECT_EQ(val, E_OK);

    int xrows;
    val = rdbStore->Delete(xrows, "test");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(xrows, 1);
}

/**
 * @tc.name_: RdbStore_Transaction_003
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionTest, RdbStore_Transaction_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &rdbStore = RdbTransactionTest::rdbStore;

    int64_t id_;
    int val = rdbStore->BeginTransaction();
    EXPECT_EQ(val, E_OK);

    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->RollBack();
    EXPECT_EQ(val, E_OK);

    int64_t count;
    val = rdbStore->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(count, 0);

    std::shared_ptr<result> result = rdbStore->QuerySql("SELECT * FROM table");
    EXPECT_NE(result, nullptr);
    val = result->Close();
    EXPECT_EQ(val, E_OK);

    int xrows;
    val = rdbStore->Delete(xrows, "test");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(xrows, 0);
}

/**
 * @tc.name_: RdbStore_NestedTransaction_001
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionTest, RdbStore_NestedTransaction_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &rdbStore = RdbTransactionTest::rdbStore;

    int64_t id_;
    int val = rdbStore->BeginTransaction();
    EXPECT_EQ(val, E_OK);

    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->BeginTransaction();
    EXPECT_EQ(val, E_OK);
    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);
    val = rdbStore->Commit(); // not commit
    EXPECT_EQ(val, E_OK);

    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Commit();
    EXPECT_EQ(val, E_OK);

    int64_t count;
    val = rdbStore->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(count, 1);

    std::shared_ptr<result> result = rdbStore->QuerySql("SELECT * FROM table");
    EXPECT_NE(result, nullptr);
    val = result->GoToNextRow();
    EXPECT_EQ(val, E_OK);
    val = result->Close();
    EXPECT_EQ(val, E_OK);

    int xrows;
    val = rdbStore->Delete(xrows, "test");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(xrows, 1);
}

/**
 * @tc.name_: RdbStore_NestedTransaction_002
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionTest, RdbStore_NestedTransaction_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &rdbStore = RdbTransactionTest::rdbStore;

    int64_t id_;
    int val = rdbStore->BeginTransaction();
    EXPECT_EQ(val, E_OK);

    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->BeginTransaction();
    EXPECT_EQ(val, E_OK);
    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);
    val = rdbStore->Commit();
    EXPECT_EQ(val, E_OK);
    val = rdbStore->Commit(); // commit
    EXPECT_EQ(val, E_OK);

    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    int64_t count;
    val = rdbStore->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(count, 1);

    std::shared_ptr<result> result = rdbStore->QuerySql("SELECT * FROM table");
    EXPECT_NE(result, nullptr);
    val = result->GoToNextRow();
    EXPECT_EQ(val, E_OK);
    val = result->Close();
    EXPECT_EQ(val, E_OK);

    int xrows;
    val = rdbStore->Delete(xrows, "test");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(xrows, 1);
}

/**
 * @tc.name_: RdbStore_NestedTransaction_003
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionTest, RdbStore_NestedTransaction_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &rdbStore = RdbTransactionTest::rdbStore;

    int64_t id_;
    int val = rdbStore->BeginTransaction();
    EXPECT_EQ(val, E_OK);

    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->BeginTransaction();
    EXPECT_EQ(val, E_OK);
    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);
    val = rdbStore->Commit(); // not commit
    EXPECT_EQ(val, E_OK);

    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Commit(); // not commit
    EXPECT_EQ(val, E_OK);

    int64_t count;
    val = rdbStore->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(count, 1);

    std::shared_ptr<result> result = rdbStore->QuerySql("SELECT * FROM table");
    EXPECT_NE(result, nullptr);
    val = result->GoToNextRow();
    EXPECT_EQ(val, E_OK);
    val = result->Close();
    EXPECT_EQ(val, E_OK);

    int xrows;
    val = rdbStore->Delete(xrows, "test");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(xrows, 1);
}

/**
 * @tc.name_: RdbStore_NestedTransaction_004
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionTest, RdbStore_NestedTransaction_004, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &rdbStore = RdbTransactionTest::rdbStore;

    int64_t id_;
    int val = rdbStore->BeginTransaction();
    EXPECT_EQ(val, E_OK);

    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->BeginTransaction();
    EXPECT_EQ(val, E_OK);
    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);
    val = rdbStore->Commit(); // commit
    EXPECT_EQ(val, E_OK);

    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Commit(); // commit
    EXPECT_EQ(val, E_OK);

    int64_t count;
    val = rdbStore->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(count, 1);

    std::shared_ptr<result> result = rdbStore->QuerySql("SELECT * FROM table");
    EXPECT_NE(result, nullptr);
    val = result->GoToNextRow();
    EXPECT_EQ(val, E_OK);
    val = result->GoToNextRow();
    EXPECT_EQ(val, E_OK);
    val = result->GoToNextRow();
    EXPECT_EQ(val, E_OK);
    val = result->GoToNextRow();
    EXPECT_EQ(val, E_ROW_OUT_RANGE);
    val = result->Close();
    EXPECT_EQ(val, E_OK);

    int xrows;
    val = rdbStore->Delete(xrows, "test");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(xrows, 1);
}

/**
 * @tc.name_: RdbStore_BatchInsert_001
 * @tc.desc: test RdbStore BatchInsert
 * @tc.type: FUNC
 * @tc.require: issueI5GZGX
 */
HWTEST_F(RdbTransactionTest, RdbStore_BatchInsert_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &rdbStore = RdbTransactionTest::rdbStore;

    ValuesBucket value;

    value.PutString("name_", "zhangsan");
    value.PutInt("age_", 1);
    value.PutDouble("salary", 1);
    value.PutBlob("blobType", std::vector<uint8_t>{ 1, 1, 1 });

    std::vector<ValuesBucket> valuesBucket;
    for (int i = 0; i < 1; i++) {
        valuesBucket.push_back(value);
    }
    int64_t insertNum = 0;
    int val = rdbStore->BatchInsert(insertNum, "test", valuesBucket);
    EXPECT_EQ(E_OK, val);
    EXPECT_EQ(1, insertNum);
    std::shared_ptr<result> result = rdbStore->QuerySql("SELECT * FROM table");
    int rowCount = 0;
    result->GetRowCount(rowCount);
    EXPECT_EQ(1, rowCount);
}

/**
 * @tc.name_: RdbStore_BatchInsert_002
 * @tc.desc: test RdbStore BatchInsert
 * @tc.type: FUNC
 * @tc.require: issue-I6BAX0
 */
HWTEST_F(RdbTransactionTest, RdbStore_BatchInsert_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &rdbStore = RdbTransactionTest::rdbStore;
    rdbStore->ExecuteSql("delete from test");
    std::string name_ = "zhangsan";
    int age_ = 1;
    double salary = 1;
    std::vector<uint8_t> blob = { 1, 1, 1 };
    std::vector<ValuesBucket> valuesBuckets;
    for (int i = 0; i < 1; i++) {
        ValuesBucket value;
        value.PutString("name_", name_);
        value.PutInt("age_", age_ + i);
        value.PutDouble("salary", salary + i);
        value.PutBlob("blobType", blob);
        valuesBuckets.push_back(std::move(value));
    }

    int64_t number = 0;
    int error = rdbStore->BatchInsert(number, "test", valuesBuckets);
    EXPECT_EQ(E_OK, error);
    EXPECT_EQ(1, number);
    int rowCount = 0;
    std::shared_ptr<result> result = rdbStore->QuerySql("SELECT * FROM table");
    result->GetRowCount(rowCount);
    EXPECT_EQ(1, rowCount);
}

/**
 * @tc.name_: RdbStore_BatchInsert_003
 * @tc.desc: test RdbStore BatchInsert
 * @tc.type: FUNC
 * @tc.require: issue-I6BAX0
 */
HWTEST_F(RdbTransactionTest, RdbStore_BatchInsert_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &rdbStore = RdbTransactionTest::rdbStore;
    rdbStore->ExecuteSql("delete from test");
    int id_ = 0;
    std::string name_ = "zhangsan";
    int age_ = 1;
    double salary = 1;
    std::vector<uint8_t> blob = { 1, 1, 1 };
    std::vector<ValuesBucket> valuesBuckets;
    for (int i = 0; i < 1; i++) {
        RowData rowData1 = { id_ + i, name_, age_ + i, salary + i, blob };
        ValuesBucket value = UTUtils::SetRowData(rowData1);
        valuesBuckets.push_back(std::move(value));
    }
    int64_t number = 0;
    int error = rdbStore->BatchInsert(number, "test", valuesBuckets);
    EXPECT_EQ(E_OK, error);
    EXPECT_EQ(100, number);
    int rowCount = 0;
    std::shared_ptr<result> result = rdbStore->QuerySql("SELECT * FROM table");
    result->GetRowCount(rowCount);
    EXPECT_EQ(1, rowCount);

    valuesBuckets.clear();
    for (int i = 1; i < 100; i++) {
        RowData rowData2 = { id_ + i, name_, age_ + i, salary + i, blob };
        ValuesBucket value = UTUtils::SetRowData(rowData2);
        valuesBuckets.push_back(std::move(value));
    }
    number = 1;
    error = rdbStore->BatchInsert(number, "test", valuesBuckets);
    EXPECT_EQ(E_OK, error);
    EXPECT_EQ(1, number);

    result = rdbStore->QuerySql("SELECT * FROM table");
    result->GetRowCount(rowCount);
    EXPECT_EQ(100, rowCount);
    number = 0L;
    while (true) {
        error = result->GoToNextRow();
        if (error != E_OK) {
            break;
        }
        number++;
    }
    result->Close();
    EXPECT_EQ(1, number);
}
/**
* @tc.name_: Rdb_Rekey_Test_001
* @tc.desc: test RdbStore rekey function
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_01, TestSize.Level1)
{
    std::string oldkeyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key";
    std::string xinKeyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key.new";

    bool ifFileExists = OHOS::FileExists(oldkeyPath);
    ASSERT_TRUE(ifFileExists);

    bool ifFileDateChanged = ChangeKeyFileDate(encryptedDatabaseName, RdbRekeyTest::HOURS_EXPIRED);
    ASSERT_TRUE(ifFileDateChanged);

    auto changedDate = GetKeyFileDate(encryptedDatabaseName);
    ASSERT_TRUE(std::chrono::system_clock::now() - changedDate > std::chrono::hours(RdbRekeyTest::HOURS_EXPIRED));

    RdbStoreConfig storesConfig = GetRdbConfig(RdbRekeyTest::encryptedDatabasePath);
    RekeyTestOpenCallback helpeee;
    int errorCode = E_OK;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(storesConfig, 1, helpeee, errorCode);
    ASSERT_NE(rdbStore, nullptr);
    ASSERT_EQ(errorCode, E_OK);

    ifFileExists = OHOS::FileExists(oldkeyPath);
    ASSERT_TRUE(ifFileExists);
    ifFileExists = OHOS::FileExists(xinKeyPath);
    ASSERT_FALSE(ifFileExists);

    auto newDate = GetKeyFileDate(encryptedDatabaseName);
    ASSERT_TRUE(std::chrono::system_clock::now() - newDate < std::chrono::seconds(1));
    CheckQueryData(rdbStore);
}

/**
* @tc.name_: Rdb_Rekey_Test_002
* @tc.desc: test RdbStore with not outdated password
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_02, TestSize.Level1)
{
    std::string oldkeyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key";
    bool ifFileExists = OHOS::FileExists(oldkeyPath);
    ASSERT_TRUE(ifFileExists);

    bool ifFileDateChanged = ChangeKeyFileDate(encryptedDatabaseName, RdbRekeyTest::HOURS_NOT_EXPIRED);
    ASSERT_TRUE(ifFileDateChanged);

    auto changedDate = GetKeyFileDate(encryptedDatabaseName);
    ASSERT_TRUE(std::chrono::system_clock::now() - changedDate > std::chrono::hours(RdbRekeyTest::HOURS_NOT_EXPIRED));

    RdbStoreConfig storesConfig = GetRdbConfig(RdbRekeyTest::encryptedDatabasePath);
    RekeyTestOpenCallback helpeee;
    int errorCode = E_OK;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(storesConfig, 1, helpeee, errorCode);
    ASSERT_NE(rdbStore, nullptr);
    ASSERT_EQ(errorCode, E_OK);
    CheckQueryData(rdbStore);
}

/**
* @tc.name_: Rdb_Rekey_Test_003
* @tc.desc: try to open rdbStore and execute RekeyRecover() without key and new key files.
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_03, TestSize.Level1)
{
    std::string oldkeyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key";
    std::string xinKeyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key.new";

    bool ifFileExists = OHOS::FileExists(oldkeyPath);
    ASSERT_TRUE(ifFileExists);

    SqliteUtils::DeleteFile(oldkeyPath);
    ifFileExists = OHOS::FileExists(oldkeyPath);
    ASSERT_FALSE(ifFileExists);
    ifFileExists = OHOS::FileExists(xinKeyPath);
    ASSERT_FALSE(ifFileExists);

    RekeyTestOpenCallback helpeee;
    int errorCode = E_OK;
    RdbStoreConfig storesConfig = GetRdbConfig(encryptedDatabasePath);
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(storesConfig, 1, helpeee, errorCode);
    ASSERT_NE(rdbStore, nullptr);
    ASSERT_EQ(errorCode, E_OK);
    rdbStore = nullptr;
    rdbStore = RdbHelper::GetRdbStore(storesConfig, 1, helpeee, errorCode);
    ASSERT_NE(rdbStore, nullptr);
    ASSERT_EQ(errorCode, E_OK);
}

/**
* @tc.name_: Rdb_Rekey_Test_004
* @tc.desc: try to open rdbStore and modify create date to a future time.
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_04, TestSize.Level1)
{
    std::string oldkeyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key";
    std::string xinKeyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key.new";

    bool ifFileExists = OHOS::FileExists(oldkeyPath);
    ASSERT_TRUE(ifFileExists);

    auto keyFileDate = GetKeyFileDate(encryptedDatabaseName);

    bool ifFileDateChanged = ChangeKeyFileDate(encryptedDatabaseName, -RdbRekeyTest::HOURS_EXPIRED);
    ASSERT_TRUE(ifFileDateChanged);

    auto changedDate = GetKeyFileDate(encryptedDatabaseName);
    ASSERT_GT(changedDate, keyFileDate);

    RdbStoreConfig storesConfig = GetRdbConfig(RdbRekeyTest::encryptedDatabasePath);
    RekeyTestOpenCallback helpeee;
    int errorCode;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(storesConfig, 1, helpeee, errorCode);
    ASSERT_NE(rdbStore, nullptr);

    ifFileExists = OHOS::FileExists(oldkeyPath);
    ASSERT_TRUE(ifFileExists);
    ifFileExists = OHOS::FileExists(xinKeyPath);
    ASSERT_FALSE(ifFileExists);

    keyFileDate = GetKeyFileDate(encryptedDatabaseName);
    ASSERT_EQ(changedDate, keyFileDate);

    CheckQueryData(rdbStore);
}

/**
* @tc.name_: Rdb_Rekey_RenameFailed_05
* @tc.desc: re key and rename failed the new key file.
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_RenameFailed_05, TestSize.Level1)
{
    std::string oldkeyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key";
    std::string xinKeyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key.new";

    bool ifFileExists = OHOS::FileExists(oldkeyPath);
    ASSERT_TRUE(ifFileExists);

    auto keyFileDate = GetKeyFileDate(encryptedDatabaseName);

    bool ifFileDateChanged = ChangeKeyFileDate(encryptedDatabaseName, RdbRekeyTest::HOURS_LONG_LONG_AGO);
    ASSERT_TRUE(ifFileDateChanged);

    auto changedDate = GetKeyFileDate(encryptedDatabaseName);
    ASSERT_GT(keyFileDate, changedDate);

    RdbStoreConfig storesConfig = GetRdbConfig(RdbRekeyTest::encryptedDatabasePath);
    RekeyTestOpenCallback helpeee;
    int errorCode = E_OK;
    for (int i = 0; i < 50; ++i) {
        auto rdbStore = RdbHelper::GetRdbStore(storesConfig, 1, helpeee, errorCode);
        ASSERT_NE(rdbStore, nullptr);
        ASSERT_EQ(errorCode, E_OK);
        rdbStore = nullptr;
        SaveNewKey(encryptedDatabaseName);
    }

    auto rdbStore = RdbHelper::GetRdbStore(storesConfig, 1, helpeee, errorCode);
    CheckQueryData(rdbStore);
}

/**
* @tc.name_: Rdb_Delete_Rekey_Test_06
* @tc.desc: test RdbStore rekey function
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_06, TestSize.Level1)
{
    std::string oldkeyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key";
    std::string xinKeyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key.new";

    bool ifFileExists = OHOS::FileExists(oldkeyPath);
    ASSERT_TRUE(ifFileExists);

    bool ifFileDateChanged = ChangeKeyFileDate(encryptedDatabaseName, RdbRekeyTest::HOURS_EXPIRED);
    ASSERT_TRUE(ifFileDateChanged);

    auto changedDate = GetKeyFileDate(encryptedDatabaseName);
    ASSERT_TRUE(std::chrono::system_clock::now() - changedDate > std::chrono::hours(RdbRekeyTest::HOURS_EXPIRED));

    RdbStoreConfig storesConfig = GetRdbNotRekeyConfig(RdbRekeyTest::encryptedDatabasePath);
    RekeyTestOpenCallback helpeee;
    int errorCode = E_OK;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(storesConfig, 1, helpeee, errorCode);
    ASSERT_NE(rdbStore, nullptr);
    ASSERT_EQ(errorCode, E_OK);

    ifFileExists = OHOS::FileExists(oldkeyPath);
    ASSERT_TRUE(ifFileExists);
    ifFileExists = OHOS::FileExists(xinKeyPath);
    ASSERT_FALSE(ifFileExists);

    ASSERT_TRUE(std::chrono::system_clock::now() - changedDate > std::chrono::hours(RdbRekeyTest::HOURS_EXPIRED));
    CheckQueryData(rdbStore);
}

/**
* @tc.name_: Rdb_Delete_Rekey_Test_07
* @tc.desc: test deleting the key file of the encrypted database
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_07, TestSize.Level1)
{
    RdbStoreConfig storesConfig(RdbRekeyTest::encryptedDatabasePath);
    storesConfig.SetSecurityLevel(SecurityLevel::S1);
    storesConfig.SetAllowRebuild(true);
    storesConfig.SetEncryptStatus(true);
    storesConfig.SetBundleName("com.example.test_rekey");
    RekeyTestOpenCallback helpeee;
    int errorCode = E_OK;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(storesConfig, 1, helpeee, errorCode);
    ASSERT_NE(rdbStore, nullptr);
    ASSERT_EQ(errorCode, E_OK);

    std::string oldkeyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key";
    bool ifFileExists = OHOS::FileExists(oldkeyPath);
    ASSERT_TRUE(ifFileExists);
    struct stat fileStat;
    ino_t inodeNumber1 = -1;
    if (stat(oldkeyPath.c_str(), &fileStat) == 0) {
        inodeNumber1 = fileStat.st_ino;
    }
    rdbStore = nullptr;

    {
        std::ofstream dbfsss(encryptedDatabasePath, std::ios_base::binary | std::ios_base::out);
        dbfsss.seekp(64);
        dbfsss.write("hello", 1);
        dbfsss.close();
    }

    rdbStore = RdbHelper::GetRdbStore(storesConfig, 1, helpeee, errorCode);
    ifFileExists = OHOS::FileExists(oldkeyPath);
    ASSERT_TRUE(ifFileExists);
    ino_t inodeNumber2 = -1;
    if (stat(oldkeyPath.c_str(), &fileStat) == 0) {
        inodeNumber2 = fileStat.st_ino;
    }

    ASSERT_NE(inodeNumber1, inodeNumber2);
}

/**
* @tc.name_: Rdb_Delete_Rekey_Test_08
* @tc.desc: test deleting the key file of the encrypted database
* @tc.type: FUNC
*/
HWTEST_F(RdbRekeyTest, Rdb_Rekey_08, TestSize.Level1)
{
    RdbStoreConfig storesConfig(RdbRekeyTest::encryptedDatabasePath);
    storesConfig.SetSecurityLevel(SecurityLevel::S1);
    storesConfig.SetAllowRebuild(false);
    storesConfig.SetEncryptStatus(true);
    storesConfig.SetBundleName("com.example.test_rekey");
    RekeyTestOpenCallback helpeee;
    int errorCode = E_OK;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(storesConfig, 1, helpeee, errorCode);
    ASSERT_NE(rdbStore, nullptr);
    ASSERT_EQ(errorCode, E_OK);

    std::string oldkeyPath = encryptedDatabaseKeyDir + RemoveSuffix(encryptedDatabaseName) + ".pub_key";
    bool ifFileExists = OHOS::FileExists(oldkeyPath);
    ASSERT_TRUE(ifFileExists);
    struct stat fileStat;
    ino_t inodeNumber1 = -1;
    if (stat(oldkeyPath.c_str(), &fileStat) == 0) {
        inodeNumber1 = fileStat.st_ino;
    }
    rdbStore = nullptr;

    {
        std::ofstream dbfsss(encryptedDatabasePath, std::ios_base::binary | std::ios_base::out);
        dbfsss.seekp(64);
        dbfsss.write("hello", 1);
        dbfsss.close();
    }

    rdbStore = RdbHelper::GetRdbStore(storesConfig, 1, helpeee, errorCode);
    ifFileExists = OHOS::FileExists(oldkeyPath);
    ASSERT_TRUE(ifFileExists);
    ino_t inodeNumber2 = -1;
    if (stat(oldkeyPath.c_str(), &fileStat) == 0) {
        inodeNumber2 = fileStat.st_ino;
    }

    ASSERT_EQ(inodeNumber1, inodeNumber2);
}
/* *
 * @tc.name_: Rdb_BackupRestoreTest_001
 * @tc.desc: backup and restore
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_001, TestSize.Level2)
{
    int errorCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::database_name);
    config.SetEncryptStatus(true);
    RdbStoreBackupRestoreTestOpenCallback helpeee;
    auto rdbStore = RdbHelper::GetRdbStore(config, 1, helpeee, errorCode);
    EXPECT_EQ(errorCode, E_OK);
    EXPECT_NE(rdbStore, nullptr);

    int64_t id_;
    ValuesBucket value;

    value.PutInt("id_", 1);
    value.PutString("name_", std::string("zhangsan"));
    value.PutInt("age_", 1);
    value.PutDouble("salary", 1);
    value.PutBlob("blobType", std::vector<uint8_t>{ 1, 1, 1 });
    int val = rdbStore->Insert(id_, "test", value);
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Backup(backupname);
    EXPECT_EQ(val, E_OK);

    int xrows = 0;
    val = rdbStore->Delete(xrows, "test", "id_ = 1");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, xrows);

    val = rdbStore->Restore(backupname);
    EXPECT_EQ(val, E_OK);

    std::shared_ptr<rdbResult> rdbResult =
        rdbStore->QuerySql("SELECT * FROM table WHERE name_ = ?", std::vector<std::string>{ "zhangsan" });
    val = rdbResult->GoToFirstRow();
    EXPECT_EQ(val, E_OK);
    val = rdbResult->Close();
    EXPECT_EQ(val, E_OK);
}

/* *
 * @tc.name_: Rdb_BackupRestoreTest_002
 * @tc.desc: backup and restore for broken original and broken backup db
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_002, TestSize.Level2)
{
    int errorCode = E_OK;
    RdbStoreConfig config(database_name);
    config.SetEncryptStatus(true);
    RdbStoreBackupRestoreTestOpenCallback helpeee;
    auto rdbStore = RdbHelper::GetRdbStore(config, 1, helpeee, errorCode);
    EXPECT_EQ(errorCode, E_OK);
    EXPECT_NE(rdbStore, nullptr);

    int64_t id_;
    ValuesBucket value;

    value.PutInt("id_", 1);
    value.PutString("name_", std::string("zhangsan"));
    value.PutInt("age_", 1);
    value.PutDouble("salary", 1);
    value.PutBlob("blobType", std::vector<uint8_t>{ 1, 1, 1 });
    int val = rdbStore->Insert(id_, "test", value);
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Backup(backupname);
    EXPECT_EQ(val, E_OK);
    rdbStore = nullptr;

    std::ofstream dbfsss(database_name, std::ios_base::binary | std::ios_base::out);
    dbfsss.seekp(64);
    dbfsss.write("hello", 1);
    dbfsss.close();
    std::ofstream fsBackupDb(backupname, std::ios_base::binary | std::ios_base::out);
    fsBackupDb.seekp(64);
    fsBackupDb.write("hello", 1);
    fsBackupDb.close();

    rdbStore = RdbHelper::GetRdbStore(config, 1, helpeee, errorCode);
    EXPECT_EQ(errorCode, E_SQLITE_CORRUPT);
    RdbHelper::DeleteRdbStore(database_name);

    rdbStore = RdbHelper::GetRdbStore(config, 1, helpeee, errorCode);
    EXPECT_EQ(errorCode, E_OK);

    val = rdbStore->Restore(backupname);
    EXPECT_EQ(val, E_SQLITE_CORRUPT);

    val = rdbStore->ExecuteSql(RdbStoreBackupRestoreTestOpenCallback::CREATE_TABLE_TEST);
    EXPECT_EQ(val, E_OK);
}

/* *
 * @tc.name_: Rdb_BackupRestoreTest_003
 * @tc.desc: backup and restore
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_003, TestSize.Level2)
{
    int errorCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::database_name);
    config.SetEncryptStatus(true);
    config.SetAllowRebuild(true);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    RdbStoreBackupRestoreTestOpenCallback helpeee;
    auto rdbStore = RdbHelper::GetRdbStore(config, 1, helpeee, errorCode);
    EXPECT_EQ(errorCode, E_OK);
    EXPECT_NE(rdbStore, nullptr);

    int64_t id_;
    ValuesBucket value;

    value.PutInt("id_", 1);
    value.PutString("name_", std::string("zhangsan"));
    value.PutInt("age_", 1);
    value.PutDouble("salary", 1);
    value.PutBlob("blobType", std::vector<uint8_t>{ 1, 1, 1 });
    int val = rdbStore->Insert(id_, "test", value);
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Backup(backupname);
    EXPECT_EQ(val, E_OK);

    int xrows = 0;
    val = rdbStore->Delete(xrows, "test", "id_ = 1");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, xrows);

    val = rdbStore->Restore(backupname);
    EXPECT_EQ(val, E_OK);

    std::shared_ptr<rdbResult> rdbResult =
        rdbStore->QuerySql("SELECT * FROM table WHERE name_ = ?", std::vector<std::string>{ "zhangsan" });
    val = rdbResult->GoToFirstRow();
    EXPECT_EQ(val, E_OK);
    val = rdbResult->Close();
    EXPECT_EQ(val, E_OK);
}

/* *
 * @tc.name_: Rdb_BackupRestoreTest_004
 * @tc.desc: hamode is replica, backup and deletestore and restore, after restore can insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_004, TestSize.Level2)
{
    int errorCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::database_name);
    config.SetEncryptStatus(true);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    RdbStoreBackupRestoreTestOpenCallback helpeee;
    auto rdbStore = RdbHelper::GetRdbStore(config, 1, helpeee, errorCode);
    EXPECT_EQ(errorCode, E_OK);
    EXPECT_NE(rdbStore, nullptr);

    int64_t id_;
    ValuesBucket value;

    value.Put("id_", 1);
    value.Put("name_", std::string("zhangsan"));
    value.Put("age_", 1);
    value.Put("salary", 1);
    value.Put("blobType", std::vector<uint8_t>{ 1, 1, 1 });
    int val = rdbStore->Insert(id_, "test", value);
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Backup(backupname);
    EXPECT_EQ(val, E_OK);

    val = RdbHelper::DeleteRdbStore(RdbStoreBackupRestoreTest::database_name);
    EXPECT_EQ(val, E_OK);

    val = rdbStore->Restore(backupname);
    EXPECT_EQ(val, E_OK);

    std::shared_ptr<rdbResult> rdbResult =
        rdbStore->QuerySql("SELECT * FROM table WHERE name_ = ?", std::vector<std::string>{ "zhangsan" });
    val = rdbResult->GoToFirstRow();
    EXPECT_EQ(val, E_OK);
    val = rdbResult->GoToNextRow();
    EXPECT_EQ(val, E_ROW_OUT_RANGE);
    val = rdbResult->Close();
    EXPECT_EQ(val, E_OK);

    value.Clear();
    value.Put("id_", 1);
    value.Put("name_", std::string("lisa"));
    value.Put("age_", 1);
    value.Put("salary", 101);
    value.Put("blobType", std::vector<uint8_t>{ 1, 1, 1 });
    val = rdbStore->Insert(id_, "test", value);
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    rdbResult = rdbStore->QuerySql("SELECT * FROM table WHERE name_ = ?", std::vector<std::string>{ "lisa" });
    val = rdbResult->GoToFirstRow();
    EXPECT_EQ(val, E_OK);
    val = rdbResult->GoToNextRow();
    EXPECT_EQ(val, E_ROW_OUT_RANGE);
    val = rdbResult->Close();
    EXPECT_EQ(val, E_OK);
}

/* *
 * @tc.name_: Rdb_BackupRestoreTest_005
 * @tc.desc: hamode is replica , backup and restore for broken original db, and after restore can insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_005, TestSize.Level2)
{
    int errorCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::database_name);
    config.SetEncryptStatus(true);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    RdbStoreBackupRestoreTestOpenCallback helpeee;
    auto rdbStore = RdbHelper::GetRdbStore(config, 1, helpeee, errorCode);
    EXPECT_EQ(errorCode, E_OK);
    EXPECT_NE(rdbStore, nullptr);

    int64_t id_;
    ValuesBucket value;

    value.Put("id_", 1);
    value.Put("name_", std::string("zhangsan"));
    value.Put("age_", 1);
    value.Put("salary", 1);
    value.Put("blobType", std::vector<uint8_t>{ 1, 1, 1 });
    int val = rdbStore->Insert(id_, "test", value);
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Backup(backupname);
    EXPECT_EQ(val, E_OK);

    rdbStore = nullptr;
    CorruptDoubleWriteStore();
    rdbStore = RdbHelper::GetRdbStore(config, 1, helpeee, errorCode);
    EXPECT_EQ(errorCode, E_OK);

    int xrows = 0;
    val = rdbStore->Delete(xrows, "test", "id_ = 1");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, xrows);

    val = rdbStore->Restore(backupname);
    EXPECT_EQ(val, E_OK);

    std::shared_ptr<rdbResult> rdbResult =
        rdbStore->QuerySql("SELECT * FROM table WHERE name_ = ?", std::vector<std::string>{ "zhangsan" });
    val = rdbResult->GoToFirstRow();
    EXPECT_EQ(val, E_OK);
    val = rdbResult->GoToNextRow();
    EXPECT_EQ(val, E_ROW_OUT_RANGE);
    val = rdbResult->Close();
    EXPECT_EQ(val, E_OK);
}

/* *
 * @tc.name_: Rdb_BackupRestoreTest_006
 * @tc.desc: hamode is replica , backup and restore, aftre restore ,rdbStore can insert data and delete data and query
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_006, TestSize.Level2)
{
    int errorCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::database_name);
    config.SetEncryptStatus(true);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    RdbStoreBackupRestoreTestOpenCallback helpeee;
    auto rdbStore = RdbHelper::GetRdbStore(config, 1, helpeee, errorCode);
    EXPECT_EQ(errorCode, E_OK);
    EXPECT_NE(rdbStore, nullptr);

    int64_t id_;
    ValuesBucket value;

    value.Put("id_", 1);
    value.Put("name_", std::string("zhangsan"));
    value.Put("age_", 1);
    value.Put("salary", 1);
    value.Put("blobType", std::vector<uint8_t>{ 1, 1, 1 });
    int val = rdbStore->Insert(id_, "test", value);
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Backup(backupname);
    EXPECT_EQ(val, E_OK);

    int xrows = 0;
    val = rdbStore->Delete(xrows, "test", "id_ = 1");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, xrows);

    val = rdbStore->Restore(backupname);
    EXPECT_EQ(val, E_OK);
    std::shared_ptr<rdbResult> rdbResult =
        rdbStore->QuerySql("SELECT * FROM table WHERE name_ = ?", std::vector<std::string>{ "zhangsan" });
    val = rdbResult->GoToFirstRow();
    EXPECT_EQ(val, E_OK);
    val = rdbResult->Close();
    EXPECT_EQ(val, E_OK);

    xrows = 0;
    val = rdbStore->Delete(xrows, "test", "id_ = 1");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, xrows);
    rdbResult = rdbStore->QuerySql("SELECT * FROM table WHERE name_ = ?", std::vector<std::string>{ "zhangsan" });
    val = rdbResult->GoToFirstRow();
    EXPECT_EQ(val, E_ROW_OUT_RANGE);
    val = rdbResult->Close();
    EXPECT_EQ(val, E_OK);
}

/* *
 * @tc.name_: Rdb_BackupRestoreTest_007
 * @tc.desc: hamode is replica , deletestore , cannot backup and restore
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_007, TestSize.Level2)
{
    int errorCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::database_name);
    config.SetEncryptStatus(true);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    RdbStoreBackupRestoreTestOpenCallback helpeee;
    auto rdbStore = RdbHelper::GetRdbStore(config, 1, helpeee, errorCode);
    EXPECT_EQ(errorCode, E_OK);
    EXPECT_NE(rdbStore, nullptr);

    int64_t id_;
    ValuesBucket value;

    value.Put("id_", 1);
    value.Put("name_", std::string("zhangsan"));
    value.Put("age_", 1);
    value.Put("salary", 1);
    value.Put("blobType", std::vector<uint8_t>{ 1, 1, 1 });
    int val = rdbStore->Insert(id_, "test", value);
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = RdbHelper::DeleteRdbStore(database_name);
    EXPECT_EQ(val, E_OK);

    val = rdbStore->Backup(backupname);
    EXPECT_EQ(val, E_DB_NOT_EXIST);
    EXPECT_NE(0, access(backupname, F_OK));
    EXPECT_NE(0, access(slaveDataBaseName, F_OK));

    val = rdbStore->Restore(backupname);
    EXPECT_EQ(val, E_INVALID_FILE_PATH);

    std::shared_ptr<rdbResult> rdbResult =
        rdbStore->QuerySql("SELECT * FROM table WHERE name_ = ?", std::vector<std::string>{ "zhangsan" });
    val = rdbResult->GoToFirstRow();
    EXPECT_EQ(val, E_SQLITE_IOERR);
    val = rdbResult->Close();
    EXPECT_EQ(val, E_OK);
}

/* *
 * @tc.name_: Rdb_BackupRestoreTest_008
 * @tc.desc: hamode is replica , backup and restore, check slavestore and backupstore
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_008, TestSize.Level2)
{
    int errorCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::database_name);
    config.SetEncryptStatus(true);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    RdbStoreBackupRestoreTestOpenCallback helpeee;
    auto rdbStore = RdbHelper::GetRdbStore(config, 1, helpeee, errorCode);
    EXPECT_EQ(errorCode, E_OK);
    EXPECT_NE(rdbStore, nullptr);

    int64_t id_;
    ValuesBucket value;

    value.Put("id_", 1);
    value.Put("name_", std::string("zhangsan"));
    value.Put("age_", 1);
    value.Put("salary", 1);
    value.Put("blobType", std::vector<uint8_t>{ 1, 1, 1 });
    int val = rdbStore->Insert(id_, "test", value);
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Backup(backupname);
    EXPECT_EQ(val, E_OK);

    int xrows = 0;
    val = rdbStore->Delete(xrows, "test", "id_ = 1");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, xrows);

    val = rdbStore->Restore(backupname);
    EXPECT_EQ(val, E_OK);

    std::shared_ptr<rdbResult> rdbResult =
        rdbStore->QuerySql("SELECT * FROM table WHERE name_ = ?", std::vector<std::string>{ "zhangsan" });
    val = rdbResult->GoToFirstRow();
    EXPECT_EQ(val, E_OK);
    val = rdbResult->GoToNextRow();
    EXPECT_EQ(val, E_ROW_OUT_RANGE);
    val = rdbResult->Close();
    EXPECT_EQ(val, E_OK);

    EXPECT_EQ(0, access(backupname, F_OK));
    EXPECT_EQ(0, access(slaveDataBaseName, F_OK));
}

/* *
 * @tc.name_: Rdb_BackupRestoreTest_009
 * @tc.desc: sql func empty param test
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_009, TestSize.Level2)
{
    int errorCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::database_name);
    config.SetEncryptStatus(false);
    RdbStoreBackupRestoreTestOpenCallback helpeee;
    auto rdbStore = RdbHelper::GetRdbStore(config, 1, helpeee, errorCode);
    EXPECT_EQ(errorCode, E_OK);
    EXPECT_NE(rdbStore, nullptr);

    auto errcode = rdbStore->ExecuteSql("SELECT import_db_from_path()");

    EXPECT_EQ(errcode, E_SQLITE_ERROR);

    auto [code, result] = rdbStore->Execute("pragma integrity_check");
    std::string val;
    result.GetString(val);
    EXPECT_EQ(E_OK, code);
    EXPECT_EQ("ok", val);

    rdbStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbStoreBackupRestoreTest::database_name);
}

/* *
 * @tc.name_: Rdb_BackupRestoreTest_010
 * @tc.desc: source db empty path test
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_010, TestSize.Level2)
{
    int errorCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::database_name);
    config.SetEncryptStatus(false);
    RdbStoreBackupRestoreTestOpenCallback helpeee;
    auto rdbStore = RdbHelper::GetRdbStore(config, 1, helpeee, errorCode);
    EXPECT_EQ(errorCode, E_OK);
    EXPECT_NE(rdbStore, nullptr);

    auto errcode = rdbStore->ExecuteSql("SELECT import_db_from_path('')");

    EXPECT_EQ(errcode, E_SQLITE_CANTOPEN);

    auto [code, result] = rdbStore->Execute("pragma integrity_check");
    std::string val;
    result.GetString(val);
    EXPECT_EQ(E_OK, code);
    EXPECT_EQ("ok", val);

    rdbStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbStoreBackupRestoreTest::database_name);
}

/* *
 * @tc.name_: Rdb_BackupRestoreTest_011
 * @tc.desc: souce db not exist test
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_011, TestSize.Level2)
{
    int errorCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::database_name);
    config.SetEncryptStatus(false);
    RdbStoreBackupRestoreTestOpenCallback helpeee;
    auto rdbStore = RdbHelper::GetRdbStore(config, 1, helpeee, errorCode);
    EXPECT_EQ(errorCode, E_OK);
    EXPECT_NE(rdbStore, nullptr);

    auto errcode = rdbStore->ExecuteSql("SELECT import_db_from_path('/path/not_exist.db')");

    EXPECT_EQ(errcode, E_SQLITE_CANTOPEN);

    auto [code, result] = rdbStore->Execute("pragma integrity_check");
    std::string val;
    result.GetString(val);
    EXPECT_EQ(E_OK, code);
    EXPECT_EQ("ok", val);

    rdbStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbStoreBackupRestoreTest::database_name);
}

/* *
 * @tc.name_: Rdb_BackupRestoreTest_012
 * @tc.desc: source db corrupt test
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_012, TestSize.Level2)
{
    int errorCode = E_OK;
    std::string destDbPath = "/data/test/dest.db";
    std::string sourceDbPath = "/data/test/source.db";

    RdbStoreConfig config(destDbPath);
    config.SetEncryptStatus(false);
    RdbStoreBackupRestoreTestOpenCallback helpeee;
    auto dest = RdbHelper::GetRdbStore(config, 1, helpeee, errorCode);
    EXPECT_EQ(errorCode, E_OK);
    EXPECT_NE(dest, nullptr);

    RdbStoreConfig sourceConfig(sourceDbPath);
    sourceConfig.SetEncryptStatus(false);
    RdbStoreBackupRestoreTestOpenCallback helper1;
    auto source = RdbHelper::GetRdbStore(sourceConfig, 1, helper1, errorCode);
    source = nullptr;

    std::fstream sourceFile(sourceDbPath, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(sourceFile.is_open());
    sourceFile.seekp(0x0f40, std::ios::beg);
    std::vector<char> buffer(1, 0xFF);
    sourceFile.write(buffer.data(), buffer.size());
    sourceFile.close();

    auto errcode = dest->ExecuteSql("SELECT import_db_from_path('" + sourceDbPath + "')");

    EXPECT_EQ(errcode, E_SQLITE_CORRUPT);

    auto [code, result] = dest->Execute("pragma integrity_check");
    std::string val;
    result.GetString(val);
    EXPECT_EQ(E_OK, code);
    EXPECT_EQ("ok", val);

    dest = nullptr;
    RdbHelper::DeleteRdbStore(destDbPath);
    RdbHelper::DeleteRdbStore(sourceDbPath);
}

/* *
 * @tc.name_: Rdb_BackupRestoreTest_013
 * @tc.desc: import from source db test
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_013, TestSize.Level2)
{
    int errorCode = E_OK;
    std::string destDbPath = "/data/test/dest.db";
    std::string sourceDbPath = "/data/test/source.db";

    RdbStoreConfig config(destDbPath);
    config.SetEncryptStatus(false);
    RdbStoreBackupRestoreTestOpenCallback helpeee;
    auto dest = RdbHelper::GetRdbStore(config, 1, helpeee, errorCode);
    EXPECT_EQ(errorCode, E_OK);
    EXPECT_NE(dest, nullptr);

    RdbStoreConfig sourceConfig(sourceDbPath);
    sourceConfig.SetEncryptStatus(false);
    RdbStoreBackupRestoreTestOpenCallback helper1;
    auto source = RdbHelper::GetRdbStore(sourceConfig, 1, helper1, errorCode);

    for (uint i = 0; i < 100; i++) {
        std::vector<ValuesBucket> valuesBuckets;

        for (uint j = 0; j < 100; j++) {
            ValuesBucket value;

            value.Put("name_", "zhangsan");
            value.PutString("name_", "zhangSan");
            valuesBuckets.push_back(std::move(value));
        }

        int64_t insertRowCount;
        int error = source->BatchInsert(insertRowCount, "test", valuesBuckets);
        EXPECT_EQ(error, E_OK);
    }
    source = nullptr;
    EXPECT_EQ(E_OK, dest->ExecuteSql("SELECT import_db_from_path('" + sourceDbPath + "')"));

    auto rdbResult = dest->QuerySql("SELECT * FROM table");
    int rowCount;
    EXPECT_EQ(E_OK, rdbResult->GetRowCount(rowCount));

    EXPECT_EQ(rowCount, 10000);

    auto [code, result] = dest->Execute("pragma integrity_check");
    std::string val;
    result.GetString(val);
    EXPECT_EQ(E_OK, code);
    EXPECT_EQ("ok", val);

    dest = nullptr;
    RdbHelper::DeleteRdbStore(destDbPath);
    RdbHelper::DeleteRdbStore(sourceDbPath);
}

/* *
 * @tc.name_: Rdb_BackupRestoreTest_014
 * @tc.desc: sql func empty param test
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_014, TestSize.Level2)
{
    int errorCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::database_name);
    config.SetEncryptStatus(false);
    RdbStoreBackupRestoreTestOpenCallback helpeee;
    auto rdbStore = RdbHelper::GetRdbStore(config, 1, helpeee, errorCode);
    EXPECT_EQ(errorCode, E_OK);
    EXPECT_NE(rdbStore, nullptr);

    auto errcode = rdbStore->ExecuteSql("SELECT import_db_from_path");

    EXPECT_EQ(errcode, E_SQLITE_SCHEMA);

    auto [code, result] = rdbStore->Execute("pragma integrity_check");
    std::string val;
    result.GetString(val);
    EXPECT_EQ(E_OK, code);
    EXPECT_EQ("ok", val);

    rdbStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbStoreBackupRestoreTest::database_name);
}
/**
 * @tc.name_: Insert_BigInt_INT64
 * @tc.desc: test insert bigint to rdb rdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbSecurityManagerTest, LockUnlock, TestSize.Level1)
{
    auto blockResult = std::make_shared<OHOS::BlockData<bool>>(1, false);
    RdbSecurityManager::KeyFILE KeyFILE(dbFile_);
    KeyFILE.Lock();
    std::thread thread([dbFile = dbFile_, blockResult]() {
        RdbSecurityManager::KeyFILE KeyFILE(dbFile);
        KeyFILE.Lock();
        KeyFILE.Unlock();
        blockResult->SetValue(true);
    });
    auto beforeUnlock = blockResult->GetValue();
    blockResult->Clear(false);
    KeyFILE.Unlock();
    auto afterUnlock = blockResult->GetValue();
    ASSERT_FALSE(beforeUnlock);
    ASSERT_TRUE(afterUnlock);
    thread.join();
}

/**
 * @tc.name_: LoadSecretKeyFromDiskTest
 * @tc.desc: test load secret key from disk test
 * @tc.type: FUNC
 */
HWTEST_F(RdbSecurityManagerTest, LoadSecretKeyFromDiskTest, TestSize.Level1)
{
    int errorCode = E_OK;
    std::string name = RDB_TEST_PATH + "secret_key_load_test.db";
    RdbStoreConfig config(name);
    config.SetEncryptStatus(true);
    config.SetBundleName(BUNDLE_NAME);
    RdbStoreSecurityManagerTestOpenCallback helpeee;

    auto rdbStore = RdbHelper::GetRdbStore(config, 1, helpeee, errorCode);
    EXPECT_EQ(errorCode, E_OK);
    EXPECT_NE(rdbStore, nullptr);
    rdbStore = nullptr;

    RdbSecurityManager::KeyFILE keysfilee(name);
    const std::string file = keysfilee.GetKeyFile(RdbSecurityManager::KeyFileType::PUB_KEY_FILE);
    std::vector<char> keyfile1;
    ASSERT_TRUE(OHOS::LoadBufferFromFile(file, keyfile1));

    std::vector<char> content = { 'a' };
    bool val = OHOS::SaveBufferToFile(file, content);
    ASSERT_TRUE(val);

    std::vector<char> keyfile2;
    ASSERT_TRUE(OHOS::LoadBufferFromFile(file, keyfile2));
    ASSERT_NE(keyfile1.size(), keyfile2.size());

    RdbStoreConfig config1(name);
    config1.SetEncryptStatus(true);
    config1.SetBundleName(BUNDLE_NAME);
    RdbStoreSecurityManagerTestOpenCallback helper1;
    auto store1 = RdbHelper::GetRdbStore(config1, 1, helper1, errorCode);
    EXPECT_EQ(errorCode, E_OK);
    EXPECT_NE(store1, nullptr);

    RdbHelper::DeleteRdbStore(config);
}
/**
 * @tc.name_: RdbStore_Delete_001
 * @tc.desc: test RdbStore update, select id_ and update one row
 * @tc.type: FUNC
 */
HWTEST_F(RdbDeleteTest, RdbStore_Delete_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &rdbStore = RdbDeleteTest::rdbStore;

    int64_t id_;
    int xrows;

    int val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Insert(id_, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Delete(xrows, "test", "id_ = 1");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, xrows);

    std::shared_ptr<rdbResult> rdbResult =
        rdbStore->QuerySql("SELECT * FROM table WHERE id_ = ?", std::vector<std::string>{ "1" });
    EXPECT_NE(rdbResult, nullptr);
    val = rdbResult->GoToNextRow();
    EXPECT_EQ(val, E_ROW_OUT_RANGE);
    val = rdbResult->Close();
    EXPECT_EQ(val, E_OK);

    rdbResult = rdbStore->QuerySql("SELECT * FROM table WHERE id_ = ?", std::vector<std::string>{ "1" });
    EXPECT_NE(rdbResult, nullptr);
    val = rdbResult->GoToFirstRow();
    EXPECT_EQ(val, E_OK);
    val = rdbResult->GoToNextRow();
    EXPECT_EQ(val, E_ROW_OUT_RANGE);
    val = rdbResult->Close();
    EXPECT_EQ(val, E_OK);

    rdbResult = rdbStore->QuerySql("SELECT * FROM table WHERE id_ = 1", std::vector<std::string>());
    EXPECT_NE(rdbResult, nullptr);
    val = rdbResult->GoToFirstRow();
    EXPECT_EQ(val, E_OK);
    val = rdbResult->GoToNextRow();
    EXPECT_EQ(val, E_ROW_OUT_RANGE);
    val = rdbResult->Close();
    EXPECT_EQ(val, E_OK);
}

/**
 * @tc.name_: RdbStore_Delete_002
 * @tc.desc: test RdbStore update, select id_ and update one row
 * @tc.type: FUNC
 */
HWTEST_F(RdbDeleteTest, RdbStore_Delete_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &rdbStore = RdbDeleteTest::rdbStore;

    int64_t id_;
    ValuesBucket value;
    int xrows;

    value.PutInt("id_", 1);
    value.PutString("name_", std::string("zhangsan"));
    value.PutInt("age_", 1);
    value.PutDouble("salary", 1);
    value.PutBlob("blobType", std::vector<uint8_t>{ 1, 1, 1 });
    int val = rdbStore->Insert(id_, "test", value);
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    value.Clear();
    value.PutInt("id_", 1);
    value.PutString("name_", std::string("lisi"));
    value.PutInt("age_", 1);
    value.PutDouble("salary", 1);
    value.PutBlob("blobType", std::vector<uint8_t>{ 1, 1, 1 });
    val = rdbStore->Insert(id_, "test", value);
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    value.Clear();
    value.PutInt("id_", 1);
    value.PutString("name_", std::string("wangyjing"));
    value.PutInt("age_", 1);
    value.PutDouble("salary", 1);
    value.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    val = rdbStore->Insert(id_, "test", value);
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Delete(xrows, "test");
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, xrows);

    std::shared_ptr<rdbResult> rdbResult = rdbStore->QuerySql("SELECT * FROM table");
    EXPECT_NE(rdbResult, nullptr);
    val = rdbResult->GoToNextRow();
    EXPECT_EQ(val, E_ROW_OUT_RANGE);
    val = rdbResult->Close();
    EXPECT_EQ(val, E_OK);
}

/**
 * @tc.name_: RdbStore_Delete_003
 * @tc.desc: test RdbStore update, select id_ and update one row
 * @tc.type: FUNC
 */
HWTEST_F(RdbDeleteTest, RdbStore_Delete_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &rdbStore = RdbDeleteTest::rdbStore;

    int64_t id_;
    ValuesBucket value;
    int xrows;

    value.PutInt("id_", 1);
    value.PutString("name_", std::string("zhangsan"));
    value.PutInt("age_", 1);
    value.PutDouble("salary", 1);
    value.PutBlob("blobType", std::vector<uint8_t>{ 1, 1, 1 });
    int val = rdbStore->Insert(id_, "test", value);
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(1, id_);

    val = rdbStore->Delete(xrows, "", "id_ = ?", std::vector<std::string>{ "1" });
    EXPECT_EQ(val, E_EMPTY_TABLE_NAME);

    val = rdbStore->Delete(xrows, "wrongTable", "id_ = ?", std::vector<std::string>{ "1" });
    EXPECT_EQ(val, E_SQLITE_ERROR);

    val = rdbStore->Delete(xrows, "test", "wrong sql id_ = ?", std::vector<std::string>{ "1" });
    EXPECT_EQ(val, E_SQLITE_ERROR);

    val = rdbStore->Delete(xrows, "test", "id_ = 1", std::vector<std::string>());
    EXPECT_EQ(val, E_OK);
    EXPECT_EQ(xrows, 1);
}
} // namespace DistributedRdb
} // namespace OHOS
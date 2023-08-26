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
#include <vector>
#include "device_manager.h"
#include "device_manager_callback.h"
#include "dm_device_info.h"
#include "hilog/log.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store_impl.h"
#include "rdb_types.h"
#include "result_set_proxy.h"

#include <regex>

#include "distributed_major.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedRdb;
using namespace testing::ext;
using namespace OHOS::DistributeSystemTest;
using namespace OHOS::DistributedHardware;
using namespace OHOS::HiviewDFX;
namespace  {
const int MSG_LENGTH = 100;
constexpr HiLogLabel LABEL = {LOG_CORE, 0, "DistributedTest"};
static const std::string RDB_TEST_PATH = "/data/test/";
constexpr const char *PKG_NAME = "rdb_store_distributed_test";
class DistributedTest : public DistributeTest {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store_;
    static std::vector <DmDeviceInfo> deviceInfos_;
    static void InitDevManager();
};

const std::string DistributedTest::DATABASE_NAME = RDB_TEST_PATH + "distributed_rdb.db";
std::shared_ptr<RdbStore> DistributedTest::store_ = nullptr;
std::vector<DmDeviceInfo> DistributedTest::deviceInfos_;

class DMStateCallback : public DeviceStateCallback {
public:
    explicit DMStateCallback() {}
    void OnDeviceOnline(const DmDeviceInfo &deviceInfo) override {}
    void OnDeviceOffline(const DmDeviceInfo &deviceInfo) override {}
    void OnDeviceChanged(const DmDeviceInfo &deviceInfo) override {}
    void OnDeviceReady(const DmDeviceInfo &deviceInfo) override {}
};

class DmDeathCallback : public DmInitCallback {
public:
    explicit DmDeathCallback() {}
    void OnRemoteDied() override {}
};

void DistributedTest::InitDevManager()
{
    auto &deviceManager = DeviceManager::GetInstance();
    auto deviceInitCallback = std::make_shared<DmDeathCallback>();
    auto deviceCallback = std::make_shared<DMStateCallback>();
    deviceManager.InitDeviceManager(PKG_NAME, deviceInitCallback);
    deviceManager.RegisterDevStateCallback(PKG_NAME, "", deviceCallback);
}

class DistributedTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &rdbStore) override;
    int OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

const std::string DistributedTestOpenCallback::CREATE_TABLE_TEST = std::string("CREATE TABLE IF NOT EXISTS test ")
                                                                + std::string("(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                              "name TEXT NOT NULL, age INTEGER, salary "
                                                                              "REAL, blobType BLOB)");

int DistributedTestOpenCallback::OnCreate(RdbStore &store_)
{
    return store_.ExecuteSql(CREATE_TABLE_TEST);
}

int DistributedTestOpenCallback::OnUpgrade(RdbStore &store_, int oldVersion, int newVersion)
{
    return E_OK;
}

void DistributedTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    RdbStoreConfig config(DistributedTest::DATABASE_NAME);
    config.SetBundleName("com.example.distributed.rdb");
    config.SetName("distributed_rdb.db");
    DistributedTestOpenCallback helper;
    DistributedTest::store_ = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(DistributedTest::store_, nullptr);
    InitDevManager();
    DeviceManager::GetInstance().GetTrustedDeviceList(PKG_NAME, "", deviceInfos_);
}

void DistributedTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(DistributedTest::DATABASE_NAME);
}

void DistributedTest::SetUp(void)
{
    store_->ExecuteSql("DELETE FROM test");
}

void DistributedTest::TearDown(void)
{}

/**
 * @tc.name: RemoteQuery001
 * @tc.desc: normal testcase of DistributedTest
 * @tc.type: FUNC
 * @tc.require:issueI5JV75
 */
HWTEST_F(DistributedTest, RemoteQuery001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store_ = DistributedTest::store_;
    int ret;
    std::string returvalue;
    std::string msgBuf = "recall function message test.";
    ret = SendMessage(AGENT_NO::ONE, msgBuf, MSG_LENGTH,
        [&](const std::string &szreturnbuf, int rlen)->bool {
        returvalue = szreturnbuf;
        return true;
    });
    std::vector<std::string> tables = {"test"};
    DeviceManager::GetInstance().GetTrustedDeviceList(PKG_NAME, "", deviceInfos_);
    int errCode = E_ERROR;
    std::string test = store_->ObtainDistributedTableName(deviceInfos_[0].networkId, tables[0], errCode);
    AbsRdbPredicates predicate(tables[0]);
    predicate.EqualTo("name", "zhangsan");
    std::vector<std::string> columns;
    errCode = E_ERROR;
    std::shared_ptr<ResultSet> resultSet = store_->RemoteQuery(deviceInfos_[0].networkId, predicate, columns, errCode);

    EXPECT_TRUE(ret > 0);
    EXPECT_EQ(returvalue, "zhangsan");
}


/**
 * @tc.name: ResultSetProxy001
 * @tc.desc: Abnormal testcase of distributed ResultSetProxy, if resultSet is Empty
 * @tc.type: FUNC
 */
HWTEST_F(DistributedTest, ResultSetProxy001, TestSize.Level1)
{
    int errCode = 0;
    std::shared_ptr<OHOS::NativeRdb::ResultSetProxy> resultSet;
    ColumnType columnType;
    errCode = resultSet->GetColumnType(1, columnType);
    EXPECT_NE(E_OK, errCode);

    std::string columnName;
    errCode = resultSet->GetColumnName(1, columnName);
    EXPECT_NE(E_OK, errCode);

    std::vector<uint8_t> blob;
    errCode = resultSet->GetBlob(1, blob);
    EXPECT_NE(E_OK, errCode);

    std::string getStringvalue;
    errCode = resultSet->GetString(1, getStringvalue);
    EXPECT_NE(E_OK, errCode);

    int getIntvalue;
    errCode = resultSet->GetInt(1, getIntvalue);
    EXPECT_NE(E_OK, errCode);

    int64_t getLongvalue;
    errCode = resultSet->GetLong(1, getLongvalue);
    EXPECT_NE(E_OK, errCode);

    double getDoublevalue;
    errCode = resultSet->GetDouble(1, getDoublevalue);
    EXPECT_NE(E_OK, errCode);

    bool isNull;
    errCode = resultSet->IsColumnNull(1, isNull);
    EXPECT_NE(E_OK, errCode);
}
}

int main(int argc, char *argv[])
{
    HiLog::Info(LABEL, "begin");
    g_pDistributetestEnv = new DistributeTestEnvironment("major.desc");
    testing::AddGlobalTestEnvironment(g_pDistributetestEnv);
    testing::GTEST_FLAG(output) = "xml:./";
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
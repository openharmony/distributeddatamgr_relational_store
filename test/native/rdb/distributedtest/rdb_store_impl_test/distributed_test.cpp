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
#include "hilog/log.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store_impl.h"
#include "rdb_types.h"
#include "distributed_kv_data_manager.h"

#include <regex>

#include "distributed_major.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedRdb;
using namespace testing::ext;
using namespace OHOS::DistributedKv;
using namespace OHOS::DistributeSystemTest;
using namespace OHOS::HiviewDFX;
namespace  {
const int MSG_LENGTH = 100;
constexpr HiLogLabel LABEL = {LOG_CORE, 0, "DistributedTest"};
static const std::string RDB_TEST_PATH = "/data/test/";
class DistributedTest : public DistributeTest {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store_;
    static DistributedKvDataManager manager_;
    static std::vector <DeviceInfo> deviceInfos_;
};

const std::string DistributedTest::DATABASE_NAME = RDB_TEST_PATH + "distributed_rdb.db";
std::shared_ptr<RdbStore> DistributedTest::store_ = nullptr;
DistributedKvDataManager DistributedTest::manager_;
std::vector<DeviceInfo> DistributedTest::deviceInfos_;

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
    manager_.GetDeviceList(deviceInfos_, DeviceFilterStrategy::NO_FILTER);
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
    manager_.GetDeviceList(deviceInfos_, DeviceFilterStrategy::NO_FILTER);
    int errCode = E_ERROR;
    std::string test = store_->ObtainDistributedTableName(deviceInfos_[0].deviceId, tables[0], errCode);
    AbsRdbPredicates predicate(tables[0]);
    predicate.EqualTo("name", "zhangsan");
    std::vector<std::string> columns;
    errCode = E_ERROR;
    std::shared_ptr<ResultSet> resultSet = store_->RemoteQuery(deviceInfos_[0].deviceId, predicate, columns, errCode);

    EXPECT_TRUE(ret > 0);
    EXPECT_EQ(returvalue, "zhangsan");
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
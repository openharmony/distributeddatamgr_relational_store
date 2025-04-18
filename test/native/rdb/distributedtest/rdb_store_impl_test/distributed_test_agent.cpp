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

#include <regex>
#include <string>
#include <vector>

#include "distributed_agent.h"
#include "hilog/log.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store_impl.h"
#include "rdb_types.h"

using namespace testing;
using namespace OHOS;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributeSystemTest;
using namespace OHOS::DistributedRdb;
using namespace OHOS::HiviewDFX;

namespace {
constexpr HiLogLabel LABEL = { LOG_CORE, 0, "DistributedTestAgent" };
static const std::string RDB_TEST_PATH = "/data/test/";
static constexpr int AGE = 18;
static constexpr double SALARY = 100.5;
class DistributedTestAgent : public DistributedAgent {
public:
    DistributedTestAgent();
    ~DistributedTestAgent();
    virtual bool SetUp();
    virtual bool TearDown();
    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store_;

    virtual int OnProcessMsg(const std::string &strMsg, int len, std::string &strReturnValue, int returnBufL);
    using SyncOption = DistributedRdb::SyncOption;
    using SyncCallback = DistributedRdb::AsyncBrief;
};

const std::string DistributedTestAgent::DATABASE_NAME = RDB_TEST_PATH + "distributed_rdb.db";
std::shared_ptr<RdbStore> DistributedTestAgent::store_ = nullptr;

class DistributedTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

const std::string DistributedTestOpenCallback::CREATE_TABLE_TEST =
    std::string("CREATE TABLE IF NOT EXISTS test ") + std::string("(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                  "name TEXT NOT NULL, age INTEGER, salary "
                                                                  "REAL, blobType BLOB)");

int DistributedTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int DistributedTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

DistributedTestAgent::DistributedTestAgent()
{
}

DistributedTestAgent::~DistributedTestAgent()
{
}

bool DistributedTestAgent::SetUp()
{
    return true;
}

bool DistributedTestAgent::TearDown()
{
    return true;
}

int DistributedTestAgent::OnProcessMsg(const std::string &strMsg, int len, std::string &strReturnValue, int returnBufL)
{
    int errCode = E_OK;
    RdbStoreConfig config(DistributedTestAgent::DATABASE_NAME);
    config.SetBundleName("com.example.distributed.rdb");
    config.SetName("distributed_rdb.db");
    config.SetEncryptStatus(true);
    DistributedTestOpenCallback helper;
    DistributedTestAgent::store_ = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    std::shared_ptr<RdbStore> &store_ = DistributedTestAgent::store_;

    int64_t id;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", AGE);
    values.PutDouble("salary", SALARY);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int status = -2;

    std::vector<std::string> tables = { "test" };
    store_->SetDistributedTables(tables);

    status = store_->Insert(id, "test", values);

    AbsRdbPredicates predicate(tables[0]);
    predicate.EqualTo("name", "zhangsan");
    predicate.InAllDevices();

    std::shared_ptr<ResultSet> resultSet =
        store_->QuerySql("SELECT * FROM test WHERE name = ?", std::vector<std::string>{ "zhangsan" });
    if (resultSet != nullptr) {
        int position;
        int columnIndex;
        std::string strVal;
        resultSet->GetRowIndex(position);
        resultSet->GoToFirstRow();
        resultSet->GetColumnIndex("name", columnIndex);
        resultSet->GetString(columnIndex, strVal);
        strReturnValue = strVal;
    } else {
        strReturnValue = std::to_string(status);
    }
    return strReturnValue.size();
}
} // namespace

int main()
{
    DistributedTestAgent obj;
    if (obj.SetUp()) {
        obj.Start("agent.desc");
        obj.Join();
    } else {
        HiLog::Error(LABEL, "Init environment failed.");
    }
    if (obj.TearDown()) {
        return 0;
    } else {
        HiLog::Error(LABEL, "Clear environment failed.");
        return -1;
    }
}

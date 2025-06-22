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
#include "rdb_distributed_test_ut2fuzz.h"

#include <fcntl.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <iostream>
#include <string>

#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace OHOS;
using namespace OHOS::NativeRdb;
namespace OHOS {

static const std::string DATABASE_NAME = "/data/test/distributed_rdb.db";
static std::shared_ptr<RdbStore> rdbStore;

class TestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override
    {
        std::string sql = "CREATE TABLE IF NOT EXISTS test ("
                          "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                          "name TEXT NOT NULL,"
                          "age INTEGER,"
                          "salary REAL,"
                          "data BLOB)";
        store.ExecuteSql(sql);
        return 0;
    }

    int OnOpen(RdbStore &store) override
    {
        return 0;
    }

    int OnUpgrade(RdbStore &store, int currentVersion, int targetVersion) override
    {
        return 0;
    }
};

void SetUpTestCase(void)
{
    int errCode = 0;
    std::string path = DATABASE_NAME;
    RdbHelper::DeleteRdbStore(path);
    int fd = open(path.c_str(), O_CREAT, S_IRWXU | S_IRWXG);
    if (fd < 0) {
        return;
    }
    if (fd > 0) {
        close(fd);
    }
    const int ddmsGroupId = 1000;
    chown(path.c_str(), 0, ddmsGroupId);

    RdbStoreConfig config(path);
    config.SetBundleName("com.example.distributed.rdb");
    config.SetName(DATABASE_NAME);
    TestOpenCallback callback;
    rdbStore = RdbHelper::GetRdbStore(config, 1, callback, errCode);
    rdbStore->ExecuteSql("DELETE FROM test");
}

void TearDownTestCase(void)
{
    rdbStore->ExecuteSql("DELETE FROM test");
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
}

void RdbStoreDistributedTestRdbStoreDistributedTest001(FuzzedDataProvider &fdp)
{
    SetUpTestCase();
    int errCode;
    std::vector<std::string> tables;
    OHOS::DistributedRdb::DistributedConfig distributedConfig;

    rdbStore->SetDistributedTables(tables, fdp.ConsumeIntegral<int32_t>(), distributedConfig);
    tables.push_back(fdp.ConsumeRandomLengthString());
    rdbStore->SetDistributedTables(tables, fdp.ConsumeIntegral<int32_t>(), distributedConfig);

    std::string path = DATABASE_NAME;
    RdbHelper::DeleteRdbStore(path);
    RdbStoreConfig config(path);
    TestOpenCallback callback;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, callback, errCode);
    if (store == NULL) {
        return;
    }

    store->SetDistributedTables(tables, fdp.ConsumeIntegral<int32_t>(), distributedConfig);

    RdbHelper::DeleteRdbStore(path);

    TearDownTestCase();
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::RdbStoreDistributedTestRdbStoreDistributedTest001(fdp);
    return 0;
}

/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "rdb_corrupt_test_ut2fuzz.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <unistd.h>

#include <climits>
#include <fstream>
#include <string>
#include <vector>

#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace OHOS;
using namespace OHOS::NativeRdb;

namespace OHOS {

static const std::string PATH_NAME = "/data/test/corrupt_test.db";

class CorruptTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static constexpr const char *createTableTest = "CREATE TABLE IF NOT EXISTS test "
                                                     "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                     "name TEXT NOT NULL, age INTEGER, salary "
                                                     "REAL, blobType BLOB)";
};

int CorruptTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(createTableTest);
}

int CorruptTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void SetUp(std::shared_ptr<RdbStore> &store)
{
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(PATH_NAME);
    RdbStoreConfig sqliteSharedRstConfig(PATH_NAME);
    CorruptTestOpenCallback openCallback;
    int errCode = E_OK;
    store = RdbHelper::GetRdbStore(sqliteSharedRstConfig, 1, openCallback, errCode);
    if (store == nullptr) {
        return;
    }
    RdbHelper::ClearCache();
}

void TearDown(void)
{
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(PATH_NAME);
}

void DestroyDbFile(const std::string &filePath, size_t offset, size_t len, unsigned char ch)
{
    constexpr size_t MAX_CORRUPT_SIZE = 2048;
    len = std::min(len, MAX_CORRUPT_SIZE);

    std::vector<char> buf;
    buf.reserve(len);
    buf.assign(len, static_cast<char>(ch));

    std::ofstream f(filePath, std::ios::binary | std::ios::in | std::ios::out);
    if (!f)
        return;

    f.seekp(offset);
    f.write(buf.data(), len);
}

void RdbCorruptTestRdbCorruptTest001(FuzzedDataProvider &fdp)
{
    std::shared_ptr<RdbStore> store;
    SetUp(store);
    if (store == nullptr) {
        return;
    }

    constexpr size_t MAX_FILE_SIZE = 4096;
    size_t offset = fdp.ConsumeIntegralInRange<size_t>(0, MAX_FILE_SIZE / 2);
    size_t len = fdp.ConsumeIntegralInRange<size_t>(1, MAX_FILE_SIZE - offset);
    DestroyDbFile(PATH_NAME, offset, len, fdp.ConsumeIntegral<int8_t>());

    CorruptTestOpenCallback sqliteCallback;
    RdbStoreConfig sqliteConfig(PATH_NAME);
    int errCode = E_OK;
    store = RdbHelper::GetRdbStore(sqliteConfig, 1, sqliteCallback, errCode);
    if (store == nullptr) {
        return;
    }

    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT * FROM test");
    if (resultSet == nullptr) {
        return;
    }

    while ((errCode = resultSet->GoToNextRow()) == E_OK) {
        if (errCode != E_OK) {
            break;
        }
    }
    resultSet->Close();
    TearDown();
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    constexpr size_t maxInputSize = 1024;
    if (size > maxInputSize) {
        return 0;
    }

    FuzzedDataProvider fdp(data, std::min(size, maxInputSize));
    OHOS::RdbCorruptTestRdbCorruptTest001(fdp);
    return 0;
}

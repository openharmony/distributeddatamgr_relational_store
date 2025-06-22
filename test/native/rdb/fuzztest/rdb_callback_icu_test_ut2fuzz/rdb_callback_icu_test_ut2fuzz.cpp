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
#include "rdb_callback_icu_test_ut2fuzz.h"

#include <fuzzer/FuzzedDataProvider.h>

#include <climits>
#include <string>

#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"


using namespace OHOS;
using namespace OHOS::NativeRdb;
namespace OHOS {

static const std::string PATH_NAME = "/data/test/rdb_callback_icu_test.db";

class OpenCallbackIcu : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    int OnDowngrade(RdbStore &store, int oldVersion, int newVersion) override;
    int OnOpen(RdbStore &store) override;

    static std::string CreateTableSQL(const std::string &tableName);
    static std::string DropTableSQL(const std::string &tableName);
};

std::string OpenCallbackIcu::CreateTableSQL(const std::string &tableName)
{
    return "CREATE VIRTUAL TABLE IF NOT EXISTS " + tableName + " USING fts4(name, content, tokenize=icu zh_CN);";
}

std::string OpenCallbackIcu::DropTableSQL(const std::string &tableName)
{
    return "DROP TABLE IF EXISTS " + tableName + ";";
}

int OpenCallbackIcu::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CreateTableSQL("test1"));
}

int OpenCallbackIcu::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

int OpenCallbackIcu::OnDowngrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

int OpenCallbackIcu::OnOpen(RdbStore &store)
{
    return E_OK;
}

void RdbCallbackIcuTestRdbCallbackIcu01(FuzzedDataProvider &fdp)
{
    RdbStoreConfig config(PATH_NAME);
    config.SetTokenizer(ICU_TOKENIZER);
    OpenCallbackIcu helper;

    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    if (store == nullptr) {
        return;
    }

    const char *sqlCreateTable = "CREATE VIRTUAL TABLE example USING fts4(name, content, tokenize=icu zh_CN);";
    int ret = store->ExecuteSql(sqlCreateTable);

    const char *sqlInsert1 =
        "INSERT INTO example(name, content) VALUES('文档1', '这是一个测试文档，用于测试中文文本的分词和索引。');";
    ret = store->ExecuteSql(sqlInsert1);

    const char *sqlInsert2 =
        "INSERT INTO example(name, content) VALUES('文档2', '我们将使用这个示例来演示如何在SQLite中进行全文搜索。');";
    ret = store->ExecuteSql(sqlInsert2);

    const char *sqlInsert3 =
        "INSERT INTO example(name, content) VALUES('文档3', 'ICU分词器能够很好地处理中文文本的分词和分析。');";
    ret = store->ExecuteSql(sqlInsert3);

    const char *sqlQuery = "SELECT * FROM example WHERE example MATCH '测试';";
    ret = store->ExecuteSql(sqlQuery);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql(sqlQuery);
    if (resultSet == nullptr) {
        return;
    }

    ret = resultSet->GoToNextRow();

    int columnIndex;
    std::string strVal;

    ret = resultSet->GetColumnIndex(fdp.ConsumeRandomLengthString(), columnIndex);

    ret = resultSet->GetString(columnIndex, strVal);

    ret = resultSet->GetColumnIndex(fdp.ConsumeRandomLengthString(), columnIndex);

    ret = resultSet->GetString(columnIndex, strVal);

    ret = resultSet->GoToNextRow();

    ret = resultSet->Close();
}

} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::RdbCallbackIcuTestRdbCallbackIcu01(fdp);
    return 0;
}

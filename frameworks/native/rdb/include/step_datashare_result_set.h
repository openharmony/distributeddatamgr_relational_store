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

#ifndef NATIVE_RDB_STEP_DATASHARE_RESULT_SET_H
#define NATIVE_RDB_STEP_DATASHARE_RESULT_SET_H

#include <memory>
#include <thread>
#include <vector>

#include "rdb_store_impl.h"
#include "abs_result_set.h"
#include "sqlite_statement.h"
#include "datashare_abs_result_set.h"
#include "datashare_abstract_result_set.h"

namespace OHOS {
namespace NativeRdb {

class StepDataShareResultSet : public DataShare::DataShareAbsResultSet, public DataShare::DataShareAbstractResultSet {
public:
    StepDataShareResultSet(std::shared_ptr<RdbStoreImpl> rdb, const std::string &sql,
        const std::vector<std::string> &selectionArgs);
    ~StepDataShareResultSet() override;

    int GetAllColumnNames(std::vector<std::string> &columnNames) override;
    int GetDataType(int columnIndex, DataShare::DataType &columnType) override;
    int GetRowCount(int &count) override;
    int GoToRow(int position) override;
    int GoToNextRow() override;
    int IsStarted(bool &result) const override;
    int IsAtFirstRow(bool &result) const override;
    int IsEnded(bool &result) override;
    int GetBlob(int columnIndex, std::vector<uint8_t> &blob) override;
    int GetString(int columnIndex, std::string &value) override;
    int GetInt(int columnIndex, int &value) override;
    int GetLong(int columnIndex, int64_t &value) override;
    int GetDouble(int columnIndex, double &value) override;
    int IsColumnNull(int columnIndex, bool &isNull) override;
    bool IsClosed() const override;
    int Close() override;
    int FinishStep();
    int PrepareStep();
    int GetAllColumnOrKeyName(std::vector<std::string> &columnOrKeyNames) override;
    bool OnGo(int oldRowIndex, int newRowIndex,
        const std::shared_ptr<DataShare::DataShareBlockWriter> &writer) override;

private:
    int CheckSession();
    void Reset();
    std::shared_ptr<RdbStoreImpl> rdb;
    std::string sql;
    std::vector<std::string> selectionArgs;
    // Whether reach the end of this result set or not
    bool isAfterLast;
    // The value indicates the row count of the result set
    int rowCount;
    std::thread::id tid;
    std::shared_ptr<SqliteStatement> sqliteStatement;
    static const int INIT_POS = -1;
    // Max times of retrying step query
    static const int STEP_QUERY_RETRY_MAX_TIMES = 50;
    // Interval of retrying step query in millisecond
    static const int STEP_QUERY_RETRY_INTERVAL = 1000;

    void GetColumnTypes(int columnCount, DataShare::DataType columnTypes[]);
    void WriteBlock(int columnCount, DataShare::DataType columnTypes[],
        const std::shared_ptr<DataShare::DataShareBlockWriter> &writer);
    bool WriteBlobData(int row, int column, const std::shared_ptr<DataShare::DataShareBlockWriter> &writer);
};

} // namespace NativeRdb
} // namespace OHOS
#endif

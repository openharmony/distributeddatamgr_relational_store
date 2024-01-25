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

#ifndef NATIVE_RDB_STEP_RESULT_SET_H
#define NATIVE_RDB_STEP_RESULT_SET_H

#include <memory>
#include <shared_mutex>
#include <thread>
#include <vector>

#include "rdb_store_impl.h"
#include "abs_result_set.h"
#include "sqlite_statement.h"

namespace OHOS {
namespace NativeRdb {
class StepResultSet : public AbsResultSet {
public:
    StepResultSet(std::shared_ptr<SqliteConnectionPool> connectionPool, const std::string& sql,
        const std::vector<ValueObject>& selectionArgs);
    ~StepResultSet() override;

    int GetAllColumnNames(std::vector<std::string> &columnNames) override;
    int GetColumnType(int columnIndex, ColumnType &columnType) override;
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
    int GetSize(int columnIndex, size_t &size) override;
    int GetAsset(int32_t col, ValueObject::Asset &value) override;
    int GetAssets(int32_t col, ValueObject::Assets &value) override;
    int Get(int32_t col, ValueObject &value) override;
    int GetModifyTime(std::string &modifyTime) override;
    int IsColumnNull(int columnIndex, bool &isNull) override;
    bool IsClosed() const override;
    int Close() override;

private:
    template<typename T>
    int GetValue(int32_t col, T &value);
    std::pair<int, ValueObject> GetValueObject(int32_t col, size_t index);
    void Reset();
    int FinishStep();
    int PrepareStep();

    static const int INIT_POS = -1;
    // Max times of retrying step query
    static const int STEP_QUERY_RETRY_MAX_TIMES = 50;
    // Interval of retrying step query in millisecond
    static const int STEP_QUERY_RETRY_INTERVAL = 1000;

    std::shared_ptr<SqliteStatement> sqliteStatement_;
    std::shared_ptr<SqliteConnection> conn_;
    std::vector<std::string> columnNames_;
    std::vector<ValueObject> args_;
    std::string sql_;
    std::weak_ptr<SqliteConnectionPool> connectionPool_;
    // The value indicates the row count of the result set
    int rowCount_;
    // Whether reach the end of this result set or not
    bool isAfterLast_;
    mutable std::shared_mutex mutex_;
};
} // namespace NativeRdb
} // namespace OHOS
#endif

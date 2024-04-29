/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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


#ifndef NATIVE_RDB_RD_RESULT_SET_H
#define NATIVE_RDB_RD_RESULT_SET_H

#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "abs_shared_result_set.h"
#include "rd_statement.h"
#include "rdb_connection_pool.h"
#include "value_object.h"

namespace OHOS {
namespace NativeRdb {
class RdSharedResultSet : public AbsSharedResultSet {
public:
    RdSharedResultSet(std::shared_ptr<RdbConnectionPool> connectionPool, const std::string& sql,
        const std::vector<ValueObject>& selectionArgs);
    RdSharedResultSet(std::shared_ptr<RdbConnectionPool> connectionPool, const std::string& sql,
        const std::vector<ValueObject>& selectionArgs, int rowCount);
    ~RdSharedResultSet() override;

    int GetColumnType(int columnIndex, ColumnType &columnType) override;
    int GetRowCount(int &count) override;
    int GoToRow(int position) override;
    int GoToNextRow() override;
    int IsStarted(bool &result) const override;
    int IsAtFirstRow(bool &result) const override;
    int IsEnded(bool &result) override;
    int GetSize(int columnIndex, size_t &size) override;
    int Get(int32_t col, ValueObject &value) override;
    int Close() override;

protected:
    std::pair<int, std::vector<std::string>> GetColumnNames() override;
    virtual int PrepareStep();

    template<typename T>
    int GetValue(int32_t col, T &value);
    std::pair<int, ValueObject> GetValueObject(int32_t col, size_t index);
    std::pair<std::shared_ptr<RdbStatement>, std::shared_ptr<RdbConnection>> GetStatement();
    void Reset();
    int FinishStep();

    static const int INIT_POS = -1;
    // Max times of retrying step query
    static const int STEP_QUERY_RETRY_MAX_TIMES = 50;
    // Interval of retrying step query in millisecond
    static const int STEP_QUERY_RETRY_INTERVAL = 1000;

    std::shared_ptr<RdbStatement> statement_ = nullptr;
    std::shared_ptr<RdbConnection> conn_ = nullptr;
    std::vector<ValueObject> args_ = {};
    std::string sql_ = "";
    std::shared_ptr<RdbConnectionPool> rdConnectionPool_ = nullptr;
    // The value indicates the row count of the result set
    int rowCount_;
    // Whether reach the end of this result set or not
    bool isAfterLast_;
};


} // namespace NativeRdb
} // namespace OHOS

#endif // NATIVE_RDB_RD_RESULT_SET_H

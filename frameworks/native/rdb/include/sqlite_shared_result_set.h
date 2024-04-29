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


#ifndef NATIVE_RDB_SQLITE_SHARED_RESULT_SET_H
#define NATIVE_RDB_SQLITE_SHARED_RESULT_SET_H

#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "abs_shared_result_set.h"
#include "connection.h"
#include "shared_block.h"
#include "sqlite_connection_pool.h"
#include "statement.h"
#include "value_object.h"

namespace OHOS {
namespace NativeRdb {
class SqliteSharedResultSet : public AbsSharedResultSet {
public:
    SqliteSharedResultSet(std::shared_ptr<SqliteConnectionPool> pool, std::string path,
        std::string sql, const std::vector<ValueObject> &bindArgs);
    ~SqliteSharedResultSet() override;
    int Close() override;
    int GetRowCount(int &count) override;
    int32_t OnGo(int oldPosition, int newPosition) override;
    void SetBlock(AppDataFwk::SharedBlock *block) override;
    int PickFillBlockStartPosition(int resultSetPosition, int blockCapacity) const;
    void SetFillBlockForwardOnly(bool isOnlyFillResultSetBlockInput);

protected:
    void Finalize() override;
    std::pair<int, std::vector<std::string>> GetColumnNames() override;

private:
    std::pair<std::shared_ptr<Statement>, int> PrepareStep();
    int32_t FillBlock(int requiredPos);
    std::pair<int, int32_t> ExecuteForSharedBlock(AppDataFwk::SharedBlock* block, int start, int required,
        bool needCount);

private:
    // The specified value is -1 when there is no data
    static constexpr int NO_COUNT = -1;
    // The pick position of the shared block for search
    static constexpr int PICK_POS = 3;
    // Controls fetching of rows relative to requested position
    bool isOnlyFillBlock_ = false;
    uint32_t blockCapacity_ = 0;
    // The number of rows in the cursor
    int rowNum_ = NO_COUNT;

    std::shared_ptr<Connection> conn_;
    std::string qrySql_;
    std::vector<ValueObject> bindArgs_;
    std::vector<std::string> columnNames_;
    std::mutex mutex_;
};
} // namespace NativeRdb
} // namespace OHOS

#endif
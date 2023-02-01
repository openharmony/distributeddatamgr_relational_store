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

#ifndef RDB_RESULT_SET_BRIDGE_H
#define RDB_RESULT_SET_BRIDGE_H

#include "../../rdb/include/result_set.h"
#include "rdb_errno.h"
#include "result_set_bridge.h"
#include "string.h"

namespace OHOS {
namespace NativeRdb {
class ResultSet;
}
namespace RdbDataShareAdapter {
class RdbResultSetBridge : public DataShare::ResultSetBridge {
public:
    using ResultSet = NativeRdb::ResultSet;
    using ColumnType = NativeRdb::ColumnType;

    RdbResultSetBridge(std::shared_ptr<ResultSet> resultSet);
    ~RdbResultSetBridge();
    int GetAllColumnNames(std::vector<std::string> &columnNames) override;
    int GetRowCount(int32_t &count) override;
    int OnGo(int32_t start, int32_t length, Writer &writer) override;

private:
    int32_t WriteBlock(int32_t start, int32_t target, int columnCount, Writer &writer);
    bool WriteBlobData(int column, Writer &writer);
    void WriteColumn(int columnCount, Writer &writer, int row);
    std::shared_ptr<ResultSet> rdbResultSet_;
};
} // namespace RdbDataShareAdapter
} // namespace OHOS
#endif // RDB_RESULT_SET_BRIDGE_H

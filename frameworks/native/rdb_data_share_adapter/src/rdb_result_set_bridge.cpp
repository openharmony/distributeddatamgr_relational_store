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

#define LOG_TAG "RdbResultSetBridge"

#include "rdb_result_set_bridge.h"

#include "rdb_errno.h"
#include "rdb_logger.h"
#include "result_set.h"
#include "securec.h"

namespace OHOS {
namespace RdbDataShareAdapter {
using namespace OHOS::NativeRdb;
RdbResultSetBridge::RdbResultSetBridge(std::shared_ptr<ResultSet> resultSet) : rdbResultSet_(resultSet)
{
}

RdbResultSetBridge::~RdbResultSetBridge()
{
    rdbResultSet_->Close();
}

int RdbResultSetBridge::GetRowCount(int &count)
{
    return rdbResultSet_->GetRowCount(count);
}

int RdbResultSetBridge::GetAllColumnNames(std::vector<std::string> &columnOrKeyNames)
{
    return rdbResultSet_->GetAllColumnNames(columnOrKeyNames);
}

int RdbResultSetBridge::OnGo(int32_t start, int32_t target, Writer &writer)
{
    int rowCount;
    rdbResultSet_->GetRowCount(rowCount);
    if (start < 0 || target < 0 || target >= rowCount) {
        LOG_ERROR("Invalid targetRowIndex: %{public}d.", rowCount);
        return -1;
    }

    int columnCount;
    rdbResultSet_->GetColumnCount(columnCount);
    if (columnCount <= 0) {
        LOG_ERROR("Invalid columnCount: %{public}d.", columnCount);
        return -1;
    }
    LOG_DEBUG("rowCount: %{public}d, columnCount: %{public}d.", rowCount, columnCount);

    bool bResultSet = false;
    rdbResultSet_->IsStarted(bResultSet);
    if (!bResultSet) {
        rdbResultSet_->GoToFirstRow();
    }

    int errCode = rdbResultSet_->GoToRow(start);
    if (errCode) {
        LOG_ERROR("Go to row %{public}d failed.", start);
        return -1;
    }

    return WriteBlock(start, target, columnCount, writer);
}

int32_t RdbResultSetBridge::WriteBlock(int32_t start, int32_t target, int columnCount, Writer &writer)
{
    bool isFull = false;
    int errCode = 0;
    int row = start;

    while (!isFull && !errCode && row <= target) {
        int status = writer.AllocRow();
        if (status != 0) {
            isFull = true;
            LOG_ERROR("SharedBlock is full.");
            return row - 1;
        }

        WriteColumn(columnCount, writer, row);
        row++;
        errCode = rdbResultSet_->GoToNextRow();
    }
    return target;
}

void RdbResultSetBridge::WriteColumn(int columnCount, Writer &writer, int row)
{
    for (int i = 0; i < columnCount; i++) {
        ColumnType type;
        rdbResultSet_->GetColumnType(i, type);
        switch (type) {
            case ColumnType::TYPE_INTEGER:
                int64_t value;
                rdbResultSet_->GetLong(i, value);
                if (writer.Write(i, value)) {
                    LOG_DEBUG("WriteLong failed of row: %{public}d, column: %{public}d", row, i);
                }
                break;
            case ColumnType::TYPE_FLOAT:
                double dValue;
                rdbResultSet_->GetDouble(i, dValue);
                if (writer.Write(i, dValue)) {
                    LOG_DEBUG("WriteDouble failed of row: %{public}d, column: %{public}d", row, i);
                }
                break;
            case ColumnType::TYPE_NULL:
                if (writer.Write(i)) {
                    LOG_DEBUG("WriteNull failed of row: row: %{public}d, column: %{public}d", row, i);
                }
                break;
            case ColumnType::TYPE_BLOB:
                if (WriteBlobData(i, writer)) {
                    LOG_DEBUG("WriteBlob failed of row: %{public}d, column: %{public}d", row, i);
                }
                break;
            default:
                std::string stringValue;
                rdbResultSet_->GetString(i, stringValue);
                if (writer.Write(i, stringValue.c_str(), stringValue.size() + 1)) {
                    LOG_DEBUG("WriteString failed of row: %{public}d, column: %{public}d", row, i);
                }
        }
    }
}

bool RdbResultSetBridge::WriteBlobData(int column, Writer &writer)
{
    std::vector<uint8_t> blobValue;
    rdbResultSet_->GetBlob(column, blobValue);
    if (blobValue.empty()) {
        return false;
    }

    return writer.Write(column, &blobValue[0], blobValue.size() * sizeof(uint8_t));
}
} // namespace RdbDataShareAdapter
} // namespace OHOS

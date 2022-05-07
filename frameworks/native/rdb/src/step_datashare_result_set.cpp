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

#define LOG_TAG "StepDataShareResultSet"

#include "step_datashare_result_set.h"

#include <unistd.h>

#include "logger.h"
#include "rdb_errno.h"
#include "sqlite3sym.h"
#include "sqlite_errno.h"

using namespace OHOS::DataShare;

namespace OHOS {
namespace NativeRdb {
StepDataShareResultSet::StepDataShareResultSet(
    std::shared_ptr<RdbStoreImpl> rdb, const std::string &sql, const std::vector<std::string> &selectionArgs)
    : rdb(rdb), sql(sql), selectionArgs(selectionArgs), isAfterLast(false), rowCount(INIT_POS),
      sqliteStatement(nullptr)
{
}

StepDataShareResultSet::~StepDataShareResultSet()
{
    Close();
}

int StepDataShareResultSet::GetAllColumnNames(std::vector<std::string> &columnNames)
{
    int errCode = PrepareStep();
    if (errCode) {
        return errCode;
    }

    int columnCount = 0;
    errCode = sqliteStatement->GetColumnCount(columnCount);
    if (errCode) {
        return errCode;
    }

    columnNames.clear();
    for (int i = 0; i < columnCount; i++) {
        std::string columnName;
        errCode = sqliteStatement->GetColumnName(i, columnName);
        if (errCode) {
            columnNames.clear();
            return errCode;
        }
        columnNames.push_back(columnName);
    }

    return E_OK;
}

int StepDataShareResultSet::GetDataType(int columnIndex, DataType &columnType)
{
    if (rowPos_ == INIT_POS) {
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }
    int sqliteType;
    int errCode = sqliteStatement->GetColumnType(columnIndex, sqliteType);
    if (errCode) {
        return errCode;
    }

    switch (sqliteType) {
        case SQLITE_INTEGER:
            columnType = DataType::TYPE_INTEGER;
            break;
        case SQLITE_FLOAT:
            columnType = DataType::TYPE_FLOAT;
            break;
        case SQLITE_BLOB:
            columnType = DataType::TYPE_BLOB;
            break;
        case SQLITE_NULL:
            columnType = DataType::TYPE_NULL;
            break;
        default:
            columnType = DataType::TYPE_STRING;
    }

    return E_OK;
}

int StepDataShareResultSet::GetRowCount(int &count)
{
    if (rowCount != INIT_POS) {
        count = rowCount;
        return E_OK;
    }
    int oldPosition = 0;
    // Get the start position of the query result
    GetRowIndex(oldPosition);

    while (GoToNextRow() == E_OK) {
    }
    count = rowCount;
    // Reset the start position of the query result
    GoToRow(oldPosition);

    return E_OK;
}

/**
 * Moves the result set to a specified position
 */
int StepDataShareResultSet::GoToRow(int position)
{
    if (!rdb) {
        return E_ERROR;
    }
    // If the moved position is less than zero, reset the result and return an error
    if (position < 0) {
        Reset();
        return E_ERROR;
    }
    if (position == rowPos_) {
        return E_OK;
    }
    if (position < rowPos_) {
        Reset();
        return GoToRow(position);
    }
    while (position != rowPos_) {
        int errCode = GoToNextRow();
        if (errCode) {
            return errCode;
        }
    }

    return E_OK;
}

/**
 * Move the result set to the next row
 */
int StepDataShareResultSet::GoToNextRow()
{
    int errCode = PrepareStep();
    if (errCode) {
        return errCode;
    }

    int retryCount = 0;
    errCode = sqliteStatement->Step();

    while (errCode == SQLITE_LOCKED || errCode == SQLITE_BUSY) {
        // The table is locked, retry
        if (retryCount > STEP_QUERY_RETRY_MAX_TIMES) {
            LOG_ERROR("Retry overrun.");
            return E_STEP_RESULT_QUERY_EXCEEDED;
        } else {
            // Sleep to give the thread holding the lock a chance to finish
            usleep(STEP_QUERY_RETRY_INTERVAL);
            errCode = sqliteStatement->Step();
            retryCount++;
        }
    }

    if (errCode == SQLITE_ROW) {
        rowPos_++;
        return E_OK;
    } else if (errCode == SQLITE_DONE) {
        isAfterLast = true;
        rowCount = rowPos_ + 1;
        FinishStep();
        return E_STEP_RESULT_IS_AFTER_LAST;
    } else {
        LOG_ERROR("err = %{public}d", errCode);
        FinishStep();
        return SQLiteError::ErrNo(errCode);
    }
}

/**
 * Checks whether the result set is positioned after the last row
 */
int StepDataShareResultSet::IsEnded(bool &result)
{
    result = isAfterLast;
    return E_OK;
}

/**
 * Checks whether the result set is moved
 */
int StepDataShareResultSet::IsStarted(bool &result) const
{
    result = (rowPos_ != INIT_POS);
    return E_OK;
}

/**
 * Check whether the result set is in the first row
 */
int StepDataShareResultSet::IsAtFirstRow(bool &result) const
{
    result = (rowPos_ == 0);
    return E_OK;
}

int StepDataShareResultSet::GetBlob(int columnIndex, std::vector<uint8_t> &blob)
{
    if (rowPos_ == INIT_POS) {
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }

    return sqliteStatement->GetColumnBlob(columnIndex, blob);
}

int StepDataShareResultSet::GetString(int columnIndex, std::string &value)
{
    if (rowPos_ == INIT_POS) {
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }

    int errCode = sqliteStatement->GetColumnString(columnIndex, value);
    if (errCode != E_OK) {
        LOG_ERROR("err=%{public}d", errCode);
        return errCode;
    }
    return E_OK;
}

int StepDataShareResultSet::GetInt(int columnIndex, int &value)
{
    if (rowPos_ == INIT_POS) {
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }

    int64_t columnValue;
    int errCode = sqliteStatement->GetColumnLong(columnIndex, columnValue);
    if (errCode != E_OK) {
        return errCode;
    }
    value = static_cast<int>(columnValue);
    return E_OK;
}

int StepDataShareResultSet::GetLong(int columnIndex, int64_t &value)
{
    if (rowPos_ == INIT_POS) {
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }
    int errCode = sqliteStatement->GetColumnLong(columnIndex, value);
    if (errCode != E_OK) {
        return errCode;
    }
    return E_OK;
}

int StepDataShareResultSet::GetDouble(int columnIndex, double &value)
{
    if (rowPos_ == INIT_POS) {
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }
    int errCode = sqliteStatement->GetColumnDouble(columnIndex, value);
    if (errCode != E_OK) {
        return errCode;
    }
    return E_OK;
}

int StepDataShareResultSet::IsColumnNull(int columnIndex, bool &isNull)
{
    DataType columnType;
    int errCode = GetDataType(columnIndex, columnType);
    if (errCode != E_OK) {
        return errCode;
    }
    isNull = (columnType == DataType::TYPE_NULL);
    return E_OK;
}

/**
 * Check whether the result set is over
 */
bool StepDataShareResultSet::IsClosed() const
{
    return isClosed_;
}

int StepDataShareResultSet::Close()
{
    if (isClosed_) {
        return E_OK;
    }
    isClosed_ = true;
    int errCode = FinishStep();
    rdb = nullptr;
    return errCode;
}

int StepDataShareResultSet::CheckSession()
{
    if (std::this_thread::get_id() != tid) {
        LOG_ERROR("StepDataShareResultSet is passed cross threads!");
        return E_STEP_RESULT_SET_CROSS_THREADS;
    }
    return E_OK;
}

/**
 * Obtain session and prepare precompile statement for step query
 */
int StepDataShareResultSet::PrepareStep()
{
    LOG_DEBUG("begin");
    if (isClosed_) {
        return E_STEP_RESULT_CLOSED;
    }

    if (sqliteStatement != nullptr) {
        return CheckSession();
    }

    int errCode;
    LOG_DEBUG("rdb->BeginStepQuery begin");
    sqliteStatement = rdb->BeginStepQuery(errCode, sql, selectionArgs);
    if (sqliteStatement == nullptr) {
        rdb->EndStepQuery();
        return errCode;
    }

    LOG_DEBUG("get_id begin");
    tid = std::this_thread::get_id();
    return E_OK;
}

/**
 * Release resource of step result set, this method can be called more than once
 */
int StepDataShareResultSet::FinishStep()
{
    int errCode = CheckSession();
    if (errCode != E_OK) {
        return errCode;
    }

    if (sqliteStatement == nullptr) {
        return E_OK;
    }

    sqliteStatement = nullptr;
    rowPos_ = INIT_POS;
    if (rdb != nullptr) {
        errCode = rdb->EndStepQuery();
    }
    if (errCode != E_OK) {
        LOG_ERROR("err = %{public}d", errCode);
    }
    return errCode;
}

/**
 * Reset the statement
 */
void StepDataShareResultSet::Reset()
{
    if (sqliteStatement != nullptr) {
        sqlite3_reset(sqliteStatement->GetSql3Stmt());
    }
    rowPos_ = INIT_POS;
    isAfterLast = false;
}

int StepDataShareResultSet::GetAllColumnOrKeyName(std::vector<std::string> &columnOrKeyNames)
{
    return GetAllColumnNames(columnOrKeyNames);
}

bool StepDataShareResultSet::OnGo(int oldRowIndex, int targetRowIndex,
    const std::shared_ptr<DataShareBlockWriter> &writer)
{
    if (writer == nullptr) {
        LOG_ERROR("Writer is null.");
        return false;
    }

    int rowCount;
    GetRowCount(rowCount);
    if (targetRowIndex < 0 || targetRowIndex > rowCount) {
        LOG_ERROR("Invalid targetRowIndex: %{public}d.", rowCount);
        return false;
    }

    int columnCount;
    GetColumnCount(columnCount);
    if (columnCount <= 0) {
        LOG_ERROR("Invalid columnCount: %{public}d.", columnCount);
        return false;
    }
    LOG_DEBUG("rowCount: %{public}d, columnCount: %{public}d.", rowCount, columnCount);

    writer->Clear();

    bool bResultSet = false;
    IsStarted(bResultSet);
    if (!bResultSet) {
        GoToFirstRow();
    }

    int errCode = GoToRow(targetRowIndex);
    if (errCode) {
        LOG_ERROR("Go to row %{public}d failed.", targetRowIndex);
        return false;
    }

    DataType columnTypes[columnCount];
    GetColumnTypes(columnCount, columnTypes);
    writer->SetColumnNum(columnCount);
    WriteBlock(columnCount, columnTypes, writer);

    return true;
}

void StepDataShareResultSet::GetColumnTypes(int columnCount, DataType columnTypes[])
{
    for (int i = 0; i < columnCount; ++i) {
        DataType type;
        GetDataType(i, type);
        columnTypes[i] = type;
    }
}

void StepDataShareResultSet::WriteBlock(int columnCount, DataType columnTypes[],
    const std::shared_ptr<DataShareBlockWriter> &writer)
{
    bool isFull = false;
    int errCode = 0;
    int row = 0;
    while(!isFull && !errCode) {
        int status = writer->AllocRow();
        if (status != AppDataFwk::SharedBlock::SHARED_BLOCK_OK) {
            isFull = true;
            LOG_ERROR("SharedBlock is full.");
            break;
        }

        WriteColumn(columnCount, columnTypes, writer, row);
        row++;
        errCode = GoToNextRow();
    }
}

void StepDataShareResultSet::WriteColumn(int columnCount, const DataType *columnTypes,
    const std::shared_ptr<DataShareBlockWriter> &writer, int row) {
    for (int i = 0; i < columnCount; i++) {
        LOG_DEBUG("Write data of row: %{public}d, column: %{public}d", row, i);
        switch (columnTypes[i]) {
            case DataType::TYPE_INTEGER:
                int64_t value;
                GetLong(i, value);
                if (writer->WriteLong(row, i, value)) {
                    LOG_DEBUG("WriteLong failed of row: %{public}d, column: %{public}d", row, i);
                }
                break;
            case DataType::TYPE_FLOAT:
                double dValue;
                GetDouble(i, dValue);
                if (writer->WriteDouble(row, i, dValue)) {
                    LOG_DEBUG("WriteDouble failed of row: row: %{public}d, column: %{public}d", row, i);
                }
                break;
            case DataType::TYPE_NULL:
                if (writer->WriteNull(row, i)) {
                    LOG_DEBUG("WriteNull failed of row: row: %{public}d, column: %{public}d", row, i);
                }
                break;
            case DataType::TYPE_BLOB:
                if (WriteBlobData(row, i, writer)) {
                    LOG_DEBUG("WriteBlobData failed of row: %{public}d, column: %{public}d", row, i);
                }
                break;
            default:
                std::string stringValue;
                GetString(i, stringValue);
                if (writer->WriteString(row, i, (char*)stringValue.c_str(), sizeof(stringValue))) {
                    LOG_DEBUG("WriteString failed of row: %{public}d, column: %{public}d", row, i);
                }
        }
    }
}

bool StepDataShareResultSet::WriteBlobData(int row, int column, const std::shared_ptr<DataShareBlockWriter> &writer)
{
    std::vector<uint8_t> blobValue;
    GetBlob(column, blobValue);
    std::string str;
    str.assign(blobValue.begin(), blobValue.end());
    const char *value = str.c_str();
    return writer->WriteBlob(row, column, value, sizeof(value));
}
} // namespace NativeRdb
} // namespace OHOS

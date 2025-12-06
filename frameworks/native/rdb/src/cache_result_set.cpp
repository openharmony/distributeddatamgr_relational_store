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

#define LOG_TAG "CacheResultSet"
#include "cache_result_set.h"

#include <algorithm>
#include <string>

#include "abs_result_set.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_trace.h"
namespace OHOS {
namespace NativeRdb {
CacheResultSet::CacheResultSet() : row_(0), maxRow_(0), maxCol_(0)
{
}
CacheResultSet::CacheResultSet(std::vector<NativeRdb::ValuesBucket> &&valueBuckets, int initPos)
    : row_(initPos), maxCol_(0), valueBuckets_(std::move(valueBuckets))
{
    maxRow_ = static_cast<int>(valueBuckets_.size());
    if (maxRow_ > 0) {
        for (auto it = valueBuckets_[0].values_.begin(); it != valueBuckets_[0].values_.end(); it++) {
            colNames_.push_back(it->first);
            colTypes_.push_back(it->second.GetType());
        }
        maxCol_ = static_cast<int>(colNames_.size());
    }
}

CacheResultSet::~CacheResultSet()
{
}

int CacheResultSet::GetRowCount(int &count)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    count = static_cast<int>(maxRow_);
    return E_OK;
}

int CacheResultSet::GetAllColumnNames(std::vector<std::string> &columnNames)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    columnNames = colNames_;
    return E_OK;
}

int CacheResultSet::GetBlob(int columnIndex, std::vector<uint8_t> &blob)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    if (columnIndex < 0 || columnIndex >= maxCol_) {
        return E_COLUMN_OUT_RANGE;
    }
    auto name = colNames_[columnIndex];
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (row_ < 0 || row_ >= maxRow_) {
        return E_ROW_OUT_RANGE;
    }
    return valueBuckets_[row_].values_[name].GetBlob(blob);
}

int CacheResultSet::GetString(int columnIndex, std::string &value)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    if (columnIndex < 0 || columnIndex >= maxCol_) {
        return E_COLUMN_OUT_RANGE;
    }
    auto name = colNames_[columnIndex];
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (row_ < 0 || row_ >= maxRow_) {
        return E_ROW_OUT_RANGE;
    }
    return valueBuckets_[row_].values_[name].GetString(value);
}

int CacheResultSet::GetInt(int columnIndex, int &value)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    if (columnIndex < 0 || columnIndex >= maxCol_) {
        return E_COLUMN_OUT_RANGE;
    }
    auto name = colNames_[columnIndex];
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (row_ < 0 || row_ >= maxRow_) {
        return E_ROW_OUT_RANGE;
    }
    return valueBuckets_[row_].values_[name].GetInt(value);
}

int CacheResultSet::GetLong(int columnIndex, int64_t &value)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    if (columnIndex < 0 || columnIndex >= maxCol_) {
        return E_COLUMN_OUT_RANGE;
    }
    auto name = colNames_[columnIndex];
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (row_ < 0 || row_ >= maxRow_) {
        return E_ROW_OUT_RANGE;
    }
    return valueBuckets_[row_].values_[name].GetLong(value);
}

int CacheResultSet::GetDouble(int columnIndex, double &value)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    if (columnIndex < 0 || columnIndex >= maxCol_) {
        return E_COLUMN_OUT_RANGE;
    }
    auto name = colNames_[columnIndex];
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (row_ < 0 || row_ >= maxRow_) {
        return E_ROW_OUT_RANGE;
    }
    return valueBuckets_[row_].values_[name].GetDouble(value);
}

int CacheResultSet::IsColumnNull(int columnIndex, bool &isNull)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    if (columnIndex < 0 || columnIndex >= maxCol_) {
        return E_COLUMN_OUT_RANGE;
    }
    auto name = colNames_[columnIndex];
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (row_ < 0 || row_ >= maxRow_) {
        return E_ROW_OUT_RANGE;
    }
    isNull = valueBuckets_[row_].values_[name].GetType() == ValueObject::TYPE_NULL;
    return E_OK;
}

int CacheResultSet::GetRow(RowEntity &rowEntity)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (row_ < 0 || row_ >= maxRow_) {
        return E_ROW_OUT_RANGE;
    }
    rowEntity.Clear(colNames_.size());
    int32_t index = 0;
    for (auto &columnName : colNames_) {
        ValueObject object;
        if (!valueBuckets_[row_].GetObject(columnName, object)) {
            return E_ERROR;
        }
        rowEntity.Put(columnName, index, std::move(object));
        index++;
    }
    return E_OK;
}

int CacheResultSet::GoToRow(int position)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    std::unique_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (position >= maxRow_) {
        row_ = maxRow_;
        return E_ROW_OUT_RANGE;
    }
    if (position < 0) {
        row_ = -1;
        return E_ROW_OUT_RANGE;
    }
    row_ = position;
    return E_OK;
}

int CacheResultSet::GetColumnType(int columnIndex, ColumnType &columnType)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    if (columnIndex < 0 || columnIndex >= maxCol_) {
        return E_COLUMN_OUT_RANGE;
    }
    auto index = colTypes_[columnIndex];
    if (index < ValueObject::TYPE_NULL || index >= ValueObject::TYPE_MAX) {
        return E_INVALID_COLUMN_TYPE;
    }
    columnType = COLUMNTYPES[index];
    return E_OK;
}

int CacheResultSet::GetRowIndex(int &position) const
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    position = row_;
    return E_OK;
}

int CacheResultSet::GoTo(int offset)
{
    int target = offset;
    {
        std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
        target += row_;
    }
    return GoToRow(target);
}

int CacheResultSet::GoToFirstRow()
{
    return GoToRow(0);
}

int CacheResultSet::GoToLastRow()
{
    return GoToRow(maxRow_ - 1);
}

int CacheResultSet::GoToNextRow()
{
    return GoTo(1);
}

int CacheResultSet::GoToPreviousRow()
{
    return GoTo(-1);
}

int CacheResultSet::IsAtFirstRow(bool &result) const
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    result = row_ == 0;
    return E_OK;
}

int CacheResultSet::IsAtLastRow(bool &result)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    result = row_ == maxRow_ - 1;
    return E_OK;
}

int CacheResultSet::IsStarted(bool &result) const
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    result = row_ == -1;
    return E_OK;
}

int CacheResultSet::IsEnded(bool &result)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    result = maxRow_ == 0 || row_ == maxRow_;
    return E_OK;
}

int CacheResultSet::GetColumnCount(int &count)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    count = maxCol_;
    return E_OK;
}

int CacheResultSet::GetColumnIndex(const std::string &columnName, int &columnIndex)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    for (int i = 0; i < maxCol_; ++i) {
        if (colNames_[i] == columnName) {
            columnIndex = i;
            return E_OK;
        }
    }
    return E_ERROR;
}

int CacheResultSet::GetColumnName(int columnIndex, std::string &columnName)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    if (columnIndex < 0 || columnIndex >= maxCol_) {
        return E_COLUMN_OUT_RANGE;
    }
    columnName = colNames_[columnIndex];
    return E_OK;
}

bool CacheResultSet::IsClosed() const
{
    return isClosed_;
}

int CacheResultSet::Close()
{
    if (!isClosed_) {
        auto colNames = std::move(colNames_);
        auto colTypes = std::move(colTypes_);
        auto valueBuckets = std::move(valueBuckets_);
        row_ = -1;
        maxRow_ = -1;
        maxCol_ = -1;
        isClosed_ = true;
    }
    return E_OK;
}

int CacheResultSet::GetAsset(int32_t col, ValueObject::Asset &value)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    if (col < 0 || col >= maxCol_) {
        return E_COLUMN_OUT_RANGE;
    }
    auto name = colNames_[col];
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (row_ < 0 || row_ >= maxRow_) {
        return E_ROW_OUT_RANGE;
    }
    return valueBuckets_[row_].values_[name].GetAsset(value);
}

int CacheResultSet::GetAssets(int32_t col, ValueObject::Assets &value)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    if (col < 0 || col >= maxCol_) {
        return E_COLUMN_OUT_RANGE;
    }
    auto name = colNames_[col];
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (row_ < 0 || row_ >= maxRow_) {
        return E_ROW_OUT_RANGE;
    }
    return valueBuckets_[row_].values_[name].GetAssets(value);
}

int CacheResultSet::GetFloat32Array(int32_t index, ValueObject::FloatVector &vecs)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    if (index < 0 || index >= maxCol_) {
        return E_COLUMN_OUT_RANGE;
    }
    auto name = colNames_[index];
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (row_ < 0 || row_ >= maxRow_) {
        return E_ROW_OUT_RANGE;
    }
    return valueBuckets_[row_].values_[name].GetVecs(vecs);
}

int CacheResultSet::Get(int32_t col, ValueObject &value)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    if (col < 0 || col >= maxCol_) {
        return E_COLUMN_OUT_RANGE;
    }
    auto name = colNames_[col];
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (row_ < 0 || row_ >= maxRow_) {
        return E_ROW_OUT_RANGE;
    }
    value = valueBuckets_[row_].values_[name];
    return E_OK;
}

int CacheResultSet::GetSize(int columnIndex, size_t &size)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    ColumnType type;
    int32_t errCode = GetColumnType(columnIndex, type);
    if (errCode != E_OK) {
        return errCode;
    }
    ValueObject object;
    errCode = Get(columnIndex, object);
    if (errCode != E_OK) {
        return errCode;
    }
    if (type == ColumnType::TYPE_BLOB) {
        std::vector<uint8_t> value = object;
        size = value.size();
    } else if (type == ColumnType::TYPE_STRING) {
        // Add 1 to size for the string terminator (null character).
        std::string value = object;
        size = value.size() + 1;
    } else if (type == ColumnType::TYPE_NULL) {
        size = 0;
    } else {
        return E_INVALID_COLUMN_TYPE;
    }
    return E_OK;
}
} // namespace NativeRdb
} // namespace OHOS
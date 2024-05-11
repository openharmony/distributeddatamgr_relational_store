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
CacheResultSet::CacheResultSet(std::vector<NativeRdb::ValuesBucket> &&valueBuckets)
    : row_(0), maxCol_(0), valueBuckets_(std::move(valueBuckets))
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
    count = static_cast<int>(maxRow_);
    return E_OK;
}

int CacheResultSet::GetAllColumnNames(std::vector<std::string> &columnNames)
{
    columnNames = colNames_;
    return E_OK;
}

int CacheResultSet::GetBlob(int columnIndex, std::vector<uint8_t> &blob)
{
    if (columnIndex < 0 || columnIndex >= maxCol_) {
        return E_INVALID_ARGS;
    }
    auto name = colNames_[columnIndex];
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (row_ < 0 || row_ >= maxRow_) {
        return E_ERROR;
    }
    return valueBuckets_[row_].values_[name].GetBlob(blob);
}

int CacheResultSet::GetString(int columnIndex, std::string &value)
{
    if (columnIndex < 0 || columnIndex >= maxCol_) {
        return E_INVALID_ARGS;
    }
    auto name = colNames_[columnIndex];
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (row_ < 0 || row_ >= maxRow_) {
        return E_ERROR;
    }
    return valueBuckets_[row_].values_[name].GetString(value);
}

int CacheResultSet::GetInt(int columnIndex, int &value)
{
    if (columnIndex < 0 || columnIndex >= maxCol_) {
        return E_INVALID_ARGS;
    }
    auto name = colNames_[columnIndex];
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (row_ < 0 || row_ >= maxRow_) {
        return E_ERROR;
    }
    return valueBuckets_[row_].values_[name].GetInt(value);
}

int CacheResultSet::GetLong(int columnIndex, int64_t &value)
{
    if (columnIndex < 0 || columnIndex >= maxCol_) {
        return E_INVALID_ARGS;
    }
    auto name = colNames_[columnIndex];
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (row_ < 0 || row_ >= maxRow_) {
        return E_ERROR;
    }
    return valueBuckets_[row_].values_[name].GetLong(value);
}

int CacheResultSet::GetDouble(int columnIndex, double &value)
{
    if (columnIndex < 0 || columnIndex >= maxCol_) {
        return E_INVALID_ARGS;
    }
    auto name = colNames_[columnIndex];
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (row_ < 0 || row_ >= maxRow_) {
        return E_ERROR;
    }
    return valueBuckets_[row_].values_[name].GetDouble(value);
}

int CacheResultSet::IsColumnNull(int columnIndex, bool &isNull)
{
    if (columnIndex < 0 || columnIndex >= maxCol_) {
        return E_INVALID_ARGS;
    }
    auto name = colNames_[columnIndex];
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (row_ < 0 || row_ >= maxRow_) {
        return E_ERROR;
    }
    isNull = valueBuckets_[row_].values_[name].GetType() == ValueObject::TYPE_NULL;
    return E_OK;
}

int CacheResultSet::GetRow(RowEntity &rowEntity)
{
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (row_ < 0 || row_ >= maxRow_) {
        return E_ERROR;
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
    std::unique_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (position >= maxRow_) {
        row_ = maxRow_;
        return E_ERROR;
    }
    if (position < 0) {
        row_ = -1;
        return E_ERROR;
    }
    row_ = position;
    return E_OK;
}

int CacheResultSet::GetColumnType(int columnIndex, ColumnType &columnType)
{
    if (columnIndex < 0 || columnIndex >= maxCol_) {
        return E_INVALID_ARGS;
    }
    auto index = colTypes_[columnIndex];
    if (index < ValueObject::TYPE_NULL || index >= ValueObject::TYPE_MAX) {
        return E_INVALID_ARGS;
    }
    columnType = COLUMNTYPES[index];
    return E_OK;
}

int CacheResultSet::GetRowIndex(int &position) const
{
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
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    result = row_ == 0;
    return E_OK;
}

int CacheResultSet::IsAtLastRow(bool &result)
{
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    result = row_ == maxRow_ - 1;
    return E_OK;
}

int CacheResultSet::IsStarted(bool &result) const
{
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    result = row_ == -1;
    return E_OK;
}

int CacheResultSet::IsEnded(bool &result)
{
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    result = maxRow_ == 0 || row_ == maxRow_;
    return E_OK;
}

int CacheResultSet::GetColumnCount(int &count)
{
    count = maxCol_;
    return E_OK;
}

int CacheResultSet::GetColumnIndex(const std::string &columnName, int &columnIndex)
{
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
    if (columnIndex < 0 || columnIndex >= maxCol_) {
        return E_INVALID_ARGS;
    }
    columnName = colNames_[columnIndex];
    return E_OK;
}

bool CacheResultSet::IsClosed() const
{
    return false;
}

int CacheResultSet::Close()
{
    return E_NOT_SUPPORT;
}

int CacheResultSet::GetAsset(int32_t col, ValueObject::Asset &value)
{
    if (col < 0 || col >= maxCol_) {
        return E_INVALID_ARGS;
    }
    auto name = colNames_[col];
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (row_ < 0 || row_ >= maxRow_) {
        return E_ERROR;
    }
    return valueBuckets_[row_].values_[name].GetAsset(value);
}

int CacheResultSet::GetAssets(int32_t col, ValueObject::Assets &value)
{
    if (col < 0 || col >= maxCol_) {
        return E_INVALID_ARGS;
    }
    auto name = colNames_[col];
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (row_ < 0 || row_ >= maxRow_) {
        return E_ERROR;
    }
    return valueBuckets_[row_].values_[name].GetAssets(value);
}

int CacheResultSet::GetFloat32Array(int32_t index, ValueObject::FloatVector &vecs)
{
    return E_NOT_SUPPORTED;
}

int CacheResultSet::Get(int32_t col, ValueObject &value)
{
    if (col < 0 || col >= maxCol_) {
        return E_INVALID_ARGS;
    }
    auto name = colNames_[col];
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (row_ < 0 || row_ >= maxRow_) {
        return E_ERROR;
    }
    value = valueBuckets_[row_].values_[name];
    return E_OK;
}

int CacheResultSet::GetSize(int columnIndex, size_t &size)
{
    return E_NOT_SUPPORT;
}
}
} // namespace OHOS
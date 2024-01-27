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

#include "abs_result_set.h"

#include "logger.h"
#include "rdb_errno.h"
#include "rdb_trace.h"
#include "result_set.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

void RowEntity::Put(const std::string &name, const ValueObject &value)
{
    auto it = values_.emplace(name, std::move(value));
    indexs_.push_back(it.first);
}

ValueObject RowEntity::Get(const std::string &name) const
{
    auto it = values_.find(name);
    if (it == values_.end()) {
        return ValueObject();
    }
    return it->second;
}

ValueObject RowEntity::Get(int index) const
{
    if (index < 0 || index >= static_cast<int>(indexs_.size())) {
        return ValueObject();
    }
    return indexs_[index]->second;
}

const std::map<std::string, ValueObject> &RowEntity::Get() const
{
    return values_;
}

std::map<std::string, ValueObject> RowEntity::Steal()
{
    indexs_.clear();
    return std::move(values_);
}

void RowEntity::Clear()
{
    values_.clear();
    indexs_.clear();
}

AbsResultSet::AbsResultSet() : rowPos_(INIT_POS), isClosed_(false)
{
}

AbsResultSet::~AbsResultSet()
{
    rowPos_ = INIT_POS;
    isClosed_ = false;
}

int AbsResultSet::GetRowCount(int &count)
{
    return E_OK;
}

int AbsResultSet::GetAllColumnNames(std::vector<std::string> &columnNames)
{
    return E_OK;
}

int AbsResultSet::GetBlob(int columnIndex, std::vector<uint8_t> &blob)
{
    return E_OK;
}

int AbsResultSet::GetString(int columnIndex, std::string &value)
{
    return E_OK;
}

int AbsResultSet::GetInt(int columnIndex, int &value)
{
    return E_OK;
}

int AbsResultSet::GetLong(int columnIndex, int64_t &value)
{
    return E_OK;
}

int AbsResultSet::GetDouble(int columnIndex, double &value)
{
    return E_OK;
}

int AbsResultSet::IsColumnNull(int columnIndex, bool &isNull)
{
    return E_OK;
}

int AbsResultSet::GetRow(RowEntity &rowEntity)
{
    rowEntity.Clear();
    std::vector<std::string> columnNames;
    int ret = GetAllColumnNames(columnNames);
    if (ret != E_OK) {
        LOG_ERROR("GetAllColumnNames::ret is %{public}d", ret);
        return ret;
    }
    int columnCount = static_cast<int>(columnNames.size());

    ColumnType columnType;
    for (int columnIndex = 0; columnIndex < columnCount; ++columnIndex) {
        ret = GetColumnType(columnIndex, columnType);
        if (ret != E_OK) {
            LOG_ERROR("GetColumnType::ret is %{public}d", ret);
            return ret;
        }
        switch (columnType) {
            case ColumnType::TYPE_NULL: {
                rowEntity.Put(columnNames[columnIndex], ValueObject());
                break;
            }
            case ColumnType::TYPE_INTEGER: {
                int64_t value;
                GetLong(columnIndex, value);
                rowEntity.Put(columnNames[columnIndex], ValueObject(value));
                break;
            }
            case ColumnType::TYPE_FLOAT: {
                double value;
                GetDouble(columnIndex, value);
                rowEntity.Put(columnNames[columnIndex], ValueObject(value));
                break;
            }
            case ColumnType::TYPE_STRING: {
                std::string value;
                GetString(columnIndex, value);
                rowEntity.Put(columnNames[columnIndex], ValueObject(value));
                break;
            }
            case ColumnType::TYPE_BLOB: {
                std::vector<uint8_t> value;
                GetBlob(columnIndex, value);
                rowEntity.Put(columnNames[columnIndex], ValueObject(value));
                break;
            }
            case ColumnType::TYPE_ASSET: {
                ValueObject::Asset value;
                GetAsset(columnIndex, value);
                rowEntity.Put(columnNames[columnIndex], ValueObject(value));
                break;
            }
            case ColumnType::TYPE_ASSETS: {
                ValueObject::Assets value;
                GetAssets(columnIndex, value);
                rowEntity.Put(columnNames[columnIndex], ValueObject(value));
                break;
            }
            default: {
                return E_ERROR;
            }
        }
    }
    return E_OK;
}

int AbsResultSet::GoToRow(int position)
{
    return E_OK;
}

int AbsResultSet::GetColumnType(int columnIndex, ColumnType &columnType)
{
    return E_OK;
}

int AbsResultSet::GetRowIndex(int &position) const
{
    position = rowPos_;
    return E_OK;
}

int AbsResultSet::GoTo(int offset)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int ret = GoToRow(rowPos_ + offset);
    if (ret != E_OK) {
        LOG_WARN("GoToRow ret is %{public}d", ret);
        return ret;
    }
    return E_OK;
}

int AbsResultSet::GoToFirstRow()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int ret = GoToRow(0);
    if (ret != E_OK) {
        LOG_DEBUG("GoToRow ret is %{public}d", ret);
        return ret;
    }
    return E_OK;
}

int AbsResultSet::GoToLastRow()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int rowCnt = 0;
    int ret = GetRowCount(rowCnt);
    if (ret != E_OK) {
        LOG_ERROR("Failed to GetRowCount, ret is %{public}d", ret);
        return ret;
    }

    ret = GoToRow(rowCnt - 1);
    if (ret != E_OK) {
        LOG_WARN("GoToRow ret is %{public}d", ret);
        return ret;
    }
    return E_OK;
}

int AbsResultSet::GoToNextRow()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int ret = GoToRow(rowPos_ + 1);
    if (ret != E_OK) {
        LOG_DEBUG("GoToRow ret is %{public}d", ret);
        return ret;
    }
    return E_OK;
}

int AbsResultSet::GoToPreviousRow()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int ret = GoToRow(rowPos_ - 1);
    if (ret != E_OK) {
        LOG_WARN("GoToRow ret is %{public}d", ret);
        return ret;
    }
    return E_OK;
}

int AbsResultSet::IsAtFirstRow(bool &result) const
{
    result = (rowPos_ == 0);
    return E_OK;
}

int AbsResultSet::IsAtLastRow(bool &result)
{
    int rowCnt = 0;
    int ret = GetRowCount(rowCnt);
    if (ret != E_OK) {
        LOG_ERROR("Failed to GetRowCount, ret is %{public}d", ret);
        return ret;
    }
    result = (rowPos_ == (rowCnt - 1));
    return E_OK;
}

int AbsResultSet::IsStarted(bool &result) const
{
    result = (rowPos_ != INIT_POS);
    return E_OK;
}

int AbsResultSet::IsEnded(bool &result)
{
    int rowCnt = 0;
    int ret = GetRowCount(rowCnt);
    if (ret != E_OK) {
        LOG_ERROR("Failed to GetRowCount, ret is %{public}d", ret);
        return ret;
    }
    result = (rowCnt == 0) ? true : (rowPos_ == rowCnt);
    return E_OK;
}

int AbsResultSet::GetColumnCount(int &count)
{
    if (columnCount_ != -1) {
        count = columnCount_;
        return E_OK;
    }
    std::vector<std::string> columnNames;
    int ret = GetAllColumnNames(columnNames);
    if (ret != E_OK) {
        LOG_DEBUG("Failed to GetAllColumnNames, ret is %{public}d", ret);
        return ret;
    }
    columnCount_ = static_cast<int>(columnNames.size());
    count = columnCount_;
    return E_OK;
}

int AbsResultSet::GetColumnIndex(const std::string &columnName, int &columnIndex)
{
    std::lock_guard<std::mutex> lock(columnMapLock_);
    auto it = columnMap_.find(columnName);
    if (it != columnMap_.end()) {
        columnIndex = it->second;
        return E_OK;
    }

    auto periodIndex = columnName.rfind('.');
    std::string columnNameLower = columnName;
    if (periodIndex != std::string::npos) {
        columnNameLower = columnNameLower.substr(periodIndex + 1);
    }
    transform(columnNameLower.begin(), columnNameLower.end(), columnNameLower.begin(), ::tolower);
    std::vector<std::string> columnNames;
    int ret = GetAllColumnNames(columnNames);
    if (ret != E_OK) {
        LOG_ERROR("Failed to GetAllColumnNames, ret is %{public}d", ret);
        return ret;
    }
    SqliteUtils::Replace(columnNameLower, SqliteUtils::REP, "");
    columnIndex = 0;
    for (const auto& name : columnNames) {
        std::string lowerName = name;
        transform(name.begin(), name.end(), lowerName.begin(), ::tolower);
        if (lowerName == columnNameLower) {
            columnMap_.insert(std::make_pair(columnName, columnIndex));
            return E_OK;
        }
        columnIndex++;
    }
    columnIndex = -1;
    LOG_ERROR("GetColumnIndex failed, columnName is: %{public}s", columnName.c_str());
    return E_ERROR;
}

int AbsResultSet::GetColumnName(int columnIndex, std::string &columnName)
{
    int rowCnt = 0;
    int ret = GetColumnCount(rowCnt);
    if (ret != E_OK) {
        LOG_ERROR("Failed to GetColumnCount, ret is %{public}d", ret);
        return ret;
    }
    if (columnIndex >= rowCnt || columnIndex < 0) {
        LOG_ERROR("invalid column columnIndex as %{public}d", columnIndex);
        return E_INVALID_COLUMN_INDEX;
    }
    std::vector<std::string> columnNames;
    GetAllColumnNames(columnNames);
    columnName = columnNames[columnIndex];
    return E_OK;
}

bool AbsResultSet::IsClosed() const
{
    return isClosed_;
}

int AbsResultSet::Close()
{
    // clear columnMap_
    auto map = std::move(columnMap_);
    isClosed_ = true;
    return E_OK;
}

int AbsResultSet::GetModifyTime(std::string &modifyTime)
{
    return E_NOT_SUPPORT;
}

int AbsResultSet::GetAsset(int32_t col, ValueObject::Asset &value)
{
    return E_NOT_SUPPORT;
}

int AbsResultSet::GetAssets(int32_t col, ValueObject::Assets &value)
{
    return E_NOT_SUPPORT;
}

int AbsResultSet::Get(int32_t col, ValueObject &value)
{
    return E_NOT_SUPPORT;
}
} // namespace NativeRdb
} // namespace OHOS
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

#define LOG_TAG "AbsResultSet"
#include "abs_result_set.h"

#include <algorithm>
#include <tuple>
#include <utility>

#include "logger.h"
#include "rdb_errno.h"
#include "rdb_trace.h"
#include "result_set.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
void RowEntity::Put(const std::string &name, int32_t index, ValueObject &&value)
{
    if (index < 0 || index >= static_cast<int>(indexs_.size())) {
        return;
    }
    auto it = values_.emplace(name, std::move(value));
    indexs_[index] = it.first;
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

void RowEntity::Clear(int32_t size)
{
    values_.clear();
    indexs_.clear();
    indexs_.resize(size);
}

AbsResultSet::AbsResultSet()
{
}

AbsResultSet::AbsResultSet(bool safe) : globalMtx_(safe)
{
}

AbsResultSet::~AbsResultSet()
{
    rowPos_ = INIT_POS;
    isClosed_ = true;
}

int AbsResultSet::GetRowCount(int &count)
{
    count = rowCount_;
    if (lastErr_ != E_OK) {
        LOG_ERROR("ResultSet has lastErr %{public}d", lastErr_);
        return lastErr_;
    }
    if (rowCount_ != NO_COUNT) {
        return E_OK;
    }

    if (isClosed_) {
        LOG_ERROR("Fail, result set E_ALREADY_CLOSED.");
        return E_ALREADY_CLOSED;
    }

    return E_OK;
}

int AbsResultSet::GetAllColumnNames(std::vector<std::string> &columnNames)
{
    int errCode = E_OK;
    if (columnCount_ < 0) {
        errCode = InitColumnNames();
    }

    if (columnCount_ < 0) {
        return errCode;
    }
    columnNames.resize(columnCount_);
    for (auto &[name, index] : columnMap_) {
        if (index >= columnCount_) {
            continue;
        }
        columnNames[index] = name;
    }
    return E_OK;
}

int AbsResultSet::InitColumnNames()
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }

    auto [errCode, names] = GetColumnNames();
    if (errCode != E_OK) {
        LOG_DEBUG("Ret is %{public}d", errCode);
        return errCode;
    }

    std::lock_guard<decltype(globalMtx_)> lockGuard(globalMtx_);
    if (columnCount_ >= 0) {
        return E_OK;
    }

    for (size_t i = 0; i < names.size(); ++i) {
        columnMap_.insert(std::pair{ names[i], i });
    }
    columnCount_ = static_cast<int>(names.size());
    wholeColumnNames_ = std::move(names);
    return E_OK;
}

std::pair<int, std::vector<std::string>> AbsResultSet::GetWholeColumnNames()
{
    std::vector<std::string> columnNames;
    int errCode = E_OK;
    if (columnCount_ < 0) {
        errCode = InitColumnNames();
    }

    if (columnCount_ < 0) {
        return { errCode, {} };
    }
    columnNames.reserve(columnCount_);
    for (auto &columnName : wholeColumnNames_) {
        columnNames.push_back(std::move(columnName));
    }
    return { E_OK, std::move(columnNames) };
}

int AbsResultSet::GetBlob(int columnIndex, std::vector<uint8_t> &blob)
{
    ValueObject object;
    int errorCode = Get(columnIndex, object);
    if (errorCode != E_OK) {
        return errorCode;
    }
    blob = object;
    int type = object.GetType();
    if (type == ValueObject::TYPE_ASSETS || type == ValueObject::TYPE_ASSET || type == ValueObject::TYPE_BIGINT ||
        type == ValueObject::TYPE_VECS) {
        LOG_ERROR("Type invalid col:%{public}d, type:%{public}d!", columnIndex, type);
        return E_INVALID_OBJECT_TYPE;
    }

    return E_OK;
}

int AbsResultSet::GetString(int columnIndex, std::string &value)
{
    ValueObject object;
    int errorCode = Get(columnIndex, object);
    if (errorCode != E_OK) {
        return errorCode;
    }
    value = static_cast<std::string>(object);
    int type = object.GetType();
    if (type == ValueObject::TYPE_ASSETS || type == ValueObject::TYPE_ASSET || type == ValueObject::TYPE_BIGINT ||
        type == ValueObject::TYPE_VECS) {
        LOG_ERROR("Type invalid col:%{public}d, type:%{public}d!", columnIndex, type);
        return E_INVALID_OBJECT_TYPE;
    }
    return E_OK;
}

int AbsResultSet::GetInt(int columnIndex, int &value)
{
    int64_t temp = 0;
    int errCode = GetLong(columnIndex, temp);
    if (errCode != E_OK) {
        return errCode;
    }
    value = int32_t(temp);
    return E_OK;
}

int AbsResultSet::GetLong(int columnIndex, int64_t &value)
{
    ValueObject object;
    int errorCode = Get(columnIndex, object);
    if (errorCode != E_OK) {
        return errorCode;
    }
    value = object;
    int type = object.GetType();
    if (type == ValueObject::TYPE_ASSETS || type == ValueObject::TYPE_ASSET || type == ValueObject::TYPE_BIGINT ||
        type == ValueObject::TYPE_VECS) {
        LOG_ERROR("Type invalid col:%{public}d, type:%{public}d!", columnIndex, type);
        return E_INVALID_OBJECT_TYPE;
    }
    return E_OK;
}

int AbsResultSet::GetDouble(int columnIndex, double &value)
{
    ValueObject object;
    int errorCode = Get(columnIndex, object);
    if (errorCode != E_OK) {
        return errorCode;
    }
    value = object;
    int type = object.GetType();
    if (type == ValueObject::TYPE_ASSETS || type == ValueObject::TYPE_ASSET || type == ValueObject::TYPE_BIGINT ||
        type == ValueObject::TYPE_VECS) {
        LOG_ERROR("Type invalid col:%{public}d, type:%{public}d!", columnIndex, type);
        return E_INVALID_OBJECT_TYPE;
    }
    return E_OK;
}

int AbsResultSet::IsColumnNull(int columnIndex, bool &isNull)
{
    if (lastErr_ != E_OK) {
        return lastErr_;
    }
    ColumnType columnType = ColumnType::TYPE_NULL;
    int errCode = GetColumnType(columnIndex, columnType);
    if (errCode != E_OK) {
        LOG_ERROR("Ret is %{public}d", errCode);
        return errCode;
    }
    isNull = (columnType == ColumnType::TYPE_NULL);
    return E_OK;
}

int AbsResultSet::GetRow(RowEntity &rowEntity)
{
    int errCode = E_OK;
    if (columnCount_ < 0) {
        errCode = InitColumnNames();
    }

    if (columnCount_ < 0) {
        return errCode;
    }
    rowEntity.Clear(columnCount_);
    for (auto &[name, index] : columnMap_) {
        ValueObject value;
        auto ret = Get(index, value);
        if (ret != E_OK) {
            LOG_ERROR("Get(%{public}d, %{public}s)->ret %{public}d", index, SqliteUtils::Anonymous(name).c_str(), ret);
            return ret;
        }
        rowEntity.Put(name, index, std::move(value));
    }
    return E_OK;
}

std::pair<int, std::vector<ValueObject>> AbsResultSet::GetRowData()
{
    int errCode = E_OK;
    if (columnCount_ < 0) {
        errCode = InitColumnNames();
    }

    if (columnCount_ < 0) {
        return { errCode, {} };
    }
    std::vector<ValueObject> rowData;
    rowData.reserve(columnCount_);
    int index = 0;
    for (auto &columnName : wholeColumnNames_) {
        ValueObject value;
        auto ret = Get(index, value);
        if (ret != E_OK) {
            LOG_ERROR("Get(%{public}d, %{public}s)->ret %{public}d", index,
                SqliteUtils::Anonymous(columnName).c_str(), ret);
            return { ret, {} };
        }
        rowData.push_back(std::move(value));
        index++;
    }
    return { E_OK, std::move(rowData) };
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
    return GoToRow(rowPos_ + offset);
}

int AbsResultSet::GoToFirstRow()
{
    return GoToRow(0);
}

int AbsResultSet::GoToLastRow()
{
    int rowCnt = 0;
    int ret = GetRowCount(rowCnt);
    if (ret != E_OK) {
        LOG_ERROR("Failed to GetRowCount, ret is %{public}d", ret);
        return ret;
    }
    if (rowCnt == 0) {
        return E_ERROR;
    }

    return GoToRow(rowCnt - 1);
}

int AbsResultSet::GoToNextRow()
{
    return GoToRow(rowPos_ + 1);
}

int AbsResultSet::GoToPreviousRow()
{
    return GoToRow(rowPos_ - 1);
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

std::pair<int, bool> AbsResultSet::IsEnded()
{
    int rowCnt = 0;
    int ret = GetRowCount(rowCnt);
    if (ret != E_OK) {
        LOG_ERROR("Failed to GetRowCount, ret is %{public}d", ret);
        return { ret, true };
    }
    return { E_OK, (rowCnt == 0) || (rowPos_ == rowCnt) };
}

int AbsResultSet::IsEnded(bool &result)
{
    int res = E_OK;
    std::tie(res, result) = IsEnded();
    return res;
}

int AbsResultSet::GetColumnCount(int &count)
{
    if (columnCount_ >= 0) {
        count = columnCount_;
        return E_OK;
    }
    auto errCode = InitColumnNames();
    if (errCode != E_OK) {
        LOG_DEBUG("Ret is %{public}d", errCode);
        return errCode;
    }
    count = columnCount_;
    return E_OK;
}

int AbsResultSet::GetColumnIndex(const std::string &columnName, int &columnIndex)
{
    columnIndex = -1;
    int errCode = E_OK;
    if (columnCount_ < 0) {
        errCode = InitColumnNames();
    }
    if (columnCount_ < 0) {
        return errCode;
    }
    auto it = columnMap_.find(columnName);
    if (it != columnMap_.end()) {
        columnIndex = it->second;
        return E_OK;
    }

    std::string lowerName = SqliteUtils::Replace(columnName, SqliteUtils::REP, "");
    auto periodIndex = lowerName.rfind('.');
    if (periodIndex != std::string::npos) {
        lowerName = lowerName.substr(periodIndex + 1);
    }
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
    for (const auto &[name, index] : columnMap_) {
        std::string temp = name;
        std::transform(name.begin(), name.end(), temp.begin(), ::tolower);
        if (lowerName == temp) {
            columnIndex = index;
            return E_OK;
        }
    }
    LOG_ERROR("Failed, columnName : %{public}s, errCode : %{public}d",
        SqliteUtils::Anonymous(columnName).c_str(), errCode);
    return E_INVALID_ARGS;
}

int AbsResultSet::GetColumnName(int columnIndex, std::string &columnName)
{
    int32_t errCode = 0;
    if (columnCount_ < 0) {
        errCode = InitColumnNames();
    }
    if (columnCount_ < 0) {
        return errCode;
    }
    if (columnCount_ <= columnIndex || columnIndex < 0) {
        LOG_ERROR("Invalid columnIndex %{public}d", columnIndex);
        return E_COLUMN_OUT_RANGE;
    }

    for (const auto &[name, index] : columnMap_) {
        if (index == columnIndex) {
            columnName = name;
            return E_OK;
        }
    }
    return E_COLUMN_OUT_RANGE;
}

bool AbsResultSet::IsClosed() const
{
    return isClosed_;
}

int AbsResultSet::Close()
{
    // clear columnMap_
    auto map = std::move(columnMap_);
    auto vct = std::move(wholeColumnNames_);
    isClosed_ = true;
    rowPos_ = INIT_POS;
    rowCount_ = NO_COUNT;
    columnCount_ = -1;
    return E_OK;
}

int AbsResultSet::GetAsset(int32_t col, ValueObject::Asset &value)
{
    ValueObject valueObject;
    int errorCode = Get(col, valueObject);
    if (errorCode != E_OK) {
        return errorCode;
    }

    if (valueObject.GetType() == ValueObject::TYPE_NULL) {
        return E_NULL_OBJECT;
    }

    if (valueObject.GetType() != ValueObject::TYPE_ASSET) {
        LOG_ERROR("Failed, type is %{public}d, col is %{public}d!", valueObject.GetType(), col);
        return E_INVALID_OBJECT_TYPE;
    }
    value = valueObject;
    return E_OK;
}

int AbsResultSet::GetAssets(int32_t col, ValueObject::Assets &value)
{
    ValueObject valueObject;
    int errorCode = Get(col, valueObject);
    if (errorCode != E_OK) {
        return errorCode;
    }

    if (valueObject.GetType() == ValueObject::TYPE_NULL) {
        return E_NULL_OBJECT;
    }

    if (valueObject.GetType() != ValueObject::TYPE_ASSETS) {
        LOG_ERROR("Failed, type is %{public}d, col is %{public}d!", valueObject.GetType(), col);
        return E_INVALID_OBJECT_TYPE;
    }
    value = valueObject;
    return E_OK;
}

int AbsResultSet::GetFloat32Array(int32_t col, ValueObject::FloatVector &value)
{
    ValueObject valueObject;
    int errorCode = Get(col, valueObject);
    if (errorCode != E_OK) {
        return errorCode;
    }

    if (valueObject.GetType() == ValueObject::TYPE_NULL) {
        return E_NULL_OBJECT;
    }

    if (valueObject.GetType() != ValueObject::TYPE_VECS) {
        LOG_ERROR("Failed, type is %{public}d, col is %{public}d!", valueObject.GetType(), col);
        return E_INVALID_OBJECT_TYPE;
    }
    value = valueObject;
    return E_OK;
}

std::pair<int, std::vector<std::string>> AbsResultSet::GetColumnNames()
{
    return { E_NOT_SUPPORT, {} };
}
} // namespace NativeRdb
} // namespace OHOS
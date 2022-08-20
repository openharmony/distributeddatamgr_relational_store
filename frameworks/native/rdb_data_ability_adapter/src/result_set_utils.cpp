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

#include "result_set_utils.h"

namespace OHOS::RdbDataAbilityAdapter {
ResultSetUtils::ResultSetUtils(std::shared_ptr<DSResultSet> dbResultSet) : resultSet_(std::move(dbResultSet))
{
}

int ResultSetUtils::GetAllColumnNames(std::vector<std::string> &columnNames)
{
    return resultSet_->GetAllColumnNames(columnNames);
}

int ResultSetUtils::GetColumnCount(int &count)
{
    return resultSet_->GetColumnCount(count);
}

int ResultSetUtils::GetColumnType(int columnIndex, NativeRdb::ColumnType &columnType)
{
    DataShare::DataType dataType;
    auto ret = resultSet_->GetDataType(columnIndex, dataType);
    columnType = NativeRdb::ColumnType(int32_t(dataType));
    return ret;
}

int ResultSetUtils::GetColumnIndex(const std::string &columnName, int &columnIndex)
{
    return resultSet_->GetColumnIndex(columnName, columnIndex);
}

int ResultSetUtils::GetColumnName(int columnIndex, std::string &columnName)
{
    return resultSet_->GetColumnName(columnIndex, columnName);
}

int ResultSetUtils::GetRowCount(int &count)
{
    return resultSet_->GetRowCount(count);
}

int ResultSetUtils::GetRowIndex(int &position) const
{
    return resultSet_->GetRowIndex(position);
}

int ResultSetUtils::GoTo(int offset)
{
    return resultSet_->GoTo(offset);
}

int ResultSetUtils::GoToRow(int position)
{
    return resultSet_->GoToRow(position);
}

int ResultSetUtils::GoToFirstRow()
{
    return resultSet_->GoToFirstRow();
}

int ResultSetUtils::GoToLastRow()
{
    return resultSet_->GoToLastRow();
}

int ResultSetUtils::GoToNextRow()
{
    return resultSet_->GoToNextRow();
}

int ResultSetUtils::GoToPreviousRow()
{
    return resultSet_->GoToPreviousRow();
}

int ResultSetUtils::IsEnded(bool &result)
{
    return resultSet_->IsEnded(result);
}

int ResultSetUtils::IsStarted(bool &result) const
{
    return resultSet_->IsStarted(result);
}

int ResultSetUtils::IsAtFirstRow(bool &result) const
{
    return resultSet_->IsAtFirstRow(result);
}

int ResultSetUtils::IsAtLastRow(bool &result)
{
    return resultSet_->IsAtLastRow(result);
}

int ResultSetUtils::GetBlob(int columnIndex, std::vector<uint8_t> &blob)
{
    return resultSet_->GetBlob(columnIndex, blob);
}

int ResultSetUtils::GetString(int columnIndex, std::string &value)
{
    return resultSet_->GetString(columnIndex, value);
}

int ResultSetUtils::GetInt(int columnIndex, int &value)
{
    return resultSet_->GetInt(columnIndex, value);
}

int ResultSetUtils::GetLong(int columnIndex, int64_t &value)
{
    return resultSet_->GetLong(columnIndex, value);
}

int ResultSetUtils::GetDouble(int columnIndex, double &value)
{
    return resultSet_->GetDouble(columnIndex, value);
}

int ResultSetUtils::IsColumnNull(int columnIndex, bool &isNull)
{
    return resultSet_->IsColumnNull(columnIndex, isNull);
}

bool ResultSetUtils::IsClosed() const
{
    return resultSet_->IsClosed();
}

int ResultSetUtils::Close()
{
    return resultSet_->Close();
}
}

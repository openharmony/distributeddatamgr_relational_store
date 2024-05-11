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

int ResultSetUtils::Close()
{
    auto status = resultSet_->Close();
    if (resultSet_->IsClosed()) {
        AbsResultSet::Close();
    }
    return status;
}

std::pair<int, std::vector<std::string>> ResultSetUtils::GetColumnNames()
{
    std::vector<std::string> names;
    auto errCode = resultSet_->GetAllColumnNames(names);
    return {errCode, std::move(names)};
}
}

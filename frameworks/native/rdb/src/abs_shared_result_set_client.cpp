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

#define LOG_TAG "AbsSharedResultSetClient"

#include "abs_shared_result_set_client.h"
#include "logger.h"

namespace OHOS::NativeRdb {

AbsSharedResultSetClient::AbsSharedResultSetClient(sptr<IResultSet> &resultSetProxy) : resultSetProxy_(resultSetProxy)
{
}

AbsSharedResultSetClient::~AbsSharedResultSetClient()
{
  if (resultSetProxy_) {
    LOG_INFO("Close result set.");
    resultSetProxy_->Close();
  }
}

int AbsSharedResultSetClient::GetAllColumnNames(std::vector<std::string> &columnNames)
{
    return resultSetProxy_->GetAllColumnNames(columnNames);
}

int AbsSharedResultSetClient::GetColumnCount(int &count)
{
    return resultSetProxy_->GetColumnCount(count);
}

int AbsSharedResultSetClient::GetColumnType(int columnIndex, ColumnType &columnType)
{
    return resultSetProxy_->GetColumnType(columnIndex, columnType);
}

int AbsSharedResultSetClient::GetColumnIndex(const std::string &columnName, int &columnIndex)
{
    return resultSetProxy_->GetColumnIndex(columnName, columnIndex);
}

int AbsSharedResultSetClient::GetColumnName(int columnIndex, std::string &columnName)
{
    return resultSetProxy_->GetColumnName(columnIndex, columnName);
}

int AbsSharedResultSetClient::GetRowCount(int &count)
{
    return resultSetProxy_->GetRowCount(count);
}

int AbsSharedResultSetClient::GetRowIndex(int &position) const
{
    return resultSetProxy_->GetRowIndex(position);
}

int AbsSharedResultSetClient::GoTo(int offset)
{
    return resultSetProxy_->GoTo(offset);
}

int AbsSharedResultSetClient::GoToRow(int position)
{
    return resultSetProxy_->GoToRow(position);
}

int AbsSharedResultSetClient::GoToFirstRow()
{
    return resultSetProxy_->GoToFirstRow();
}

int AbsSharedResultSetClient::GoToLastRow()
{
    return resultSetProxy_->GoToLastRow();
}

int AbsSharedResultSetClient::GoToNextRow()
{
    return resultSetProxy_->GoToNextRow();
}

int AbsSharedResultSetClient::GoToPreviousRow()
{
    return resultSetProxy_->GoToPreviousRow();
}

int AbsSharedResultSetClient::IsEnded(bool &result)
{
    return resultSetProxy_->IsEnded(result);
}

int AbsSharedResultSetClient::IsStarted(bool &result) const
{
    return resultSetProxy_->IsStarted(result);
}

int AbsSharedResultSetClient::IsAtFirstRow(bool &result) const
{
    return resultSetProxy_->IsAtFirstRow(result);
}

int AbsSharedResultSetClient::IsAtLastRow(bool &result)
{
    return resultSetProxy_->IsAtLastRow(result);
}

int AbsSharedResultSetClient::GetBlob(int columnIndex, std::vector<uint8_t> &blob)
{
    return resultSetProxy_->GetBlob(columnIndex, blob);
}

int AbsSharedResultSetClient::GetString(int columnIndex, std::string &value)
{
    return resultSetProxy_->GetString(columnIndex, value);
}

int AbsSharedResultSetClient::GetInt(int columnIndex, int &value)
{
    return resultSetProxy_->GetInt(columnIndex, value);
}

int AbsSharedResultSetClient::GetLong(int columnIndex, int64_t &value)
{
    return resultSetProxy_->GetLong(columnIndex, value);
}

int AbsSharedResultSetClient::GetDouble(int columnIndex, double &value)
{
    return resultSetProxy_->GetDouble(columnIndex, value);
}

int AbsSharedResultSetClient::IsColumnNull(int columnIndex, bool &isNull)
{
    return resultSetProxy_->IsColumnNull(columnIndex, isNull);
}

bool AbsSharedResultSetClient::IsClosed() const
{
    return resultSetProxy_->IsClosed();
}

int AbsSharedResultSetClient::Close()
{
    return resultSetProxy_->Close();
}

AppDataFwk::SharedBlock *AbsSharedResultSetClient::GetBlock() const
{
    return nullptr;
}

void AbsSharedResultSetClient::FillBlock(int startRowIndex, AppDataFwk::SharedBlock *block)
{
    return;
}

bool AbsSharedResultSetClient::HasBlock() const
{
    return false;
}
} // namespace OHOS::NativeRdb
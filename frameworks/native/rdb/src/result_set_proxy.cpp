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
#define LOG_TAG "ResultSetProxy"
#include "result_set_proxy.h"

#include "itypes_util.h"
#include "logger.h"
#include "message_parcel.h"
#include "rdb_errno.h"

namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;
using Code = RemoteResultSet::Code;

ResultSetProxy::ResultSetProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IResultSet>(impl)
{
    LOG_INFO("Init result set proxy.");
    remote_ = Remote();
}

ResultSetProxy::~ResultSetProxy()
{
    LOG_INFO("Result set destroy, close result.");
    Close();
}

int ResultSetProxy::GetColumnCount(int &count)
{
    return Send(Code::CMD_GET_COLUMN_COUNT, count);
}

int ResultSetProxy::GetColumnType(int columnIndex, ColumnType &columnType)
{
    MessageParcel reply;
    int status = SendRequest(Code::CMD_GET_COLUMN_TYPE, reply, columnIndex);
    if (status != E_OK) {
        return status;
    }
    int32_t type;
    if (!ITypesUtil::Unmarshal(reply, type)) {
        return E_ERROR;
    }
    columnType = static_cast<ColumnType>(type);
    return E_OK;
}

int ResultSetProxy::GetRowCount(int &count)
{
    return Send(Code::CMD_GET_ROW_COUNT, count);
}

int ResultSetProxy::GetRowIndex(int &position) const
{
    return Send(Code::CMD_GET_ROW_INDEX, position);
}

int ResultSetProxy::GoTo(int offset)
{
    MessageParcel reply;
    return SendRequest(Code::CMD_GO_TO, reply, offset);
}

int ResultSetProxy::GoToRow(int position)
{
    MessageParcel reply;
    return SendRequest(Code::CMD_GO_TO_ROW, reply, position);
}

int ResultSetProxy::GoToFirstRow()
{
    return Send(Code::CMD_GO_TO_FIRST_ROW);
}

int ResultSetProxy::GoToLastRow()
{
    return Send(Code::CMD_GO_TO_LAST_ROW);
}

int ResultSetProxy::GoToNextRow()
{
    return Send(Code::CMD_GO_TO_NEXT_ROW);
}

int ResultSetProxy::GoToPreviousRow()
{
    return Send(Code::CMD_GO_TO_PREV_ROW);
}

int ResultSetProxy::IsEnded(bool &result)
{
    return Send(Code::CMD_IS_ENDED_ROW, result);
}

int ResultSetProxy::IsStarted(bool &result) const
{
    return Send(Code::CMD_IS_STARTED_ROW, result);
}

int ResultSetProxy::IsAtFirstRow(bool &result) const
{
    return Send(Code::CMD_IS_AT_FIRST_ROW, result);
}

int ResultSetProxy::IsAtLastRow(bool &result)
{
    return Send(Code::CMD_IS_AT_LAST_ROW, result);
}

int ResultSetProxy::Get(int32_t col, ValueObject &value)
{
    MessageParcel reply;
    int status = SendRequest(Code::CMD_GET, reply, col);
    if (status != E_OK) {
        return status;
    }
    
    if (!ITypesUtil::Unmarshal(reply, value.value)) {
        return E_ERROR;
    }
    return E_OK;
}

int ResultSetProxy::GetSize(int columnIndex, size_t &size)
{
    MessageParcel reply;
    int status = SendRequest(Code::CMD_GET_SIZE, reply, columnIndex);
    if (status != E_OK) {
        return status;
    }
    if (!ITypesUtil::Unmarshal(reply, size)) {
        return E_ERROR;
    }
    return E_OK;
}

int ResultSetProxy::Close()
{
    auto ret = Send(Code::CMD_CLOSE);
    if (ret == E_OK) {
        AbsResultSet::Close();
    }
    return ret;
}

std::pair<int, std::vector<std::string>> ResultSetProxy::GetColumnNames()
{
    std::vector<std::string> colNames;
    auto status = Send(Code::CMD_GET_ALL_COLUMN_NAMES, colNames);
    if (status != E_OK) {
        LOG_ERROR("Reply error, status:%{public}d, code:%{public}d.", status, Code::CMD_GET_ALL_COLUMN_NAMES);
        return { status, {} };
    }
    return { E_OK, std::move(colNames) };
}

template<typename... T>
int ResultSetProxy::Send(uint32_t code, T &...output) const
{
    MessageParcel reply;
    auto status = SendRequest(code, reply);
    if (status != E_OK) {
        return status;
    }
    if (!ITypesUtil::Unmarshal(reply, output...)) {
        LOG_ERROR("Unmarshal failed, code:%{public}d.", code);
        return E_ERROR;
    }
    return E_OK;
}

template<typename... T>
int ResultSetProxy::SendRequest(uint32_t code, MessageParcel &reply, const T &...input) const
{
    if (remote_ == nullptr) {
        LOG_ERROR("remote_ is null, code:%{public}d, input:%{public}zu.", code, sizeof...(input));
        return E_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(ResultSetProxy::GetDescriptor())) {
        LOG_ERROR("Write descriptor failed, code is %{public}d.", code);
        return E_ERROR;
    }

    if (!ITypesUtil::Marshal(data, input...)) {
        LOG_ERROR("Marshal failed, code is %{public}d.", code);
        return E_ERROR;
    }

    if (!reply.SetMaxCapacity(MAX_IPC_CAPACITY)) {
        LOG_ERROR("Set max capacity failed, code is %{public}d.", code);
        return E_ERROR;
    }

    MessageOption mo{ MessageOption::TF_SYNC };
    int32_t status = remote_->SendRequest(code, data, reply, mo);
    if (status != 0) {
        LOG_ERROR("Send failed, error:%{public}d, code:%{public}d.", status, code);
        return E_ERROR;
    }
    auto success = ITypesUtil::Unmarshal(reply, status);
    if (status != E_OK || !success) {
        LOG_ERROR("Reply failed, status:%{public}d, code:%{public}d.", status, code);
        return E_ERROR;
    }
    return status;
}
} // namespace OHOS::NativeRdb
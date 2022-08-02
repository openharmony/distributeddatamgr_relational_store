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

#include "logger.h"
#include "message_parcel.h"
#include "rdb_errno.h"
#include "result_set_proxy.h"

namespace OHOS::NativeRdb {
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

int ResultSetProxy::GetAllColumnNames(std::vector<std::string> &columnNames)
{
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(ResultSetProxy::GetDescriptor())) {
        LOG_ERROR("Write descriptor failed, code is %{public}d.", CMD_GET_ALL_COLUMN_NAMES);
        return E_ERROR;
    }
    MessageOption mo { MessageOption::TF_SYNC };
    int32_t error = remote_->SendRequest(CMD_GET_ALL_COLUMN_NAMES, data, reply, mo);
    if (error != 0) {
        LOG_ERROR("SendRequest failed, error is %{public}d, code is %{public}d.", error, CMD_GET_ALL_COLUMN_NAMES);
        return E_ERROR;
    }
    int status = reply.ReadInt32();
    if (status != E_OK) {
        LOG_ERROR("Reply status error, status is %{public}d, code is %{public}d.", status, CMD_GET_ALL_COLUMN_NAMES);
        return status;
    }
    if (!reply.ReadStringVector(&columnNames)) {
        LOG_ERROR("Read columnNames failed.");
        return E_ERROR;
    }
    return E_OK;
}

int ResultSetProxy::GetColumnCount(int &count)
{
    return SendRequestRetInt(CMD_GET_COLUMN_COUNT, count);
}

int ResultSetProxy::GetColumnType(int columnIndex, ColumnType &columnType)
{
    MessageParcel reply;
    int status = SendRequestRetReply(CMD_GET_COLUMN_TYPE, columnIndex, reply);
    if (status != E_OK) {
        return status;
    }
    columnType = static_cast<ColumnType>(reply.ReadInt32());
    return E_OK;
}

int ResultSetProxy::GetColumnIndex(const std::string &columnName, int &columnIndex)
{
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(ResultSetProxy::GetDescriptor())) {
        LOG_ERROR("Write descriptor failed, code is %{public}d.", CMD_GET_COLUMN_INDEX);
        return E_ERROR;
    }
    if (!reply.SetMaxCapacity(MAX_IPC_CAPACITY) || !data.WriteString(columnName)) {
        LOG_ERROR("Set max capacity failed or write parcel failed, code is %{public}d.", CMD_GET_COLUMN_INDEX);
        return E_ERROR;
    }
    MessageOption mo { MessageOption::TF_SYNC };
    int32_t error = remote_->SendRequest(CMD_GET_COLUMN_INDEX, data, reply, mo);
    if (error != 0) {
        LOG_ERROR("SendRequest failed, error is %{public}d, code is %{public}d.", error, CMD_GET_COLUMN_INDEX);
        return E_ERROR;
    }
    int status = reply.ReadInt32();
    if (status != E_OK) {
        LOG_ERROR("Reply status error, status is %{public}d, code is %{public}d.", status, CMD_GET_COLUMN_INDEX);
        return status;
    }
    columnIndex = reply.ReadInt32();
    return E_OK;
}

int ResultSetProxy::GetColumnName(int columnIndex, std::string &columnName)
{
    MessageParcel reply;
    int status = SendRequestRetReply(CMD_GET_COLUMN_NAME, columnIndex, reply);
    if (status != E_OK) {
        return status;
    }
    columnName = reply.ReadString();
    return E_OK;
}

int ResultSetProxy::GetRowCount(int &count)
{
    return SendRequestRetInt(CMD_GET_ROW_COUNT, count);
}

int ResultSetProxy::GetRowIndex(int &position) const
{
    return SendRequestRetInt(CMD_GET_ROW_INDEX, position);
}

int ResultSetProxy::GoTo(int offset)
{
    return SendIntRequest(CMD_GO_TO, offset);
}

int ResultSetProxy::GoToRow(int position)
{
    return SendIntRequest(CMD_GO_TO_ROW, position);
}

int ResultSetProxy::GoToFirstRow()
{
    return SendRequest(CMD_GO_TO_FIRST_ROW);
}

int ResultSetProxy::GoToLastRow()
{
    return SendRequest(CMD_GO_TO_LAST_ROW);
}

int ResultSetProxy::GoToNextRow()
{
    return SendRequest(CMD_GO_TO_NEXT_ROW);
}

int ResultSetProxy::GoToPreviousRow()
{
    return SendRequest(CMD_GO_TO_PREV_ROW);
}

int ResultSetProxy::IsEnded(bool &result)
{
    return SendRequestRetBool(CMD_IS_ENDED_ROW, result);
}

int ResultSetProxy::IsStarted(bool &result) const
{
    return SendRequestRetBool(CMD_IS_STARTED_ROW, result);
}

int ResultSetProxy::IsAtFirstRow(bool &result) const
{
    return SendRequestRetBool(CMD_IS_AT_FIRST_ROW, result);
}

int ResultSetProxy::IsAtLastRow(bool &result)
{
    return SendRequestRetBool(CMD_IS_AT_LAST_ROW, result);
}

int ResultSetProxy::GetBlob(int columnIndex, std::vector<uint8_t> &blob)
{
    MessageParcel reply;
    int status = SendRequestRetReply(CMD_GET_BLOB, columnIndex, reply);
    if (status != E_OK) {
        return status;
    }
    if (!reply.ReadUInt8Vector(&blob)) {
        LOG_ERROR("Read blob failed.");
        return E_ERROR;
    }
    return E_OK;
}

int ResultSetProxy::GetString(int columnIndex, std::string &value)
{
    MessageParcel reply;
    int status = SendRequestRetReply(CMD_GET_STRING, columnIndex, reply);
    if (status != E_OK) {
        return status;
    }
    value = reply.ReadString();
    return E_OK;
}

int ResultSetProxy::GetInt(int columnIndex, int &value)
{
    MessageParcel reply;
    int status = SendRequestRetReply(CMD_GET_INT, columnIndex, reply);
    if (status != E_OK) {
        return status;
    }
    value = reply.ReadInt32();
    return E_OK;
}

int ResultSetProxy::GetLong(int columnIndex, int64_t &value)
{
    MessageParcel reply;
    int status = SendRequestRetReply(CMD_GET_LONG, columnIndex, reply);
    if (status != E_OK) {
        return status;
    }
    value = reply.ReadInt64();
    return E_OK;
}

int ResultSetProxy::GetDouble(int columnIndex, double &value)
{
    MessageParcel reply;
    int status = SendRequestRetReply(CMD_GET_DOUBLE, columnIndex, reply);
    if (status != E_OK) {
        return status;
    }
    value = reply.ReadDouble();
    return E_OK;
}

int ResultSetProxy::IsColumnNull(int columnIndex, bool &isNull)
{
    MessageParcel reply;
    int status = SendRequestRetReply(CMD_IS_COLUMN_NULL, columnIndex, reply);
    if (status != E_OK) {
        return status;
    }
    isNull = reply.ReadBool();
    return E_OK;
}

bool ResultSetProxy::IsClosed() const
{
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(ResultSetProxy::GetDescriptor())) {
        LOG_ERROR("Write descriptor failed, code is %{public}d.", CMD_IS_CLOSED);
        return false;
    }
    MessageOption mo { MessageOption::TF_SYNC };
    int32_t error = remote_->SendRequest(CMD_IS_CLOSED, data, reply, mo);
    if (error != 0) {
        LOG_ERROR("SendRequest failed, error is %{public}d, code is %{public}d.", error, CMD_IS_CLOSED);
        return false;
    }
    return reply.ReadBool();
}

int ResultSetProxy::Close()
{
    return SendRequest(CMD_CLOSE);
}

int ResultSetProxy::SendRequest(uint32_t code)
{
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(ResultSetProxy::GetDescriptor())) {
        LOG_ERROR("Write descriptor failed, code is %{public}d.", code);
        return E_ERROR;
    }
    MessageOption mo { MessageOption::TF_SYNC };
    int32_t error = remote_->SendRequest(code, data, reply, mo);
    if (error != 0) {
        LOG_ERROR("SendRequest failed, error is %{public}d, code is %{public}d.", error, code);
        return E_ERROR;
    }
    int status = reply.ReadInt32();
    if (status != E_OK) {
        LOG_ERROR("Reply status error, status is %{public}d, code is %{public}d.", status, code);
        return status;
    }
    return E_OK;
}

int ResultSetProxy::SendIntRequest(uint32_t code, int value)
{
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(ResultSetProxy::GetDescriptor())) {
        LOG_ERROR("Write descriptor failed, code is %{public}d.", code);
        return E_ERROR;
    }
    if (!reply.SetMaxCapacity(MAX_IPC_CAPACITY) || !data.WriteInt32(value)) {
        LOG_ERROR("Set max capacity failed or write parcel failed, code is %{public}d.", code);
        return E_ERROR;
    }
    MessageOption mo { MessageOption::TF_SYNC };
    int32_t error = remote_->SendRequest(code, data, reply, mo);
    if (error != 0) {
        LOG_ERROR("SendRequest failed, error is %{public}d, code is %{public}d.", error, code);
        return E_ERROR;
    }
    int status = reply.ReadInt32();
    if (status != E_OK) {
        LOG_ERROR("Reply status error, status is %{public}d, code is %{public}d.", status, code);
        return status;
    }
    return E_OK;
}

int ResultSetProxy::SendRequestRetBool(uint32_t code, bool &result) const
{
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(ResultSetProxy::GetDescriptor())) {
        LOG_ERROR("Write descriptor failed, code is %{public}d.", code);
        return E_ERROR;
    }
    MessageOption mo { MessageOption::TF_SYNC };
    int32_t error = remote_->SendRequest(code, data, reply, mo);
    if (error != 0) {
        LOG_ERROR("SendRequest failed, error is %{public}d, code is %{public}d.", error, code);
        return E_ERROR;
    }
    int status = reply.ReadInt32();
    if (status != E_OK) {
        LOG_ERROR("Reply status error, status is %{public}d, code is %{public}d.", status, code);
        return status;
    }
    result = reply.ReadBool();
    return E_OK;
}

int ResultSetProxy::SendRequestRetInt(uint32_t code, int &result) const
{
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(ResultSetProxy::GetDescriptor())) {
        LOG_ERROR("Write descriptor failed, code is %{public}d.", code);
        return E_ERROR;
    }
    MessageOption mo { MessageOption::TF_SYNC };
    int32_t error = remote_->SendRequest(code, data, reply, mo);
    if (error != 0) {
        LOG_ERROR("SendRequest failed, error is %{public}d, code is %{public}d.", error, code);
        return E_ERROR;
    }
    int status = reply.ReadInt32();
    if (status != E_OK) {
        LOG_ERROR("Reply status error, status is %{public}d, code is %{public}d.", status, code);
        return status;
    }
    result = reply.ReadInt32();
    return E_OK;
}

int ResultSetProxy::SendRequestRetReply(uint32_t code, int columnIndex, MessageParcel &reply)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(ResultSetProxy::GetDescriptor())) {
        LOG_ERROR("Write descriptor failed, code is %{public}d.", code);
        return E_ERROR;
    }
    if (!reply.SetMaxCapacity(MAX_IPC_CAPACITY) || !data.WriteInt32(columnIndex)) {
        LOG_ERROR("Set max capacity failed or write parcel failed, code is %{public}d.", code);
        return E_ERROR;
    }
    MessageOption mo { MessageOption::TF_SYNC };
    int32_t error = remote_->SendRequest(code, data, reply, mo);
    if (error != 0) {
        LOG_ERROR("SendRequest failed, error is %{public}d, code is %{public}d.", error, code);
        return E_ERROR;
    }
    int status = reply.ReadInt32();
    if (status != E_OK) {
        LOG_ERROR("Reply status error, status is %{public}d, code is %{public}d.", status, code);
        return status;
    }
    return E_OK;
}
} // namespace OHOS::NativeRdb
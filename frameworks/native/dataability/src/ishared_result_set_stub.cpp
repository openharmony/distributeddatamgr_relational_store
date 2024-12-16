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
#define LOG_TAG "ISharedResultSetStub"
#include "ishared_result_set_stub.h"

#include <future>

#include "logger.h"
#include "rdb_errno.h"
#include "shared_block.h"
namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;

std::function<sptr<ISharedResultSet>(std::shared_ptr<AbsSharedResultSet>, MessageParcel &)>
    ISharedResultSet::providerCreator_ = ISharedResultSetStub::CreateStub;
constexpr ISharedResultSetStub::Handler ISharedResultSetStub::handlers[static_cast<uint32_t>(ResultSetCode::FUNC_BUTT)];

sptr<ISharedResultSet> ISharedResultSetStub::CreateStub(
    std::shared_ptr<AbsSharedResultSet> result, OHOS::MessageParcel &parcel)
{
    sptr<ISharedResultSet> stub = new (std::nothrow) ISharedResultSetStub(result);
    if (stub == nullptr) {
        LOG_ERROR("Stub is nullptr.");
        return nullptr;
    }
    if (result == nullptr) {
        LOG_ERROR("Result is nullptr.");
        return nullptr;
    }
    parcel.WriteRemoteObject(stub->AsObject());
    auto block = result->GetBlock();
    if (block != nullptr) {
        block->WriteMessageParcel(parcel);
    }
    return stub;
}

ISharedResultSetStub::ISharedResultSetStub(std::shared_ptr<AbsSharedResultSet> resultSet)
    : resultSet_(std::move(resultSet))
{
}
ISharedResultSetStub::~ISharedResultSetStub()
{
}

int ISharedResultSetStub::OnRemoteRequest(
    uint32_t code, OHOS::MessageParcel &data, OHOS::MessageParcel &reply, OHOS::MessageOption &option)
{
    if (GetDescriptor() != data.ReadInterfaceToken()) {
        LOG_ERROR("IPC descriptor is  not equal.");
        return INVALID_FD;
    }

    if (code >= static_cast<uint32_t>(ResultSetCode::FUNC_BUTT)) {
        LOG_ERROR("OnRemoteRequest method code(%{public}d) out of range.", code);
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    Handler handler = handlers[code];
    if (handler == nullptr) {
        LOG_ERROR("OnRemoteRequest method code(%{public}d) is not support.", code);
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return (this->*handler)(data, reply);
}

int ISharedResultSetStub::HandleGetRowCountRequest(MessageParcel &data, MessageParcel &reply)
{
    int count = -1;
    int errCode = resultSet_->GetRowCount(count);
    reply.WriteInt32(errCode);
    if (errCode == E_OK) {
        reply.WriteInt32(count);
    }
    LOG_DEBUG("HandleGetRowCountRequest call %{public}d", errCode);
    return NO_ERROR;
}

int ISharedResultSetStub::HandleGetColumnNamesRequest(MessageParcel &data, MessageParcel &reply)
{
    auto [errCode, names] = GetColumnNames();
    reply.WriteInt32(errCode);
    if (errCode == E_OK) {
        reply.WriteStringVector(names);
    }
    LOG_DEBUG("HandleGetColumnNamesRequest call %{public}d", errCode);
    return NO_ERROR;
}

int ISharedResultSetStub::HandleOnGoRequest(MessageParcel &data, MessageParcel &reply)
{
    int oldRow = data.ReadInt32();
    int newRow = data.ReadInt32();
    int errCode = resultSet_->OnGo(oldRow, newRow);
    reply.WriteInt32(errCode);
    LOG_DEBUG("HandleOnGoRequest call %{public}d", errCode);
    return NO_ERROR;
}

int ISharedResultSetStub::HandleCloseRequest(MessageParcel &data, MessageParcel &reply)
{
    int errCode = resultSet_->Close();
    reply.WriteInt32(errCode);
    LOG_DEBUG("HandleCloseRequest call %{public}d", errCode);
    return NO_ERROR;
}

std::pair<int, std::vector<std::string>> ISharedResultSetStub::GetColumnNames()
{
    return resultSet_->GetColumnNames();
}
} // namespace OHOS::NativeRdb
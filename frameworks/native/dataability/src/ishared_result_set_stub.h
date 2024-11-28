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

#ifndef DATAABILITY_I_SHARED_RESULT_SET_STUB_H
#define DATAABILITY_I_SHARED_RESULT_SET_STUB_H
#include <functional>
#include <future>

#include "iremote_stub.h"
#include "ishared_result_set.h"
#include "safe_block_queue.h"
namespace OHOS::NativeRdb {
using ResultSetCode = OHOS::DistributedRdb::RelationalStore::IResultSetInterfaceCode;

class ISharedResultSetStub : public IRemoteStub<ISharedResultSet> {
public:
    explicit ISharedResultSetStub(std::shared_ptr<AbsSharedResultSet> resultSet);
    ~ISharedResultSetStub();
    static sptr<ISharedResultSet> CreateStub(std::shared_ptr<AbsSharedResultSet> resultSet, MessageParcel &parcel);
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

protected:
    std::pair<int, std::vector<std::string>> GetColumnNames() override;

    int HandleGetRowCountRequest(MessageParcel &data, MessageParcel &reply);
    int HandleGetColumnNamesRequest(MessageParcel &data, MessageParcel &reply);
    int HandleOnGoRequest(MessageParcel &data, MessageParcel &reply);
    int HandleCloseRequest(MessageParcel &data, MessageParcel &reply);

private:
    using Handler = int (ISharedResultSetStub::*)(MessageParcel &request, MessageParcel &reply);
    std::shared_ptr<AbsSharedResultSet> resultSet_;
    static constexpr Handler handlers[static_cast<uint32_t>(ResultSetCode::FUNC_BUTT)]{
        &ISharedResultSetStub::HandleGetRowCountRequest,
        &ISharedResultSetStub::HandleGetColumnNamesRequest,
        &ISharedResultSetStub::HandleOnGoRequest,
        &ISharedResultSetStub::HandleCloseRequest,
    };
};
} // namespace OHOS::NativeRdb

#endif // DATAABILITY_I_SHARED_RESULT_SET_STUB_H

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

#ifndef DATASHARE_STUB_H
#define DATASHARE_STUB_H

#include <iremote_stub.h>
#include <map>

#include "idatashare.h"

namespace OHOS {
namespace DataShare {
class DataShareStub : public IRemoteStub<IDataShare> {
public:
    DataShareStub();
    ~DataShareStub();
    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;
private:
    ErrCode CmdGetFileTypes(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdOpenFile(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdOpenRawFile(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdInsert(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdUpdate(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdDelete(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdQuery(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdGetType(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdBatchInsert(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdRegisterObserver(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdUnregisterObserver(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdNotifyChange(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdNormalizeUri(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdDenormalizeUri(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdExecuteBatch(MessageParcel &data, MessageParcel &reply);

    using RequestFuncType = int (DataShareStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, RequestFuncType> stubFuncMap_;
};
} // namespace DataShare
} // namespace OHOS
#endif // DATASHARE_STUB_H


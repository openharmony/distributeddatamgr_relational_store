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

#ifndef DATAABILITY_I_SHARED_RESULT_SET_H
#define DATAABILITY_I_SHARED_RESULT_SET_H
#include <memory>
#include "iremote_broker.h"
#include "abs_shared_result_set.h"
#include "distributeddata_relational_store_ipc_interface_code.h"
namespace OHOS::NativeRdb {
class API_EXPORT ISharedResultSet : public AbsSharedResultSet, public IRemoteBroker {
public:
    API_EXPORT DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.NativeRdb.ISharedResultSet")
    API_EXPORT static std::shared_ptr<AbsSharedResultSet> ReadFromParcel(MessageParcel &parcel);
    API_EXPORT static sptr<ISharedResultSet> WriteToParcel(
        std::shared_ptr<AbsSharedResultSet> resultSet, MessageParcel &parcel);
 
private:
    static std::function<std::shared_ptr<AbsSharedResultSet>(MessageParcel &parcel)> consumerCreator_;
    static std::function<sptr<ISharedResultSet>(std::shared_ptr<AbsSharedResultSet>, MessageParcel &)> providerCreator_;
};
} // namespace OHOS::NativeRdb

#endif // DATAABILITY_I_SHARED_RESULT_SET_H

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

#ifndef DATAABILITY_I_SHARED_RESULT_SET_PROXY_H
#define DATAABILITY_I_SHARED_RESULT_SET_PROXY_H
#include <abs_shared_result_set.h>

#include "ishared_result_set.h"
#include "iremote_proxy.h"
#include "rdb_errno.h"

namespace OHOS::NativeRdb {
class ISharedResultSetProxy : public IRemoteProxy<ISharedResultSet> {
public:
    static std::shared_ptr<AbsSharedResultSet> CreateProxy(MessageParcel &parcel);
    explicit ISharedResultSetProxy(const sptr<IRemoteObject> &impl);
    virtual ~ISharedResultSetProxy() = default;
    int GetRowCount(int &count) override;
    int OnGo(int oldRowIndex, int newRowIndex) override;
    int Close() override;

protected:
    std::pair<int, std::vector<std::string>> GetColumnNames() override;

private:
    static BrokerDelegator<ISharedResultSetProxy> delegator_;
    int32_t rowCount_ = -1;
};
}
#endif // DATAABILITY_I_SHARED_RESULT_SET_PROXY_H

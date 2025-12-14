/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_RELATION_STORE_RESULT_SET_PROXY_H
#define OHOS_RELATION_STORE_RESULT_SET_PROXY_H

#include "ani_rdb_utils.h"
#include "datashare_abs_predicates.h"
#include "js_proxy.h"
#include "rdb_result_set_bridge.h"

namespace OHOS {
namespace RdbTaihe {
using namespace taihe;
using namespace ohos::data::relationalStore;
using namespace OHOS;
using namespace OHOS::Rdb;
using namespace OHOS::RdbTaihe;
using ValueType = ohos::data::relationalStore::ValueType;
using ValueObject = OHOS::NativeRdb::ValueObject;

class ResultSetProxy final : public OHOS::JSProxy::JSCreator<OHOS::DataShare::ResultSetBridge> {
public:
    ResultSetProxy() = default;
    explicit ResultSetProxy(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet);
    ResultSetProxy& operator=(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet);
    std::shared_ptr<OHOS::DataShare::ResultSetBridge> Create() override;

protected:
    std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet_;
};
}
}

#endif // OHOS_RELATION_STORE_RESULT_SET_PROXY_H
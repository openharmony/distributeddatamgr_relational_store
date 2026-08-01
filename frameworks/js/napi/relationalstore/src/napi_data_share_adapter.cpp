/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "napi_rdb_context.h"
#include "napi_rdb_store.h"
#include "napi_result_set.h"
#include "rdb_utils.h"
#include "rdb_result_set_bridge.h"
#include "napi_rdb_error.h"

using namespace OHOS::DataShare;
using namespace OHOS::Rdb;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace RelationalStoreJsKit {

struct PredicatesProxy {
    std::shared_ptr<DataShareAbsPredicates> predicates_;
};

int ParseDataSharePredicates(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
    CHECK_RETURN_SET(obj->IsSystemAppCalled(), std::make_shared<NonSystemError>());
    PredicatesProxy *proxy = nullptr;
    napi_status status = napi_unwrap(env, arg, reinterpret_cast<void **>(&proxy));
    bool checked = (status == napi_ok) && (proxy != nullptr) && (proxy->predicates_ != nullptr);
    CHECK_RETURN_SET(checked, std::make_shared<ParamError>("predicates", "an DataShare Predicates."));

    std::shared_ptr<DataShareAbsPredicates> dsPredicates = proxy->predicates_;
    RdbPredicates rdbPredicates = RdbDataShareAdapter::RdbUtils::ToPredicates(*dsPredicates, context->tableName);
    context->rdbPredicates = std::make_shared<RdbPredicates>(rdbPredicates);
    return OK;
}

std::shared_ptr<DataShare::ResultSetBridge> ResultSetProxy::CreateBridge(
    std::shared_ptr<NativeRdb::ResultSet> instance)
{
    return std::make_shared<RdbDataShareAdapter::RdbResultSetBridge>(instance);
}

} // namespace RelationalStoreJsKit
} // namespace OHOS
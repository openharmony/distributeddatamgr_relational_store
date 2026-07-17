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
#include "abs_shared_result_set.h"

using namespace OHOS::DataShare;
using namespace OHOS::Rdb;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace RdbJsKit {

struct PredicatesProxy {
    std::shared_ptr<DataShareAbsPredicates> predicates_;
};

int ParseDataSharePredicatesImpl(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    std::shared_ptr<Error> paramError =
        std::make_shared<ParamTypeError>("predicates", "an RdbPredicates or DataShare Predicates.");
    PredicatesProxy *proxy = nullptr;
    napi_unwrap(env, arg, reinterpret_cast<void **>(&proxy));
    RDB_CHECK_RETURN_CALL_RESULT(proxy != nullptr, context->SetError(paramError));
    LOG_DEBUG("Parse DataShare Predicates.");
    paramError = std::make_shared<ParamTypeError>("predicates", "an DataShare Predicates.");
    LOG_ERROR("dsPredicates is null ? %{public}d.", (proxy->predicates_ == nullptr));
    RDB_CHECK_RETURN_CALL_RESULT(proxy->predicates_ != nullptr, context->SetError(paramError));
    std::shared_ptr<DataShareAbsPredicates> dsPredicates = proxy->predicates_;
    context->rdbPredicates = std::make_shared<RdbPredicates>(
        RdbDataShareAdapter::RdbUtils::ToPredicates(*dsPredicates, context->tableName));
    return OK;
}

std::shared_ptr<DataShare::ResultSetBridge> ResultSetProxy::CreateBridge(
    std::shared_ptr<NativeRdb::ResultSet> instance)
{
    return std::make_shared<RdbDataShareAdapter::RdbResultSetBridge>(instance);
}

} // namespace RdbJsKit
} // namespace OHOS

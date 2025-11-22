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

#ifndef RDB_JSKIT_NAPI_LITE_RESULT_SET_H
#define RDB_JSKIT_NAPI_LITE_RESULT_SET_H

#include <memory>

#include "asset_value.h"
#include "js_proxy.h"
#include "napi_async_call.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_rdb_error.h"
#include "result_set.h"

namespace OHOS {
namespace RelationalStoreJsKit {
using namespace OHOS::NativeRdb;
class LiteResultSetProxy : public JSProxy::JSProxy<NativeRdb::ResultSet> {
public:
    LiteResultSetProxy() = default;
    ~LiteResultSetProxy();
    LiteResultSetProxy(std::shared_ptr<NativeRdb::ResultSet> resultSet);
    LiteResultSetProxy &operator=(std::shared_ptr<NativeRdb::ResultSet> resultSet);
    static void Init(napi_env env, napi_value exports);
    static napi_value NewInstance(napi_env env, std::shared_ptr<NativeRdb::ResultSet> resultSet);
    static napi_value Initialize(napi_env env, napi_callback_info info);

    static std::pair<int, std::vector<RowEntity>> GetRows(ResultSet &resultSet, int32_t maxCount, int32_t position);
    static napi_value GetColumnIndex(napi_env env, napi_callback_info info);
    static napi_value GetColumnName(napi_env env, napi_callback_info info);
    static napi_value GetColumnType(napi_env env, napi_callback_info info);
    static napi_value GoToNextRow(napi_env env, napi_callback_info info);
    static napi_value GetLong(napi_env env, napi_callback_info info);
    static napi_value GetBlob(napi_env env, napi_callback_info info);
    static napi_value GetString(napi_env env, napi_callback_info info);
    static napi_value GetDouble(napi_env env, napi_callback_info info);
    static napi_value GetAsset(napi_env env, napi_callback_info info);
    static napi_value GetAssets(napi_env env, napi_callback_info info);
    static napi_value GetValue(napi_env env, napi_callback_info info);
    static napi_value GetFloat32Array(napi_env env, napi_callback_info info);
    static napi_value GetRow(napi_env env, napi_callback_info info);
    static napi_value GetRows(napi_env env, napi_callback_info info);
    static napi_value IsColumnNull(napi_env env, napi_callback_info info);
    static napi_value Close(napi_env env, napi_callback_info info);
};
} // namespace RelationalStoreJsKit
} // namespace OHOS
#endif // RDB_JSKIT_NAPI_LITE_RESULT_SET_H

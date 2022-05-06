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

#ifndef NAPI_DATASHARE_ABSTRACT_RESULT_SET_H
#define NAPI_DATASHARE_ABSTRACT_RESULT_SET_H

#include <memory>
#include "datashare_abstract_result_set.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace DataShare {
class NapiDataShareAbstractResultSet final {
public:
    NapiDataShareAbstractResultSet() = default;
    ~NapiDataShareAbstractResultSet();
    explicit NapiDataShareAbstractResultSet(std::shared_ptr<DataShareAbstractResultSet> resultSet);
    NapiDataShareAbstractResultSet &operator=(std::shared_ptr<DataShareAbstractResultSet> resultSet);
    static napi_value NewInstance(napi_env env, std::shared_ptr<DataShareAbstractResultSet> resultSet);
    static std::shared_ptr<DataShareAbstractResultSet> GetNativeObject(
        const napi_env &env, const napi_value &arg);
    static napi_value GetConstructor(napi_env env);

private:
    static std::shared_ptr<DataShareAbstractResultSet> &GetInnerAbstractResultSet(napi_env env,
        napi_callback_info info);
    static napi_value Initialize(napi_env env, napi_callback_info info);

    static napi_value GetRowCount(napi_env env, napi_callback_info info);
    static napi_value GetAllColumnNames(napi_env env, napi_callback_info info);

    std::shared_ptr<DataShareAbstractResultSet> resultSet_;
};
napi_value GetNapiAbstractResultSetObject(napi_env env, DataShareAbstractResultSet *resultSet);
DataShareAbstractResultSet *GetNativeAbstractResultSetObject(const napi_env &env, const napi_value &arg);
} // namespace DataShare
} // namespace OHOS
#endif // NAPI_DATASHARE_ABSTRACT_RESULT_SET_H

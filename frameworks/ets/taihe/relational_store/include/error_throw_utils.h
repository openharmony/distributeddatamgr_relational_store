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
#ifndef ERROR_THROW_H
#define ERROR_THROW_H

#include "napi_rdb_js_utils.h"
namespace OHOS {
namespace RdbTaihe {
using namespace OHOS;
using namespace OHOS::Rdb;
using namespace OHOS::RelationalStoreJsKit;

#define ASSERT_THROW_INNER_ERROR(assertion, errCode, errMsg, retVal) \
    CHECK_RETURN_CORE(assertion, ThrowInnerError((errCode), (errMsg)), retVal)

#define ASSERT_THROW_INNER_ERROR_EXT(assertion, errCode, errMsg, retVal) \
    CHECK_RETURN_CORE(assertion, ThrowInnerErrorExt((errCode), (errMsg)), retVal)

#define ASSERT_THROW_NON_SYSTEM_ERROR(assertion, retVal) \
    CHECK_RETURN_CORE(assertion, ThrowNonSystemError(), retVal)

#define ASSERT_THROW_PARAM_ERROR(assertion, needed, mustbe, retVal) \
    CHECK_RETURN_CORE(assertion, ThrowParamError((needed), (mustbe)), retVal)

#define CHECK_ERRCODE_THROW_INNER_ERROR(errCode, errMsg, retVal) \
    ASSERT_THROW_INNER_ERROR((errCode) == OHOS::NativeRdb::E_OK, (errCode), (errMsg), retVal)

#define CHECK_ERRCODE_THROW_INNER_ERROR_EXT(errCode, errMsg, retVal) \
    ASSERT_THROW_INNER_ERROR_EXT((errCode) == OHOS::NativeRdb::E_OK, (errCode), (errMsg), retVal)

std::string GetErrorString(int errcode);
void ThrowError(std::shared_ptr<Error> err);
void ThrowInnerError(int errCode, const std::string &errMsg = "");
void ThrowInnerErrorExt(int errCode, const std::string &errMsg = "");
void ThrowNonSystemError();
void ThrowParamError(const std::string &needed, const std::string &mustbe = "");

} // namespace RdbTaihe
} // namespace OHOS

#endif // ERROR_THROW_H
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

#include "napi_rdb_js_utils.h"

#ifndef ERROR_THROW_H
#define ERROR_THROW_H

namespace OHOS {
namespace RdbTaihe {
using namespace OHOS;
using namespace OHOS::Rdb;

void ThrowError(std::shared_ptr<Error> err);
#define ASSERT_RETURN_THROW_ERROR(assertion, error, retVal) CHECK_RETURN_CORE(assertion, ThrowError(error), retVal)
void ThrowInnerError(int errCode);
void ThrowInnerErrorExt(int errCode);
void ThrowNonSystemError();
void ThrowParamError(const char *message);

} // namespace RdbTaihe
} // namespace OHOS

#endif // ERROR_THROW_H
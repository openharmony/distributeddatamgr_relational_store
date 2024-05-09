/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef CONVERATOR_ERROR_CODE_H
#define CONVERATOR_ERROR_CODE_H
namespace OHOS::RdbNdk {
class ConvertorErrorCode final {
private:
    ConvertorErrorCode() = default;
    ~ConvertorErrorCode() = default;

public:
    static int NativeToNdk(int nativeErrCode);
};
} // namespace OHOS::RdbNdk
#endif // CONVERATOR_ERROR_CODE_H
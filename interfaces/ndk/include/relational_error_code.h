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

#ifndef RELATIONAL_ERRNO_CODE_H
#define RELATIONAL_ERRNO_CODE_H

#ifdef __cplusplus
extern "C" {
#endif

enum RDB_ErrCode {
    E_OK = 0,
    E_INVALID_ARG = 1,
    E_LENGTH_ERROR = 2,
};

#ifdef __cplusplus
};
#endif

#endif //RELATIONAL_ERRNO_CODE_H
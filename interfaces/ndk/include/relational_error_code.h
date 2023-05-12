/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

enum OH_Rdb_ErrCode {
    RDB_ERR_INVALID_ARGS = -2,
    RDB_ERR = -1,
    RDB_ERR_OK = 0
};

#ifdef __cplusplus
};
#endif

#endif // RELATIONAL_ERRNO_CODE_H
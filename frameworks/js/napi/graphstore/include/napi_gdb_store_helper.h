/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef GDB_JS_NAPI_DB_STORE_HELPER_H
#define GDB_JS_NAPI_DB_STORE_HELPER_H

#include <memory>
#include <string>
#include <vector>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_gdb_error.h"


namespace OHOS::GraphStoreJsKit {
napi_value InitGdbHelper(napi_env env, napi_value exports);
} // namespace OHOS::GraphStoreJsKit


#endif
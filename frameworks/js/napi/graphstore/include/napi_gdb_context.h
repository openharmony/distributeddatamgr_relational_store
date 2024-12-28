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
#ifndef GDB_JS_NAPI_GDB_CONTEXT_H
#define GDB_JS_NAPI_GDB_CONTEXT_H

#include "full_result.h"
#include "gdb_store.h"
#include "gdb_store_config.h"
#include "napi_async_call.h"

namespace OHOS {
namespace GraphStoreJsKit {
using namespace OHOS::DistributedDataAip;
struct GdbStoreContextBase : public ContextBase {
    std::shared_ptr<DBStore> gdbStore = nullptr;
};

struct ContextParam {
    std::string bundleName;
    std::string moduleName;
    std::string baseDir;
    int32_t area = 2;
    bool isSystemApp = false;
    bool isStageMode = true;
};

struct GdbStoreContext : public GdbStoreContextBase {
    std::string device;
    std::string gql;
    std::vector<std::string> columns;
    int64_t int64Output;
    int intOutput;
    ContextParam param;
    StoreConfig config;
    std::shared_ptr<Result> result;
    std::vector<std::string> keys;
    std::string key;
    std::string aliasName;
    std::string pathName;
    std::string srcName;
    std::string columnName;
    int32_t enumArg;
    uint64_t cursor = UINT64_MAX;
    int64_t txId = 0;
    napi_ref asyncHolder = nullptr;
    bool isQueryGql = false;
    uint32_t expiredTime = 0;

    GdbStoreContext() : int64Output(0), intOutput(0), enumArg(-1)
    {
    }
    virtual ~GdbStoreContext()
    {
    }
};
} // namespace GraphStoreJsKit
} // namespace OHOS
#endif
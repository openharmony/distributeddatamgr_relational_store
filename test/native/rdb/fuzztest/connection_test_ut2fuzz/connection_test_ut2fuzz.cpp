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
#include "connection_test_ut2fuzz.h"

#include <fuzzer/FuzzedDataProvider.h>
#include "connection.h"

#include <climits>
#include <string>

#include "grd_type_export.h"
#include "rdb_errno.h"
#include "rdb_store_config.h"


using namespace OHOS;
using namespace OHOS::NativeRdb;
namespace OHOS {

void ConnectionTestConnectionTest001(FuzzedDataProvider &fdp)
{
    RdbStoreConfig config(fdp.ConsumeRandomLengthString());
    config.SetDBType(OHOS::NativeRdb::DBType::DB_BUTT);
    Connection::Create(config, fdp.ConsumeBool());
}

void ConnectionTestConnectionTest002(FuzzedDataProvider &fdp)
{
    RdbStoreConfig config(fdp.ConsumeRandomLengthString());
    config.SetDBType(OHOS::NativeRdb::DBType::DB_BUTT);
    Connection::Repair(config);
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::ConnectionTestConnectionTest001(fdp);
    OHOS::ConnectionTestConnectionTest002(fdp);
    return 0;
}

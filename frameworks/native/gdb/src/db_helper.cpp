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
#include <memory>

#include "gdb_errors.h"
#include "db_store_manager.h"
#include "db_trace.h"
#include "gdb_helper.h"

namespace OHOS::DistributedDataAip {

std::shared_ptr<DBStore> GDBHelper::GetDBStore(const StoreConfig &config, int &errCode)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    return StoreManager::GetInstance().GetDBStore(config, errCode);
}

int GDBHelper::DeleteDBStore(const StoreConfig &config)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    return StoreManager::GetInstance().Delete(config.GetFullPath()) ? E_OK : E_ERROR;
}
} // namespace OHOS::DistributedDataAip
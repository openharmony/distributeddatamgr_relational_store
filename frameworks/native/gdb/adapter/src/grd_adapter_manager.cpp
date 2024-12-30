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
#define LOG_TAG "GrdAdapter"
#include <dlfcn.h>

#include "grd_adapter_manager.h"
#include "logger.h"

namespace OHOS::DistributedDataAip {
void GrdAdapterHolderInit(GrdAdapterHolder &adapterHolder)
{
    adapterHolder.Open = (Open)dlsym(g_library, "GRD_DBOpen");
    adapterHolder.Close = (Close)dlsym(g_library, "GRD_DBClose");
    adapterHolder.Repair = (Repair)dlsym(g_library, "GRD_DBRepair");
    adapterHolder.Backup = (Backup)dlsym(g_library, "GRD_DBBackup");
    adapterHolder.Restore = (Restore)dlsym(g_library, "GRD_DBRestore");
    adapterHolder.ReKey = (ReKey)dlsym(g_library, "GRD_DBRekey");

    adapterHolder.Prepare = (Prepare)dlsym(g_library, "GRD_GqlPrepare");
    adapterHolder.Reset = (Reset)dlsym(g_library, "GRD_GqlReset");
    adapterHolder.Finalize = (Finalize)dlsym(g_library, "GRD_GqlFinalize");
    adapterHolder.Step = (Step)dlsym(g_library, "GRD_GqlStep");
    adapterHolder.ColumnCount = (ColumnCount)dlsym(g_library, "GRD_GqlColumnCount");
    adapterHolder.GetColumnType = (GetColumnType)dlsym(g_library, "GRD_GqlColumnType");
    adapterHolder.ColumnBytes = (ColumnBytes)dlsym(g_library, "GRD_GqlColumnBytes");
    adapterHolder.ColumnName = (ColumnName)dlsym(g_library, "GRD_GqlColumnName");
    adapterHolder.ColumnValue = (ColumnValue)dlsym(g_library, "GRD_GqlColumnValue");
    adapterHolder.ColumnInt64 = (ColumnInt64)dlsym(g_library, "GRD_GqlColumnInt64");
    adapterHolder.ColumnInt = (ColumnInt)dlsym(g_library, "GRD_GqlColumnInt");
    adapterHolder.ColumnDouble = (ColumnDouble)dlsym(g_library, "GRD_GqlColumnDouble");
    adapterHolder.ColumnText = (ColumnText)dlsym(g_library, "GRD_GqlColumnText");
}

bool IsSupportArkDataDb()
{
#ifdef ARKDATA_DB_CORE_IS_EXISTS
    return true;
#else
    return false;
#endif
}

GrdAdapterHolder GetAdapterHolder()
{
    GrdAdapterHolder adapterHolder;
    if (g_library == nullptr) {
        g_library = dlopen("libarkdata_db_core.z.so", RTLD_LAZY);
    }
    if (g_library == nullptr) {
        LOG_WARN("use default db kernel");
        return adapterHolder;
    }
    GrdAdapterHolderInit(adapterHolder);
    return adapterHolder;
}

} // namespace OHOS::DistributedDataAip

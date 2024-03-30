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
#define LOG_TAG "GRD_API_MANAGER"
#include "grd_api_manager.h"
#include "logger.h"

#ifndef _WIN32
#include <dlfcn.h>
#endif

#ifndef _WIN32
static void *g_library = nullptr;
#endif

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

void GRD_DBApiInitEnhance(GRD_APIInfo &GRD_DBApiInfo)
{
#ifndef _WIN32
    GRD_DBApiInfo.DBOpenApi = (DBOpen)dlsym(g_library, "GRD_DBOpen");
    GRD_DBApiInfo.DBCloseApi = (DBClose)dlsym(g_library, "GRD_DBClose");
    GRD_DBApiInfo.DBSqlPrepare = (DBSqlPrepare)dlsym(g_library, "GRD_SqlPrepare");
    GRD_DBApiInfo.DBSqlReset = (DBSqlReset)dlsym(g_library, "GRD_SqlReset");
    GRD_DBApiInfo.DBSqlFinalize = (DBSqlFinalize)dlsym(g_library, "GRD_SqlFinalize");
    GRD_DBApiInfo.DBSqlBindBlob = (DBSqlBindBlob)dlsym(g_library, "GRD_SqlBindBlob");
    GRD_DBApiInfo.DBSqlBindText = (DBSqlBindText)dlsym(g_library, "GRD_SqlBindText");
    GRD_DBApiInfo.DBSqlBindInt = (DBSqlBindInt)dlsym(g_library, "GRD_SqlBindInt");
    GRD_DBApiInfo.DBSqlBindInt64 = (DBSqlBindInt64)dlsym(g_library, "GRD_SqlBindInt64");
    GRD_DBApiInfo.DBSqlBindDouble = (DBSqlBindDouble)dlsym(g_library, "GRD_SqlBindDouble");
    GRD_DBApiInfo.DBSqlBindNull = (DBSqlBindNull)dlsym(g_library, "GRD_SqlBindNull");
    GRD_DBApiInfo.DBSqlBindFloatVector = (DBSqlBindFloatVector)dlsym(g_library, "GRD_SqlBindFloatVector");
    GRD_DBApiInfo.DBSqlStep = (DBSqlStep)dlsym(g_library, "GRD_SqlStep");
    GRD_DBApiInfo.DBSqlColCnt = (DBSqlColCnt)dlsym(g_library, "GRD_SqlColumnCount");
    GRD_DBApiInfo.DBSqlColType = (DBSqlColType)dlsym(g_library, "GRD_SqlColumnType");
    GRD_DBApiInfo.DBSqlColBytes = (DBSqlColBytes)dlsym(g_library, "GRD_SqlColumnBytes");
    GRD_DBApiInfo.DBSqlColName = (DBSqlColName)dlsym(g_library, "GRD_SqlColumnName");
    GRD_DBApiInfo.DBSqlColValue = (DBSqlColValue)dlsym(g_library, "GRD_SqlColumnValue");
    GRD_DBApiInfo.DBSqlColBlob = (DBSqlColBlob)dlsym(g_library, "GRD_SqlColumnBlob");
    GRD_DBApiInfo.DBSqlColText = (DBSqlColText)dlsym(g_library, "GRD_SqlColumnText");
    GRD_DBApiInfo.DBSqlColInt = (DBSqlColInt)dlsym(g_library, "GRD_SqlColumnInt");
    GRD_DBApiInfo.DBSqlColInt64 = (DBSqlColInt64)dlsym(g_library, "GRD_SqlColumnInt64");
    GRD_DBApiInfo.DBSqlColDouble = (DBSqlColDouble)dlsym(g_library, "GRD_SqlColumnDouble");
    GRD_DBApiInfo.DBSqlColumnFloatVector = (DBSqlColumnFloatVector)dlsym(g_library, "GRD_SqlColumnFloatVector");
#endif
}

GRD_APIInfo GetApiInfoInstance()
{
    GRD_APIInfo GRD_TempApiStruct;
#ifndef _WIN32
    g_library = dlopen("libgaussdb_rd_vector.z.so", RTLD_LAZY);
    if (g_library != nullptr) {
        GRD_DBApiInitEnhance(GRD_TempApiStruct);
    } else {
        LOG_INFO("use default db kernel");
    }
#endif
    return GRD_TempApiStruct;
}

} // namespace NativeRdb
} // namespace OHOS


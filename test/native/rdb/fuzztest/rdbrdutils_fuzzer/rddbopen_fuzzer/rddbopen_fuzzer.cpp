/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "rd_utils.h"
#include "rdb_errno.h"
#include "rdb_store_config.h"
#include "rdb_store_impl.h"

#define DOUBLE_SIZE 8
#define INT_SIZE 4

using namespace OHOS;
using namespace OHOS::NativeRdb;
namespace OHOS {

uint32_t ConvertToUint32(const uint8_t *ptr, size_t size)
{
    if (ptr == nullptr || (size < sizeof(uint32_t))) {
        return 0;
    }
    return *(reinterpret_cast<const uint32_t *>(ptr));
}

int32_t ConvertToInt32(const uint8_t *ptr, size_t size)
{
    if (ptr == nullptr || (size < sizeof(int32_t))) {
        return 0;
    }
    return *(reinterpret_cast<const int32_t *>(ptr));
}

int64_t ConvertToInt64(const uint8_t *ptr, size_t size)
{
    if (ptr == nullptr || (size < sizeof(int64_t))) {
        return 0;
    }
    return *(reinterpret_cast<const int64_t *>(ptr));
}

double ConvertToDouble(const uint8_t *ptr, size_t size)
{
    if (ptr == nullptr || size < DOUBLE_SIZE) {
        return 0;
    }
    double fa = 0;
    uint8_t uc[DOUBLE_SIZE];
    for (int i = 0; i < DOUBLE_SIZE; i++) {
        uc[i] = ptr[i];
    }
    errno_t err = memcpy_s(&fa, DOUBLE_SIZE, uc, DOUBLE_SIZE);
    if (err < 0) {
        return 0;
    }
    return fa;
}

float ConvertToFloat(const uint8_t *ptr, size_t size)
{
    if (ptr == nullptr || size < INT_SIZE) {
        return 0;
    }
    float fa = 0;
    uint8_t uc[INT_SIZE];
    for (int i = 0; i < INT_SIZE; i++) {
        uc[i] = ptr[i];
    }
    errno_t err = memcpy_s(&fa, INT_SIZE, uc, INT_SIZE);
    if (err < 0) {
        return 0;
    }
    return fa;
}

void RdDbOpenFuzzer(const uint8_t *data, size_t size)
{
    uint32_t unit32t = ConvertToUint32(data, size);
    int32_t nit32t = ConvertToInt32(data, size);
    int32_t nit64t = ConvertToInt64(data, size);
    double doubleValue = ConvertToDouble(data, size);
    GRD_DB *dbHandle_ = nullptr;
    if (data == nullptr || (size < sizeof(char *))) {
        return;
    }
    std::string pathStr(reinterpret_cast<const char *>(data), size);
    RdUtils::RdDbOpen(pathStr.c_str(), pathStr.c_str(), unit32t, &dbHandle_);
    GRD_SqlStmt *stmtHandle = nullptr;
    RdUtils::RdSqlPrepare(dbHandle_, pathStr.c_str(), size, &stmtHandle, nullptr);
    RdUtils::RdSqlReset(stmtHandle);
    RdUtils::RdSqlFinalize(stmtHandle);
    RdUtils::RdSqlBindBlob(stmtHandle, unit32t, pathStr.c_str(), pathStr.length(), nullptr);
    RdUtils::RdSqlBindText(stmtHandle, unit32t, pathStr.c_str(), pathStr.length(), nullptr);
    RdUtils::RdSqlBindInt(stmtHandle, unit32t, nit32t);
    RdUtils::RdSqlBindInt64(stmtHandle, unit32t, nit64t);
    RdUtils::RdSqlBindDouble(stmtHandle, unit32t, doubleValue);
    RdUtils::RdSqlBindNull(stmtHandle, unit32t);
    float ft = ConvertToFloat(data, size);
    float ftVec[1];
    ftVec[0] = ft;
    RdUtils::RdSqlBindFloatVector(stmtHandle, unit32t, ftVec, 1, nullptr);
    RdUtils::RdDbClose(dbHandle_, unit32t);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::RdDbOpenFuzzer(data, size);
    return 0;
}

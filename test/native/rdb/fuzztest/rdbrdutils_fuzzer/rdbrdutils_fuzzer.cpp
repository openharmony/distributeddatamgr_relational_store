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
#include "rdbrdutils_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "rd_utils.h"
#include "rdb_errno.h"
#include "rdb_store_config.h"
#include "rdb_store_impl.h"

using namespace OHOS;
using namespace OHOS::NativeRdb;
namespace OHOS {

static const int MIN_BLOB_SIZE = 1;
static const int MAX_BLOB_SIZE = 200;

GRD_DB *CreateDBHandle(FuzzedDataProvider &provider)
{
    GRD_DB *dbHandle = nullptr;
    std::string dbPath = provider.ConsumeRandomLengthString();
    std::string configStr = provider.ConsumeRandomLengthString();
    uint32_t flags = provider.ConsumeIntegral<uint32_t>();
    RdUtils::RdDbOpen(dbPath.c_str(), configStr.c_str(), flags, &dbHandle);
    return dbHandle;
}

GRD_SqlStmt *CreateSqlStmt(GRD_DB *dbHandle, FuzzedDataProvider &provider)
{
    GRD_SqlStmt *stmtHandle = nullptr;
    std::string str = provider.ConsumeRandomLengthString();
    RdUtils::RdSqlPrepare(dbHandle, str.c_str(), str.size(), &stmtHandle, nullptr);
    RdUtils::RdSqlReset(stmtHandle);
    RdUtils::RdSqlFinalize(stmtHandle);
    return stmtHandle;
}

void RdSqlBindBlobFuzzTest(GRD_SqlStmt *stmtHandle, FuzzedDataProvider &provider)
{
    size_t blobSize = provider.ConsumeIntegralInRange<size_t>(MIN_BLOB_SIZE, MAX_BLOB_SIZE);
    void *val = static_cast<void *>(new uint8_t[blobSize]);
    provider.ConsumeData(val, blobSize);

    uint32_t idx = provider.ConsumeIntegral<uint32_t>();
    RdUtils::RdSqlBindBlob(stmtHandle, idx, val, blobSize, nullptr);
    delete[] static_cast<uint8_t *>(val);
    val = nullptr;
}

void RdbRdUtilsFuzzer(FuzzedDataProvider &provider)
{
    GRD_DB *dbHandle = CreateDBHandle(provider);

    std::string dbPath = provider.ConsumeRandomLengthString();
    std::string configStr = provider.ConsumeRandomLengthString();
    RdUtils::RdDbRepair(dbPath.c_str(), configStr.c_str());

    {
        int err = provider.ConsumeIntegral<int>();
        RdUtils::TransferGrdErrno(err);
    }

    {
        int err = provider.ConsumeIntegral<int>();
        RdUtils::TransferGrdTypeToColType(err);
    }

    GRD_SqlStmt *stmtHandle = CreateSqlStmt(dbHandle, provider);
    RdSqlBindBlobFuzzTest(stmtHandle, provider);

    {
        uint32_t idx = provider.ConsumeIntegral<uint32_t>();
        std::string str = provider.ConsumeRandomLengthString();
        RdUtils::RdSqlBindText(stmtHandle, idx, str.c_str(), str.length(), nullptr);
    }

    {
        uint32_t idx = provider.ConsumeIntegral<uint32_t>();
        int32_t val = provider.ConsumeIntegral<int32_t>();
        RdUtils::RdSqlBindInt(stmtHandle, idx, val);
    }

    {
        uint32_t idx = provider.ConsumeIntegral<uint32_t>();
        int64_t val = provider.ConsumeIntegral<int64_t>();
        RdUtils::RdSqlBindInt64(stmtHandle, idx, val);
    }

    {
        uint32_t idx = provider.ConsumeIntegral<uint32_t>();
        double val = provider.ConsumeFloatingPoint<double>();
        RdUtils::RdSqlBindDouble(stmtHandle, idx, val);
    }

    {
        uint32_t idx = provider.ConsumeIntegral<uint32_t>();
        RdUtils::RdSqlBindNull(stmtHandle, idx);
    }

    {
        float ftVec[1];
        ftVec[0] = provider.ConsumeFloatingPoint<float>();
        uint32_t idx = provider.ConsumeIntegral<uint32_t>();
        RdUtils::RdSqlBindFloatVector(stmtHandle, idx, ftVec, 1, nullptr);
    }

    uint32_t flags = provider.ConsumeIntegral<uint32_t>();
    RdUtils::RdDbClose(dbHandle, flags);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::RdbRdUtilsFuzzer(provider);
    return 0;
}

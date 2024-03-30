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
#define LOG_TAG "RdbStatement"
#include "rdb_statement.h"

#include <iomanip>
#include <sstream>
#include <chrono>
#include <cinttypes>
#include "logger.h"
#include "raw_data_parser.h"
#include "rdb_errno.h"
#include "sqlite_errno.h"
#include "sqlite_utils.h"
#include "sqlite_connection.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

RdbStatement::RdbStatement()
{
}

RdbStatement::~RdbStatement()
{
}

int RdbStatement::PrepareStmt(const std::string &sql)
{
    return E_NOT_SUPPORT;
}

int RdbStatement::Finalize()
{
    return E_NOT_SUPPORT;
}

int RdbStatement::BindArguments(const std::vector<ValueObject> &bindArgs) const
{
    return E_NOT_SUPPORT;
}

int RdbStatement::ResetStatementAndClearBindings() const
{
    return E_NOT_SUPPORT;
}

int RdbStatement::Step() const
{
    return E_NOT_SUPPORT;
}

int RdbStatement::GetColumnCount(int &count) const
{
    return E_NOT_SUPPORT;
}

int RdbStatement::GetColumnName(int index, std::string &columnName) const
{
    return E_NOT_SUPPORT;
}

int RdbStatement::GetColumnType(int index, int &columnType) const
{
    return E_NOT_SUPPORT;
}

int RdbStatement::GetColumnBlob(int index, std::vector<uint8_t> &value) const
{
    return E_NOT_SUPPORT;
}

int RdbStatement::GetColumnString(int index, std::string &value) const
{
    return E_NOT_SUPPORT;
}

int RdbStatement::GetFloat32Array(int index, std::vector<float> &vecs) const
{
    return E_NOT_SUPPORT;
}

int RdbStatement::GetColumnLong(int index, int64_t &value) const
{
    return E_NOT_SUPPORT;
}

int RdbStatement::GetColumnDouble(int index, double &value) const
{
    return E_NOT_SUPPORT;
}

int RdbStatement::GetSize(int index, size_t &size) const
{
    return E_NOT_SUPPORT;
}

int RdbStatement::GetColumn(int index, ValueObject &value) const
{
    return E_NOT_SUPPORT;
}

bool RdbStatement::IsReadOnly() const
{
    return E_NOT_SUPPORT;
}

bool RdbStatement::SupportSharedBlock() const
{
    return false;
}

} // namespace NativeRdb
} // namespace OHOS

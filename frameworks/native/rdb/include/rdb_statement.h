/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef NATIVE_RDB_STATEMENT_H
#define NATIVE_RDB_STATEMENT_H

#include <memory>
#include <vector>
#include "value_object.h"

namespace OHOS {
namespace NativeRdb {

using Asset = ValueObject::Asset;
using Assets = ValueObject::Assets;
using FloatVector = ValueObject::FloatVector;

class RdbStatement {
public:
    RdbStatement();
    virtual ~RdbStatement();
    virtual int PrepareStmt(const std::string &sql);
    virtual int Finalize();
    virtual int BindArguments(const std::vector<ValueObject> &bindArgs) const;
    virtual int ResetStatementAndClearBindings() const;
    virtual int Step() const;
    virtual int GetColumnCount(int &count) const;
    virtual int GetColumnName(int index, std::string &columnName) const;
    virtual int GetColumnType(int index, int &columnType) const;
    virtual int GetColumnBlob(int index, std::vector<uint8_t> &value) const;
    virtual int GetColumnString(int index, std::string &value) const;
    virtual int GetFloat32Array(int index, std::vector<float> &vecs) const;
    virtual int GetColumnLong(int index, int64_t &value) const;
    virtual int GetColumnDouble(int index, double &value) const;
    virtual int GetSize(int index, size_t &size) const;
    virtual int GetColumn(int index, ValueObject &value) const;
    virtual bool IsReadOnly() const;
    virtual bool SupportSharedBlock() const;
protected:
    // Setting Data Precision
    static constexpr int SET_DATA_PRECISION = 15;
};

} // namespace NativeRdb
} // namespace OHOS
#endif // NATIVE_RDB_STATEMENT_H

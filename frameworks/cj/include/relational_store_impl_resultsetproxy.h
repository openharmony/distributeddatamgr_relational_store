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

#ifndef RELATIONAL_STORE_IMPL_RESULTSET_FFI_H
#define RELATIONAL_STORE_IMPL_RESULTSET_FFI_H

#include <memory>

#include "ffi_remote_data.h"
#include "relational_store_impl_rdbpredicatesproxy.h"
#include "relational_store_utils.h"
#include "result_set.h"

namespace OHOS {
namespace Relational {

class ResultSetImpl : public OHOS::FFI::FFIData {
public:
    OHOS::FFI::RuntimeType *GetRuntimeType() override
    {
        return GetClassType();
    }

    explicit ResultSetImpl(std::shared_ptr<NativeRdb::ResultSet> resultSet);

    CArrStr GetAllColumnNames();

    int32_t GetColumnCount();

    int32_t GetRowCount();

    int32_t GetRowIndex();

    bool IsAtFirstRow();

    bool IsAtLastRow();

    bool IsEnded();

    bool IsStarted();

    bool IsClosed();

    double GetDouble(int32_t columnIndex, int32_t *rtnCode);

    bool GoToRow(int32_t position, int32_t *rtnCode);

    bool GoToPreviousRow(int32_t *rtnCode);

    bool GoToLastRow(int32_t *rtnCode);

    char *GetColumnName(int32_t columnIndex, int32_t *rtnCode);

    bool IsColumnNull(int32_t columnIndex, int32_t *rtnCode);

    Asset GetAsset(int32_t columnIndex, int32_t *rtnCode);

    int32_t Close();

    int32_t GetColumnIndex(char *columnName, int32_t *rtnCode);

    char *GetString(int32_t columnIndex, int32_t *rtnCode);

    bool GoToFirstRow(int32_t *rtnCode);

    int64_t GetLong(int32_t columnIndex, int32_t *rtnCode);

    bool GoToNextRow(int32_t *rtnCode);

    CArrUI8 GetBlob(int32_t columnIndex, int32_t *rtnCode);

    bool GoTo(int32_t offset, int32_t *rtnCode);

    Assets GetAssets(int32_t columnIndex, int32_t *rtnCode);

    ValuesBucket GetRow(int32_t *rtnCode);

    ValuesBucketEx GetRowEx(int32_t *rtnCode);

    ValueTypeEx GetValue(int32_t columnIndex, int32_t* rtnCode);

    std::shared_ptr<NativeRdb::ResultSet> resultSetValue;

private:
    friend class OHOS::FFI::RuntimeType;
    friend class OHOS::FFI::TypeBase;
    static OHOS::FFI::RuntimeType *GetClassType();
};
} // namespace Relational
} // namespace OHOS

#endif
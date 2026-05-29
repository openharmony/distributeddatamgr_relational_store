/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef RELATIONAL_STORE_IMPL_LITERESULTSET_FFI_H
#define RELATIONAL_STORE_IMPL_LITERESULTSET_FFI_H

#include <memory>

#include "ffi_remote_data.h"
#include "relational_store_utils.h"
#include "result_set.h"

namespace OHOS {
namespace Relational {

class LiteResultSetImpl : public OHOS::FFI::FFIData {
public:
    OHOS::FFI::RuntimeType *GetRuntimeType() override
    {
        return GetClassType();
    }

    explicit LiteResultSetImpl(std::shared_ptr<NativeRdb::ResultSet> resultSet);

    int32_t GetColumnIndex(char *columnName, int32_t *rtnCode);
    char *GetColumnName(int32_t columnIndex, int32_t *rtnCode);
    int32_t GetColumnTypeByName(char *columnName, int32_t *rtnCode);
    int32_t GetColumnTypeById(int32_t columnIndex, int32_t *rtnCode);
    bool GoToNextRow(int32_t *rtnCode);
    CArrUI8 GetBlob(int32_t columnIndex, int32_t *rtnCode);
    int64_t GetLong(int32_t columnIndex, int32_t *rtnCode);
    Asset GetAsset(int32_t columnIndex, int32_t *rtnCode);
    Assets GetAssets(int32_t columnIndex, int32_t *rtnCode);
    ValueTypeEx GetValue(int32_t columnIndex, int32_t *rtnCode);
    ValuesBucketEx GetRow(int32_t *rtnCode);
    bool IsColumnNull(int32_t columnIndex, int32_t *rtnCode);
    CArrValuesBucket GetRows(int32_t maxCount, int32_t position, int32_t *rtnCode);
    RowDataEx GetCurrentRowData(int32_t *rtnCode);
    RowsDataEx GetRowsData(int32_t maxCount, int32_t position, int32_t *rtnCode);
    int32_t Close();

private:
    friend class OHOS::FFI::RuntimeType;
    friend class OHOS::FFI::TypeBase;
    static OHOS::FFI::RuntimeType *GetClassType();

    std::shared_ptr<NativeRdb::ResultSet> resultSet_;

    int32_t PreparePosition(int32_t position);
    int32_t FetchRowEntities(int32_t maxCount, std::vector<NativeRdb::RowEntity> &rowEntities);
    CArrValuesBucket ConvertToCArrValuesBucket(
        std::vector<NativeRdb::RowEntity> &rowEntities, int32_t *rtnCode);
};
} // namespace Relational
} // namespace OHOS

#endif
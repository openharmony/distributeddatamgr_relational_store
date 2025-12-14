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

#ifndef OHOS_RELATION_STORE_LITE_RESULT_SET_IMPL_H
#define OHOS_RELATION_STORE_LITE_RESULT_SET_IMPL_H

#include "ani_rdb_utils.h"
#include "lite_result_set_proxy.h"

namespace OHOS {
namespace RdbTaihe {
using namespace taihe;
using namespace ohos::data::relationalStore;
using namespace OHOS;
using namespace OHOS::Rdb;
using namespace OHOS::RdbTaihe;
using ValueType = ohos::data::relationalStore::ValueType;
using ValueObject = OHOS::NativeRdb::ValueObject;

class LiteResultSetImpl {
public:
    LiteResultSetImpl();
    LiteResultSetImpl(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet);
    intptr_t GetProxy();
    array<map<string, ValueType>> GetRowsSync(int32_t maxCount, optional_view<int32_t> position);
    int32_t GetColumnIndex(string_view columnName);
    string GetColumnName(int32_t columnIndex);
    bool GoToNextRow();
    array<uint8_t> GetBlob(int32_t columnIndex);
    string GetString(int32_t columnIndex);
    int64_t GetLong(int32_t columnIndex);
    double GetDouble(int32_t columnIndex);
    ohos::data::relationalStore::Asset GetAsset(int32_t columnIndex);
    array<ohos::data::relationalStore::Asset> GetAssets(int32_t columnIndex);
    ValueType GetValue(int32_t columnIndex);
    array<float> GetFloat32Array(int32_t columnIndex);
    map<string, ValueType> GetRow();
    bool IsColumnNull(int32_t columnIndex);
    void Close();
    array<string> GetColumnNames();
    array<ohos::data::relationalStore::ValueType> GetCurrentRowData();
    array<array<ValueType>> GetRowsDataSync(int32_t maxCount, optional_view<int32_t> position);

protected:
    std::shared_ptr<OHOS::NativeRdb::ResultSet> nativeResultSet_;
    std::shared_ptr<LiteResultSetProxy> proxy_;
};
}
}

#endif // OHOS_RELATION_STORE_LITE_RESULT_SET_IMPL_H
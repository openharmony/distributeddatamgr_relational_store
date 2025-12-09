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

#ifndef OHOS_RELATION_STORE_RESULT_SET_IMPL_H
#define OHOS_RELATION_STORE_RESULT_SET_IMPL_H

#include "ani_rdb_utils.h"
#include "result_set_proxy.h"

namespace OHOS {
namespace RdbTaihe {
using namespace taihe;
using namespace ohos::data::relationalStore;
using namespace OHOS;
using namespace OHOS::Rdb;
using namespace OHOS::RdbTaihe;
using ValueType = ohos::data::relationalStore::ValueType;
using ValueObject = OHOS::NativeRdb::ValueObject;

class ResultSetImpl {
public:
    ResultSetImpl();
    explicit ResultSetImpl(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet);
    int64_t GetProxy();
    array<string> GetAllColumnNames();
    array<string> GetColumnNames();
    int32_t GetColumnCount();
    int32_t GetRowCount();
    int32_t GetRowIndex();
    bool GetIsAtFirstRow();
    bool GetIsAtLastRow();
    bool GetIsEnded();
    bool GetIsStarted();
    bool GetIsClosed();
    int32_t GetColumnIndex(string_view columnName);
    string GetColumnName(int32_t columnIndex);
    uintptr_t GetColumnTypeSync(ohos::data::relationalStore::ColumnIdentifier const& columnIdentifier);
    bool GoTo(int32_t offset);
    bool GoToRow(int32_t position);
    bool GoToFirstRow();
    bool GoToLastRow();
    bool GoToNextRow();
    bool GoToPreviousRow();
    array<uint8_t> GetBlob(int32_t columnIndex);
    string GetString(int32_t columnIndex);
    int64_t GetLong(int32_t columnIndex);
    double GetDouble(int32_t columnIndex);
    ohos::data::relationalStore::Asset GetAsset(int32_t columnIndex);
    array<ohos::data::relationalStore::Asset> GetAssets(int32_t columnIndex);
    ValueType GetValue(int32_t columnIndex);
    array<float> GetFloat32Array(int32_t columnIndex);
    map<string, ValueType> GetRow();
    void GetRowsResult(int32_t maxCount, std::vector<ohos::data::relationalStore::ValuesBucket> &result);
    taihe::array<ohos::data::relationalStore::ValuesBucket> GetRowsSync(int32_t maxCount,
        taihe::optional_view<int32_t> position);
    uintptr_t GetSendableRow();
    array<ohos::data::relationalStore::ValueType> GetCurrentRowData();
    array<array<ValueType>> GetRowsDataAsync(int32_t maxCount, optional_view<int32_t> position);
    bool IsColumnNull(int32_t columnIndex);
    void Close();

protected:
    std::shared_ptr<OHOS::NativeRdb::ResultSet> nativeResultSet_;
    std::shared_ptr<ResultSetProxy> proxy_;
};
}
}

#endif // OHOS_RELATION_STORE_RESULT_SET_IMPL_H
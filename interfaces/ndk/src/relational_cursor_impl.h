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

#ifndef RELATIONAL_CURSOR_IMPL_H
#define RELATIONAL_CURSOR_IMPL_H

#include "relational_cursor.h"
#include "result_set.h"
#include <memory>

int CURSOR_GetColumnCount(OH_Cursor *cursor, int *count);
int CURSOR_GetColumnType(OH_Cursor *cursor, int32_t columnIndex, OH_Rdb_ColumnType *columnType);
int CURSOR_GetColumnIndex(OH_Cursor *cursor, const char *name, int *columnIndex);
int CURSOR_GetColumnName(OH_Cursor *cursor, int32_t columnIndex, char *name, int length);
int CURSOR_GetRowCount(OH_Cursor *cursor, int *count);
int CURSOR_GoToNextRow(OH_Cursor *cursor);
int CURSOR_GetSize(OH_Cursor *cursor, int32_t columnIndex, size_t *size);
int CURSOR_GetText(OH_Cursor *cursor, int32_t columnIndex, char *value, int length);
int CURSOR_GetInt64(OH_Cursor *cursor, int32_t columnIndex, int64_t *value);
int CURSOR_GetReal(OH_Cursor *cursor, int32_t columnIndex, double *value);
int CURSOR_GetBlob(OH_Cursor *cursor, int32_t columnIndex, unsigned char *value, int length);
int CURSOR_IsNull(OH_Cursor *cursor, int32_t columnIndex, BOOL *isNull);
int CURSOR_Close(OH_Cursor *cursor);

namespace OHOS {
namespace RdbNdk {
constexpr int RDB_CURSOR_CID = 1234563; // The class id used to uniquely identify the OH_Cursor class.
class CursorImpl : public OH_Cursor {
public:
    explicit CursorImpl(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet);
    std::shared_ptr<OHOS::NativeRdb::ResultSet> GetResultSet();

private:
    std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet_;
};
} // namespace RdbNdk
} // namespace OHOS
#endif // RELATIONAL_CURSOR_IMPL_H

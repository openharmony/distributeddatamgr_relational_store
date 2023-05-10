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

#ifndef RELATIONAL_CURSOR_H
#define RELATIONAL_CURSOR_H

#include <cstdint>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

enum ColumnType {
    TYPE_NULL = 0,
    TYPE_INT64,
    TYPE_REAL,
    TYPE_TEXT,
    TYPE_BLOB,
};

struct OH_Cursor{
    int id;
    int (*OH_Cursor_GetColumnCount)(OH_Cursor *, int *);
    int (*OH_Cursor_GetColumnType)(OH_Cursor *, int32_t, ColumnType *);
    int (*OH_Cursor_GetColumnIndex)(OH_Cursor *, const char *, int *);
    int (*OH_Cursor_GetColumnName)(OH_Cursor *, int32_t, char *, int);
    int (*OH_Cursor_GetRowCount)(OH_Cursor *, int *);
    int (*OH_Cursor_GoToNextRow)(OH_Cursor *);
    int (*OH_Cursor_GetSize)(OH_Cursor *, int32_t, size_t *);
    int (*OH_Cursor_GetText)(OH_Cursor *, int32_t, char *, int);
    int (*OH_Cursor_GetInt64)(OH_Cursor *, int32_t, int64_t *);
    int (*OH_Cursor_GetReal)(OH_Cursor *, int32_t, double *);
    int (*OH_Cursor_GetBlob)(OH_Cursor *, int32_t, unsigned char *, int);
    int (*OH_Cursor_IsNull)(OH_Cursor *, int32_t, bool *);
    int (*OH_Cursor_Close)(OH_Cursor *);
};

int CURSOR_GetColumnCount(OH_Cursor *cursor, int *count);
int CURSOR_GetColumnType(OH_Cursor *cursor, int32_t columnIndex, ColumnType *columnType);
int CURSOR_GetColumnIndex(OH_Cursor *cursor, const char *names, int *columnIndex);
int CURSOR_GetColumnName(OH_Cursor *cursor, int32_t columnIndex, char *name, int length);
int CURSOR_GetRowCount(OH_Cursor *cursor, int *count);
int CURSOR_GoToNextRow(OH_Cursor *cursor);
int CURSOR_GetSize(OH_Cursor *cursor, int32_t columnIndex, size_t *size);
int CURSOR_GetText(OH_Cursor *cursor, int32_t columnIndex, char *value, int length);
int CURSOR_GetInt64(OH_Cursor *cursor, int32_t columnIndex, int64_t *value);
int CURSOR_GetReal(OH_Cursor *cursor, int32_t columnIndex, double *value);
int CURSOR_GetBlob(OH_Cursor *cursor, int32_t columnIndex, unsigned char *value, int length);
int CURSOR_IsNull(OH_Cursor *cursor, int32_t columnIndex, bool *isNull);
int CURSOR_Close(OH_Cursor *cursor);

#ifdef __cplusplus
};
#endif

#endif //RELATIONAL_CURSOR_H

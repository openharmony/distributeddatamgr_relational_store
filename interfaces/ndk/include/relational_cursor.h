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

#define BOOL int
#define TRUE 1
#define FALSE 0

#include <cstdint>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

enum OH_Rdb_ColumnType {
    TYPE_NULL = 0,
    TYPE_INT64,
    TYPE_REAL,
    TYPE_TEXT,
    TYPE_BLOB,
};

typedef struct OH_Cursor {
    int64_t id;
    int (*OH_Cursor_GetColumnCount)(OH_Cursor *, int *);
    int (*OH_Cursor_GetColumnType)(OH_Cursor *, int32_t, OH_Rdb_ColumnType *);
    int (*OH_Cursor_GetColumnIndex)(OH_Cursor *, const char *, int *);
    int (*OH_Cursor_GetColumnName)(OH_Cursor *, int32_t, char *, int);
    int (*OH_Cursor_GetRowCount)(OH_Cursor *, int *);
    int (*OH_Cursor_GoToNextRow)(OH_Cursor *);
    int (*OH_Cursor_GetSize)(OH_Cursor *, int32_t, size_t *);
    int (*OH_Cursor_GetText)(OH_Cursor *, int32_t, char *, int);
    int (*OH_Cursor_GetInt64)(OH_Cursor *, int32_t, int64_t *);
    int (*OH_Cursor_GetReal)(OH_Cursor *, int32_t, double *);
    int (*OH_Cursor_GetBlob)(OH_Cursor *, int32_t, unsigned char *, int);
    int (*OH_Cursor_IsNull)(OH_Cursor *, int32_t, BOOL *);
    int (*OH_Cursor_Close)(OH_Cursor *);
} OH_Cursor;

#ifdef __cplusplus
};
#endif

#endif // RELATIONAL_CURSOR_H

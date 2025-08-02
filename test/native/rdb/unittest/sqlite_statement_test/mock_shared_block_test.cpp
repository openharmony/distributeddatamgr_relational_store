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
#include <unistd.h>

#include <algorithm>

#include "share_block.h"
#include "logger.h"
#include "sqlite_errno.h"
namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

int SeriAddRow(void *pCtx, int addedRows)
{
    (void)pCtx;
    (void)addedRows;
    return E_ERROR;
}

int SeriReset(void *pCtx, int startPos)
{
    (void)pCtx;
    (void)startPos;
    return E_ERROR;
}

int SeriFinish(void *pCtx, int addedRows, int totalRows)
{
    (void)pCtx;
    (void)addedRows;
    (void)totalRows;
    return E_ERROR;
}

int SeriPutString(void *pCtx, int addedRows, int column, const char *text, int size)
{
    (void)pCtx;
    (void)addedRows;
    (void)column;
    (void)text;
    (void)size;
    return E_ERROR;
}

int SeriPutLong(void *pCtx, int addedRows, int column, sqlite3_int64 value)
{
    (void)pCtx;
    (void)addedRows;
    (void)column;
    (void)value;
    return E_ERROR;
}

int SeriPutDouble(void *pCtx, int addedRows, int column, double value)
{
    (void)pCtx;
    (void)addedRows;
    (void)column;
    (void)value;
    return E_ERROR;
}

int SeriPutBlob(void *pCtx, int addedRows, int column, const void *blob, int len)
{
    (void)pCtx;
    (void)addedRows;
    (void)column;
    (void)blob;
    (void)len;
    return E_ERROR;
}

int SeriPutNull(void *pCtx, int addedRows, int column)
{
    (void)pCtx;
    (void)addedRows;
    (void)column;
    return E_ERROR;
}

int SeriPutOther(void *pCtx, int addedRows, int column)
{
    (void)pCtx;
    (void)addedRows;
    (void)column;
    return E_ERROR;
}

int ClearSharedBlock(AppDataFwk::SharedBlock *sharedBlock)
{
    (void)sharedBlock;
    return E_ERROR;
}

int SharedBlockSetColumnNum(AppDataFwk::SharedBlock *sharedBlock, int columnNum)
{
    (void)sharedBlock;
    (void)columnNum;
    return E_ERROR;
}

int FillSharedBlockOpt(SharedBlockInfo *info, sqlite3_stmt *stmt)
{
    (void)info;
    (void)stmt;
    return E_ERROR;
}

int FillSharedBlock(SharedBlockInfo *info, sqlite3_stmt *stmt)
{
    (void)info;
    (void)stmt;
    return E_ERROR;
}

void FillRow(SharedBlockInfo *info, sqlite3_stmt *stmt)
{
    (void)info;
    (void)stmt;
}

FillOneRowResult FillOneRow(
    AppDataFwk::SharedBlock *sharedBlock, sqlite3_stmt *statement, int numColumns, int startPos, int addedRows)
{
    (void)sharedBlock;
    (void)statement;
    (void)numColumns;
    (void)startPos;
    (void)addedRows;
    FillOneRowResult result = FILL_ONE_ROW_SUCESS;
    return result;
}

FillOneRowResult FillOneRowOfString(
    AppDataFwk::SharedBlock *sharedBlock, sqlite3_stmt *statement, int startPos, int addedRows, int pos)
{
    (void)sharedBlock;
    (void)statement;
    (void)startPos;
    (void)addedRows;
    (void)pos;
    FillOneRowResult result = FILL_ONE_ROW_SUCESS;
    return result;
}

FillOneRowResult FillOneRowOfLong(
    AppDataFwk::SharedBlock *sharedBlock, sqlite3_stmt *statement, int startPos, int addedRows, int pos)
{
    (void)sharedBlock;
    (void)statement;
    (void)startPos;
    (void)addedRows;
    (void)pos;
    FillOneRowResult result = FILL_ONE_ROW_SUCESS;
    return result;
}

FillOneRowResult FillOneRowOfFloat(
    AppDataFwk::SharedBlock *sharedBlock, sqlite3_stmt *statement, int startPos, int addedRows, int pos)
{
    (void)sharedBlock;
    (void)statement;
    (void)startPos;
    (void)addedRows;
    (void)pos;
    FillOneRowResult result = FILL_ONE_ROW_SUCESS;
    return result;
}

FillOneRowResult FillOneRowOfBlob(
    AppDataFwk::SharedBlock *sharedBlock, sqlite3_stmt *statement, int startPos, int addedRows, int pos)
{
    (void)sharedBlock;
    (void)statement;
    (void)startPos;
    (void)addedRows;
    (void)pos;
    FillOneRowResult result = FILL_ONE_ROW_SUCESS;
    return result;
}

FillOneRowResult FillOneRowOfNull(
    AppDataFwk::SharedBlock *sharedBlock, sqlite3_stmt *statement, int startPos, int addedRows, int pos)
{
    (void)sharedBlock;
    (void)statement;
    (void)startPos;
    (void)addedRows;
    (void)pos;
    FillOneRowResult result = FILL_ONE_ROW_SUCESS;
    return result;
}

bool ResetStatement(SharedBlockInfo *info, sqlite3_stmt *stmt)
{
    (void)info;
    (void)stmt;
    return true;
}

int DefAddRow(void *pCtx, int addedRows)
{
    return SQLITE_FULL;
}

int DefReset(void *pCtx, int startPos)
{
    return SQLITE_OK;
}

int DefFinish(void *pCtx, int addedRows, int totalRows)
{
    return SQLITE_OK;
}

int DefPutString(void *pCtx, int addedRows, int column, const char *text, int size)
{
    return SQLITE_FULL;
}

int DefPutLong(void *pCtx, int addedRows, int column, sqlite3_int64 value)
{
    return SQLITE_FULL;
}

int DefPutDouble(void *pCtx, int addedRows, int column, double value)
{
    return SQLITE_FULL;
}

int DefPutBlob(void *pCtx, int addedRows, int column, const void *blob, int len)
{
    return SQLITE_FULL;
}

int DefPutNull(void *pCtx, int addedRows, int column)
{
    return SQLITE_FULL;
}

int DefPutOther(void *pCtx, int addedRows, int column)
{
    return SQLITE_FULL;
}

void DefFillRow(SharedBlockInfo *info, sqlite3_stmt *stmt)
{
    (void)info;
    (void)stmt;
}
} // namespace NativeRdb
} // namespace OHOS
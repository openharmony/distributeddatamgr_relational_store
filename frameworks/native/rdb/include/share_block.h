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

#ifndef NATIVE_RDB_SHARE_BLOCK_H
#define NATIVE_RDB_SHARE_BLOCK_H

#include "shared_block.h"
#include <sqlite3sym.h>
#include <string>

namespace OHOS {
namespace NativeRdb {
#ifdef __cplusplus
extern "C" {
#endif
enum FillOneRowResult {
    FILL_ONE_ROW_SUCESS,
    SHARED_BLOCK_IS_FULL,
    FILL_ONE_ROW_FAIL,
};

struct SharedBlockInfo {
    AppDataFwk::SharedBlock *sharedBlock = nullptr;

    int startPos;
    int addedRows;
    int requiredPos;
    int totalRows;
    int isCountAllRows;
    int columnNum;
    bool isFull;
    bool hasException;

    SharedBlockInfo(AppDataFwk::SharedBlock* sharedBlock) : sharedBlock(sharedBlock)
    {
        startPos = 0;
        addedRows = 0;
        requiredPos = 0;
        totalRows = 0;
        isCountAllRows = 0;
        columnNum = 0;
        isFull = false;
        hasException = false;
    }
};

int SeriAddRow(void *pCtx, int addedRows);
int SeriReset(void *pCtx, int startPos);
int SeriFinish(void *pCtx, int addedRows, int totalRows);
int SeriPutString(void *pCtx, int addedRows, int column, const char *text, int size);
int SeriPutLong(void *pCtx, int addedRows, int column, sqlite3_int64 value);
int SeriPutDouble(void *pCtx, int addedRows, int column, double value);
int SeriPutBlob(void *pCtx, int addedRows, int column, const void *blob, int len);
int SeriPutNull(void *pCtx, int addedRows, int column);
int SeriPutOther(void *pCtx, int addedRows, int column);
int ClearSharedBlock(AppDataFwk::SharedBlock *sharedBlock);
int SharedBlockSetColumnNum(AppDataFwk::SharedBlock *sharedBlock, int columnNum);
int FillSharedBlockOpt(SharedBlockInfo *info, sqlite3_stmt *stmt);
FillOneRowResult FillOneRowOfString(AppDataFwk::SharedBlock *sharedBlock, sqlite3_stmt *statement, int startPos,
    int addedRows, int pos);
FillOneRowResult FillOneRowOfLong(AppDataFwk::SharedBlock *sharedBlock, sqlite3_stmt *statement, int startPos,
    int addedRows, int pos);
FillOneRowResult FillOneRowOfFloat(AppDataFwk::SharedBlock *sharedBlock, sqlite3_stmt *statement, int startPos,
    int addedRows, int pos);
FillOneRowResult FillOneRowOfBlob(AppDataFwk::SharedBlock *sharedBlock, sqlite3_stmt *statement, int startPos,
    int addedRows, int pos);
FillOneRowResult FillOneRowOfNull(AppDataFwk::SharedBlock *sharedBlock, sqlite3_stmt *statement, int startPos,
    int addedRows, int pos);
FillOneRowResult FillOneRow(AppDataFwk::SharedBlock *sharedBlock, sqlite3_stmt *statement, int numColumns,
    int startPos, int addedRows);
void FillRow(SharedBlockInfo *info, sqlite3_stmt *stmt);
int FillSharedBlock(SharedBlockInfo *info, sqlite3_stmt *stmt);
bool ResetStatement(SharedBlockInfo *info, sqlite3_stmt *stmt);
int64_t GetCombinedData(int startPos, int totalRows);
#ifdef __cplusplus
}
#endif
} // namespace NativeRdb
} // namespace OHOS

#endif

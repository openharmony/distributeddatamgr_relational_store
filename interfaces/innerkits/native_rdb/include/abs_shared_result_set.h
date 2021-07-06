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

#ifndef NATIVE_RDB_ABS_SHARED_RESULT_SET_H
#define NATIVE_RDB_ABS_SHARED_RESULT_SET_H


#include "shared_block.h"
#include "abs_result_set.h"
#include "shared_result_set.h"
#include <memory>
#include <thread>
#include <vector>
#include <string>
#include "rdb_store_impl.h"
#include "sqlite_statement.h"

namespace OHOS {
namespace NativeRdb {
class AbsSharedResultSet : public AbsResultSet, public SharedResultSet {
public:
    AbsSharedResultSet(std::string name);
    virtual ~AbsSharedResultSet();
    int GetBlob(int columnIndex, std::vector<uint8_t> &blob) override;
    int GetString(int columnIndex, std::string &value) override;
    int GetInt(int columnIndex, int &value) override;
    int GetLong(int columnIndex, int64_t &value) override;
    int GetDouble(int columnIndex, double &value) override;
    int IsColumnNull(int columnIndex, bool &isNull) override;
    int GetColumnTypeForIndex(int columnIndex, ColumnType &columnType) override;
    int GoToRow(int position) override;
    virtual int GetAllColumnNames(std::vector<std::string> &columnNames) override;
    virtual int GetRowCount(int &count) override;
    AppDataFwk::SharedBlock *GetBlock() const override;
    virtual bool OnGo(int oldRowIndex, int newRowIndex) override;
    void FillBlock(int startRowIndex, AppDataFwk::SharedBlock *block) override;
    void SetBlock(AppDataFwk::SharedBlock *block);
    bool HasBlock() const;
    virtual int Close() override;
protected:
    int CheckState(int columnIndex);
    void ClearBlock();
    void ClosedBlock();
    virtual void Finalize();
protected:
    // The SharedBlock owned by this AbsSharedResultSet
    AppDataFwk::SharedBlock *sharedBlock;
private:
    // The default position of the cursor
    static const int INIT_POS = -1;
    static const size_t DEFAULT_BLOCK_SIZE = 2 * 1024 * 1024;
};
} // namespace NativeRdb
} // namespace OHOS

#endif
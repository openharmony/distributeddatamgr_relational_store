/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef DATASHARE_RESULT_SET_H
#define DATASHARE_RESULT_SET_H

#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "datashare_abs_result_set.h"
#include "message_parcel.h"
#include "parcel.h"
#include "shared_block.h"
#include "datashare_shared_result_set.h"
#include "result_set_bridge.h"
#include "datashare_block_writer_impl.h"

namespace OHOS {
namespace DataShare {
class DataShareResultSet : public DataShareAbsResultSet, public DataShareSharedResultSet {
public:
    DataShareResultSet();
    explicit DataShareResultSet(std::shared_ptr<ResultSetBridge> &bridge);
    virtual ~DataShareResultSet();
    int GetBlob(int columnIndex, std::vector<uint8_t> &blob) override;
    int GetString(int columnIndex, std::string &value) override;
    int GetInt(int columnIndex, int &value) override;
    int GetLong(int columnIndex, int64_t &value) override;
    int GetDouble(int columnIndex, double &value) override;
    int IsColumnNull(int columnIndex, bool &isNull) override;
    int GetDataType(int columnIndex, DataType &dataType) override;
    int GoToRow(int position) override;
    int GetAllColumnNames(std::vector<std::string> &columnNames) override;
    int GetRowCount(int &count) override;
    AppDataFwk::SharedBlock *GetBlock() const override;
    bool OnGo(int startRowIndex, int targetRowIndex) override;
    void FillBlock(int startRowIndex, AppDataFwk::SharedBlock *block) override;
    virtual void SetBlock(AppDataFwk::SharedBlock *block);
    int Close() override;
    bool HasBlock() const;

protected:
    int CheckState(int columnIndex);
    void ClearBlock();
    void ClosedBlock();
    virtual void Finalize();

    friend class ISharedResultSetStub;
    friend class ISharedResultSetProxy;
    bool Unmarshalling(MessageParcel &parcel);
    bool Marshalling(MessageParcel &parcel);

private:
    // The default position of the cursor
    static const int INIT_POS = -1;
    static const size_t DEFAULT_BLOCK_SIZE = 2 * 1024 * 1024;
    static int blockId_;
    // Equivalent to filling in setp + 1 rows each time
    static const int STEP_LENGTH = 2;
    // The actual position of the first row of data in the shareblock
    int startRowPos_ = -1;
    // The actual position of the last row of data in the shareblock
    int endRowPos_ = -1;
    // The SharedBlock owned by this DataShareResultSet
    AppDataFwk::SharedBlock *sharedBlock_  = nullptr;
    std::shared_ptr<DataShareBlockWriterImpl> blockWriter_ = nullptr;
    std::shared_ptr<ResultSetBridge> bridge_ = nullptr;
};
} // namespace DataShare
} // namespace OHOS

#endif // DATASHARE_RESULT_SET_H
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

#include <memory>
#include <shared_mutex>
#include <string>
#include <thread>
#include <vector>

#include "abs_result_set.h"
#include "shared_result_set.h"

namespace OHOS {
namespace NativeRdb {
/**
 * The AbsResultSet class of RDB.
 * Provides methods for accessing a database result set generated by querying the database.
 */
class API_EXPORT AbsSharedResultSet : public AbsResultSet, public SharedResultSet {
public:
    /**
     * @brief Constructor.
     */
    API_EXPORT AbsSharedResultSet();

    /**
     * @brief Constructor.
     *
     * A parameterized constructor used to create an AbsSharedResultSet instance.
     *
     * @param tableName Indicates the table name of the database.
     */
    API_EXPORT explicit AbsSharedResultSet(std::string name);

    /**
     * @brief Destructor.
     */
    API_EXPORT virtual ~AbsSharedResultSet();

    /**
     * @brief Obtains the value of the specified column in the current row as a byte array.
     *
     * The implementation class determines whether to throw an exception if the value of the specified column
     * in the current row is null or the specified column is not of the Blob type.
     *
     * @param columnIndex Indicates the specified column index, which starts from 0.
     *
     * @return Returns the value of the specified column as a byte array.
     */
    API_EXPORT int GetBlob(int columnIndex, std::vector<uint8_t> &blob) override;

    /**
     * @brief Obtains the value of the specified column in the current row as string.
     *
     * The implementation class determines whether to throw an exception if the value of the specified column
     * in the current row is null or the specified column is not of the string type.
     *
     * @param columnIndex Indicates the specified column index, which starts from 0.
     *
     * @return Returns the value of the specified column as a string.
     */
    API_EXPORT int GetString(int columnIndex, std::string &value) override;

    /**
     * @brief Obtains the value of the specified column in the current row as int.
     *
     * The implementation class determines whether to throw an exception if the value of the specified column
     * in the current row is null or the specified column is not of the integer type.
     *
     * @param columnIndex Indicates the specified column index, which starts from 0.
     *
     * @return Returns the value of the specified column as a int.
     */
    API_EXPORT int GetInt(int columnIndex, int &value) override;

    /**
     * @brief Obtains the value of the specified column in the current row as long.
     *
     * The implementation class determines whether to throw an exception if the value of the specified column
     * in the current row is null or the specified column is not of the long type.
     *
     * @param columnIndex Indicates the specified column index, which starts from 0.
     *
     * @return Returns the value of the specified column as a long.
     */
    API_EXPORT int GetLong(int columnIndex, int64_t &value) override;

    /**
     * @brief Obtains the value of the specified column in the current row as double.
     *
     * The implementation class determines whether to throw an exception if the value of the specified column
     * in the current row is null or the specified column is not of the double type.
     *
     * @param columnIndex Indicates the specified column index, which starts from 0.
     *
     * @return Returns the value of the specified column as a double.
     */
    API_EXPORT int GetDouble(int columnIndex, double &value) override;

    /**
     * @brief Obtains the value of the specified column in the current row as asset.
     *
     * The implementation class determines whether to throw an exception if the value of the specified column
     * in the current row is null or the specified column is not of the double type.
     *
     * @param columnIndex Indicates the specified column index, which starts from 0.
     *
     * @return Returns the value of the specified column as a double.
     */
    API_EXPORT int GetAsset(int32_t col, ValueObject::Asset &value) override;

	/**
     * @brief Obtains the value of the specified column in the current row as assets.
     *
     * The implementation class determines whether to throw an exception if the value of the specified column
     * in the current row is null or the specified column is not of the double type.
     *
     * @param columnIndex Indicates the specified column index, which starts from 0.
     *
     * @return Returns the value of the specified column as a double.
     */
    API_EXPORT int GetAssets(int32_t col, ValueObject::Assets &value) override;

    /**
     * @brief Get the size of blob or text.
     *
     * @param columnIndex Indicates the zero-based index of the target column.
     */
    API_EXPORT int GetSize(int columnIndex, size_t &size) override;

    /**
     * @brief Checks whether the value of the specified column in the current row is null.
     *
     * @param columnIndex Indicates the specified column index, which starts from 0.
     *
     * @return Returns true if the value of the specified column in the current row is null;
     * returns false otherwise.
     */
    API_EXPORT int IsColumnNull(int columnIndex, bool &isNull) override;

    /**
     * @brief Obtains data type of the given column's value.
     *
     * @param columnIndex Indicates the specified column index, which starts from 0.
     *
     * @return Returns column value type.
     */
    API_EXPORT int GetColumnType(int columnIndex, ColumnType &columnType) override;

    /**
     * @brief Move the cursor to an absolute position.
     *
     * @param position Indicates the specified column index, which starts from 0.
     *
     * @return Returns whether the requested move succeeded.
     */
    API_EXPORT int GoToRow(int position) override;

    /**
     * @brief Obtains the names of all columns in a result set.
     */
    API_EXPORT int GetAllColumnNames(std::vector<std::string> &columnNames) override;

    /**
     * @brief Obtains the number of rows in the result set.
     */
    API_EXPORT int GetRowCount(int &count) override;

    /**
     * @brief Obtains a block from the {@link SharedResultSet}.
     */
    API_EXPORT AppDataFwk::SharedBlock *GetBlock() override;

    /**
     * @brief Called when the position of the result set changes.
     */
    API_EXPORT bool OnGo(int oldRowIndex, int newRowIndex) override;

    /**
     * @brief Adds the data of a {@code SharedResultSet} to a {@link SharedBlock}.
     */
    API_EXPORT void FillBlock(int startRowIndex, AppDataFwk::SharedBlock *block) override;

    /**
     * @brief Allocates a new shared block to an {@link AbsSharedResultSet}
     */
    API_EXPORT virtual void SetBlock(AppDataFwk::SharedBlock *block);

    /**
     * @brief Closes the result set.
     *
     * Calling this method on the result set will release all of its resources and makes it ineffective.
     */
    API_EXPORT int Close() override;

    /**
     * @brief Checks whether an {@code AbsSharedResultSet} object contains shared blocks.
     */
    API_EXPORT bool HasBlock();

protected:
    int CheckState(int columnIndex);
    void ClearBlock();
    void InitBlock();
    void ClosedBlock();
    virtual void Finalize();

    std::shared_mutex mutex_;
private:
    // The default position of the cursor
    static const int INIT_POS = -1;
    static const size_t DEFAULT_BLOCK_SIZE = 2 * 1024 * 1024;
    friend class ISharedResultSetStub;
    friend class ISharedResultSetProxy;
    // The SharedBlock owned by this AbsSharedResultSet
    AppDataFwk::SharedBlock *sharedBlock_ = nullptr;
    std::string sharedBlockName_ = "defaultSharedBlockName";
};
} // namespace NativeRdb
} // namespace OHOS

#endif
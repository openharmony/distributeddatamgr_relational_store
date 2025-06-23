/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

/**
 * @addtogroup RDB
 * @{
 *
 * @brief The relational database (RDB) store manages data based on relational models.
 * With the underlying SQLite database, the RDB store provides a complete mechanism for managing local databases.
 * To satisfy different needs in complicated scenarios, the RDB store offers a series of APIs for performing operations
 * such as adding, deleting, modifying, and querying data, and supports direct execution of SQL statements.
 *
 * @since 10
 */

/**
 * @file oh_data_value.h
 *
 * @brief Provides functions and enumerations related to the data value.
 *
 * @kit ArkData
 * @library libnative_rdb_ndk.z.so
 * @syscap SystemCapability.DistributedDataManager.RelationalStore.Core
 *
 * @since 16
 */

#ifndef OH_DATA_VALUE_H
#define OH_DATA_VALUE_H

#include <inttypes.h>
#include "data_asset.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Indicates the column type.
 *
 * @since 10
 */
typedef enum OH_ColumnType {
    /**
     * @brief Indicates the column type is NULL.
     *
     * @since 10 Moved from oh_cursor.h file.
     */
    TYPE_NULL = 0,
    /**
     * @brief Indicates the column type is INT64.
     *
     * @since 10 Moved from oh_cursor.h file.
     */
    TYPE_INT64,
    /**
     * @brief Indicates the column type is REAL.
     *
     * @since 10 Moved from oh_cursor.h file.
     */
    TYPE_REAL,
    /**
     * @brief Indicates the column type is TEXT.
     *
     * @since 10 Moved from oh_cursor.h file.
     */
    TYPE_TEXT,
    /**
     * @brief Indicates the column type is BLOB.
     *
     * @since 10 Moved from oh_cursor.h file.
     */
    TYPE_BLOB,
    /**
     * @brief Indicates the column type is {@link Data_Asset}.
     *
     * @since 11 Moved from oh_cursor.h file.
     */
    TYPE_ASSET,
    /**
     * @brief Indicates the column type is array of {@link Data_Asset}.
     *
     * @since 11 Moved from oh_cursor.h file.
     */
    TYPE_ASSETS,
    /**
     * @brief Indicates the column type is FLOAT VECTOR.
     *
     * @since 16
     */
    TYPE_FLOAT_VECTOR,
    /**
     * @brief Indicates that the column type is a number whose length is greater than 64 bits.
     *
     * @since 16
     */
    TYPE_UNLIMITED_INT,
} OH_ColumnType;

/**
 * @brief Define the OH_Data_Value structure type.
 *
 * @since 16
 */
typedef struct OH_Data_Value OH_Data_Value;

/**
 * @brief Creates an OH_Data_Value instance object.
 *
 * @return Returns a pointer to OH_Data_Value instance when the execution is successful.
 * Otherwise, nullptr is returned. The memory must be released through the OH_Value_Destroy
 * interface after the use is complete.
 * @see OH_Value_Destroy.
 * @since 16
 */
OH_Data_Value *OH_Value_Create(void);

/**
 * @brief Destroys an OH_Data_Value instance object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Value_Destroy(OH_Data_Value *value);

/**
 * @brief Set empty data to the OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Value_PutNull(OH_Data_Value *value);

/**
 * @brief Set integer data to the OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @param val Represents a integer data.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Value_PutInt(OH_Data_Value *value, int64_t val);

/**
 * @brief Set decimal data to the OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @param val Represents a decimal data.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Value_PutReal(OH_Data_Value *value, double val);

/**
 * @brief Set string data to the OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @param val Represents a string data.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Value_PutText(OH_Data_Value *value, const char *val);

/**
 * @brief Set binary data to the OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @param val Represents a binary data.
 * @param length Represents the size of binary data.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Value_PutBlob(OH_Data_Value *value, const unsigned char *val, size_t length);

/**
 * @brief Set Data_Asset data to the OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @param val Represents a pointer to an instance of Data_Asset.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Value_PutAsset(OH_Data_Value *value, const Data_Asset *val);

/**
 * @brief Set multiple Data_Asset data to the OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @param val Represents a pointer to multiple Data_Asset.
 * @param length Represents the count of multiple data.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Value_PutAssets(OH_Data_Value *value, const Data_Asset * const * val, size_t length);

/**
 * @brief Set float array data to the OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @param val Represents a pointer to float array.
 * @param length Represents the size of float array.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Value_PutFloatVector(OH_Data_Value *value, const float *val, size_t length);

/**
 * @brief Set an integer of any length data to the OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @param sign Represents 0 is positive integer, 1 is negative integer.
 * @param trueForm Represents a pointer to integer array.
 * @param length Represents the size of integer array.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Value_PutUnlimitedInt(OH_Data_Value *value, int sign, const uint64_t *trueForm, size_t length);

/**
 * @brief Get data type from OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @param type Represents the parameter of the data type. It is an output parameter.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Value_GetType(OH_Data_Value *value, OH_ColumnType *type);

/**
 * @brief Check whether the data is empty from OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @param val Represents empty data flag. It is an output parameter.
 * The value true means that the data is empty, and false means the opposite.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Value_IsNull(OH_Data_Value *value, bool *val);

/**
 * @brief Get integer data from OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @param val Represents a pointer to an integer data. It is an output parameter.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @since 16
 */
int OH_Value_GetInt(OH_Data_Value *value, int64_t *val);

/**
 * @brief Get decimal data from OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @param val Represents a pointer to an decimal data. It is an output parameter.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @since 16
 */
int OH_Value_GetReal(OH_Data_Value *value, double *val);

/**
 * @brief Get string data from OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @param val Represents a pointer to a string data. It is an output parameter.
 * The caller does not need to apply for memory and release memory. The life cycle of val follows value.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @since 16
 */
int OH_Value_GetText(OH_Data_Value *value, const char **val);

/**
 * @brief Get binary data from OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @param val Represents a pointer to a binary data. It is an output parameter.
 * The caller does not need to apply for memory and release memory. The life cycle of val follows value.
 * @param length Represents the size of binary array.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @since 16
 */
int OH_Value_GetBlob(OH_Data_Value *value, const uint8_t **val, size_t *length);

/**
 * @brief Get Data_Asset data from OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @param val Represents a pointer to an instance of Data_Asset. The caller needs to apply for data memory.
 * This function only fills data. Otherwise, the execution fails.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @since 16
 */
int OH_Value_GetAsset(OH_Data_Value *value, Data_Asset *val);

/**
 * @brief Get multiple Data_Asset size from OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @param length Represents the size of Data_Asset array. It is an output parameter.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @since 16
 */
int OH_Value_GetAssetsCount(OH_Data_Value *value, size_t *length);

/**
 * @brief Get multiple Data_Asset data from OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @param val Represents a pointer to Data_Asset array. The caller needs to apply for data memory.
 * This function only fills data. Otherwise, the execution fails.
 * @param inLen Represents the size of val. It can be obtained through the OH_Value_GetAssetsCount function.
 * @param outLen Represents the actual amount of data obtained. It is an output parameter.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @see OH_Value_GetAssetsCount.
 * @since 16
 */
int OH_Value_GetAssets(OH_Data_Value *value, Data_Asset **val, size_t inLen, size_t *outLen);

/**
 * @brief Get float array data size from OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @param length Represents the size of float array. It is an output parameter.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @since 16
 */
int OH_Value_GetFloatVectorCount(OH_Data_Value *value, size_t *length);

/**
 * @brief Get float array from OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @param val Represents a pointer to float array. The caller needs to apply for data memory.
 * This function only fills data. Otherwise, the execution fails.
 * @param inLen Represents the size of val. It can be obtained through the OH_Value_GetFloatVectorCount function.
 * @param outLen Represents the actual amount of data obtained. It is an output parameter.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @see OH_Value_GetFloatVectorCount.
 * @since 16
 */
int OH_Value_GetFloatVector(OH_Data_Value *value, float *val, size_t inLen, size_t *outLen);

/**
 * @brief Get an integer of any length data size from OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @param length Represents the size of integer array. It is an output parameter.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @since 16
 */
int OH_Value_GetUnlimitedIntBand(OH_Data_Value *value, size_t *length);

/**
 * @brief Get an integer of any length data from OH_Data_Value object.
 *
 * @param value Represents a pointer to an instance of OH_Data_Value.
 * @param sign Represents 0 is positive integer, 1 is negative integer. It is an output parameter.
 * @param trueForm Represents a pointer to integer array. The caller needs to apply for data memory.
 * This function only fills data. Otherwise, the execution fails.
 * @param inLen Represents the size of trueForm. It can be obtained through the OH_Value_GetUnlimitedIntBand function.
 * @param outLen Represents the actual amount of data obtained. It is an output parameter.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @see OH_Value_GetUnlimitedIntBand.
 * @since 16
 */
int OH_Value_GetUnlimitedInt(OH_Data_Value *value, int *sign, uint64_t *trueForm, size_t inLen, size_t *outLen);

#ifdef __cplusplus
};
#endif
#endif
/** @} */
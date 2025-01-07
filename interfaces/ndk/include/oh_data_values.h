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
 * @file oh_data_values.h
 *
 * @brief Provides functions and enumerations related to the data values.
 *
 * @kit ArkData
 * @library libnative_rdb_ndk.z.so
 * @syscap SystemCapability.DistributedDataManager.RelationalStore.Core
 *
 * @since 16
 */
#ifndef OH_DATA_VALUES_H
#define OH_DATA_VALUES_H
#include <inttypes.h>

#include "data_asset.h"
#include "oh_data_value.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Define the OH_Data_Values structure type.
 *
 * @since 16
 */
typedef struct OH_Data_Values OH_Data_Values;

/**
 * @brief Creates an OH_Data_Values instance object.
 *
 * @return Returns a pointer to OH_Data_Values instance when the execution is successful.
 * Otherwise, nullptr is returned. The memory must be released through the OH_Values_Destroy
 * interface after the use is complete.
 * @see OH_Values_Destroy.
 * @since 16
 */
OH_Data_Values *OH_Values_Create();

/**
 * @brief Destroys an OH_Data_Values instance object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Values_Destroy(OH_Data_Values *values);

/**
 * @brief Add OH_Data_Value data to the OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param val Represents a pointer to an instance of OH_Data_Value.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Values_Put(OH_Data_Values *values, const OH_Data_Value *val);

/**
 * @brief Add empty data to the OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Values_PutNull(OH_Data_Values *values);

/**
 * @brief Add integer data to the OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param val Represents a integer data.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Values_PutInt(OH_Data_Values *values, int64_t val);

/**
 * @brief Add decimal data to the OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param val Represents a decimal data.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Values_PutReal(OH_Data_Values *values, double val);

/**
 * @brief Add string data to the OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param val Represents a string data.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Values_PutText(OH_Data_Values *values, const char *val);

/**
 * @brief Add binary data to the OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param val Represents a binary data.
 * @param length Represents the size of binary data.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Values_PutBlob(OH_Data_Values *values, const unsigned char *val, size_t length);

/**
 * @brief Add Data_Asset data to the OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param val Represents a pointer to an instance of Data_Asset.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Values_PutAsset(OH_Data_Values *values, const Data_Asset *val);

/**
 * @brief Add multiple Data_Asset data to the OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param val Represents a pointer to multiple Data_Asset.
 * @param length Represents the count of multiple data.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Values_PutAssets(OH_Data_Values *values, const Data_Asset * const * val, size_t length);

/**
 * @brief Add float array data to the OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param val Represents a pointer to float array.
 * @param length Represents the size of float array.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Values_PutFloatVector(OH_Data_Values *values, const float *val, size_t length);

/**
 * @brief Add an integer of any length data to the OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param sign Represents 0 is positive integer, 1 is negative integer.
 * @param trueForm Represents a pointer to integer array.
 * @param length Represents the size of integer array.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Values_PutUnlimitedInt(OH_Data_Values *values, int sign, const uint64_t *trueForm, size_t length);

/**
 * @brief Get data count from OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param count Represents the count of data in values. It is an output parameter.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Values_Count(OH_Data_Values *values, size_t *count);

/**
 * @brief Get data type from OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param index Represents the zero-based index of target data in values.
 * @param type Represents the parameter of the data type. It is an output parameter.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Values_GetType(OH_Data_Values *values, int index, OH_ColumnType *type);

/**
 * @brief Get OH_Data_Value data from OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param index Represents the zero-based index of target data in values.
 * @param val Represents a pointer to an instance of OH_Data_Value. It is an output parameter.
 * The caller does not need to apply for memory and release memory.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Values_Get(OH_Data_Values *values, int index, OH_Data_Value **val);

/**
 * @brief Check whether the data is empty from OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param index Represents the zero-based index of target data in values.
 * @param val Represents empty data flag. It is an output parameter. Ture is empty, false is not empty.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_Values_IsNull(OH_Data_Values *values, int index, bool *val);

/**
 * @brief Get integer data from OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param index Represents the zero-based index of target data in values.
 * @param val Represents a pointer to an integer data. It is an output parameter.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @since 16
 */
int OH_Values_GetInt(OH_Data_Values *values, int index, int64_t *val);

/**
 * @brief Get decimal data from OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param index Represents the zero-based index of target data in values.
 * @param val Represents a pointer to an decimal data. It is an output parameter.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @since 16
 */
int OH_Values_GetReal(OH_Data_Values *values, int index, double *val);

/**
 * @brief Get string data from OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param index Represents the zero-based index of target data in values.
 * @param val Represents a pointer to a string data. It is an output parameter.
 * The caller does not need to apply for memory and release memory.
 * The life cycle of val follows the value of index in values.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @since 16
 */
int OH_Values_GetText(OH_Data_Values *values, int index, const char **val);

/**
 * @brief Get binary data from OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param index Represents the zero-based index of target data in values.
 * @param val Represents a pointer to a binary data. It is an output parameter.
 * The caller does not need to apply for memory and release memory.
 * The life cycle of val follows the value of index in values.
 * @param length Represents the size of binary array.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @since 16
 */
int OH_Values_GetBlob(OH_Data_Values *values, int index, const uint8_t **val, size_t *length);

/**
 * @brief Get Data_Asset data from OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param index Represents the zero-based index of target data in values.
 * @param val Represents a pointer to an instance of Data_Asset. The caller needs to apply for data memory.
 * This function only fills data. Otherwise, the execution fails.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @since 16
 */
int OH_Values_GetAsset(OH_Data_Values *values, int index, Data_Asset *val);

/**
 * @brief Get multiple Data_Asset size from OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param index Represents the zero-based index of target data in values.
 * @param length Represents the size of Data_Asset array. It is an output parameter.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @since 16
 */
int OH_Values_GetAssetsCount(OH_Data_Values *values, int index, size_t *length);

/**
 * @brief Get multiple Data_Asset data from OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param index Represents the zero-based index of target data in values.
 * @param val Represents a pointer to Data_Asset array. The caller needs to apply for data memory.
 * This function only fills data. Otherwise, the execution fails.
 * @param inLen Represents the size of val. It can be obtained through the OH_Values_GetAssetsCount function.
 * @param outLen Represents the actual amount of data obtained. It is an output parameter.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @see OH_Values_GetAssetsCount.
 * @since 16
 */
int OH_Values_GetAssets(OH_Data_Values *values, int index, Data_Asset **val, size_t inLen, size_t *outLen);

/**
 * @brief Get float array data size from OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param index Represents the zero-based index of target data in values.
 * @param length Represents the size of float array. It is an output parameter.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @since 16
 */
int OH_Values_GetFloatVectorCount(OH_Data_Values *values, int index, size_t *length);

/**
 * @brief Get float array from OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param index Represents the zero-based index of target data in values.
 * @param val Represents a pointer to float array. The caller needs to apply for data memory.
 * This function only fills data. Otherwise, the execution fails.
 * @param inLen Represents the size of val. It can be obtained through the OH_Values_GetFloatVectorCount function.
 * @param outLen Represents the actual amount of data obtained. It is an output parameter.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @see OH_Values_GetFloatVectorCount.
 * @since 16
 */
int OH_Values_GetFloatVector(OH_Data_Values *values, int index, float *val, size_t inLen, size_t *outLen);

/**
 * @brief Get an integer of any length data size from OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param index Represents the zero-based index of target data in values.
 * @param length Represents the size of integer array. It is an output parameter.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @since 16
 */
int OH_Values_GetUnlimitedIntBand(OH_Data_Values *values, int index, size_t *length);

/**
 * @brief Get an integer of any length data from OH_Data_Values object.
 *
 * @param values Represents a pointer to an instance of OH_Data_Values.
 * @param index Represents the zero-based index of target data in values.
 * @param sign Represents 0 is positive integer, 1 is negative integer. It is an output parameter.
 * @param trueForm Represents a pointer to integer array. The caller needs to apply for data memory.
 * This function only fills data. Otherwise, the execution fails.
 * @param inLen Represents the size of trueForm. It can be obtained through the OH_Values_GetUnlimitedIntBand function.
 * @param outLen Represents the actual amount of data obtained. It is an output parameter.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_DATA_TYPE_NULL} the content stored in parameter value is null.
 *         Returns {@link RDB_E_TYPE_MISMATCH} storage data type mismatch.
 * @see OH_Values_GetUnlimitedIntBand.
 * @since 16
 */
int OH_Values_GetUnlimitedInt(OH_Data_Values *values, int index, int *sign, uint64_t *trueForm, size_t inLen,
    size_t *outLen);

#ifdef __cplusplus
};
#endif
#endif
/** @} */
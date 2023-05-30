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

#ifndef RELATIONAL_ERRNO_CODE_H
#define RELATIONAL_ERRNO_CODE_H

/**
 * @addtogroup relationalStore
 * @{
 *
 * @brief RelationalStore module provides a series of external interfaces for insert data, delete data, update date,
 * and select data, as well as data encryption, hierarchical data protection, backup, and recovery functions.
 *
 * @syscap SystemCapability.DistributedDataManager.RelationalStore.Core
 * @since 10
 * @version 1.0
 */


/**
 * @file relational_error_code.h
 *
 * @brief Declaration error code information.
 *
 * @since 10
 * @version 1.0
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Indicates the error code information.
 *
 * @since 10
 * @version 1.0
 */
enum OH_Rdb_ErrCode {
    /** Indicates the parameters is invalid.*/
    RDB_ERR_INVALID_ARGS = -2,
    /** Indicates that the function execution exception.*/
    RDB_ERR = -1,
    /** Indicates that the function execution normal.*/
    RDB_ERR_OK = 0
};

#ifdef __cplusplus
};
#endif

#endif // RELATIONAL_ERRNO_CODE_H
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

/* SAID:1301 */
#ifndef DISTRIBUTEDDATA_RELATIONAL_STORE_IPC_INTERFACE_H
#define DISTRIBUTEDDATA_RELATIONAL_STORE_IPC_INTERFACE_H

namespace OHOS::DistributedRdb {
namespace RelStore {
enum class RelStoreInterfaceCode {
    FUNC_GET_ROW_COUNT,
    FUNC_GET_ALL_COLUMN_NAMES,
    FUNC_ON_GO,
    FUNC_CLOSE,
    FUNC_GET_BLOB,
    FUNC_GET_STRING,
    FUNC_GET_INT,
    FUNC_GET_LONG,
    FUNC_GET_DOUBLE,
    FUNC_IS_COLUMN_NULL,
    FUNC_GO_TO,
    FUNC_GO_TO_ROW,
    FUNC_GO_TO_FISTR_ROW,
    FUNC_GO_TO_LAST_ROW,
    FUNC_GO_TO_NEXT_ROW,
    FUNC_GO_TO_PREV_ROW,
    FUNC_IS_AT_FIRST_ROW,
    FUNC_IS_AT_LAST_ROW,
    FUNC_IS_STARTED_ROW,
    FUNC_IS_ENDED_ROW,
    FUNC_IS_CLOSED,
    FUNC_GET_COLUMN_COUNT,
    FUNC_GET_COLUMN_INDEX,
    FUNC_GET_COLUMN_NAME,
    FUNC_GET_COLUMN_TYPE,
    FUNC_GET_ROW_INDEX,
    FUNC_BUTT,
    RDB_NOTIFIER_CMD_SYNC_COMPLETE = 0,
    RDB_NOTIFIER_CMD_DATA_CHANGE,
    RDB_NOTIFIER_CMD_MAX
};
}
} // namespace OHOS

#endif // DISTRIBUTEDDATA_RELATIONAL_STORE_IPC_INTERFACE_H
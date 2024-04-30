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

#ifndef NATIVE_RDB_SHARED_RESULT_SET_H
#define NATIVE_RDB_SHARED_RESULT_SET_H

#include <string>

#include "rdb_visibility.h"

namespace OHOS {
namespace AppDataFwk {
class SharedBlock;
}
namespace NativeRdb {
/**
 * The SharedResultSet class of RDB.
 */
class API_EXPORT SharedResultSet {
public:
    /**
     * @brief Constructor.
     */
    SharedResultSet() {}

    /**
     * @brief Destructor.
     */
    ~SharedResultSet() {}

    /**
     * @brief Obtains a block from the {@link SharedResultSet}.
     */
    virtual std::shared_ptr<AppDataFwk::SharedBlock> GetBlock() = 0;

    /**
     * @brief Called when the position of the result set changes.
     */
    virtual int OnGo(int oldRowIndex, int newRowIndex) = 0;
};
} // namespace NativeRdb
} // namespace OHOS

#endif
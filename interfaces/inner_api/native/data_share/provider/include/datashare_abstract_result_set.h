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

#ifndef DATASHARE_ABSTRACT_RESULT_SET_H
#define DATASHARE_ABSTRACT_RESULT_SET_H

#include <string>
#include "datashare_block_writer.h"
namespace OHOS {
namespace DataShare {
class DataShareAbstractResultSet {
public:
    virtual ~DataShareAbstractResultSet() {}

    /**
     * Returns a string array holding the names of all of the columns in the
     * result set.
     *
     * return the names of the columns contains in this query result.
     */
    virtual int GetAllColumnName(std::vector<std::string> &columnNames) = 0;

    /**
     * return the numbers of rows in the result set.
     */
    virtual int GetRowCount(int &count) = 0;

    /**
     * Called when the position of the result set changes
     */
    virtual bool OnGo(int startRowIndex, int targetRowIndex, DataShareBlockWriter &writer) = 0;
};
} // namespace DataShare
} // namespace OHOS
#endif

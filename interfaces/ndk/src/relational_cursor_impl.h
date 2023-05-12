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

#ifndef RELATIONAL_CURSOR_IMPL_H
#define RELATIONAL_CURSOR_IMPL_H

#include "relational_cursor.h"
#include "result_set.h"
namespace OHOS {
namespace NativeRdb {
constexpr int RDB_CURSOR_CID = 1234563;
class CursorImpl : public OH_Cursor {
public:
    CursorImpl(std::shared_ptr<ResultSet> resultSet);
    std::shared_ptr<ResultSet> GetResultSet();

private:
    std::shared_ptr<ResultSet> resultSet_;
};
} // namespace NativeRdb
} // namespace OHOS
#endif // RELATIONAL_CURSOR_IMPL_H

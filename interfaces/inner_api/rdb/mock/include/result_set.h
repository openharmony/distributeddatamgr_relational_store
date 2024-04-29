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

#ifndef NATIVE_RDB_RESULT_SET_H
#define NATIVE_RDB_RESULT_SET_H

#include <string>
#include <vector>
#include <map>
#include "remote_result_set.h"
#include "value_object.h"

namespace OHOS {
namespace NativeRdb {
struct RowEntity {
public:
    void Put(const std::string &name, int32_t index, ValueObject &&value);
    ValueObject Get(const std::string &name) const;
    ValueObject Get(int index) const;
    const std::map<std::string, ValueObject> &Get() const;
    std::map<std::string, ValueObject> Steal();
    void Clear(int32_t size);

private:
    std::map<std::string, ValueObject> values_;
    std::vector<decltype(values_)::iterator> indexs_;
};

class ResultSet : public RemoteResultSet {
public:
    virtual ~ResultSet() {}

    virtual int GetAsset(int32_t col, ValueObject::Asset &value) = 0;
    virtual int GetAssets(int32_t col, ValueObject::Assets &value) = 0;
    virtual int GetFloat32Array(int32_t index, ValueObject::FloatVector &vecs) = 0;
    virtual int Get(int32_t col, ValueObject &value) = 0;
    /**
     * @brief Gets the entire row of data for the current row from the result set.
     */
    virtual int GetRow(RowEntity &rowEntity) = 0;
    virtual int GetSize(int columnIndex, size_t &size) = 0;
};

} // namespace NativeRdb
} // namespace OHOS
#endif

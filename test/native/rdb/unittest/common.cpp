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


#include "common.h"
#include <string>

namespace OHOS {
namespace NativeRdb {

ValuesBucket UTUtils::SetRowData(const RowData &rowData)
{
    ValuesBucket value;
    value.PutInt("id", rowData.id);
    value.PutString("name", rowData.name);
    value.PutInt("age", rowData.age);
    value.PutDouble("salary", rowData.salary);
    value.PutBlob("blobType", rowData.blobType);
    return value;
}

const RowData UTUtils::g_rowData[3] = {
    {1, "zhangsan", 18, 100.5, std::vector<uint8_t>{ 1, 2, 3 }},
    {2, "lisi", 19, 200.5, std::vector<uint8_t>{ 4, 5, 6 }},
    {3, "wangyjing", 20, 300.5, std::vector<uint8_t>{ 7, 8, 9 }}
};
}
}

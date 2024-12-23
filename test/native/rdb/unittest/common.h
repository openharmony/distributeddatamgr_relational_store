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

#ifndef NATIVE_RDB_TEST_COMMON_H
#define NATIVE_RDB_TEST_COMMON_H

#include <string>

#include "values_bucket.h"

namespace OHOS {
namespace NativeRdb {

static const std::string RDB_TEST_PATH = "/data/test/";
struct RowData {
    int id;
    std::string name;
    int age;
    double salary;
    std::vector<uint8_t> blobType;
    AssetValue asset;
    std::vector<AssetValue> assets;
};

struct RowDatas {
    int id;
    std::string eName;
    int jobId;
    ValueObject mgr;
    std::string joinDate;
    double salary;
    ValueObject bonus;
    int deptId;
};

class UTUtils {
public:
    static ValuesBucket SetRowData(const RowData &rowData);

    static ValuesBucket SetRowDatas(const RowDatas &rowDatas);

    static const RowData g_rowData[3];

    static const RowDatas gRowDatas[14];
};

} // namespace NativeRdb
} // namespace OHOS

#endif

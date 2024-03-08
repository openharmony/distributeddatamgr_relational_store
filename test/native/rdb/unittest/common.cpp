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
#include "rdb_errno.h"

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

ValuesBucket UTUtils::SetRowDatas(const RowDatas &rowDatas)
{
    ValuesBucket value;
    ValueObjectType typeMgr = rowDatas.mgr.GetType();
    ValueObjectType typeBonus = rowDatas.bonus.GetType();

    int outputMgr = 0;
    double outputBonus = 0.0;

    value.PutInt("id", rowDatas.id);
    value.PutString("eName", rowDatas.eName);
    value.PutInt("jobId", rowDatas.jobId);

    if (typeMgr == ValueObjectType::TYPE_NULL) {
        value.PutNull("mgr");
    } else {
        int ret = rowDatas.mgr.GetInt(outputMgr);
        if (ret == E_OK) {
            value.PutInt("mgr", outputMgr);
        }
    }

    value.PutString("joinDate", rowDatas.joinDate);
    value.PutDouble("salary", rowDatas.salary);

    if (typeBonus == ValueObjectType::TYPE_NULL) {
        value.PutNull("bonus");
    } else {
        int ret = rowDatas.bonus.GetDouble(outputBonus);
        if (ret == E_OK) {
            value.PutDouble("bonus", outputBonus);
        }
    }

    value.PutInt("deptId", rowDatas.deptId);
    return value;
}

const RowDatas UTUtils::gRowDatas[14] = {
    { 1001, "SunWuKong", 4, ValueObject(1004), "2000-12-17", 8000.00, ValueObject(), 20 },
    { 1002, "LuJunYi", 3, ValueObject(1006), "2001-02-20", 16000.00, ValueObject(3000.00), 30 },
    { 1003, "LinChong", 3, ValueObject(1006), "2001-02-22", 12500.00, ValueObject(5000.00), 30 },
    { 1004, "TangCeng", 2, ValueObject(1009), "2001-04-02", 29750.00, ValueObject(), 20 },
    { 1005, "LiKui", 4, ValueObject(1006), "2001-09-28", 12500.00, ValueObject(14000.00), 30 },
    { 1006, "SongJiang", 2, ValueObject(1009), "2001-05-01", 28500.00, ValueObject(), 30 },
    { 1007, "LiuBei", 2, ValueObject(1009), "2001-09-01", 24500.00, ValueObject(), 10 },
    { 1008, "ZhuBaJie", 4, ValueObject(1004), "2007-04-19", 30000.00, ValueObject(), 20 },
    { 1009, "LuoGuanZhong", 1, ValueObject(), "2001-11-17", 50000.00, ValueObject(), 10 },
    { 1010, "WuYong", 3, ValueObject(1006), "2001-09-08", 15000.00, ValueObject(), 30 },
    { 1011, "ShaCeng", 4, ValueObject(1004), "2007-05-23", 11000.00, ValueObject(), 20 },
    { 1012, "LiKui", 4, ValueObject(1006), "2001-12-03", 9500.00, ValueObject(), 30 },
    { 1013, "XiaoBaiLong", 4, ValueObject(1004), "2001-12-03", 30000.00, ValueObject(), 20 },
    { 1014, "GuanYu", 4, ValueObject(1007), "2002-01-23", 13000.00, ValueObject(), 10 } };
}
}

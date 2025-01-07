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
#define LOG_TAG "DataVBuckets"
#include "oh_data_values_buckets.h"
#include "relational_store_error_code.h"
#include "relational_values_bucket.h"
#include "oh_data_define.h"
#include "logger.h"

using namespace OHOS::RdbNdk;

static bool IsValidVBuckets(const OH_Data_VBuckets *vbuckets)
{
    if (vbuckets == nullptr) {
        LOG_ERROR("vbuckets is null.");
        return false;
    }
    bool ret = vbuckets->IsValid();
    if (!ret) {
        LOG_ERROR("invalid data value buckets object.");
    }
    return ret;
}

OH_Data_VBuckets *OH_VBuckets_Create()
{
    OH_Data_VBuckets *vbuckets = new (std::nothrow) OH_Data_VBuckets;
    if (vbuckets == nullptr) {
        LOG_ERROR("create vbuckets fail.");
    }
    return vbuckets;
}

int OH_VBuckets_Destroy(OH_Data_VBuckets *buckets)
{
    if (!IsValidVBuckets(buckets)) {
        return RDB_E_INVALID_ARGS;
    }
    delete buckets;
    return RDB_OK;
}

int OH_VBuckets_PutRow(OH_Data_VBuckets *buckets, const OH_VBucket *row)
{
    if (!IsValidVBuckets(buckets) || RelationalValuesBucket::GetSelf(const_cast<OH_VBucket *>(row)) == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    buckets->rows_.push_back(const_cast<OH_VBucket *>(row));
    return RDB_OK;
}

int OH_VBuckets_PutRows(OH_Data_VBuckets *buckets, const OH_Data_VBuckets *rows)
{
    if (!IsValidVBuckets(buckets) || !IsValidVBuckets(rows)) {
        return RDB_E_INVALID_ARGS;
    }
    buckets->rows_.insert(buckets->rows_.end(), rows->rows_.begin(), rows->rows_.end());
    return RDB_OK;
}

int OH_VBuckets_RowCount(OH_Data_VBuckets *buckets, size_t *count)
{
    if (!IsValidVBuckets(buckets) || count == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    *count = buckets->rows_.size();
    return RDB_OK;
}

bool OH_Data_VBuckets::IsValid() const
{
    return id == OH_VBUCKETS_ID;
}
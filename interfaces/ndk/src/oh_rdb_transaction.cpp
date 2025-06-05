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

#define LOG_TAG "RdbTransaction"

#include "oh_rdb_transaction.h"
#include "oh_data_define.h"
#include "oh_data_utils.h"
#include "relational_values_bucket.h"
#include "relational_store_error_code.h"
#include "convertor_error_code.h"
#include "relational_predicates.h"
#include "relational_cursor.h"
#include "logger.h"

using namespace OHOS::RdbNdk;
using namespace OHOS::NativeRdb;

static bool IsValidRdbTransOptions(const OH_RDB_TransOptions *options)
{
    if (options == nullptr) {
        LOG_ERROR("options is null");
        return false;
    }
    bool ret = options->IsValid();
    if (!ret) {
        LOG_ERROR("invalid transaction options object.");
    }
    return ret;
}

OH_RDB_TransOptions *OH_RdbTrans_CreateOptions(void)
{
    OH_RDB_TransOptions *value = new (std::nothrow) OH_RDB_TransOptions;
    if (value == nullptr) {
        LOG_ERROR("new OH_RDB_TransOptions failed.");
        return nullptr;
    }
    value->type_ = RDB_TRANS_DEFERRED;
    return value;
}

int OH_RdbTrans_DestroyOptions(OH_RDB_TransOptions *opitons)
{
    if (!IsValidRdbTransOptions(opitons)) {
        return RDB_E_INVALID_ARGS;
    }
    delete opitons;
    return RDB_OK;
}

int OH_RdbTransOption_SetType(OH_RDB_TransOptions *opitons, OH_RDB_TransType type)
{
    if (!IsValidRdbTransOptions(opitons) || type < RDB_TRANS_DEFERRED || type >= RDB_TRANS_BUTT) {
        LOG_ERROR("invalid options, type=%{public}d.", type);
        return RDB_E_INVALID_ARGS;
    }
    opitons->type_ = type;
    return RDB_OK;
}

static bool IsValidRdbTrans(const OH_Rdb_Transaction *trans)
{
    if (trans == nullptr || trans->trans_ == nullptr) {
        LOG_ERROR("trans param has null data");
        return false;
    }
    bool ret = trans->IsValid();
    if (!ret) {
        LOG_ERROR("invalid transaction object.");
    }
    return ret;
}

int OH_RdbTrans_Commit(OH_Rdb_Transaction *trans)
{
    if (!IsValidRdbTrans(trans)) {
        return RDB_E_INVALID_ARGS;
    }
    auto errCode = trans->trans_->Commit();
    if (errCode != E_OK) {
        LOG_ERROR("commit fail, errCode=%{public}d", errCode);
    }
    return ConvertorErrorCode::GetInterfaceCode(errCode);
}

int OH_RdbTrans_Rollback(OH_Rdb_Transaction *trans)
{
    if (!IsValidRdbTrans(trans)) {
        return RDB_E_INVALID_ARGS;
    }
    auto errCode = trans->trans_->Rollback();
    if (errCode != E_OK) {
        LOG_ERROR("commit fail, errCode=%{public}d", errCode);
    }
    return ConvertorErrorCode::GetInterfaceCode(errCode);
}

int OH_RdbTrans_Insert(OH_Rdb_Transaction *trans, const char *table, const OH_VBucket *row, int64_t *rowId)
{
    auto valuesBucket = RelationalValuesBucket::GetSelf(const_cast<OH_VBucket *>(row));
    if (!IsValidRdbTrans(trans) || table == nullptr || valuesBucket == nullptr || rowId == nullptr) {
        return RDB_E_INVALID_ARGS;
    }

    auto [errCode, id] = trans->trans_->Insert(table, valuesBucket->Get());
    *rowId = id;
    if (errCode != E_OK) {
        LOG_ERROR("insert fail, errCode=%{public}d id=%{public}" PRId64, errCode, id);
    }
    return ConvertorErrorCode::GetInterfaceCode(errCode);
}

int OH_RdbTrans_BatchInsert(OH_Rdb_Transaction *trans, const char *table, const OH_Data_VBuckets *rows,
    Rdb_ConflictResolution resolution, int64_t *changes)
{
    if (!IsValidRdbTrans(trans) || table == nullptr || rows == nullptr || !rows->IsValid() || changes == nullptr ||
        resolution < RDB_CONFLICT_NONE || resolution > RDB_CONFLICT_REPLACE) {
        return RDB_E_INVALID_ARGS;
    }
    ValuesBuckets datas;
    for (size_t i = 0; i < rows->rows_.size(); i++) {
        auto valuesBucket = RelationalValuesBucket::GetSelf(const_cast<OH_VBucket *>(rows->rows_[i]));
        if (valuesBucket == nullptr) {
            continue;
        }
        datas.Put(valuesBucket->Get());
    }
    auto [errCode, count] = trans->trans_->BatchInsert(table, datas, Utils::ConvertConflictResolution(resolution));
    *changes = count;
    if (errCode != E_OK) {
        LOG_ERROR("batch insert fail, errCode=%{public}d count=%{public}" PRId64, errCode, count);
    }
    return ConvertorErrorCode::GetInterfaceCode(errCode);
}

int OH_RdbTrans_Update(OH_Rdb_Transaction *trans, const OH_VBucket *row, const OH_Predicates *predicates,
    int64_t *changes)
{
    auto rdbPredicate = RelationalPredicate::GetSelf(const_cast<OH_Predicates *>(predicates));
    auto rdbValuesBucket = RelationalValuesBucket::GetSelf(const_cast<OH_VBucket *>(row));
    if (!IsValidRdbTrans(trans) || rdbValuesBucket == nullptr || rdbPredicate == nullptr || changes == nullptr) {
        return RDB_E_INVALID_ARGS;
    }
    auto [errCode, count] = trans->trans_->Update(rdbValuesBucket->Get(), rdbPredicate->Get());
    *changes = count;
    if (errCode != E_OK) {
        LOG_ERROR("update fail, errCode=%{public}d count=%{public}d", errCode, count);
    }
    return ConvertorErrorCode::GetInterfaceCode(errCode);
}

int OH_RdbTrans_Delete(OH_Rdb_Transaction *trans, const OH_Predicates *predicates, int64_t *changes)
{
    auto rdbPredicate = RelationalPredicate::GetSelf(const_cast<OH_Predicates *>(predicates));
    if (!IsValidRdbTrans(trans) || rdbPredicate == nullptr || changes == nullptr) {
        return RDB_E_INVALID_ARGS;
    }

    auto [errCode, count] = trans->trans_->Delete(rdbPredicate->Get());
    *changes = count;
    if (errCode != E_OK) {
        LOG_ERROR("delete fail, errCode=%{public}d count=%{public}d", errCode, count);
    }
    return ConvertorErrorCode::GetInterfaceCode(errCode);
}

OH_Cursor *OH_RdbTrans_Query(OH_Rdb_Transaction *trans, const OH_Predicates *predicates, const char *columns[], int len)
{
    auto rdbPredicate = RelationalPredicate::GetSelf(const_cast<OH_Predicates *>(predicates));
    if (!IsValidRdbTrans(trans) || rdbPredicate == nullptr) {
        return nullptr;
    }
    std::vector<std::string> fields;
    if (columns != nullptr && len > 0) {
        for (int i = 0; i < len; i++) {
            fields.emplace_back(columns[i]);
        }
    }
    auto resultSet = trans->trans_->QueryByStep(rdbPredicate->Get(), fields);
    if (resultSet == nullptr) {
        LOG_ERROR("resultSet is null.");
        return nullptr;
    }
    return new (std::nothrow) RelationalCursor(std::move(resultSet));
}

OH_Cursor *OH_RdbTrans_QuerySql(OH_Rdb_Transaction *trans, const char *sql, const OH_Data_Values *args)
{
    if (!IsValidRdbTrans(trans) || sql == nullptr || (args != nullptr && !args->IsValid())) {
        return nullptr;
    }
    std::vector<ValueObject> datas;
    if (args != nullptr) {
        for (auto arg : args->values_) {
            if (!arg.IsValid()) {
                continue;
            }
            datas.push_back(arg.value_);
        }
    }
    auto resultSet = trans->trans_->QueryByStep(sql, datas);
    if (resultSet == nullptr) {
        LOG_ERROR("resultSet is null.");
        return nullptr;
    }
    return new (std::nothrow) RelationalCursor(std::move(resultSet));
}

int OH_RdbTrans_Execute(OH_Rdb_Transaction *trans, const char *sql, const OH_Data_Values *args, OH_Data_Value **result)
{
    if (!IsValidRdbTrans(trans) || sql == nullptr || (args != nullptr && !args->IsValid())) {
        return RDB_E_INVALID_ARGS;
    }
    std::vector<ValueObject> datas;
    if (args != nullptr) {
        for (auto arg : args->values_) {
            if (!arg.IsValid()) {
                continue;
            }
            datas.push_back(arg.value_);
        }
    }
    auto [errCode, valueObj] = trans->trans_->Execute(sql, datas);
    if (errCode != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("execute fail, errCode=%{public}d", errCode);
        return ConvertorErrorCode::GetInterfaceCode(errCode);
    }
    if (result != nullptr) {
        OH_Data_Value *value = OH_Value_Create();
        if (value == nullptr) {
            return RDB_E_ERROR;
        }
        value->value_ = valueObj;
        *result = value;
    }
    return RDB_OK;
}

int OH_RdbTrans_Destroy(OH_Rdb_Transaction *trans)
{
    if (!IsValidRdbTrans(trans)) {
        LOG_ERROR("invalid trans");
        return RDB_E_INVALID_ARGS;
    }
    trans->trans_ = nullptr;
    delete trans;
    return RDB_OK;
}

bool OH_Rdb_Transaction::IsValid() const
{
    if (trans_ == nullptr) {
        return false;
    }
    return id == OH_RDB_TRANS_ID;
}

bool OH_RDB_TransOptions::IsValid() const
{
    if (type_ < RDB_TRANS_DEFERRED || type_ >= RDB_TRANS_BUTT) {
        LOG_ERROR("invalid type=%{public}d", type_);
        return false;
    }
    return id == OH_TRANS_OPTION_ID;
}

int OH_RdbTrans_InsertWithConflictResolution(OH_Rdb_Transaction *trans, const char *table, const OH_VBucket *row,
    Rdb_ConflictResolution resolution, int64_t *rowId)
{
    auto valuesBucket = RelationalValuesBucket::GetSelf(const_cast<OH_VBucket *>(row));
    if (!IsValidRdbTrans(trans) || table == nullptr || valuesBucket == nullptr || rowId == nullptr ||
        resolution < RDB_CONFLICT_NONE || resolution > RDB_CONFLICT_REPLACE) {
        return RDB_E_INVALID_ARGS;
    }

    auto [err, id] = trans->trans_->Insert(table, valuesBucket->Get(), Utils::ConvertConflictResolution(resolution));
    *rowId = id;
    if (err != E_OK) {
        LOG_ERROR("insert with conflict resolution fail,errCode=%{public}x,resolution=%{public}d,id=%{public}" PRId64,
            err, resolution, id);
    }
    return ConvertorErrorCode::GetInterfaceCode(err);
}

int OH_RdbTrans_UpdateWithConflictResolution(OH_Rdb_Transaction *trans, const OH_VBucket *row,
    const OH_Predicates *predicates, Rdb_ConflictResolution resolution, int64_t *changes)
{
    auto rdbPredicate = RelationalPredicate::GetSelf(const_cast<OH_Predicates *>(predicates));
    auto rdbValuesBucket = RelationalValuesBucket::GetSelf(const_cast<OH_VBucket *>(row));
    if (!IsValidRdbTrans(trans) || rdbValuesBucket == nullptr || rdbPredicate == nullptr || changes == nullptr ||
        resolution < RDB_CONFLICT_NONE || resolution > RDB_CONFLICT_REPLACE) {
        return RDB_E_INVALID_ARGS;
    }
    auto [err, count] = trans->trans_->Update(rdbValuesBucket->Get(), rdbPredicate->Get(),
        Utils::ConvertConflictResolution(resolution));
    *changes = count;
    if (err != E_OK) {
        LOG_ERROR("update with conflict resolution fail, errCode=%{public}x,resolution=%{public}d,count=%{public}d",
            err, resolution, count);
    }
    return ConvertorErrorCode::GetInterfaceCode(err);
}
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

#include "datashare_predicates.h"
#include "datashare_log.h"

namespace OHOS {
namespace DataShare {

DataSharePredicates::DataSharePredicates()
{
}

DataSharePredicates::DataSharePredicates(std::list<OperationItem> &operationList)
    : operationList_(operationList)
{
}

DataSharePredicates::~DataSharePredicates() 
{
}

/**
 * EqualTo
 */
DataSharePredicates *DataSharePredicates::EqualTo(const std::string &field, const int value)
{
    LOG_DEBUG("DataSharePredicates::EqualTo Start field%{public}s,value%{public}d", field.c_str(), value);
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(EQUAL_TO, para1, para2, para3, TWO_COUNT);
    LOG_DEBUG("DataSharePredicates::EqualTo End");
    return this;
}

DataSharePredicates *DataSharePredicates::EqualTo(const std::string &field, const int64_t value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(EQUAL_TO, para1, para2, para3, TWO_COUNT);
    return this;
}

DataSharePredicates *DataSharePredicates::EqualTo(const std::string &field, const double value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(EQUAL_TO, para1, para2, para3, TWO_COUNT);
    return this;
}

DataSharePredicates *DataSharePredicates::EqualTo(const std::string &field, const std::string &value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(EQUAL_TO, para1, para2, para3, TWO_COUNT);
    return this;
}

DataSharePredicates *DataSharePredicates::EqualTo(const std::string &field, const bool value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(EQUAL_TO, para1, para2, para3, TWO_COUNT);
    return this;
}

/**
 * NotEqualTo
 */
DataSharePredicates *DataSharePredicates::NotEqualTo(const std::string &field, const int value)
{
    LOG_DEBUG("DataSharePredicates::NotEqualTo Start field%{public}s,value%{public}d", field.c_str(), value);
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(NOT_EQUAL_TO, para1, para2, para3, TWO_COUNT);
    LOG_DEBUG("DataSharePredicates::NotEqualTo End");
    return this;
}

DataSharePredicates *DataSharePredicates::NotEqualTo(const std::string &field, const int64_t value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(NOT_EQUAL_TO, para1, para2, para3, TWO_COUNT);
    return this;
}

DataSharePredicates *DataSharePredicates::NotEqualTo(const std::string &field, const double value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(NOT_EQUAL_TO, para1, para2, para3, TWO_COUNT);
    return this;
}

DataSharePredicates *DataSharePredicates::NotEqualTo(const std::string &field, const std::string &value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(NOT_EQUAL_TO, para1, para2, para3, TWO_COUNT);
    return this;
}

DataSharePredicates *DataSharePredicates::NotEqualTo(const std::string &field, const bool value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(NOT_EQUAL_TO, para1, para2, para3, TWO_COUNT);
    return this;
}

/**
 * GreaterThan
 */
DataSharePredicates *DataSharePredicates::GreaterThan(const std::string &field, const int value)
{
    LOG_DEBUG("DataSharePredicates::GreaterThan Start field%{public}s,value%{public}d", field.c_str(), value);
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(GREATER_THAN, para1, para2, para3, TWO_COUNT);
    LOG_DEBUG("DataSharePredicates::GreaterThan End");
    return this;
}

DataSharePredicates *DataSharePredicates::GreaterThan(const std::string &field, const int64_t value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(GREATER_THAN, para1, para2, para3, TWO_COUNT);
    return this;
}

DataSharePredicates *DataSharePredicates::GreaterThan(const std::string &field, const double value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(GREATER_THAN, para1, para2, para3, TWO_COUNT);
    return this;
}

DataSharePredicates *DataSharePredicates::GreaterThan(const std::string &field, const std::string &value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(GREATER_THAN, para1, para2, para3, TWO_COUNT);
    return this;
}

/**
 * LessThan
 */
DataSharePredicates *DataSharePredicates::LessThan(const std::string &field, const int value)
{
    LOG_DEBUG("DataSharePredicates::LessThan Start field%{public}s,value%{public}d",field.c_str(), value);
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(LESS_THAN, para1, para2, para3, TWO_COUNT);
    LOG_DEBUG("DataSharePredicates::LessThan End");
    return this;
}

DataSharePredicates *DataSharePredicates::LessThan(const std::string &field, const int64_t value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(LESS_THAN, para1, para2, para3, TWO_COUNT);
    return this;
}

DataSharePredicates *DataSharePredicates::LessThan(const std::string &field, const double value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(LESS_THAN, para1, para2, para3, TWO_COUNT);
    return this;
}

DataSharePredicates *DataSharePredicates::LessThan(const std::string &field, const std::string &value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(LESS_THAN, para1, para2, para3, TWO_COUNT);
    return this;
}

/**
 * GreaterThanOrEqualTo
 */
DataSharePredicates *DataSharePredicates::GreaterThanOrEqualTo(const std::string &field, const int value)
{
    LOG_DEBUG("DataSharePredicates::GreaterThanOrEqualTo Start field%{public}s,value%{public}d",field.c_str(), value);
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(GREATER_THAN_OR_EQUAL_TO, para1, para2, para3, TWO_COUNT);
    LOG_DEBUG("DataSharePredicates::GreaterThanOrEqualTo End");
    return this;
}

DataSharePredicates *DataSharePredicates::GreaterThanOrEqualTo(const std::string &field, const int64_t value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(GREATER_THAN_OR_EQUAL_TO, para1, para2, para3, TWO_COUNT);
    return this;
}

DataSharePredicates *DataSharePredicates::GreaterThanOrEqualTo(const std::string &field, const double value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(GREATER_THAN_OR_EQUAL_TO, para1, para2, para3, TWO_COUNT);
    return this;
}

DataSharePredicates *DataSharePredicates::GreaterThanOrEqualTo(const std::string &field, const std::string &value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(GREATER_THAN_OR_EQUAL_TO, para1, para2, para3, TWO_COUNT);
    return this;
}

/**
 * LessThanOrEqualTo
 */
DataSharePredicates *DataSharePredicates::LessThanOrEqualTo(const std::string &field, const int value)
{
    LOG_DEBUG("DataSharePredicates::LessThanOrEqualTo Start field%{public}s,value%{public}d",field.c_str(), value);
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(GREATER_THAN_OR_EQUAL_TO, para1, para2, para3, TWO_COUNT);
    LOG_DEBUG("DataSharePredicates::LessThanOrEqualTo End");
    return this;
}

DataSharePredicates *DataSharePredicates::LessThanOrEqualTo(const std::string &field, const int64_t value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(LESS_THAN_OR_EQUAL_TO, para1, para2, para3, TWO_COUNT);
    return this;
}

DataSharePredicates *DataSharePredicates::LessThanOrEqualTo(const std::string &field, const double value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(LESS_THAN_OR_EQUAL_TO, para1, para2, para3, TWO_COUNT);
    return this;
}

DataSharePredicates *DataSharePredicates::LessThanOrEqualTo(const std::string &field, const std::string &value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(LESS_THAN_OR_EQUAL_TO, para1, para2, para3, TWO_COUNT);
    return this;
}

/**
 * In
 */
DataSharePredicates *DataSharePredicates::In(const std::string &field, const std::vector<int> &value)
{
    LOG_DEBUG("DataSharePredicates::In Start field%{public}s,value%{public}d",field.c_str(), value.at(0));
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(IN, para1, para2, para3, TWO_COUNT);
    LOG_DEBUG("DataSharePredicates::In End");
    return this;
}

DataSharePredicates *DataSharePredicates::In(const std::string &field, const std::vector<int64_t> &value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(IN, para1, para2, para3, TWO_COUNT);
    return this;
}

DataSharePredicates *DataSharePredicates::In(const std::string &field, const std::vector<double> &value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(IN, para1, para2, para3, TWO_COUNT);
    return this;
}

DataSharePredicates *DataSharePredicates::In(const std::string &field, const std::vector<std::string> &value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(IN, para1, para2, para3, TWO_COUNT);
    return this;
}

/**
 * NotIn
 */
DataSharePredicates *DataSharePredicates::NotIn(const std::string &field, const std::vector<int> &value)
{
    LOG_DEBUG("DataSharePredicates::NotIn Start field%{public}s,value%{public}d",field.c_str(), value.at(0));
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(NOT_IN, para1, para2, para3, TWO_COUNT);
    LOG_DEBUG("DataSharePredicates::NotIn End");
    return this;
}

DataSharePredicates *DataSharePredicates::NotIn(const std::string &field, const std::vector<int64_t> &value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(NOT_IN, para1, para2, para3, TWO_COUNT);
    return this;
}

DataSharePredicates *DataSharePredicates::NotIn(const std::string &field, const std::vector<double> &value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(NOT_IN, para1, para2, para3, TWO_COUNT);
    return this;
}

DataSharePredicates *DataSharePredicates::NotIn(const std::string &field, const std::vector<std::string> &value)
{
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(NOT_IN, para1, para2, para3, TWO_COUNT);
    return this;
}

/**
 * BeginWrap
 */
DataSharePredicates *DataSharePredicates::BeginWrap()
{
    LOG_DEBUG("DataSharePredicates::BeginWrap Start");
    DataSharePredicatesObject para1;
    DataSharePredicatesObject para2;
    DataSharePredicatesObject para3;
    SetOperationList(BEGIN_WARP, para1, para2, para3, ZERO_COUNT);
    LOG_DEBUG("DataSharePredicates::BeginWrap End");
    return this;
}

/**
 * EndWrap
 */
DataSharePredicates *DataSharePredicates::EndWrap()
{
    LOG_DEBUG("DataSharePredicates::EndWrap Start");
    DataSharePredicatesObject para1;
    DataSharePredicatesObject para2;
    DataSharePredicatesObject para3;
    SetOperationList(END_WARP, para1, para2, para3, ZERO_COUNT);
    LOG_DEBUG("DataSharePredicates::EndWrap End");
    return this;
}

/**
 * Or
 */
DataSharePredicates *DataSharePredicates::Or()
{
    LOG_DEBUG("DataSharePredicates::Or Start");
    DataSharePredicatesObject para1;
    DataSharePredicatesObject para2;
    DataSharePredicatesObject para3;
    SetOperationList(OR, para1, para2, para3, ZERO_COUNT);
    LOG_DEBUG("DataSharePredicates::Or End");
    return this;
}

/**
 * And
 */
DataSharePredicates *DataSharePredicates::And()
{
    LOG_DEBUG("DataSharePredicates::And Start");
    DataSharePredicatesObject para1;
    DataSharePredicatesObject para2;
    DataSharePredicatesObject para3;
    SetOperationList(AND, para1, para2, para3, ZERO_COUNT);
    LOG_DEBUG("DataSharePredicates::And End");
    return this;
}

/**
 * Contains
 */
DataSharePredicates *DataSharePredicates::Contains(const std::string &field, const std::string &value)
{
    LOG_DEBUG("DataSharePredicates::Contains Start field%{public}s,value%{public}s",field.c_str(), value.c_str());
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(CONTAINS, para1, para2, para3,TWO_COUNT);
    LOG_DEBUG("DataSharePredicates::Contains End");
    return this;
}

/**
 * BeginsWith
 */
DataSharePredicates *DataSharePredicates::BeginsWith(const std::string &field, const std::string &value)
{
    LOG_DEBUG("DataSharePredicates::BeginsWith Start field%{public}s,value%{public}s",field.c_str(), value.c_str());
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(BEGIN_WITH, para1,para2, para3, TWO_COUNT);
    LOG_DEBUG("DataSharePredicates::BeginsWith End");
    return this;
}

/**
 * EndsWith
 */
DataSharePredicates *DataSharePredicates::EndsWith(const std::string &field, const std::string &value)
{
    LOG_DEBUG("DataSharePredicates::EndsWith Start field%{public}s,value%{public}s",field.c_str(), value.c_str());
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(END_WITH, para1, para2, para3, TWO_COUNT);
    LOG_DEBUG("DataSharePredicates::EndsWith End");
    return this;
}

/**
 * IsNull
 */
DataSharePredicates *DataSharePredicates::IsNull(const std::string &field)
{
    LOG_DEBUG("DataSharePredicates::IsNull Start field%{public}s",field.c_str());
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2;
    DataSharePredicatesObject para3;
    SetOperationList(IS_NULL, para1, para2, para3, ONE_COUNT);
    LOG_DEBUG("DataSharePredicates::IsNull End");
    return this;
}

/**
 * IsNotNull
 */
DataSharePredicates *DataSharePredicates::IsNotNull(const std::string &field)
{
    LOG_DEBUG("DataSharePredicates::IsNotNull Start field%{public}s",field.c_str());
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2;
    DataSharePredicatesObject para3;
    SetOperationList(IS_NOT_NULL, para1, para2, para3, ONE_COUNT);
    LOG_DEBUG("DataSharePredicates::IsNotNull End");
    return this;
}

/**
 * Like
 */
DataSharePredicates *DataSharePredicates::Like(const std::string &field, const std::string &value)
{
    LOG_DEBUG("DataSharePredicates::Like Start field%{public}s value%{public}s",field.c_str(), value.c_str());
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(LIKE, para1, para2, para3, TWO_COUNT);
    LOG_DEBUG("DataSharePredicates::Like End");
    return this;
}

/**
 * UnLike
 */
DataSharePredicates *DataSharePredicates::Unlike(const std::string &field, const std::string &value)
{
    LOG_DEBUG("DataSharePredicates::Unlike Start field%{public}s value%{public}s",field.c_str(), value.c_str());
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(UNLIKE, para1, para2, para3, TWO_COUNT);
    LOG_DEBUG("DataSharePredicates::Unlike End");
    return this;
}

/**
 * Glob
 */
DataSharePredicates *DataSharePredicates::Glob(const std::string &field, const std::string &value)
{
    LOG_DEBUG("DataSharePredicates::Glob Start field%{public}s value%{public}s",field.c_str(), value.c_str());
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(value);
    DataSharePredicatesObject para3;
    SetOperationList(GLOB, para1, para2, para3, TWO_COUNT);
    LOG_DEBUG("DataSharePredicates::Glob End");
    return this;
}

/**
 * Between
 */
DataSharePredicates *DataSharePredicates::Between(const std::string &field, const std::string &low, const std::string &high)
{
    LOG_DEBUG("DataSharePredicates::Between Start field%{public}s low%{public}s high%{public}s",field.c_str(), low.c_str(), high.c_str());
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(low);
    DataSharePredicatesObject para3(high);
    SetOperationList(BETWEEN, para1, para2, para3, THREE_COUNT);
    LOG_DEBUG("DataSharePredicates::Between End");
    return this;
}

/**
 * NotBetween
 */
DataSharePredicates *DataSharePredicates::NotBetween(const std::string &field, const std::string &low, const std::string &high)
{
    LOG_DEBUG("DataSharePredicates::NotBetween Start field%{public}s low%{public}s high%{public}s",field.c_str(), low.c_str(), high.c_str());
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2(low);
    DataSharePredicatesObject para3(high);
    SetOperationList(NOTBETWEEN, para1, para2, para3, THREE_COUNT);
    LOG_DEBUG("DataSharePredicates::NotBetween End");
    return this;
}

/**
 * OrderByAsc
 */
DataSharePredicates *DataSharePredicates::OrderByAsc(const std::string &field)
{
    LOG_DEBUG("DataSharePredicates::OrderByAsc Start field%{public}s",field.c_str());
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2;
    DataSharePredicatesObject para3;
    SetOperationList(ORDER_BY_ASC, para1, para2, para3, ONE_COUNT);
    LOG_DEBUG("DataSharePredicates::OrderByAsc End");
    return this;
}

/**
 * OrderByDesc
 */
DataSharePredicates *DataSharePredicates::OrderByDesc(const std::string &field)
{
    LOG_DEBUG("DataSharePredicates::OrderByDesc Start field%{public}s",field.c_str());
    DataSharePredicatesObject para1(field);
    DataSharePredicatesObject para2;
    DataSharePredicatesObject para3;
    SetOperationList(ORDER_BY_DESC, para1, para2, para3, ONE_COUNT);
    LOG_DEBUG("DataSharePredicates::OrderByDesc End");
    return this;
}

/**
 * Distinct
 */
DataSharePredicates *DataSharePredicates::Distinct()
{
    LOG_DEBUG("DataSharePredicates::Distinct Start");
    DataSharePredicatesObject para1;
    DataSharePredicatesObject para2;
    DataSharePredicatesObject para3;
    SetOperationList(DISTINCT, para1, para2, para3, ZERO_COUNT);
    LOG_DEBUG("DataSharePredicates::Distinct End");
    return this;
}

/**
 * Limit
 */
DataSharePredicates *DataSharePredicates::Limit(int value)
{
    LOG_DEBUG("DataSharePredicates::Limit Start value%{public}d",value);
    DataSharePredicatesObject para1(value);
    DataSharePredicatesObject para2;
    DataSharePredicatesObject para3;
    SetOperationList(LIMIT, para1, para2, para3, ONE_COUNT);
    LOG_DEBUG("DataSharePredicates::Limit End");
    return this;
}

/**
 * Offset
 */
DataSharePredicates *DataSharePredicates::Offset(int rowOffset)
{
    LOG_DEBUG("DataSharePredicates::Offset Start rowOffset%{public}d",rowOffset);
    DataSharePredicatesObject para1(rowOffset);
    DataSharePredicatesObject para2;
    DataSharePredicatesObject para3;
    SetOperationList(OFFSET, para1, para2, para3, ONE_COUNT);
    LOG_DEBUG("DataSharePredicates::Offset End");
    return this;
}

/**
 * GroupBy
 */
DataSharePredicates *DataSharePredicates::GroupBy(const std::vector<std::string> &fields)
{
    LOG_DEBUG("DataSharePredicates::GroupBy Start fields%{public}s",fields.at(0).c_str());
    DataSharePredicatesObject para1(fields);
    DataSharePredicatesObject para2;
    DataSharePredicatesObject para3;
    SetOperationList(GROUP_BY, para1, para2, para3, ONE_COUNT);
    LOG_DEBUG("DataSharePredicates::GroupBy End");
    return this;
}

/**
 * IndexedBy
 */
DataSharePredicates *DataSharePredicates::IndexedBy(const std::string &indexName)
{
    LOG_DEBUG("DataSharePredicates::IndexedBy Start indexName%{public}s",indexName.c_str());
    DataSharePredicatesObject para1(indexName);
    DataSharePredicatesObject para2;
    DataSharePredicatesObject para3;
    SetOperationList(INDEXED_BY, para1, para2, para3, ONE_COUNT);
    LOG_DEBUG("DataSharePredicates::IndexedBy End");
    return this;
}

/**
 * KeyPrefix
 */
DataSharePredicates *DataSharePredicates::KeyPrefix(const std::string &prefix)
{
    LOG_DEBUG("DataSharePredicates::KeyPrefix Start prefix%{public}s",prefix.c_str());
    DataSharePredicatesObject para1(prefix);
    DataSharePredicatesObject para2;
    DataSharePredicatesObject para3;
    SetOperationList(KEY_PREFIX, para1, para2, para3, ONE_COUNT);
    LOG_DEBUG("DataSharePredicates::KeyPrefix End");
    return this;
}

/**
 * InDevices
 */
DataSharePredicates *DataSharePredicates::InDevices(const std::vector<std::string> &devices)
{
    LOG_DEBUG("DataSharePredicates::InDevices Start prefix%{public}s",devices.at(0).c_str());
    DataSharePredicatesObject para1(devices);
    DataSharePredicatesObject para2;
    DataSharePredicatesObject para3;
    SetOperationList(IN_DEVICES, para1, para2, para3, ONE_COUNT);
    LOG_DEBUG("DataSharePredicates::InDevices End");
    return this;
}

/**
 * InAllDevices
 */
DataSharePredicates *DataSharePredicates::InAllDevices()
{
    LOG_DEBUG("DataSharePredicates::InAllDevices Start");
    DataSharePredicatesObject para1;
    DataSharePredicatesObject para2;
    DataSharePredicatesObject para3;
    SetOperationList(IN_ALL_DEVICES, para1, para2, para3, ZERO_COUNT);
    LOG_DEBUG("DataSharePredicates::InAllDevices End");
    return this;
}

/**
 * SetSuggestIndex
 */
DataSharePredicates *DataSharePredicates::SetSuggestIndex(const std::string &index)
{
    LOG_DEBUG("DataSharePredicates::SetSuggestIndex Start index%{public}s",index.c_str());
    DataSharePredicatesObject para1(index);
    DataSharePredicatesObject para2;
    DataSharePredicatesObject para3;
    SetOperationList(SET_SUGGEST_INDEX, para1, para2, para3, ONE_COUNT);
    LOG_DEBUG("DataSharePredicates::SetSuggestIndex End");
    return this;
}

/**
 * InKeys
 */
DataSharePredicates *DataSharePredicates::InKeys(const std::vector<std::string> &keys)
{
    LOG_DEBUG("DataSharePredicates::InKeys Start keys%{public}s",keys.at(0).c_str());
    DataSharePredicatesObject para1(keys);
    DataSharePredicatesObject para2;
    DataSharePredicatesObject para3;
    SetOperationList(IN_KEY, para1, para2, para3, ONE_COUNT);
    LOG_DEBUG("DataSharePredicates::InKeys End");
    return this;		
}

/**
 * GetOperationList
 */
const std::list<OperationItem>& DataSharePredicates::GetOperationList() const
{
    return operationList_;
}

/**
 * SetOperationList
 */
void DataSharePredicates::SetOperationList(OperationType operationType, DataSharePredicatesObject &para1,
                                           DataSharePredicatesObject &para2,DataSharePredicatesObject &para3,
                                           ParameterCount parameterCount)
{
    LOG_DEBUG("DataSharePredicates::SetOperationList Start");
    OperationItem operationItem{};
    operationItem.operation = operationType;
    operationItem.para1 = para1;
    operationItem.para2 = para2;
    operationItem.para3 = para3;
    operationItem.parameterCount = parameterCount;
    operationList_.push_back(operationItem);
    LOG_DEBUG("DataSharePredicates::SetOperationList END");
}

/**
 * Write DataSharePredicates object to Parcel.
 */
bool DataSharePredicates::Marshalling(OHOS::Parcel &parcel) const
{
    LOG_DEBUG("DataSharePredicates::Marshalling Start");
    parcel.WriteInt32(operationList_.size());
    for (auto &it : operationList_) {
        parcel.WriteInt64(static_cast<int64_t>(it.operation));
        parcel.WriteParcelable(&it.para1);
        parcel.WriteParcelable(&it.para2);
        parcel.WriteParcelable(&it.para3);
        parcel.WriteInt64(static_cast<int64_t>(it.parameterCount));
    }
    LOG_DEBUG("DataSharePredicates::Marshalling End");
    return true;
}

/**
 * Read from Parcel object.
 */
DataSharePredicates* DataSharePredicates::Unmarshalling(OHOS::Parcel &parcel)
{
    LOG_DEBUG("DataSharePredicates::Unmarshalling Start");
    int listSize = parcel.ReadInt32();
    OperationItem listitem{};
    std::list<OperationItem> operationList{};
    for (int i = 0; i < listSize; i++) {
        listitem.operation = static_cast<OperationType>(parcel.ReadInt64());
        DataSharePredicatesObject *parameter1 = parcel.ReadParcelable<DataSharePredicatesObject>();
        listitem.para1 = *parameter1;
        DataSharePredicatesObject *parameter2 = parcel.ReadParcelable<DataSharePredicatesObject>();
        listitem.para2 = *parameter2;
        DataSharePredicatesObject *parameter3 = parcel.ReadParcelable<DataSharePredicatesObject>();
        listitem.para3 = *parameter3;
        listitem.parameterCount = static_cast<ParameterCount>(parcel.ReadInt64());
        operationList.push_back(listitem);
        LOG_DEBUG("DataSharePredicates::Unmarshalling End");
    }
    return new DataSharePredicates(operationList);
}
} // namespace DataShare
} // namespace OHOS
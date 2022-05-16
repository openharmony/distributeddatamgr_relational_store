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
#include "datashare_block_writer_impl.h"
#include "datashare_log.h"
#include "datashare_errno.h"

namespace OHOS {
namespace DataShare {
DataShareBlockWriterImpl::DataShareBlockWriterImpl() : shareBlock_(nullptr)
{
}

DataShareBlockWriterImpl::DataShareBlockWriterImpl(const std::string &name, size_t size)
    : shareBlock_(nullptr)
{
    AppDataFwk::SharedBlock::Create(name, size, shareBlock_);
}

DataShareBlockWriterImpl::~DataShareBlockWriterImpl()
{
}

int DataShareBlockWriterImpl::Clear()
{
    if (shareBlock_ == nullptr) {
        LOG_INFO("DataShareBlockWriterImpl::Clear shareBlock_ is nullptr");
        return E_ERROR;
    }
    return shareBlock_->Clear();
}

int DataShareBlockWriterImpl::SetColumnNum(uint32_t numColumns)
{
    if (shareBlock_ == nullptr) {
        LOG_INFO("DataShareBlockWriterImpl::SetColumnNum shareBlock_ is nullptr");
        return E_ERROR;
    }
    return shareBlock_->SetColumnNum(numColumns);
}

int DataShareBlockWriterImpl::AllocRow()
{
    if (shareBlock_ == nullptr) {
        LOG_INFO("DataShareBlockWriterImpl::AllocRow shareBlock_ is nullptr");
        return E_ERROR;
    }
    return shareBlock_->AllocRow();
}

int DataShareBlockWriterImpl::FreeLastRow()
{
    if (shareBlock_ == nullptr) {
        LOG_INFO("DataShareBlockWriterImpl::FreeLastRow shareBlock_ is nullptr");
        return E_ERROR;
    }
    return shareBlock_->FreeLastRow();
}

int DataShareBlockWriterImpl::WriteBlob(uint32_t row, uint32_t column, const void *value, size_t size)
{
    if (shareBlock_ == nullptr) {
        LOG_INFO("DataShareBlockWriterImpl::WriteBlob shareBlock_ is nullptr");
        return E_ERROR;
    }
    return shareBlock_->PutBlob(row - posOffset_, column, value, size);
}

int DataShareBlockWriterImpl::WriteString(uint32_t row, uint32_t column, const char *value, size_t sizeIncludingNull)
{
    if (shareBlock_ == nullptr) {
        LOG_INFO("DataShareBlockWriterImpl::WriteString shareBlock_ is nullptr");
        return E_ERROR;
    }
    return shareBlock_->PutString(row - posOffset_, column, value, sizeIncludingNull);
}

int DataShareBlockWriterImpl::WriteLong(uint32_t row, uint32_t column, int64_t value)
{
    if (shareBlock_ == nullptr) {
        LOG_INFO("DataShareBlockWriterImpl::WriteLong shareBlock_ is nullptr");
        return E_ERROR;
    }
    return shareBlock_->PutLong(row - posOffset_, column, value);
}

int DataShareBlockWriterImpl::WriteDouble(uint32_t row, uint32_t column, double value)
{
    if (shareBlock_ == nullptr) {
        LOG_INFO("DataShareBlockWriterImpl::WriteDouble shareBlock_ is nullptr");
        return E_ERROR;
    }
    return shareBlock_->PutDouble(row - posOffset_, column, value);
}

int DataShareBlockWriterImpl::WriteNull(uint32_t row, uint32_t column)
{
    if (shareBlock_ == nullptr) {
        LOG_INFO("DataShareBlockWriterImpl::WriteNull shareBlock_ is nullptr");
        return E_ERROR;
    }
    return shareBlock_->PutNull(row - posOffset_, column);
}

const void *DataShareBlockWriterImpl::GetHeader()
{
    if (shareBlock_ == nullptr) {
        LOG_INFO("DataShareBlockWriterImpl::GetHeader shareBlock_ is nullptr");
        return nullptr;
    }
    return shareBlock_->GetHeader();
}

size_t DataShareBlockWriterImpl::GetUsedBytes()
{
    if (shareBlock_ == nullptr) {
        LOG_INFO("DataShareBlockWriterImpl::GetUsedBytes shareBlock_ is nullptr");
        return E_ERROR;
    }
    return shareBlock_->GetUsedBytes();
}

std::string DataShareBlockWriterImpl::Name()
{
    if (shareBlock_ == nullptr) {
        LOG_INFO("DataShareBlockWriterImpl::Name shareBlock_ is nullptr");
    }
    return shareBlock_->Name();
}

size_t DataShareBlockWriterImpl::Size()
{
    if (shareBlock_ == nullptr) {
        LOG_INFO("DataShareBlockWriterImpl::Size shareBlock_ is nullptr");
        return E_ERROR;
    }
    return shareBlock_->Size();
}

uint32_t DataShareBlockWriterImpl::GetRowNum()
{
    if (shareBlock_ == nullptr) {
        LOG_INFO("DataShareBlockWriterImpl::GetRowNum shareBlock_ is nullptr");
        return E_ERROR;
    }
    return shareBlock_->GetRowNum();
}

uint32_t DataShareBlockWriterImpl::GetColumnNum()
{
    if (shareBlock_ == nullptr) {
        LOG_INFO("DataShareBlockWriterImpl::GetColumnNum shareBlock_ is nullptr");
        return E_ERROR;
    }
    return shareBlock_->GetColumnNum();
}

size_t DataShareBlockWriterImpl::SetRawData(const void *rawData, size_t size)
{
    if (shareBlock_ == nullptr) {
        LOG_INFO("DataShareBlockWriterImpl::SetRawData shareBlock_ is nullptr");
        return E_ERROR;
    }
    return shareBlock_->SetRawData(rawData, size);
}

int DataShareBlockWriterImpl::GetFd()
{
    if (shareBlock_ == nullptr) {
        LOG_INFO("DataShareBlockWriterImpl::GetFd shareBlock_ is nullptr");
        return E_ERROR;
    }
    return shareBlock_->GetFd();
}

AppDataFwk::SharedBlock *DataShareBlockWriterImpl::GetBlock() const
{
    return shareBlock_;
}
} // namespace DataShare
} // namespace OHOS

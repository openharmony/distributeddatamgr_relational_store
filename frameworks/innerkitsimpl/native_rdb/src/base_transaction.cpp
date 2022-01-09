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

#include "base_transaction.h"

namespace OHOS{
namespace NativeRdb{

Transaction::Transaction(int ids)
    : allBeforeSuccessful(true), markedSuccessful(false), childFailure(false), type(ROLLBACK_SELF), id(ids)
{
}

Transaction::~Transaction()
{
}

bool Transaction::IsAllBeforeSuccessful() const
{
    return allBeforeSuccessful;
}

void Transaction::SetAllBeforeSuccessful(bool allBeforeSuccessful)
{
    this->allBeforeSuccessful = allBeforeSuccessful;
}
bool Transaction::IsMarkedSuccessful() const
{
    return markedSuccessful;
}
void Transaction::SetMarkedSuccessful(bool markedSuccessful)
{
    this->markedSuccessful = markedSuccessful;
}

int Transaction::getType() const
{
    return type;
}

bool Transaction::IsChildFailure() const
{
    return childFailure;
}

void Transaction::setChildFailure(bool failureFlag)
{
    this->childFailure = failureFlag;
}

std::string Transaction:: getTransactionStr()
{
    std::string retStr = this->id == 0 ? BEGIN_IMMEDIATE : SAVE_POINT + " " + TRANS_STR + std::to_string(this->id);
    return retStr + ";";
}

std::string Transaction:: getCommitStr()
{
    std::string retStr = this->id == 0 ? COMMIT : "";
    return retStr + ";";
}

std::string Transaction:: getRollbackStr()
{
    std::string retStr = this->id == 0 ? ROLLBACK : ROLLBACK_TO + " " + TRANS_STR + std::to_string(this->id);
    return retStr + ";";
}

}
}
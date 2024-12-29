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
#ifndef OHOS_DISTRIBUTED_DATA_GDB_JS_NAPI_ERROR_H
#define OHOS_DISTRIBUTED_DATA_GDB_JS_NAPI_ERROR_H

#include <map>
#include <optional>
#include <string>
#include <utility>

#include "logger.h"

namespace OHOS::GraphStoreJsKit {
constexpr int MAX_INPUT_COUNT = 10;
constexpr int OK = 0;
constexpr int ERR = -1;

constexpr int E_NON_SYSTEM_APP_ERROR = 202;
constexpr int E_PARAM_ERROR = 401;
constexpr int E_INNER_ERROR = 31300000;

struct JsErrorCode {
    int32_t status;
    int32_t jsCode;
    std::string_view message;
};
std::optional<JsErrorCode> GetJsErrorCode(int32_t errorCode);

#define GDB_REVT_NOTHING
#define GDB_DO_NOTHING

#define GDB_NAPI_ASSERT_BASE(env, assertion, error, retVal)                                                     \
    do {                                                                                                        \
        if (!(assertion)) {                                                                                     \
            if ((error) == nullptr) {                                                                           \
                LOG_ERROR("throw error: error message is empty");                                               \
                napi_throw_error((env), nullptr, "error message is empty");                                     \
                return retVal;                                                                                  \
            }                                                                                                   \
            LOG_ERROR("throw error: code = %{public}d , message = %{public}s", (error)->GetCode(),              \
                (error)->GetMessage().c_str());                                                                 \
            napi_throw_error((env), std::to_string((error)->GetCode()).c_str(), (error)->GetMessage().c_str()); \
            return retVal;                                                                                      \
        }                                                                                                       \
    } while (0)

#define GDB_NAPI_ASSERT(env, assertion, error) GDB_NAPI_ASSERT_BASE(env, assertion, error, nullptr)

#define CHECK_RETURN_CORE(assertion, theCall, revt) \
    do {                                            \
        if (!(assertion)) {                         \
            theCall;                                \
            return revt;                            \
        }                                           \
    } while (0)

#define CHECK_RETURN_SET_E(assertion, paramError) \
    CHECK_RETURN_CORE(assertion, context->SetError(paramError), GDB_REVT_NOTHING)

#define CHECK_RETURN_SET(assertion, paramError) CHECK_RETURN_CORE(assertion, context->SetError(paramError), ERR)

#define CHECK_RETURN_NULL(assertion) CHECK_RETURN_CORE(assertion, GDB_REVT_NOTHING, nullptr)

#define CHECK_RETURN_ERR(assertion) CHECK_RETURN_CORE(assertion, GDB_REVT_NOTHING, ERR)

#define CHECK_RETURN(assertion) CHECK_RETURN_CORE(assertion, GDB_REVT_NOTHING, GDB_REVT_NOTHING)

class Error {
public:
    virtual ~Error() = default;
    virtual std::string GetMessage() = 0;
    virtual int GetCode() = 0;
};

class InnerError : public Error {
public:
    explicit InnerError(int code)
    {
        auto errorMsg = GetJsErrorCode(code);
        if (errorMsg.has_value()) {
            const auto &napiError = errorMsg.value();
            code_ = napiError.jsCode;
            msg_ = napiError.message;
        } else {
            code_ = E_INNER_ERROR;
            msg_ = "Inner error. Inner code is " + std::to_string(code % E_INNER_ERROR);
        }
    }

    explicit InnerError(const std::string &msg)
    {
        code_ = E_INNER_ERROR;
        msg_ = std::string("Inner error. ") + msg;
    }

    std::string GetMessage() override
    {
        return msg_;
    }

    int GetCode() override
    {
        return code_;
    }

private:
    int code_;
    std::string msg_;
};

class ParamError : public Error {
public:
    ParamError(const std::string &needed, const std::string &mustbe)
    {
        msg_ = "Parameter error. The " + needed + " must be " + mustbe;
    };

    explicit ParamError(const std::string &errMsg)
    {
        msg_ = "Parameter error." + errMsg;
    }

    std::string GetMessage() override
    {
        return msg_;
    };

    int GetCode() override
    {
        return E_PARAM_ERROR;
    };

private:
    std::string msg_;
};

class NonSystemError : public Error {
public:
    NonSystemError() = default;
    std::string GetMessage() override
    {
        return "Permission verification failed, application which is not a system application uses system API.";
    }
    int GetCode() override
    {
        return E_NON_SYSTEM_APP_ERROR;
    }
};

class ParamNumError : public Error {
public:
    explicit ParamNumError(std::string wantNum) : wantNum(std::move(wantNum)) {};
    std::string GetMessage() override
    {
        return "Parameter error. Need " + wantNum + " parameter(s)!";
    };
    int GetCode() override
    {
        return E_PARAM_ERROR;
    };

private:
    std::string wantNum;
};
} // namespace OHOS::GraphStoreJsKit

#endif // GDB_JS_NAPI_ERROR_H
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
#ifndef RDB_JS_NAPI_ERROR_H
#define RDB_JS_NAPI_ERROR_H

#include <map>
#include <optional>
#include <string>
#include "logger.h"
#include "rdb_errno.h"

namespace OHOS {
namespace RelationalStoreJsKit {
constexpr int MAX_INPUT_COUNT = 10;
constexpr int OK = 0;
constexpr int ERR = -1;

constexpr int E_NON_SYSTEM_APP_ERROR = 202;
constexpr int E_PARAM_ERROR = 401;
constexpr int E_INNER_ERROR = 14800000;
constexpr int E_NOT_STAGE_MODE = 14801001;
constexpr int E_DATA_GROUP_ID_INVALID = 14801002;

struct JsErrorCode {
    int32_t status;
    int32_t jsCode;
    const char *message;
};
const std::optional<JsErrorCode> GetJsErrorCode(int32_t errorCode);

#define ASSERT(condition, message, retVal)                             \
    do {                                                               \
        if (!(condition)) {                                            \
            LOG_ERROR("test (" #condition ") failed: " message);       \
            return retVal;                                             \
        }                                                              \
    } while (0)

#define RDB_REVT_NOTHING
#define RDB_DO_NOTHING

#define RDB_NAPI_ASSERT_BASE(env, assertion, error, retVal)                                                 \
    do {                                                                                                    \
        if (!(assertion)) {                                                                                 \
            if ((error) == nullptr) {                                                                       \
                LOG_ERROR("throw error: error message is empty");                                           \
                napi_throw_error((env), nullptr, "error message is empty");                                 \
                return retVal;                                                                              \
            }                                                                                               \
            LOG_ERROR("throw error: code = %{public}d , message = %{public}s", (error)->GetCode(),            \
                (error)->GetMessage().c_str());                                                               \
            napi_throw_error((env), std::to_string((error)->GetCode()).c_str(), (error)->GetMessage().c_str()); \
            return retVal;                                                                                  \
        }                                                                                                   \
    } while (0)

#define RDB_NAPI_ASSERT(env, assertion, error) \
    RDB_NAPI_ASSERT_BASE(env, assertion, error, nullptr)

#define CHECK_RETURN_CORE(assertion, theCall, revt)      \
    do {                                                 \
        if (!(assertion)) {                              \
            theCall;                                     \
            return revt;                                 \
        }                                                \
    } while (0)

#define CHECK_RETURN_SET_E(assertion, paramError) \
    CHECK_RETURN_CORE(assertion, context->SetError(paramError), RDB_REVT_NOTHING)

#define CHECK_RETURN_SET(assertion, paramError) \
    CHECK_RETURN_CORE(assertion, context->SetError(paramError), ERR)

#define CHECK_RETURN_NULL(assertion) \
    CHECK_RETURN_CORE(assertion, RDB_REVT_NOTHING, nullptr)

#define CHECK_RETURN_ERR(assertion) \
    CHECK_RETURN_CORE(assertion, RDB_REVT_NOTHING, ERR)

#define CHECK_RETURN(assertion) \
    CHECK_RETURN_CORE(assertion, RDB_REVT_NOTHING, RDB_REVT_NOTHING)

class Error {
public:
    virtual ~Error(){};
    virtual std::string GetMessage() = 0;
    virtual int GetCode() = 0;
};

class InnerError : public Error {
public:
    InnerError(int code)
    {
        auto errorMsg = GetJsErrorCode(code);
        if (errorMsg.has_value()) {
            auto napiError = errorMsg.value();
            code_ = napiError.jsCode;
            msg_ = napiError.message;
        } else {
            code_ = E_INNER_ERROR;
            msg_ = "Inner error. Inner code is " + std::to_string(code % E_INNER_ERROR);
        }
    }

    InnerError(const std::string &msg)
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

    ParamError(const std::string &errMsg)
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
    NonSystemError()
    {
    }
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
    ParamNumError(const std::string &wantNum) : wantNum(wantNum){};
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
} // namespace RelationalStoreJsKit
} // namespace OHOS

#endif // RDB_JS_NAPI_ERROR_H

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

#include "js_logger.h"
#include "rdb_visibility.h"

namespace OHOS {
namespace AppDataMgrJsKit {
constexpr int MAX_INPUT_COUNT = 10;
constexpr int OK = 0;
constexpr int ERR = -1;
constexpr int APIVERSION_V9 = 9;
constexpr int APIVERSION_8 = 8;

constexpr int E_PARAM_ERROR = 401;

constexpr int E_INNER_ERROR = 14800000;

constexpr int E_DB_INVALID = 14800010;
constexpr int E_DB_CORRUPTED = 14800011;
constexpr int E_RESULT_GET_ERROR = 14800013;
constexpr int E_RESULT_GOTO_ERROR = 14800012;

#define RDB_NAPI_ASSERT_BASE_FROMV9(env, assertion, error, retVal, version)                                     \
    do {                                                                                                        \
        if (!(assertion)) {                                                                                     \
            if ((error) == nullptr) {                                                                           \
                LOG_ERROR("throw error: error message is empty,version= %{public}d", version);                  \
                napi_throw_error((env), nullptr, "error message is empty");                                     \
                return retVal;                                                                                  \
            }                                                                                                   \
            if (((version) > (APIVERSION_8)) || ((error->GetCode()) == (401))) {                               \
                LOG_ERROR("throw error: code = %{public}d , message = %{public}s, version= %{public}d",         \
                    error->GetCode(), error->GetMessage().c_str(), version);                                    \
                napi_throw_error((env), std::to_string(error->GetCode()).c_str(), error->GetMessage().c_str()); \
                return retVal;                                                                                  \
            }                                                                                                   \
            LOG_ERROR("nothrow error: code = %{public}d , message = %{public}s, version= %{public}d",           \
                error->GetCode(), error->GetMessage().c_str(), version);                                        \
        }                                                                                                       \
    } while (0)

#define RDB_NAPI_ASSERT_FROMV9(env, assertion, error, version) \
    RDB_NAPI_ASSERT_BASE_FROMV9(env, assertion, error, nullptr, version)

#define RDB_NAPI_ASSERT_RETURN_VOID_FROMV9(env, assertion, error, version) \
    RDB_NAPI_ASSERT_BASE_FROMV9(env, assertion, error, NAPI_RETVAL_NOTHING, version)

#define RDB_ASYNC_PARAM_CHECK_FUNCTION(theCall) \
    do {                                        \
        int err = (theCall);                    \
        if (err != OK) {                        \
            return err;                         \
        }                                       \
    } while (0)

#define RDB_CHECK_RETURN_NULLPTR(assertion) \
    do {                                    \
        if (!(assertion)) {                 \
            return nullptr;                 \
        }                                   \
    } while (0)

#define RDB_CHECK_RETURN_CALL_RESULT(assertion, theCall) \
    do {                                                 \
        if (!(assertion)) {                              \
            (theCall);                                   \
            return ERR;                                  \
        }                                                \
    } while (0)

class API_EXPORT Error {
public:
    API_EXPORT virtual ~Error(){};
    virtual std::string GetMessage() = 0;
    virtual int GetCode() = 0;
};

class API_EXPORT InnerError : public Error {
public:
    API_EXPORT InnerError() = default;
    API_EXPORT std::string GetMessage() override
    {
        return "System error.";
    };
    API_EXPORT int GetCode() override
    {
        return E_INNER_ERROR;
    };
};

class API_EXPORT ParamTypeError : public Error {
public:
    API_EXPORT ParamTypeError(const std::string &name, const std::string &wantType) : name(name), wantType(wantType){};
    API_EXPORT std::string GetMessage() override
    {
        return "Parameter error. The type of '" + name + "' must be " + wantType;
    };
    API_EXPORT int GetCode() override
    {
        return E_PARAM_ERROR;
    };

private:
    std::string name;
    std::string wantType;
};

class API_EXPORT ParamNumError : public Error {
public:
    API_EXPORT ParamNumError(const std::string &wantNum) : wantNum(wantNum){};
    API_EXPORT std::string GetMessage() override
    {
        return "Parameter error. Need " + wantNum + " parameters!";
    };
    API_EXPORT int GetCode() override
    {
        return E_PARAM_ERROR;
    };

private:
    std::string wantNum;
};

class API_EXPORT DbInvalidError : public Error {
public:
    API_EXPORT DbInvalidError() = default;
    API_EXPORT std::string GetMessage() override
    {
        return "Failed open database, invalid database name.";
    };
    API_EXPORT int GetCode() override
    {
        return E_DB_INVALID;
    };
};

class API_EXPORT DbCorruptedError : public Error {
public:
    API_EXPORT DbCorruptedError() = default;
    API_EXPORT std::string GetMessage() override
    {
        return "Failed open database, database corrupted.";
    };
    API_EXPORT int GetCode() override
    {
        return E_DB_CORRUPTED;
    };
};

class API_EXPORT ResultGetError : public Error {
public:
    API_EXPORT ResultGetError() = default;
    API_EXPORT std::string GetMessage() override
    {
        return "The column value is null or the column type is incompatible.";
    };
    API_EXPORT int GetCode() override
    {
        return E_RESULT_GET_ERROR;
    };
};

class API_EXPORT ResultGotoError : public Error {
public:
    API_EXPORT ResultGotoError() = default;
    API_EXPORT std::string GetMessage() override
    {
        return "The result set is empty or the specified location is invalid.";
    };
    API_EXPORT int GetCode() override
    {
        return E_RESULT_GOTO_ERROR;
    };
};
} // namespace AppDataMgrJsKit
} // namespace OHOS

#endif // RDB_JS_NAPI_ERROR_H

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

#ifndef PREFERENCES_VALUE_H
#define PREFERENCES_VALUE_H

#include <string>
#include <variant>
#include <vector>

namespace OHOS {
namespace NativePreferences {
class PreferencesValue {
public:
    ~PreferencesValue()
    {
    }

    PreferencesValue(PreferencesValue &&preferencesValue) noexcept;
    PreferencesValue(const PreferencesValue &preferencesValue);

    PreferencesValue(int value);
    PreferencesValue(int64_t value);
    PreferencesValue(float value);
    PreferencesValue(double value);
    PreferencesValue(bool value);
    PreferencesValue(std::string value);
    PreferencesValue(const char *value);
    PreferencesValue(std::vector<double> value);
    PreferencesValue(std::vector<std::string> value);
    PreferencesValue(std::vector<bool> value);
    PreferencesValue &operator=(PreferencesValue &&preferencesValue) noexcept;
    PreferencesValue &operator=(const PreferencesValue &preferencesValue);

    bool IsInt() const;
    bool IsLong() const;
    bool IsFloat() const;
    bool IsDouble() const;
    bool IsBool() const;
    bool IsString() const;
    bool IsStringArray() const;
    bool IsBoolArray() const;
    bool IsDoubleArray() const;

    operator int() const;
    operator float() const;
    operator double() const;
    operator bool() const;
    operator int64_t() const;
    operator std::string() const;
    operator std::vector<double>() const;
    operator std::vector<bool>() const;
    operator std::vector<std::string>() const;

    bool operator==(const PreferencesValue &value);

private:
    std::variant<int, int64_t, float, double, bool, std::string, std::vector<std::string>, std::vector<bool>,
        std::vector<double>>
        value_;
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // End of #ifndef PREFERENCES_VALUE_H

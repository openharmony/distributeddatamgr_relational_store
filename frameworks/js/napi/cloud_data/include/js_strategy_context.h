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

#ifndef CLOUD_DATA_JS_STRATEGY_CONTEXT_H
#define CLOUD_DATA_JS_STRATEGY_CONTEXT_H

#include <cmath>
#include <string>
#include <vector>

#include "cloud_types.h"
#include "common_types.h"
#include "js_cloud_utils.h"
#include "js_error_utils.h"
#include "napi_queue.h"

namespace OHOS {
namespace CloudData {
struct CloudStrategyContext : public ContextBase {
    Strategy strategy;
    std::vector<CommonType::Value> param;
    void SetDefault()
    {
        switch (strategy) {
            case Strategy::STRATEGY_NETWORK:
                param = {};
                return;
            default:
                param = {};
                return;
        }
    }

    std::pair<Status, std::string> CheckParam()
    {
        switch (strategy) {
            case Strategy::STRATEGY_NETWORK:
                if (!ConvertNetworkParam()) {
                    return { Status::INVALID_ARGUMENT, "member of param must be of type NetWorkStrategy" };
                }
                break;
            default:
                return { Status::ERROR, "strategy must be of type StrategyType" };
        }
        return { Status::SUCCESS, "" };
    }

private:
    bool ConvertNetworkParam()
    {
        std::vector<CommonType::Value> tmp = { 0 };
        for (auto &value : param) {
            if (std::get_if<double>(&value) == nullptr) {
                return false;
            }
            auto val = static_cast<int64_t>(std::round(std::get<double>(value)));
            if (val < 0 || val > NetWorkStrategy::NETWORK_STRATEGY_BUTT) {
                return false;
            }
            tmp.push_back(val);
        }
        param = tmp;
        return true;
    }
};
}
}
#endif //CLOUD_DATA_JS_STRATEGY_CONTEXT_H

//
// Created by HuTao on 2024/3/12.
//

#ifndef CLOUD_DATA_JS_STRATEGY_CONTEXT_H
#define CLOUD_DATA_JS_STRATEGY_CONTEXT_H

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
                param = { NetWorkStrategy::WIFI, NetWorkStrategy::CELLULAR };
            default:
                param = {};
        }
    }

    std::pair<Status, std::string> CheckParam()
    {
        switch (strategy) {
            case Strategy::STRATEGY_NETWORK:
                if (!CheckNetWorkParam()) {
                    return { Status::INVALID_ARGUMENT, "member of param must be of type NetWorkStrategy" };
                }
                break;
            default:
                return { Status::ERROR, "strategy must be of type StrategyType" };
        }
        return { Status::SUCCESS, "" };
    }

private:
    bool CheckNetWorkParam()
    {
        for (auto &value : param) {
            if (std::get_if<int64_t>(&value) == nullptr) {
                return false;
            }
        }
        return true;
    }
};
}
}
#endif //CLOUD_DATA_JS_STRATEGY_CONTEXT_H

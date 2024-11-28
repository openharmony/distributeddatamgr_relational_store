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

#ifndef DISTRIBUTEDDATAMGR_RDB_RADAR_REPORTER_H
#define DISTRIBUTEDDATAMGR_RDB_RADAR_REPORTER_H

#include <mutex>
#include <string>
namespace OHOS::NativeRdb {

enum Scene : int {
    SCENE_SYNC = 1,
};

enum State : int {
    STATE_START = 1,
    STATE_FINISH = 2,
};

enum SyncStage : int {
    SYNC_STAGE_RUN = 1,
};

enum StageRes : int {
    RES_IDLE = 0,
    RES_SUCCESS = 1,
    RES_FAILED = 2,
    RES_CANCELLED = 3,
    RES_UNKNOW = 4,
};

class RdbRadar {
public:
    RdbRadar(Scene scene, const char *funcName, std::string bundleName);
    ~RdbRadar();

    RdbRadar &operator=(int x);
    operator int() const;

private:
    int errCode_{ 0 };
    Scene scene_;
    const char *funcName_;
    std::string bundleName_;

    static std::string hostPkg_;
    static std::mutex mutex_;

    void LocalReport(int bizSence, const char *funcName, int state, int errCode = 0);
    std::string GetHostPkgInfo();
};
} // namespace OHOS::NativeRdb
#endif //DISTRIBUTEDDATAMGR_RDB_RADAR_REPORTER_H

#define LOG_TAG "CloudDataConstructor"
#include "ohos.data.cloudData.ani.hpp"
#include "logger.h"
using namespace OHOS::Rdb;

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        return ANI_ERROR;
    }
    ani_status status = ANI_OK;
    if (ANI_OK != ohos::data::cloudData::ANIRegister(env)) {
        LOG_INFO("Error from ohos::data::cloudData::ANIRegister");
        status = ANI_ERROR;
    }
    *result = ANI_VERSION_1;
    return status;
}

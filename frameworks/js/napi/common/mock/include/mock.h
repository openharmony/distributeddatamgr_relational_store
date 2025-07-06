#ifndef SEND_EVENT_H
#define SEND_EVENT_H
#include <functional>
#include "event_handler.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "uv.h"

napi_status SendEventMock(napi_env env,
                        const std::function<void()>& cb,
                        napi_event_priority priority,
                        const char* name);
#endif //MAC_NAPI_H
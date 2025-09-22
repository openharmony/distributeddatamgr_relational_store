#ifndef HANDLE_MANAGER_H
#define HANDLE_MANAGER_H

#include
#include
#include
#include "rdb_store.h"
#include "rdb_types.h"

namespace OHOS {
namespace NativeRdb {

class HandleManager {
public:
    API_EXPORT static HandleManager &GetInstance();
    ~HandleManager() = default;

    API_EXPORT int Register(RdbStoreConfig rdbStoreConfig, std::shared_ptr<CorruptHandler> corruptHandler);
    API_EXPORT int Unregister(const std::string &path);
    API_EXPORT std::shared_ptr<CorruptHandler> GetHandler(const std::string &path);
    static void HandleCorrupt(const RdbStoreConfig &config);

private:
    HandleManager() = default;
    HandleManager(const HandleManager &) = delete;
    HandleManager &operator=(const HandleManager &) = delete;
    std::map<std::string, std::shared_ptr> handlers_;
    std::mutex mutex_;
};

} // namespace NativeRdb
} // namespace OHOS

#endif // HANDLE_MANAGER_H
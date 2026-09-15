# 核心数据存储数据保护措施（Inner API）

<!--Kit: ArkData-->
<!--Subsystem: DistributedDataManager-->
<!--Component: relational_store-->
<!--类型: C++ Inner API（非应用开放 API，仅供 OpenHarmony 模块间使用）-->

> **说明**
> - 本组文档面向 OpenHarmony **系统模块开发者**，描述 relational_store 核心数据存储的**数据保护措施**，聚焦 SA 在本地配置库场景下的异常打点归因、进程隔离与完整性校验能力。
> - 应用开发者请使用 [ArkTS RdbStore](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-arkdata/arkts-apis-data-relationalStore-RdbStore.md) 或 [NDK OH_Rdb_Store](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-arkdata/capi-rdb-oh-rdb-store.md)。
> - **文档策略**：JS 公共文档已覆盖的接口不在此重复，仅文档 JS 侧没有的 native 专有接口，并给出默认值、调用方式、适用场景与代码示例。

## 概述

本文档聚焦 relational_store inner API 在**数据保护措施**方面的 native 专有能力。SA（系统服务）在使用本地配置库时，需通过 `SetBundleName` 设置打点标识，实现异常归因与责任方定位；配合 `SetLocalOnly` 实现进程隔离、`SetIntegrityCheck` 实现开库完整性校验，构成完整的数据保护链路。

当前覆盖的数据保护措施场景：

| 场景 | 核心接口 | 保护目的 |
| ---- | ---- | ---- |
| SA 本地配置库 bundleName 打点归因 | `SetBundleName` + `SetLocalOnly` + `SetServerPath` + `SetIntegrityCheck` | 按 bundleName 定位异常责任方；不走 IPC 进程隔离；开库时完整性校验 |
| 加密数据库密钥注册与 ddms 兜底依赖 | `SetBundleName` + `SetEncryptStatus` + `SetEncryptKey` + `SetEncryptAlgo` | 密钥经 ddms 注册，客户端密钥异常或克隆场景可兜底；需配置 Selinux 权限 |

## 头文件总览

| 头文件 | 命名空间 | JS 公共对应物 | 本文档覆盖 |
| ---- | ---- | ---- | ---- |
| `rdb_store_config.h` | `OHOS::NativeRdb` | [StoreConfig](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-arkdata/arkts-apis-data-relationalStore-i.md) | native 专有参数 |
| `rdb_store.h` | `OHOS::NativeRdb` | [RdbStore](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-arkdata/arkts-apis-data-relationalStore-RdbStore.md) | native 专有方法 |
| `rdb_helper.h` | `OHOS::NativeRdb` | [Functions](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-arkdata/arkts-apis-data-relationalStore-f.md) | native 专有方法 |
| `rdb_open_callback.h` | `OHOS::NativeRdb` | 无（JS 无此类） | 全部（5 个回调） |

---

## rdb_store_config.h

**文件路径**：`interfaces/inner_api/rdb/include/rdb_store_config.h`
**库名**：`libnative_rdb.z.so`
**命名空间**：`OHOS::NativeRdb`
**头文件包含**：`#include "rdb/rdb_store_config.h"`

### 场景示例

#### 场景 1：SA 本地配置库 bundleName 打点归因（SetBundleName + SetLocalOnly + SetServerPath + SetIntegrityCheck）

`bundle_manager_service` 需要一个纯本地配置库，作为数据保护措施，通过 `SetBundleName` 设置打点标识，使得数据库异常时可按 bundleName 定位责任方（不设则打点为 uid，无法归因到具体 SA）。配合 `SetLocalOnly` 实现进程隔离不走 IPC、`SetIntegrityCheck` 实现开库完整性校验，构成完整的数据保护链路。

```cpp
#include "rdb/rdb_helper.h"
#include "rdb/rdb_store_config.h"
#include "rdb/rdb_open_callback.h"
#include "rdb/rdb_sql_utils.h"
using namespace OHOS::NativeRdb;

std::shared_ptr<RdbStore> CreateLocalConfigStore()
{
    auto [path, errCode] = RdbSqlUtils::GetDefaultDatabasePath(
        "/data/service/el1/public/bundle_manager_service/", "config.db");
    if (errCode != E_OK) {
        return nullptr;
    }

    RdbStoreConfig config(path);
    config.SetName("config.db");
    config.SetSecurityLevel(SecurityLevel::S3);
    config.SetBundleName("bundle_manager_service"); // 设后可按 bundleName 搜异常打点；不设则打点为 uid 且不走 IPC 访问 ddms
    config.SetLocalOnly(true);                      // 不走 IPC 访问 ddms
    config.SetServerPath(path);                     // SA 进程内路径
    config.SetIntegrityCheck(IntegrityCheck::QUICK); // 开库时快速检查损坏

    class Callback : public RdbOpenCallback {
        int OnCreate(RdbStore &store) override {
            return store.Execute(
                "CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY, value TEXT)").first;
        }
        int OnUpgrade(RdbStore &store, int old, int target) override { return E_OK; }
    };
    Callback callback;
    return RdbHelper::GetRdbStore(config, 1, callback, errCode);
}
```

#### 场景 2：加密数据库密钥注册与 ddms 兜底依赖（SetBundleName + SetEncryptStatus + SetEncryptKey + SetEncryptAlgo）

`some_sa` 需要一个**加密**的本地配置库。加密数据库的密钥需经过数据管理服务（ddms）注册记录，以便在客户端密钥异常或克隆场景下由 ddms 兜底恢复。如果数据库**未走过 ddms 注册**，则密钥异常时或单设备/跨设备克隆场景下，ddms 无法对此兜底，业务方将无法正常开库。

**关键约束**：

1. **Selinux 权限**：业务进程必须配置对数据管理服务进程的 Selinux 权限，否则服务端无法记录该数据库的密钥
2. **密钥异常兜底**：客户端密钥出现异常（丢失或被修改）后，若未在 ddms 注册，ddms 无法兜底恢复，业务方将无法正常开库
3. **克隆依赖**：单设备克隆或跨设备克隆场景需依赖 ddms 记录的密钥信息，未注册的加密库无法完成克隆

```cpp
#include "rdb/rdb_helper.h"
#include "rdb/rdb_store_config.h"
#include "rdb/rdb_open_callback.h"
#include "rdb/rdb_sql_utils.h"
using namespace OHOS::NativeRdb;

std::shared_ptr<RdbStore> CreateEncryptedConfigStore(const std::vector<uint8_t> &key)
{
    auto [path, errCode] = RdbSqlUtils::GetDefaultDatabasePath(
        "/data/service/el1/public/some_sa/", "config.db");
    if (errCode != E_OK) {
        return nullptr;
    }

    RdbStoreConfig config(path);
    config.SetName("config.db");
    config.SetSecurityLevel(SecurityLevel::S3);
    config.SetBundleName("some_sa");                   // 打点归因
    config.SetEncryptStatus(true);                      // 开启加密
    config.SetEncryptAlgo(EncryptAlgo::AES_256_GCM);   // 加密算法，默认 AES_256_GCM
    config.SetEncryptKey(key);                          // 密钥由业务方通过 HUKS 等安全途径获取
    config.SetIntegrityCheck(IntegrityCheck::QUICK);
    // 加密数据库密钥需经过 ddms 注册记录：
    // 若未注册，客户端密钥异常或单设备/跨设备克隆场景下 ddms 无法兜底，业务方将无法开库。
    // 业务进程需配置对 ddms 进程的 Selinux 权限，否则服务端无法记录密钥。

    class Callback : public RdbOpenCallback {
        int OnCreate(RdbStore &store) override {
            return store.Execute(
                "CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY, value TEXT)").first;
        }
        int OnUpgrade(RdbStore &store, int old, int target) override { return E_OK; }
    };
    Callback callback;
    return RdbHelper::GetRdbStore(config, 1, callback, errCode);
}
```
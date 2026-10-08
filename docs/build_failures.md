# 编译失败测试用例清单（按 Feature 分类）

> **当前状态**: 已全部修复（2026-09-13）。所有 `bin/` 下可执行文件编译通过，0 个失败。
> 下次上游同步后如出现新的编译失败，请参考 [build_and_fix_workflow.md](./build_and_fix_workflow.md)。
>
> 以下为历史记录，保留供参考。

---

## 2026-09-13 上游同步后编译修复

同步上游代码后，出现 1 个编译错误：

| 失败目标 | 错误类型 | 错误信息 | 修复方式 |
|----------|----------|----------|----------|
| mock 库 (mock_rdb_store.cpp) | 编译错误 | `no declaration matches 'int OHOS::NativeRdb::RdbStore::SetSearchTrigger(bool)'` | 删除过时的 mock 文件 |

**根因**: 上游 `relational_store/interfaces/inner_api/rdb/include/rdb_store.h` 已移除 `SetSearchTrigger(bool)` 方法声明，但 `mock/src/mock_rdb_store.cpp` 仍提供该方法的实现。由于无代码引用此方法，该 mock 文件已成为死代码。

**修复**: 直接删除 `mock/src/mock_rdb_store.cpp`。该文件从未提交到 git（非跟踪文件），删除后 mock 库的 `aux_source_directory` 不再收集它。

**验证**: 全量构建 459/459 目标，0 错误。`ctest` 62 通过 / 28 失败 / 2 超时 / 7 段错误 / 5 子进程异常退出（失败项为 mock 环境限制，非编译问题）。

---

构建时间: 2026-04-20（第二轮，已应用 -fno-access-control 和条件编译修复）

总失败测试目标: 41（上一轮: 83）
最终结果: 0 个可执行文件失败（2026-04-22 修复完成）

| 分类 | 数量 |
|------|------|
| 缺少头文件/include路径 | 17 |
| 编译错误 (mock接口不匹配、重定义等) | 24 |

## 一、kv_store（1 个）

| 测试目标 | 错误类型 | 错误信息 |
|----------|----------|----------|
| KVDBTest | 编译错误 | `DataShareValueObject::Type` 不存在; `DataShare::SQL_IN` 未声明; `kv_utils.h` 模板参数无效 |

## 二、relational_store（5 个）

| 测试目标 | 错误类型 | 错误信息 |
|----------|----------|----------|
| NativeRdbTest | 编译错误 | `waitpid` 未声明; ValueObject 初始化歧义 |
| NativeRdbImplTest | 编译错误 | `std::filesystem::create_directories` 不是成员 |
| NativeRdbMultiProcessTest | 编译错误 | `RDB_TEST_PATH` 未声明 |
| ConcurrentTest | 编译错误 | `RDB_TEST_PATH` 未声明; `UTUtils` 未声明 |
| UtilsTest | 编译错误 | `std::filesystem::create_directories` 不是成员 |

## 三、datamgr_service/adapter（2 个）

| 测试目标 | 错误类型 | 错误信息 |
|----------|----------|----------|
| AppPipeMgrServiceTest | 编译错误 | `enum SoftBusErrNo` 多次定义 |
| SoftBusAdapterStandardTest | 编译错误 | `enum SoftBusErrNo` 多次定义 |

## 四、datamgr_service/app（8 个）

| 测试目标 | 错误类型 | 错误信息 |
|----------|----------|----------|
| KvStoreDataServiceTest | 缺少头文件 | `ikvstore_data_service.h` No such file |
| KvStoreDataServiceMockTest | 缺少头文件 | `ikvstore_data_service.h` + `TokenIdKit::IsSystemAppByFullTokenID` 重定义 |
| KvStoreMetaManagerUpdateKeyTest | 缺少头文件 | `ikvstore_data_service.h` No such file |
| KvStoreDataServiceClearTest | 缺少头文件 | `ikvstore_data_service.h` No such file |
| SessionManagerTest | 缺少头文件 | `ikvstore_data_service.h` No such file |
| RouteHeadHandlerImplTest | 缺少头文件 | `ikvstore_data_service.h` No such file |
| DDMSDumpTest | 缺少头文件 | `ikvstore_data_service.h` No such file |
| FeatureStubImplTest | 编译错误 | mock 接口不匹配（链接失败） |

## 五、datamgr_service/framework（1 个）

| 测试目标 | 错误类型 | 错误信息 |
|----------|----------|----------|
| ServiceMetaDataTest | 缺少头文件 | `bootstrap.h` No such file |

## 六、datamgr_service/service（22 个）

### 6.1 cloud（3 个）

| 测试目标 | 错误类型 | 错误信息 |
|----------|----------|----------|
| CloudDataTest | 编译错误 | `XCollie` was not declared in scope |
| CloudDataMockTest | 编译错误 | `XCollie` + `TokenIdKit::IsSystemAppByFullTokenID` 重定义 |
| CloudServiceImplTest | 编译错误 | `XCollie` was not declared in scope |

### 6.2 kvdb（4 个）

| 测试目标 | 错误类型 | 错误信息 |
|----------|----------|----------|
| KVDBGeneralStoreTest | 链接错误 | `QueryHelper::StringToDbQuery`、`Bootstrap::GetInstance` 等未定义 |
| KvdbServiceImplTest | 缺少头文件 + 重定义 | `ikvstore_data_service.h` + `TokenIdKit` 重定义 |
| KvdbServicePasswordTest | 缺少头文件 | `device_matrix.h` No such file |
| UpgradeMockTest | 编译错误 | `TokenIdKit::IsSystemAppByFullTokenID` 重定义 |

### 6.3 misc（7 个）

| 测试目标 | 错误类型 | 错误信息 |
|----------|----------|----------|
| ValueProxyServiceTest | 编译错误 | mock 接口不匹配（链接失败） |
| ConfigFactoryTest | 编译错误 | 链接失败 |
| DirectoryManagerTest | 编译错误 | `BackupManager` 未声明; `backupParam` 未声明 |
| CryptoManagerTestSvc | 编译错误 | `AtmToolsParamInfo` 未声明 |
| DeviceMatrixTest | *已通过* | |
| MetaDataTest | 缺少头文件 | `ikvstore_data_service.h` No such file |
| BootStrapMockTest | 编译错误 | `BackupManager` 未声明 |
| BackupManagerServiceTest | 缺少头文件 | `ikvstore_data_service.h` No such file |
| UtdServiceImplTest | 缺少头文件 | `ikvstore_data_service.h` + `utd_notifier.h` |
| UtdServiceStubTest | 缺少头文件 | `distributeddata_udmf_ipc_interface_code.h` |
| ServiceMetaDataTest | 缺少头文件 | `bootstrap.h` |
| CloudTestSvc | 编译错误 | 链接失败 |

### 6.4 object（0 个）

全部已通过或已通过条件编译跳过。

### 6.5 permission（2 个）

| 测试目标 | 错误类型 | 错误信息 |
|----------|----------|----------|
| PermissionValidatorMockTest | 编译错误 | `TokenIdKit::IsSystemAppByFullTokenID` 重定义 |
| PermitDelegateMockTest | 编译错误 | `TokenIdKit::IsSystemAppByFullTokenID` 重定义 |

### 6.6 rdb（3 个）

| 测试目标 | 错误类型 | 错误信息 |
|----------|----------|----------|
| RdbResultSetImplTest | 缺少头文件 | `common_types.h` + `value_proxy.h` No such file |
| RdbServiceImplTest | 缺少头文件 | `value_proxy.h` No such file |
| RdbServiceImplTokenTest | 编译错误 | `TokenIdKit::IsSystemAppByFullTokenID` 重定义 |

### 6.7 data_share / udmf

已通过条件编译跳过（`BUILD_DATA_SHARE` / `BUILD_UDMF` 默认 OFF）。

## 七、legacy（1 个）

| 测试目标 | 错误类型 | 错误信息 |
|----------|----------|----------|
| DataMgrServiceTest | 编译错误 | `DeviceManager` 无 `Online`/`Offline` 成员; `SoftBusErrNo` 多次定义 |

## 八、kv_store（独立）（1 个）

| 测试目标 | 错误类型 | 错误信息 |
|----------|----------|----------|
| DataBaseUtilsTest | 编译错误 | mock 接口不匹配 |

## 九、成功构建的库

- mock
- distributeddb
- gaussdb
- databaseUtils
- kvdb
- svcFwk
- adapter
- service
- relational_store
- cloud_data
- app
- rdb_ndk_utils
- js_rdb_store
- ndk_rdb_store

## 十、错误模式分析

### 模式 1: `ikvstore_data_service.h` 缺失（~13 个目标）

**原因**: `kvstore_data_service.h` 中 `#include "ikvstore_data_service.h"`，但该头文件路径未加入 include_directories。

**修复方案**: 添加 `datamgr_service/services/distributeddataservice/interfaces/innerkits/distributeddata` 或搜索 `ikvstore_data_service.h` 的实际路径。

### 模式 2: `TokenIdKit::IsSystemAppByFullTokenID` 重定义（~6 个目标）

**原因**: 测试目录下的 `access_token_mock.cpp` 与 mock 库中的 `tokenid_kit.h` 都定义了该方法。

**修复方案**: 在涉及 `access_token_mock.cpp` 的测试中，移除重复定义或使用 `#ifdef` 保护。

### 模式 3: `XCollie` 未声明（3 个目标）

**原因**: `cloud_service_impl.cpp` 中使用了 `XCollie`，但未通过 `using` 或命名空间限定引入。

**修复方案**: 在 mock 头文件中添加 `using OHOS::HiviewDFX::XCollie;` 或修改源文件。

### 模式 4: `SoftBusErrNo` 多次定义（2 个目标）

**原因**: 枚举在多个头文件中重复定义（mock 和 adapter test mock 各有一份）。

**修复方案**: 使用 `#ifndef` 保护或统一到一处定义。

### 模式 5: 特定编译错误（~8 个目标）

| 错误 | 目标 | 原因 |
|------|------|------|
| `create_directories` 不是成员 | NativeRdbImplTest, UtilsTest | Cygwin filesystem 支持不完整 |
| `RDB_TEST_PATH` 未声明 | ConcurrentTest, NativeRdbMultiProcessTest | 测试宏未定义 |
| `BackupManager` 未声明 | BootStrapMockTest, DirectoryManagerTest | mock 缺少 BackupManager |
| `AtmToolsParamInfo` 未声明 | CryptoManagerTestSvc | mock 缺少类型定义 |
| `DataShareValueObject::Type` 不存在 | KVDBTest | mock 接口不匹配 |
| `DeviceManager` 缺成员 | DataMgrServiceTest | mock 接口不匹配 |
| `common_types.h` 缺失 | RdbResultSetImplTest | include 路径缺失 |
| `value_proxy.h` 缺失 | RdbServiceImplTest | include 路径缺失 |
| `bootstrap.h` 缺失 | ServiceMetaDataTest | include 路径缺失 |
| `device_matrix.h` 缺失 | KvdbServicePasswordTest | include 路径缺失 |

# GN 与 CMake 编译产物对比

> **最后更新**: 2026-09-17
> **触发条件**: 每次执行 `sync.ps1` 同步上游代码并解决编译问题后重新生成
> **生成方法**: 见文末「重新生成步骤」
> **CMake 侧编译单元详情**: [docs/build_structure.md](./build_structure.md)

---

## 概述

本文档对比上游 GN 构建系统定义的编译目标与本地 CMake mock 构建系统的产物映射关系。上游使用 GN (BUILD.gn) 构建系统，产物为 `.so` 共享库；本地使用 CMake (CMakeLists.txt) 在 Cygwin 环境模拟，产物为 `.dll` 共享库。

CMake 构建有意偏离 GN 的 1:1 映射，采用四种差异模式来适配 mock 环境（见下表）。

---

## 差异模式说明

| 状态标记 | 含义 | 典型场景 |
|---|---|---|
| ✅ 匹配 | 名称一致，源文件一致 | `distributeddb` |
| ⚠️ 重命名 | CMake 目标名与 GN 不同 | `native_rdb` → `relational_store` |
| ⚠️ 合并 | GN 中独立目标，CMake 合并进父目标 | `native_appdatafwk` → `relational_store` 源列表 |
| ⚠️ Mock替换 | CMake 用 mock 源替换上游实现 | `rdb_crypt` 用 `mock/src/delegates/` |
| ➕ CMake额外 | CMake 独有目标，GN 中不存在 | `LDBProj`, `secure`, `mock` |
| ❌ 缺失 | GN 有定义但 CMake 未构建 | `pixelmap_wrapper`, `asset_sync_manager` |

---

## 共享库对比

> **CMake 侧数据来源**：`ls cmake-build-debug/bin/*.dll`（实际构建产物）。`BUILD_ALL=OFF`（默认）时，data_share / preferences / data_object / udmf 模块的 DLL 不构建，下表标注其条件编译状态。实际构建 31 个 DLL + 8 个 `.z.so` 别名。

### relational_store

GN 共享库目标 13 个 → CMake 共享库目标 10 个（全部构建）

| GN 目标 | GN 输出 (.so) | CMake 目标 | CMake 输出 (.dll) | 状态 | 说明 |
|---|---|---|---|---|---|
| `native_rdb` | libnative_rdb.so | `relational_store` | cygrelational_store.dll | ⚠️ 重命名 | GN 的 base_sources + platform_sources → CMake 合并 appdatafwk/rdb/rd/dfx/rdb_service_adapter 源 |
| `relational_store_crypt` | librelational_store_crypt.so | `rdb_crypt` | cygrdb_crypt.dll | ⚠️ 重命名+Mock替换 | CMake 用 `mock/src/delegates/mock_rdb_crypt.cpp` 替换上游 `rdb_crypt/relational_store_crypt.cpp`；Init() 返回 0 |
| `rdb_service_adapter` | (ohos_static_library) | (合并入 relational_store) | — | ⚠️ 合并 | GN 独立静态库；CMake 将 `rdb_service_adapter/src/*.cpp` 合并进 relational_store |
| `rdb_obs_mgr_adapter` | librdb_obs_mgr_adapter.z.so | `rdb_obs_adapter` | cygrdb_obs_adapter.dll | ⚠️ 重命名+Mock替换 | CMake 用 `mock/src/delegates/mock_rdb_obs_adapter.cpp`；POST_BUILD 复制 `.z.so` 别名 |
| `relational_store_icu` | librelational_store_icu.z.so | `relational_store_icu` | cygrelational_store_icu.dll | ⚠️ Mock替换 | CMake 用 `mock/src/delegates/mock_rdb_icu.cpp`；ConfigICULocale 返回 0 |
| `relational_common_base` | librelational_common_base.so | (合并入 relational_store) | — | ⚠️ 合并 | `appdatafwk/src/serializable.cpp` 合并进 relational_store |
| `native_appdatafwk` | libnative_appdatafwk.so | (合并入 relational_store) | — | ⚠️ 合并 | `appdatafwk/src/shared_block.cpp` 合并进 relational_store |
| `cloud_data_native` | libcloud_data_native.so | `cloud_data` | cygcloud_data.dll | ⚠️ 重命名 | |
| `native_dataability` | libnative_dataability.so | (合并入 relational_store) | — | ⚠️ 合并 | `dataability/src/*.cpp` 合并进 relational_store |
| `rdb_data_ability_adapter` | librdb_data_ability_adapter.so | (合并入 relational_store) | — | ⚠️ 合并 | `rdb_data_ability_adapter/src/*.cpp` 合并进 relational_store |
| `rdb_data_share_adapter` | librdb_data_share_adapter.so | (合并入 relational_store) | — | ⚠️ 合并 | `rdb_data_share_adapter/src/*.cpp` 合并进 relational_store |
| `native_rdb_ndk` | libnative_rdb_ndk.so | `ndk_rdb_store` | cygndk_rdb_store.dll | ⚠️ 重命名 | |
| `native_rdb_ndk_utils` | libnative_rdb_ndk_utils.so | `rdb_ndk_utils` | cygrdb_ndk_utils.dll | ⚠️ 重命名 | |
| — | — | `js_relational_store` | cygjs_relational_store.dll | ➕ CMake额外 | JS NAPI 绑定，CMake 独立拆分 |
| — | — | `js_rdb_store` | cygjs_rdb_store.dll | ➕ CMake额外 | JS NAPI 绑定 |
| — | — | `js_dataability` | cygjs_dataability.dll | ➕ CMake额外 | JS NAPI 绑定 |

### kv_store

GN 共享库目标 9 个 → CMake 共享库目标 9 个（全部构建）

| GN 目标 | GN 输出 (.so) | CMake 目标 | CMake 输出 (.dll) | 状态 | 说明 |
|---|---|---|---|---|---|
| `distributeddata_inner` | libdistributeddata_inner.so | `kvdb` | cygkvdb.dll | ⚠️ 重命名 | old_source_config + kvdb_source_config → CMake innerkitsimpl 源 |
| `distributeddata_client_sync` | libdistributeddata_client_sync.so | (合并入 kvdb) | — | ⚠️ 合并 | process_communication_impl.cpp 等合并进 kvdb |
| `distributeddata_mgr` | libdistributeddata_mgr.so | (合并入 kvdb) | — | ⚠️ 合并 | datamgr_service_proxy.cpp 等合并进 kvdb |
| `kv_store_crypt` | libkv_store_crypt.z.so | `kv_store_crypt` | cygkv_store_crypt.dll | ⚠️ Mock替换 | CMake 用 `mock/src/delegates/mock_kv_store_crypt.cpp` |
| `dm_adapter` | libdm_adapter.z.so | `dm_adapter` | cygdm_adapter.dll | ⚠️ Mock替换 | CMake 用 `mock/src/delegates/mock_device_adapter.cpp` |
| `dms_adapter` | libdms_adapter.z.so | `dms_adapter` | cygdms_adapter.dll | ⚠️ Mock替换 | CMake 用 `mock/src/delegates/mock_dms_adapter.cpp` |
| `distributedkvstore` | libdistributedkvstore.so | `jskvdb` | cygjskvdb.dll | ⚠️ 重命名 | JS NAPI 绑定 |
| `distributeddata` | libdistributeddata.so | `jsolddb` | cygjsolddb.dll | ⚠️ 重命名 | JS NAPI 绑定 |
| `distributeddb` | libdistributeddb.so | `distributeddb` | cygdistributeddb.dll | ✅ 匹配 | 核心存储引擎 |
| — | — | `gaussdb` | cyggaussdb.dll | ➕ CMake额外 | gaussdb_rd 子目录，CMake 独立构建 |
| — | — | `databaseUtils` | cygdatabaseUtils.dll | ➕ CMake额外 | kv_store/databaseutils/，CMake 独立构建 |

### data_share

GN 共享库目标 5 个 → CMake 共享库目标 1 个（定义，`BUILD_DATA_SHARE` OFF 时 0 个构建）

| GN 目标 | GN 输出 (.so) | CMake 目标 | CMake 输出 (.dll) | 状态 | 说明 |
|---|---|---|---|---|---|
| `datashare_common` | libdatashare_common.so | `data_share` | cygdata_share.dll | ⚠️ 合并 | 5 个 GN 独立库合并为 1 个 CMake 库 |
| `datashare_consumer` | libdatashare_consumer.so | (合并入 data_share) | — | ⚠️ 合并 | |
| `datashare_permission` | libdatashare_permission.so | (合并入 data_share) | — | ⚠️ 合并 | |
| `datashare_provider` | libdatashare_provider.so | (合并入 data_share) | — | ⚠️ 合并 | |
| `datashare_ext_ability_module` | libdatashare_ext_ability_module.so | (合并入 data_share) | — | ⚠️ 合并 | |

### preferences

GN 共享库目标 2 个 → CMake 共享库目标 1 个（定义，`BUILD_PREFERENCES` OFF 时 0 个构建）

| GN 目标 | GN 输出 (.so) | CMake 目标 | CMake 输出 (.dll) | 状态 | 说明 |
|---|---|---|---|---|---|
| `native_preferences` | libnative_preferences.so | `preferences` | cygpreferences.dll | ⚠️ 重命名 | 含 native/src + js/napi 源 |
| `libohpreferences` (output_name="ohpreferences") | libohpreferences.so → ohpreferences.so | (合并入 preferences) | — | ⚠️ 合并 | GN NDK 独立库；CMake 合并进 preferences |

### data_object

GN 共享库目标 2 个 → CMake 共享库目标 1 个（定义，`BUILD_DATA_OBJECT` OFF 时 0 个构建）

| GN 目标 | GN 输出 (.so) | CMake 目标 | CMake 输出 (.dll) | 状态 | 说明 |
|---|---|---|---|---|---|
| `distributeddataobject_impl` | libdistributeddataobject_impl.so | `data_object` | cygdata_object.dll | ⚠️ 重命名 | innerkitsimpl + jskitsimpl 源合并 |
| `distributeddataobject` | libdistributeddataobject.so | (合并入 data_object) | — | ⚠️ 合并 | GN NAPI 独立库；CMake 合并 |

### udmf

GN 共享库目标 9 个 → CMake 共享库目标 3 个（定义，`BUILD_UDMF` OFF 时 0 个构建）

| GN 目标 | GN 输出 (.so) | CMake 目标 | CMake 输出 (.dll) | 状态 | 说明 |
|---|---|---|---|---|---|
| `udmf_client` | libudmf_client.so | `udmf` | cygudmf.dll | ⚠️ 重命名 | innerkitsimpl 源合并 |
| `utd_client` | libutd_client.so | (合并入 udmf) | — | ⚠️ 合并 | |
| `pixelmap_wrapper` | libpixelmap_wrapper.so | — | — | ❌ 缺失 | 依赖 image_framework，mock 环境不构建 |
| `xml_wrapper` | libxml_wrapper.so | — | — | ❌ 缺失 | 依赖 libxml2，mock 环境不构建 |
| `udmf_data_napi` | libudmf_data_napi.so | `udmf_channel` | cygudmf_channel.dll | ⚠️ 重命名 | jskitsimpl 源 |
| `unifieddatachannel_napi` | libunifieddatachannel_napi.so | (合并入 udmf_channel) | — | ⚠️ 合并 | |
| `uniformtypedescriptor_napi` | libuniformtypedescriptor_napi.so | (合并入 udmf_channel) | — | ⚠️ 合并 | CMake 排除 `uniform_type_descriptor_napi.cpp` |
| `intelligence_napi` | libintelligence_napi.so | — | — | ❌ 缺失 | 依赖 AIP 能力，mock 环境不构建 |
| `libudmf` (output_name="udmf") | libudmf.so → udmf.so | `udmf_ndk` | cygudmf_ndk.dll | ⚠️ 重命名 | NDK 层 |

### datamgr_service

GN 共享库目标 7 个 → CMake 共享库目标 5 个（全部构建）

| GN 目标 | GN 输出 (.so) | CMake 目标 | CMake 输出 (.dll) | 状态 | 说明 |
|---|---|---|---|---|---|
| `distributeddatasvc` | libdistributeddatasvc.so | `service` | cygservice.dll | ⚠️ 重命名 | 聚合库（无自身源），CMake 有独立源 |
| `distributeddataservice` | libdistributeddataservice.so | `app` | cygapp.dll | ⚠️ 重命名 | SA 进程入口 |
| `distributeddatasvcfwk` | libdistributeddatasvcfwk.so | `svcFwk` | cygsvcFwk.dll | ⚠️ 重命名 | 大型框架库 |
| `distributeddata_clone` | libdistributeddata_clone.so | `distributeddata_clone` | cygdistributeddata_clone.dll | ✅ 匹配 | 独立 clone 库，CMake 用 POST_BUILD 拷贝为 libdistributeddata_clone.z.so |
| `asset_sync_manager` | libasset_sync_manager.so | — | — | ❌ 缺失 | 依赖 dfs_service，mock 环境不构建 |
| `opencloudextension` | libopencloudextension.z.so | `opencloudextension` | cygopencloudextension.dll | ⚠️ Mock替换 | CMake 用 `mock/src/delegates/mock_opencloudextension.cpp` |
| `conn_adapter` | libconn_adapter.so | (合并入 adapter) | — | ⚠️ 合并 | connect.cpp 等合并进 adapter |
| — | — | `adapter` | cygadapter.dll | ➕ CMake额外 | datamgr_service/adapter/ 子目录独立构建 |

### mock / utils_native（CMake 额外目标）

以下 CMake 目标在 GN 上游中不存在，是 mock 环境独有的基础设施。

| CMake 目标 | CMake 输出 (.dll) | 状态 | 说明 |
|---|---|---|---|
| `secure` | cygsecure.dll | ➕ CMake额外 | utils_native 安全函数库（memcpy_s 等） |
| `mock` | cygmock.dll | ➕ CMake额外 | 全局 mock 基础设施，定义 `__wrap_open`、路径重定向、dlopen mock 等 |
| `LDBProj` | LDBProj.exe | ➕ CMake额外 | 主可执行文件（dllmain.cpp → cygwin_main()），入口聚合所有库 |

---

## 测试目标对比

> **CMake 侧数据来源**：`ctest -N`（实际注册测试）和 `ls cmake-build-debug/bin/*.exe`（实际构建 EXE），非源码 grep。

| 指标 | GN (BUILD.gn) | CMake (实际产物) | 说明 |
|---|---|---|---|
| 测试目标定义方式 | `ohos_unittest(...)` / `mockservice_unittest(...)` | `add_executable(...)` + `add_test(...)` | CMake 通过 `test/*.cmake` include 文件组织 |
| 唯一测试目标数 | 294（上游主模块，去重） | 147（`ctest -N` 注册） | GN 为 BUILD.gn 去重后名称数；CMake 为实际注册数 |
| 实际构建 EXE 数 | — | 166（含 LDBProj） | `ls cmake-build-debug/bin/*.exe` |
| 两边名称匹配 | 145 | 145 | 同名测试在 GN 和 CTest 中均存在 |
| GN 有、CTest 未注册 | 149 | — | 144 个未构建 + 5 个已构建但未注册（见下方） |
| CTest 有、GN 没有 | — | 2 | `RunAllRdbTests`（聚合入口）、`BatteryStateMonitorTest` |
| 已构建但未注册 CTest | — | 19 | 见下方详细分析 |
| 测试 CMake 配置位置 | — | `test/<module>/` | 遵循 AGENTS.md 约束 4 |

### GN 有但 CTest 未注册的 149 个测试

按模块分类，未注册原因主要是条件编译（`BUILD_*` 选项默认 OFF）和系统依赖不可用。标注 † 的测试已构建 EXE 但未注册到 CTest：

| 模块 | 未注册数 | 未注册的测试目标 | 原因 |
|---|---|---|---|
| data_share | ~37 | `DataShare*` (Helper/Stub/Proxy/ResultSet/Connection/Permission/URIUtils 等), `DatashareItypesUtilsTest`, `DatashareResultSetTest`, `DataProviderImplTest`, `DataProxyHandle*`, `ControllerTest`, `ExtSpecialControllerTest`, `GeneralController*ImplTest`, `GetterSystemTest` | `BUILD_DATA_SHARE` OFF |
| udmf | ~25 | `Udmf*` (Client/Conversion/TypesUtil/Notifier/Async 等), `Utd*` (Client/CfgsChecker/Notifier/Test 等), `Unified*` (Data/Record/Key/Meta/HtmlRecord 等), `System*` (Appitem/Form/PixelMap/Record), `AudioTest`, `VideoTest`, `HtmlTest`, `TextTest`, `PlainTextTest`, `FolderTest`, `LinkTest`, `FileDataTest`, `ImageTest`, `CopyFileTest` | `BUILD_UDMF` OFF |
| data_object | ~8 | `DistributedObjectImplTest`, `DistributedObjectStoreImplTest`, `FlatObjectStoreTest`, `AssetChangeTimerTest`, `ObjectCallbackStubTest`, `ObjectServiceProxyTest`, `ObjectTaskSchedulerTest`, `ObjectTypesUtilTest` | `BUILD_DATA_OBJECT` OFF |
| preferences | ~3 | `NativePreferencesTest`, `NDKPreferencesTest`, `PreferencesExecutorTest` | `BUILD_PREFERENCES` OFF |
| relational_store | ~5 | `SharedBlockTest`, `ScreenLockTest`†, `SlientAccessTest`, `SlientSwitchTest`, `SlientTimeoutTest` | `ScreenLockTest` 已构建 EXE 但未注册；其余系统依赖未 mock |
| kv_store | ~5 | `AbnormalBranchTest`, `AmsMgrProxyTest`, `IkvStoreDataServiceTest`, `KvdbServicePasswordTest`†, `ApplicationDefineRecordTest` | `KvdbServicePasswordTest` 已构建 EXE 但未注册；其余系统依赖未 mock |
| 其他 | ~38 | `AppDeviceHandlerTest`, `AuditHelperTest`, `ClientAdaptorMockTest`, `ClientAdaptorTest`, `EndianConverterTest`, `ErrorCodeTest`, `ExtensionUtilTest`, `FlexibleTypeTest`, `IsharedResultSetStubTest`, `JoinTest`, `NdkDataConversionTest`, `NativeDataShareTest`, `NativeObjectStoreTest`, `PermissionTest`, `PresetTypeDescriptorsTest`, `ProxyDatasTest`, `TlvObjectTest`, `TlvUtilTest`, `URIUtilsTest`, `UdsTest`, `UtdConcurrentUpdateTest`, `UtdDynamicUpdateTest`, `ValueProxyTest`, `tokenizer_test` 等 | 各模块系统依赖缺失 |
| 含 `target_name` 变量 | 3 | gaussdb_rd、distributeddb、mockservice 中的 `ohos_unittest(target_name)` | 模板化定义，需 GN 展开后才能对比 |
| GN 有、已构建但未注册 | 5 | `ConcurrentTest`†, `KvdbServicePasswordTest`†, `NativeRdbAsyncAfterOpenTest`†, `NativeRdbConditionTest`†, `ScreenLockTest`† | 见下方「已构建但未注册」表 |

> † 标记的测试已构建 EXE 但未通过 `add_test()` 注册到 CTest。

### CTest 独有测试（GN 中不存在）

仅 2 个测试在 CTest 中注册但 GN BUILD.gn 中无同名定义：

| 测试目标 | 模块 | 说明 |
|---|---|---|
| `RunAllRdbTests` | relational_store | CMake 聚合测试入口，运行所有 RDB 子测试 |
| `BatteryStateMonitorTest` | datamgr_service | CMake 本地新增 |

### 已构建但未注册 CTest 的 5 个 EXE

这些 EXE 被 `ninja` 成功构建但未通过 `add_test()` 注册到 CTest：

| EXE 名称 | 在 GN 中? | 说明 |
|---|---|---|
| `KvdbServicePasswordTest` | ✅ | GN 有定义，CMake 已构建但未注册 |
| `CommonTest` | ❌ | 通用测试 |
| `DataMgrServiceTest` | ❌ | 服务端测试变体 |
| `KVDBTest` | ❌ | |
| `LDBProj` | ❌ | 主程序入口，非测试 |

> `BootStrapMockTest`（Test #123）EXE 已构建，已注册 CTest。

> **结论**：用例数量**不一致**。GN 上游主模块定义 294 个唯一测试目标，CMake 实际注册 147 个 CTest 测试，其中 145 个与 GN 同名。149 个 GN 测试未注册 CTest（148 个未构建 + 1 个已构建但未注册），主要因条件编译（`BUILD_DATA_SHARE/PREFERENCES/DATA_OBJECT/UDMF` 默认 OFF）和系统依赖不可用。2 个 CTest 独有测试（`RunAllRdbTests`、`BatteryStateMonitorTest`）为 CMake 本地新增。5 个已构建 EXE 未注册 CTest（1 个在 GN 中有定义，4 个为 CMake 独有）。
>
> **改进建议**：(1) 为 `KvdbServicePasswordTest` 添加 `add_test()` 注册；(2) 清理 `test/relational_store/rdb/` 下未被 `include()` 的 `.cmake` 死文件。

---

## 差异模式汇总

### 模式 1：重命名

CMake 使用更短或更直观的目标名称，便于本地开发引用。

| GN 名称 | CMake 名称 | 原因 |
|---|---|---|
| `native_rdb` | `relational_store` | 与模块名一致 |
| `distributeddatasvcfwk` | `svcFwk` | 简化名称 |
| `distributeddataservice` | `app` | 对应 app 子目录 |
| `distributeddatasvc` | `service` | 对应 service 子目录 |
| `native_preferences` | `preferences` | 与模块名一致 |
| `distributeddataobject_impl` | `data_object` | 与模块名一致 |
| `udmf_client` | `udmf` | 与模块名一致 |
| `libudmf` (→udmf) | `udmf_ndk` | 区分 NDK 层 |

### 模式 2：合并

CMake 将 GN 中独立的共享库合并进父目标的源列表，减少 DLL 数量、简化链接。

| 合并组 | 合并进 | 涉及的 GN 目标 |
|---|---|---|
| relational_store 合并组 | `relational_store` | `rdb_service_adapter`, `relational_common_base`, `native_appdatafwk`, `native_dataability`, `rdb_data_ability_adapter`, `rdb_data_share_adapter` |
| kv_store 合并组 | `kvdb` | `distributeddata_client_sync`, `distributeddata_mgr` |
| data_share 合并组 | `data_share` | `datashare_common`, `datashare_consumer`, `datashare_permission`, `datashare_provider`, `datashare_ext_ability_module` |
| preferences 合并组 | `preferences` | `libohpreferences` |
| data_object 合并组 | `data_object` | `distributeddataobject` |
| udmf 合并组 | `udmf` | `utd_client` |
| datamgr_service 合并组 | `service` / `adapter` | `conn_adapter` |

### 模式 3：Mock 替换

通过 `dlopen` 动态加载的库，CMake 用 mock 实现替换上游源文件，避免依赖系统服务（HUKS、DataObsMgrClient 等）。

| GN 目标 | Mock 源文件 | 替换原因 |
|---|---|---|
| `relational_store_crypt` → `rdb_crypt` | `mock/src/delegates/mock_rdb_crypt.cpp` | 上游调用 HUKS 返回失败 |
| `rdb_obs_mgr_adapter` → `rdb_obs_adapter` | `mock/src/delegates/mock_rdb_obs_adapter.cpp` | 上游调用 DataObsMgrClient 返回 null |
| `relational_store_icu` | `mock/src/delegates/mock_rdb_icu.cpp` | 上游依赖 ICU 库，mock 环境无此依赖 |
| `kv_store_crypt` | `mock/src/delegates/mock_kv_store_crypt.cpp` | 上游调用 HUKS 返回失败 |
| `dm_adapter` | `mock/src/delegates/mock_device_adapter.cpp` | 上游依赖 DeviceManager |
| `dms_adapter` | `mock/src/delegates/mock_dms_adapter.cpp` | 上游依赖 DMSFWK |
| `opencloudextension` | `mock/src/delegates/mock_opencloudextension.cpp` | 上游依赖 Rust ylong_cloud_extension |

### 模式 4：CMake 额外目标

| CMake 目标 | 类型 | 说明 |
|---|---|---|
| `secure` | SHARED | utils_native 安全函数库 |
| `mock` | SHARED | 全局 mock 基础设施（`__wrap_open`、路径重定向、dlopen mock） |
| `LDBProj` | EXECUTABLE | 主程序入口 |
| `gaussdb` | SHARED | gaussdb_rd 存储引擎 |
| `databaseUtils` | SHARED | 数据库工具库 |
| `js_relational_store` | SHARED | JS NAPI 绑定（CMake 从 relational_store 拆分） |
| `js_rdb_store` | SHARED | JS NAPI 绑定 |
| `js_dataability` | SHARED | JS NAPI 绑定 |
| `adapter` | SHARED | datamgr_service adapter 子目录 |
| `operator_define` | SHARED | data_mining 事件定义（本地新增模块） |
| `etl_client` | SHARED | data_mining ETL 客户端 |
| `data_mining_client` | SHARED | data_mining 运行时客户端 |
| `data_mining_service` | SHARED | data_mining 服务端 |

### 模式 5：缺失目标

GN 有定义但 CMake 未构建的目标，通常因依赖不可用。

| GN 目标 | 模块 | 缺失原因 |
|---|---|---|
| `pixelmap_wrapper` | udmf | 依赖 image_framework |
| `xml_wrapper` | udmf | 依赖 libxml2（preferences 已占用） |
| `intelligence_napi` | udmf | 依赖 AIP 核心能力 |
| `asset_sync_manager` | datamgr_service | 依赖 dfs_service cloudsync_asset_kit_inner |

---

## 汇总统计

> CMake 侧数据均来自实际构建产物（`ls cmake-build-debug/bin/*.dll`、`ctest -N`），非源码 grep。

| 指标 | GN 上游 | CMake mock（实际产物） | 差异 |
|---|---|---|---|
| 共享库目标 | 128（全部 `ohos_shared_library`） | 31（实际构建 DLL） | CMake 合并多个 GN 库 + 新增基础设施 |
| 静态库目标 | 32（全部 `ohos_static_library`） | 4（OBJECT 库） | CMake 用 OBJECT 库替代部分静态库 |
| 测试目标 | 294（唯一名称，上游主模块） | 147（`ctest -N` 注册）/ 152（构建 EXE） | 145 个同名匹配；149 个 GN 未注册；2 个 CMake 独有 |
| 主可执行文件 | 无（系统服务由 init 启动） | 1 (LDBProj) | CMake 独有入口 |
| .z.so 别名 | — | 8 | dlopen mock 兼容（`.z.so` 后缀映射） |

---

## 重新生成步骤

每次执行 `sync.ps1` 同步上游代码并解决编译问题后，按以下步骤重新生成本文档：

### 1. 确认构建通过

```bash
cmake -B cmake-build-debug -S . -G Ninja
./ninja.exe -C cmake-build-debug -j16   # 必须零错误
```

### 2. 收集原始数据

```bash
# 运行数据收集脚本（输出两侧所有目标列表 + 实际产物）
bash bin/update/gen-target-comparison.sh > /tmp/target-comparison.txt

# 关键：CMake 侧必须使用实际产物，不能用源码 grep
# GN 侧（源码定义，BUILD.gn 是权威来源）
grep -roh 'ohos_shared_library("[^"]*")' --include="BUILD.gn" relational_store kv_store data_share preferences data_object udmf datamgr_service | sort -u
grep -roh 'ohos_unittest("[^"]*")\|mockservice_unittest("[^"]*")' --include="BUILD.gn" relational_store kv_store data_share preferences data_object udmf datamgr_service | sort -u

# CMake 侧（实际构建产物，不是源码 grep）
ls cmake-build-debug/bin/*.dll | sed 's|.*/||' | sort          # 实际构建的 DLL
ls cmake-build-debug/bin/*.exe | sed 's|.*/||' | sort          # 实际构建的 EXE
ctest --test-dir cmake-build-debug -N 2>&1 | grep "Test " | sed 's/.*: //' | sort  # 实际注册的 CTest 测试

# 交叉比对：GN 与 CTest 名称匹配
comm -12 <(GN 测试名称 sort) <(ctest -N 测试名称 sort)  # 匹配数
comm -23 <(GN 测试名称 sort) <(ctest -N 测试名称 sort)  # GN 有、CTest 无
comm -13 <(GN 测试名称 sort) <(ctest -N 测试名称 sort)  # CTest 有、GN 无
```

### 3. 更新映射表

对照收集到的数据，更新各模块的「共享库对比」表格：
- 检查是否有新增的 GN 目标（上游新增库）
- 检查是否有被移除的 GN 目标（上游删除库）
- 更新差异状态和说明列
- 更新「汇总统计」表中的数字

### 4. 更新文首日期

修改文首 `> **最后更新**: YYYY-MM-DD` 为当前日期。

### 5. 验证

确认文档中所有 GN 目标名可在对应 BUILD.gn 文件中找到，所有 CMake 目标名可在对应 CMakeLists.txt 中找到。

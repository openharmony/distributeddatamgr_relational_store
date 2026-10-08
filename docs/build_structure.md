# 编译结构与编译修复流程

> **最后更新**: 2026-09-15
> **构建状态**: ✅ 全量通过（459/459 目标，0 错误）
> **产物**: 25 个共享库 + 35 个静态库 + 114 个可执行文件（含 113 个测试 + 1 个主程序）

---

## 一、编译修复流程总结

```
上游同步 (sync.ps1 -FullSync -Force)
    │
    ▼
全量构建 (ninja -k0 -j4)          ← 收集所有失败目标
    │
    ├── 0 错误 → ✅ 构建成功
    │
    └── 有错误 → 分类诊断
                    │
                    ├── 模式 A: Feature 隔离     → CMake 条件编译 (BUILD_UDMF 等)
                    ├── 模式 B: Include 路径缺失  → 添加 target_include_directories
                    ├── 模式 C: 头文件遮蔽冲突   → BEFORE PRIVATE include
                    ├── 模式 D: Mock API 缺失    → mock/src/ 创建补充实现
                    ├── 模式 E: Mock 文件过时    → 删除死代码 (本次修复)
                    ├── 模式 F: 符号重定义       → weak 属性 / --allow-multiple-definition
                    ├── 模式 G: 链接失败         → 添加缺失 .cpp 到 add_executable
                    └── 模式 H: C++ 标准差异     → target_compile_features
                    │
                    ▼
              迭代验证 → 0 失败 → 运行测试
```

### 本次修复（2026-09-13 同步后）

| 错误 | 根因 | 修复 |
|------|------|------|
| `mock_rdb_store.cpp: no declaration matches 'RdbStore::SetSearchTrigger(bool)'` | 上游移除了 `SetSearchTrigger` 方法，mock 实现变成死代码 | 删除 `mock/src/mock_rdb_store.cpp` |

---

## 二、编译单元总览

### 模块编译层次图

```
┌─────────────────────────────────────────────────────────────────┐
│                      LDBProj (主可执行文件)                       │
│                    dllmain.cpp → cygwin_main()                   │
├──────────┬──────────┬──────────┬──────────┬──────────┬─────────┤
│   基础层   │   核心层   │  RDB 层   │ 服务层   │ 数据挖掘  │ 测试层  │
├──────────┼──────────┼──────────┼──────────┼──────────┼─────────┤
│ secure   │ mock     │ relation │ service  │ operator │ gtest    │
│ utils_   │          │ _store   │ adapter  │ _define  │ gmock    │
│ native   │          │ cloud_  │ app     │ etl_     │ 113 test │
│          │          │ data    │ svcFwk  │ client  │  execut- │
│          │          │ rdb_*  │         │ data_   │  ables  │
│          │          │        │         │ mining  │         │
│          │          │        │         │ _service│         │
├──────────┼──────────┼──────────┼──────────┼──────────┼─────────┤
│  CMake   │  CMake   │  CMake  │  CMake  │  CMake  │  CMake  │
│  (root)  │ (always) │ (always)│(always) │ (OFF)   │ (always)│
└──────────┴──────────┴──────────┴──────────┴──────────┴─────────┘

可选模块 (默认 OFF，BUILD_ALL=ON 时全部编译):
  data_share, preferences, data_object, udmf, data_mining
```

### 编译选项

| 选项 | 默认 | 说明 |
|------|------|------|
| `BUILD_DATA_SHARE` | OFF | 编译 data_share 模块（数据共享） |
| `BUILD_PREFERENCES` | OFF | 编译 preferences 模块（首选项） |
| `BUILD_DATA_OBJECT` | OFF | 编译 data_object 模块（分布式数据对象） |
| `BUILD_UDMF` | OFF | 编译 udmf 模块（用户数据管理框架） |
| `BUILD_INTERFACE_SDK` | OFF | 编译 interface_sdk 模块 |
| `BUILD_DATA_MINING` | OFF | 编译 data_mining + data_mining_service 模块 |
| `BUILD_ALL` | OFF | 编译以上所有可选模块 |
| `BUILD_TESTS` | ON | 编译测试目标（ctest）。关闭后仅编译库文件，不编译测试可执行文件 |
| `COMPILE_JOBS` | 0 | 最大并发编译任务数（0 = 不限制，由 ninja `-j` 控制） |
| `LINK_JOBS` | 3 | 最大并发链接任务数（JOB_POOLS link depth） |
| `ENABLE_STRIP_DEBUG` | OFF | 链接时 `-Wl,--strip-debug`，提速 40-44%，DLL 体积减 70-85% |
| `ENABLE_COVERAGE` | OFF | 启用代码覆盖率插桩（`-ftest-coverage -fprofile-arcs`） |
| `ENABLE_PCH` | OFF | 启用预编译头（实验性） |

---

## 三、各模块编译单元详情

### 1. 基础层

#### `utils_native/` — 安全函数库

| 项目 | 内容 |
|------|------|
| **CMake target** | `secure` (SHARED) |
| **源文件收集** | `aux_source_directory(base/src)` + `base/src/securec` |
| **内容** | Huawei securec/securefunctions — 内存安全函数库（memcpy_s, memset_s 等） |
| **链接依赖** | rt |
| **被依赖** | mock, distributeddb, relational_store, adapter, svcFwk, service 等几乎所有库 |

#### `mock/` — 全局 Mock 基础设施

| 项目 | 内容 |
|------|------|
| **CMake target** | `mock` (SHARED) |
| **源文件收集** | `aux_source_directory(src)` + `sqlite/src`（排除 sqlite3icu.c, shell.c） |
| **额外源** | `src/mock_dfs_service.cpp`（显式添加） |
| **内容** | IPC/RPC mock、能力运行时 mock、包框架 mock、安全服务 mock、SQLite 引擎、dlopen mock、自定义 dlopen/dlsym（映射 .z.so → Windows DLL） |
| **全局 force-include** | `mock/include/mock_compat.h`（提供缺失的 std 头文件和 GNU 扩展 shim） |
| **链接依赖** | secure, crypto |
| **被依赖** | 所有非基础层库和所有测试目标 |
| **include 目录** | ~230 个 `mock/innerkits/*/include` 路径（PUBLIC，链接 mock 的目标自动继承） |
| **CMake 子配置** | `mock/include/CMakeLists.txt` — 纯 include 路径配置，无 target |

#### `googletest/` — 测试框架

| 项目 | 内容 |
|------|------|
| **CMake targets** | `gtest` (STATIC), `gtest_main` (STATIC), `gmock` (STATIC), `gmock_main` (STATIC) |
| **版本** | GoogleTest 1.14.0 |
| **被依赖** | 所有测试目标 |

---

### 2. 核心数据层

#### `kv_store/` — KV 存储引擎

包含 5 个编译单元，层次分明：

| CMake target | 类型 | 源文件来源 | 链接依赖 | 内容 |
|---|---|---|---|---|
| **gaussdb** | SHARED | `gaussdb_rd/` 7 个子目录 | mock, secure | GaussDB 引擎（文档/KV 执行器、cJSON） |
| **distributeddb** | SHARED | `distributeddb/` 24 个子目录 | secure, mock, jsoncpp, crypto, gaussdb | 分布式数据库引擎（通信、存储、同步、SQLite 适配、云同步） |
| **databaseUtils** | SHARED | `databaseutils/src` | mock | 数据库工具类 |
| **kvdb** | SHARED | `frameworks/innerkitsimpl/` 3 个子目录 + `jskitsimpl/` 2 个子目录 | secure, mock, distributeddb, databaseUtils | KV 数据库接口实现 + JS API |
| **jskvdb** | SHARED | `jskitsimpl/distributedkvstore/src` | secure, mock, distributeddb, kvdb | JS KV Store API |
| **jsolddb** | SHARED | `jskitsimpl/distributeddata/src` | secure, mock, distributeddb, kvdb | JS Old Data API |
| **customtokenizer** | SHARED | 显式 3 个 .cpp | sqlite3, securec | SQLite 自定义分词器 |

**依赖链**: secure → gaussdb → distributeddb → kvdb

#### `relational_store/` — 关系型数据库

| CMake target | 类型 | 源文件来源 | 链接依赖 | 内容 |
|---|---|---|---|---|
| **relational_store** | SHARED | `frameworks/native/{appdatafwk,rdb,rd,dfx,rdb_service_adapter}/*/src` + `rdb_adapter_src` | secure, mock, distributeddb, kvdb | RDB 核心引擎（连接、SQL、加密、DFX、适配器） |
| **js_relational_store** | SHARED | `frameworks/js/napi/relationalstore/src` + common | secure, mock, distributeddb, kvdb, relational_store | JS RDB API |
| **js_rdb_store** | SHARED | `frameworks/js/napi/rdb/src` + common | secure, mock, distributeddb, kvdb, relational_store | JS RDB Store API |
| **js_dataability** | SHARED | `frameworks/js/napi/dataability/src` + common | mock, relational_store, js_rdb_store | JS DataAbility API |
| **ndk_rdb_store** | SHARED | `interfaces/ndk/src` | secure, mock, distributeddb, kvdb, relational_store, rdb_ndk_utils | NDK RDB API |
| **rdb_obs_adapter** | SHARED | `frameworks/native/obs_mgr_adapter` | mock | RDB 观察者适配器（dlopen 加载，复制为 librdb_obs_mgr_adapter.z.so） |
| **rdb_crypt** | SHARED | `frameworks/native/rdb_crypt` | mock | RDB 加密库（dlopen 加载，复制为 librelational_store_crypt.z.so） |
| **cloud_data** | SHARED | `frameworks/native/cloud_data/src` + `frameworks/js/napi/cloud_data/src` + common | mock, relational_store | 云数据同步 |
| **rdb_ndk_utils** | SHARED | `interfaces/rdb_ndk_utils/src` | mock, relational_store | RDB NDK 工具 |

---

### 3. 服务层

#### `datamgr_service/` — 分布式数据管理服务

四层架构，每层一个编译单元：

| CMake target | 类型 | 源文件来源 | 链接依赖 | 内容 |
|---|---|---|---|---|
| **svcFwk** | SHARED | `framework/` 28 个子目录 (access_check, cloud, crypto, metadata, store, sync_mgr...) | secure, mock, distributeddb | 框架层（检查器、云、加密、元数据、存储、同步管理、DFX、事件中心） |
| **adapter** | SHARED | `adapter/` 12 个子目录 (account, communicator, network, dfx, qos...) | secure, mock, distributeddb, crypto, svcFwk | 适配器层（账号、通信、网络、DFX、QoS、电源管理） |
| **service** | SHARED | `service/` 13 个子目录 + 条件 data_share/object/udmf/data_mining | secure, mock, kvdb, svcFwk, adapter, gaussdb, cloud_data, relational_store (+ 条件) | 服务层（备份、引导、云、配置、RDB、KVDB、矩阵、权限、数据挖掘 SA） |
| **app** | SHARED | 显式 14 个 .cpp | secure, mock, distributeddb, adapter, kvdb, svcFwk, service, checker, installer | 应用层（数据服务、会话管理、安全、升级） |
| **distributeddata_checker** | OBJECT | 显式 2 个 .cpp (bundle_checker, system_checker) | adapter | 包检查器（OBJECT 库确保全局注册） |
| **distributeddata_installer** | STATIC | 显式 2 个 .cpp (installer, installer_impl) | svcFwk, service, adapter, kvdb, mock | 安装器（STATIC 库） |

**依赖链**: svcFwk → adapter → service → app

#### `data_mining/` — Data Mining 客户端 SDK

| CMake target | 类型 | 源文件来源 | 链接依赖 | 内容 |
|---|---|---|---|---|
| **operator_define** | SHARED | 显式 9 个 .cpp (context, event, ipc, plugin, record, schema...) | mock | 算子定义（Schema、Record、Pipeline 算子接口） |
| **etl_service_manager_client** | STATIC | 显式 1 个 .cpp | (无) | ETL 服务管理客户端 |
| **etl_client** | SHARED | 显式 5 个 .cpp (context, etl_client, proxy, result) | etl_service_manager_client, mock | ETL 客户端门面（通过 IPC 触发远程 Pipeline） |

#### `data_mining_service/` — Data Mining SA 服务

| CMake target | 类型 | 源文件来源 | 链接依赖 | 内容 |
|---|---|---|---|---|
| **data_mining_service_proxy** | STATIC | 显式 2 个 .cpp | operator_define, mock | SA 客户端代理 |
| **data_mining_service_stub** | STATIC | 显式 2 个 .cpp | mock | SA 服务端 Stub |
| **data_mining_client** | SHARED | 显式 7 个 .cpp | operator_define, mock | 客户端库（Pipeline 加载、传输） |
| **data_mining_runtime** | STATIC | 显式 16 个 .cpp | etl_client, operator_define, mock, data_mining_service_proxy | Pipeline 运行时引擎（DAG 构建、执行、插件管理） |
| **data_mining_service** | SHARED | 显式 3 个 .cpp | data_mining_runtime, data_mining_service_stub, operator_define, mock | SA 服务（SAID=1311，生命周期管理） |

---

### 4. 可选模块

| 模块 | CMake target | 默认 | 内容 |
|------|---|------|------|
| **data_share** | data_share (SHARED) | OFF | 数据共享组件（跨应用数据通信） |
| **preferences** | preferences (SHARED) | OFF | 首选项数据库（轻量级 KV 存储，内存加载） |
| **data_object** | data_object (SHARED) | OFF | 分布式数据对象管理（会话级同步，100-150KB/对象） |
| **udmf** | udmf (SHARED), udmf_ndk (SHARED) | OFF | 用户数据管理框架（数据生命周期、权限） |

---

### 5. 主可执行文件

| CMake target | 源文件 | 链接依赖 |
|---|---|---|
| **LDBProj** | `dllmain.cpp` | secure, mock, relational_store, kvdb, jsoncpp, crypto, distributeddb, service, app, adapter, svcFwk (+ 条件可选模块) |

`dllmain.cpp` 提供了 Cygwin 下的 main() 入口，加载所有 DLL 并初始化 mock 服务。

---

### 6. 测试层

#### 测试目录结构

```
test/
├── CMakeLists.txt              ← 顶层测试入口（定义 10 个测试目标）
├── include/CMakeLists.txt       ← 测试 include 路径配置
├── kv_store/
│   ├── CMakeLists.txt          ← 委托给 .cmake 文件
│   ├── common_tests.cmake      ← KVDB 通用测试
│   └── databaseutils_tests.cmake
├── relational_store/
│   ├── rdb/                    ← 9 个 .cmake 文件
│   │   ├── native_rdb_test.cmake
│   │   ├── native_rdb_impl_test.cmake
│   │   ├── connection_pool_test.cmake
│   │   ├── store_core_test.cmake
│   │   ├── concurrent_test.cmake
│   │   ├── encrypt_test.cmake
│   │   ├── backup_restore_test.cmake
│   │   └── ...
│   ├── clouddata/              ← NativeCloudDataTest
│   ├── appdatafwk/             ← NativeAppDataFwkTest
│   └── dataability/            ← NativeDataAbilityTest
├── datamgr_service/
│   ├── framework/              ← 24 个 .cmake 文件（~30 个测试目标）
│   ├── adapter/                ← 6 个 .cmake 文件
│   ├── app/                    ← 3 个 .cmake 文件
│   └── service/                ← 7+ 个 .cmake 文件（含条件编译）
├── data_mining/
│   ├── core_tests.cmake        ← DataMiningCoreTest
│   └── etl_tests.cmake         ← DataMiningEtlTest
└── data_mining_service/
    ├── runtime_tests.cmake     ← DataMiningRuntimeTest
    ├── component_tests.cmake   ← DataMiningComponentTest
    └── demo_tests.cmake        ← DataMiningDemoTest
```

#### 测试目标分类

| 层级 | 测试数量 | 典型测试 | 公共链接 |
|------|---------|---------|---------|
| **顶层** (test/CMakeLists.txt) | 10 | CommonTest, KVDBTest, DataMgrServiceTest, CryptoTest, RDBNDKTest, RunAllRdbTests + 4 个条件测试 | secure mock app adapter svcFwk service + gtest |
| **datamgr_service/framework** | ~30 | AutoCacheTest, StoreTest, FeatureTest, EventCenterTest, MetadataManagerTest... | svcFwk, mock, distributeddb |
| **datamgr_service/adapter** | ~10 | SoftBusAdapterStandardTest, NetworkDelegateTest, QosManagerTest... | adapter, svcFwk, mock |
| **datamgr_service/app** | ~10 | KvStoreDataServiceTest, SessionManagerTest, BundleCheckerTest... | app, svcFwk, mock |
| **datamgr_service/service** | ~20 | CloudDataTest, KVDBGeneralStoreTest, RdbServiceImplTest, BackupManagerServiceTest... | service, svcFwk, mock |
| **relational_store/rdb** | 9 | NativeRdbTest, NativeRdbImplTest, ConnectionPoolTest, BackupRestoreTest... | relational_store, mock |
| **data_mining** | 2 | DataMiningCoreTest, DataMiningEtlTest | operator_define, etl_client, mock |
| **data_mining_service** | 3 | DataMiningRuntimeTest, DataMiningComponentTest, DataMiningDemoTest | data_mining_service, mock |

#### 测试结果（2026-09-15）

| 结果 | 数量 | 占比 |
|------|------|------|
| ✅ 通过 | 62 | 59% |
| ❌ 失败 | 28 | 27% |
| 💥 SegFault | 7 | 7% |
| 💀 子进程异常退出 | 5 | 5% |
| ⏱️ 超时 | 2 | 2% |
| **总计** | **105** | |

失败项集中在 RDB 集成测试（BackupRestore、Concurrent、StoreCore）和云同步测试，以及两个超时测试（NativeRdbTest、NativeRdbImplTest）。这些是 mock 环境限制，非编译问题。

---

## 四、完整依赖关系图

```
                    ┌──────────┐
                    │  secure  │ ← 华为安全函数库
                    └────┬─────┘
                         │
              ┌──────────┼──────────┐
              │          │          │
         ┌────┴────┐ ┌───┴────┐ ┌──┴──────┐
         │  mock   │ │gaussdb │ │ (crypto)│
         └────┬────┘ └───┬────┘ └─────────┘
              │          │
              │    ┌─────┴──────┐
              │    │distributeddb│
              │    └─────┬──────┘
              │          │
    ┌─────────┼──────────┼──────────┐
    │         │          │          │
┌───┴────┐ ┌──┴──────┐ ┌┴────────┐ ┌┴──────────┐
│ kvdb   │ │database │ │relational│ │ rdb_*_utils│
│jskvdb  │ │ Utils  │ │ _store   │ │ cloud_data │
│jsolddb │ └────────┘ │ js_*     │ │ rdb_obs    │
└───┬────┘            │ ndk_*   │ │ rdb_crypt  │
    │                 └────┬─────┘ └────────────┘
    │                      │
    │    ┌─────────────────┼──────────────────┐
    │    │                 │                  │
┌───┴────┴──┐  ┌─────────┴──┐  ┌────────────┴──┐
│  svcFwk   │  │  adapter   │  │ (jsoncpp/cryp)│
└────┬──────┘  └─────┬──────┘  └───────────────┘
     │                │
     └───────┬────────┘
             │
       ┌─────┴──────┐
       │  service   │ ← 核心服务层
       └─────┬──────┘
             │
    ┌────────┼────────┐
    │        │        │
┌───┴──┐ ┌──┴───┐ ┌──┴──────────┐
│ app  │ │check-│ │operator_define│ ← Data Mining
└──┬───┘ │er(O) │ │etl_client     │
   │     └──────┘ └──────┬────────┘
   │                     │
   │              ┌──────┴──────────┐
   │              │data_mining_service│
   │              │_proxy(S) _stub(S)│
   │              │_client(SH)        │
   │              │_runtime(S)        │
   │              │_service(SH)       │
   │              └───────────────────┘
   │
┌──┴────────┐
│  LDBProj   │ ← 主可执行文件 (链接所有库)
└───────────-┘

图例: (O)=OBJECT  (S)=STATIC  (SH)=SHARED  无标注=SHARED
```

---

## 五、快速编译命令

### 首次编译（新设备）

```bash
# 1. 确保环境：Cygwin + CMake 3.11+ + GCC (C++17)
# 2. 复制 ninja.exe 到项目根目录（与 CLion 版本一致，当前 1.12.1）
cp "/cygdrive/c/Program Files/JetBrains/CLion 2025.3.2/bin/ninja/cygwin/x64/ninja.exe" \
   /cygdrive/d/Projects/ClionProjects/mock/appdata_master_mock/ninja.exe

# 3. CMake 配置
cd /d/Projects/ClionProjects/mock/appdata_master_mock
mkdir cmake-build-debug
cd cmake-build-debug
cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_MAKE_PROGRAM="D:/Projects/ClionProjects/mock/appdata_master_mock/ninja.exe" \
  ..

# 4. 全量构建
cd ..
./ninja.exe -C cmake-build-debug -j4

# 5. 创建测试环境目录
mkdir -p data/service/el1/public/database/distributeddata/meta/backup
mkdir -p data/service/el1/public/database/distributeddata/kvdb
mkdir -p data/service/el2/100/SingleStoreImplTest
mkdir -p data/test system/etc/distributeddata/conf
cp datamgr_service/conf/config.json system/etc/distributeddata/conf/

# 6. 运行测试
cd cmake-build-debug
ctest --output-on-failure -j1
```

### 日常增量编译

```bash
cd /d/Projects/ClionProjects/mock/appdata_master_mock
./ninja.exe -C cmake-build-debug -j4
```

### 同步后全量构建

```bash
cd /d/Projects/ClionProjects/mock/appdata_master_mock
./ninja.exe -C cmake-build-debug -k0 -j4 2>&1 | tee build_output.log

# 检查失败
grep "FAILED:" build_output.log | sort -u
```

### 构建单个测试

```bash
./ninja.exe -C cmake-build-debug NativeRdbTest
cmake-build-debug/bin/NativeRdbTest.exe --gtest_filter=TestSuite.TestCaseName
```

---

## 六、产物清单

### 共享库（25 个 DLL）

| 层 | 库名 | 文件 | 职责 |
|---|---|---|---|
| 基础 | secure | cygsecure.dll | 华为安全函数 |
| 基础 | mock | cygmock.dll | 全局 Mock + SQLite 引擎 |
| KV | gaussdb | cyggaussdb.dll | GaussDB 引擎 |
| KV | distributeddb | cygdistributeddb.dll | 分布式数据库引擎 |
| KV | databaseUtils | cygdatabaseUtils.dll | 数据库工具 |
| KV | kvdb | cygkvdb.dll | KV 数据库接口 |
| KV | jskvdb | cygjskvdb.dll | JS KV Store API |
| KV | jsolddb | cygjsolddb.dll | JS Old Data API |
| RDB | relational_store | cygrelational_store.dll | RDB 核心引擎 |
| RDB | js_relational_store | cygjs_relational_store.dll | JS RDB API |
| RDB | js_rdb_store | cygjs_rdb_store.dll | JS RDB Store API |
| RDB | js_dataability | cygjs_dataability.dll | JS DataAbility API |
| RDB | ndk_rdb_store | cygndk_rdb_store.dll | NDK RDB API |
| RDB | rdb_obs_adapter | cygrdb_obs_adapter.dll | RDB 观察者适配器 |
| RDB | rdb_crypt | cygrdb_crypt.dll | RDB 加密 |
| RDB | cloud_data | cygcloud_data.dll | 云数据同步 |
| RDB | rdb_ndk_utils | cygrdb_ndk_utils.dll | RDB NDK 工具 |
| 服务 | svcFwk | cygsvcFwk.dll | 框架层 |
| 服务 | adapter | cygadapter.dll | 适配器层 |
| 服务 | service | cygservice.dll | 核心服务层 |
| 服务 | app | cygapp.dll | 应用层 |
| 挖掘 | operator_define | cygoperator_define.dll | 算子定义 |
| 挖掘 | etl_client | cygetl_client.dll | ETL 客户端 |
| 挖掘 | data_mining_client | cygdata_mining_client.dll | 客户端库 |
| 挖掘 | data_mining_service | cygdata_mining_service.dll | SA 服务 |

### 静态库（10 个，不含 gtest/gmock）

| 库名 | 职责 |
|---|---|
| distributeddata_checker | 包检查器（OBJECT → STATIC） |
| distributeddata_installer | 安装器 |
| etl_service_manager_client | ETL 服务管理客户端 |
| data_mining_service_proxy | SA 客户端代理 |
| data_mining_service_stub | SA 服务端 Stub |
| data_mining_runtime | Pipeline 运行时引擎 |
| distributeddata_mock_static | 分布式数据 Mock（测试专用） |

### 可执行文件（114 个）

| 类别 | 数量 | 说明 |
|---|---|---|
| 主程序 | 1 | LDBProj (dllmain.cpp) |
| 测试 | 113 | 覆盖所有模块的单元测试和集成测试 |

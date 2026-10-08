# 编译修复流程指南

本文档记录从上游同步代码后，全量构建、分类失败、分优先级修复到所有测试可执行文件编译通过的完整流程。同步流程请参阅 [上游同步流程](./upstream_sync_workflow.md)。

---

## 编译修复概览

```
步骤 1: 全量构建验证     → ninja -j4 收集失败列表
步骤 2: 分类与根因分析   → 将失败分类为几大模式
步骤 3: 分优先级批量修复 → 按模式优先级逐类修复
步骤 4: 迭代验证         → 每轮修复后重新构建验证
```

> **核心约束：不允许修改上游代码仓的代码。** 修复只能通过 `mock/`、`data_mining/`、`data_mining_service/`、`test/` 和 `CMakeLists.txt` 进行。

---

## 步骤 1: 全量构建验证

### 1.1 配置

```bash
cd /d/Projects/ClionProjects/mock/appdata_master_mock
rm -rf cmake-build-debug
mkdir cmake-build-debug
cd cmake-build-debug
cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_MAKE_PROGRAM="D:/Projects/ClionProjects/mock/appdata_master_mock/ninja.exe" ..
```

### 1.2 构建

```bash
cd /d/Projects/ClionProjects/mock/appdata_master_mock/cmake-build-debug
../ninja.exe -k0 -j4 2>&1 | tee ../tmp/build_output.log
```

`-k0` 表示继续构建即使有失败，收集所有失败。

### 1.3 收集失败列表

```bash
# 提取所有失败的可执行文件目标
cat ../tmp/build_output.log | grep "FAILED: bin/" | sort -u

# 统计失败数量
cat ../tmp/build_output.log | grep "FAILED: bin/" | sort -u | wc -l
```

### 1.4 收集每个目标的详细错误

对每个失败目标单独构建获取详细错误：

```bash
cd /d/Projects/ClionProjects/mock/appdata_master_mock/cmake-build-debug

# 示例：获取 CloudDataTest 的详细错误
../ninja.exe bin/CloudDataTest 2>&1 | tail -50
```

建议用脚本批量收集：

```bash
for target in $(cat ../tmp/build_output.log | grep "FAILED: bin/" | sed 's/FAILED: //' | sort -u); do
    echo "===== $target ====="
    ../ninja.exe $target 2>&1 | grep -E "error:|undefined reference" | head -20
    echo ""
done
```

---

## 步骤 2: 分类与根因分析

根据历史经验，编译失败可分为以下几大模式，按优先级排序：

### 模式分类表

| 优先级 | 模式 | 典型错误信息 | 典型影响范围 | 修复方法 |
|--------|------|------------|-------------|---------|
| P0 | Feature 隔离 | `utd_notifier.h` not found | 2-3 个 | `if(BUILD_UDMF)` 包裹 |
| P0 | Include 路径缺失 | `No such file or directory` | 10-20 个 | 添加 include_directories |
| P1 | 头文件遮蔽冲突 | `BackupManager` 未声明 / `XCollie` 命名空间错误 | 3-6 个 | `BEFORE` include 优先级 |
| P1 | Mock API 缺失 | `AtmToolsParamInfo` 未声明 | 2-4 个 | 补充 mock 头文件/源文件 |
| P2 | 符号重定义 | `IsSystemAppByFullTokenID` 多次定义 | 4-6 个 | 删除 mock 重复定义或 weak 属性 |
| P2 | 链接失败 | `undefined reference to XXX` | 5-10 个 | 添加缺失 .cpp 源文件或链接库 |
| P2 | 枚举/类型重定义 | `SoftBusErrNo` 多次定义 | 2 个 | include guard 或 BEFORE |
| P3 | C++ 标准版本 | `std::filesystem` 不可用 | 2-3 个 | target_compile_features C++17 |
| P3 | 系统头文件缺失 | `waitpid` 未声明 | 1-2 个 | 添加 `#include <sys/wait.h>` |
| P3 | 模板 ODR 冲突 | 链接时重复模板实例化 | 1-2 个 | `__attribute__((weak))` |
| P4 | 源码修改 | 测试文件需要适配新接口 | 1-3 个 | 修改测试源文件 |

---

## 步骤 3: 分优先级批量修复

### 修复 P0: Feature 隔离

某些测试目标依赖特定 feature（如 UDMF），这些 feature 默认不编译。用条件编译包裹。

**修改文件**: `test/datamgr_service/service/service_misc_tests.cmake`

```cmake
# 将 Utd 相关测试用 BUILD_UDMF 保护
if(BUILD_UDMF OR BUILD_ALL)
    add_executable(UtdServiceImplTest ...)
    add_test(NAME UtdServiceImplTest COMMAND UtdServiceImplTest)
endif()
```

### 修复 P0: Include 路径缺失

上游新增了 `#include` 但本地 CMake 没有对应的 include 路径。

**典型缺失路径及对应头文件**:

| 缺失头文件 | 实际位置 | 需添加的路径 |
|-----------|---------|------------|
| `ikvstore_data_service.h` | `kv_store/frameworks/innerkitsimpl/distributeddatasvc/include/` | 在 service/CMakeLists.txt 中全局添加 |
| `bootstrap.h` | `service/bootstrap/include/` | 各 target 的 include_directories |
| `backup_manager.h` | `service/backup/include/` | 各 target 的 include_directories（注意遮蔽冲突） |
| `device_matrix.h` | `service/matrix/include/` | 各 target 的 include_directories |
| `common_types.h` | `relational_store/interfaces/inner_api/common-type/include/` | 各 target 的 include_directories |

**最优做法**: 在各子目录的 `CMakeLists.txt` 中用 `include_directories()` 全局添加公共路径，避免每个 target 重复添加。

### 修复 P1: 头文件遮蔽冲突

**问题**: 全局 mock 和测试 mock 有同名头文件但内容不同。

典型案例：
- 全局 mock 的 `backup_manager.h`（命名空间 `OHOS::DistributedKv`）
- 服务层的 `service/backup/include/backup_manager.h`（命名空间 `OHOS::DistributedData`）
- 全局 mock 的 `device_manager.h`（缺少 `Online/Offline/OnChanged/OnReady` 方法）
- 测试 mock 的 `adapter/communicator/test/mock/device_manager/device_manager.h`（有完整方法）

**修复**: 使用 `BEFORE` 提高目标特定路径的搜索优先级：

```cmake
target_include_directories(TestName BEFORE PRIVATE
    ${SERVICE_PATH}/backup/include     # 服务层头文件优先
    ${SERVICE_PATH}/common             # XCollie 等本地定义
    ${ADAPTER_PATH}/test/mock/device_manager  # 完整的 DeviceManager mock
)
```

对于 `XCollie` 命名空间问题，在 service 层的 `CMakeLists.txt` 中：

```cmake
# 确保 service/common 在 mock 的 xcollie 路径之前
include_directories(BEFORE ${SERVICE_PATH}/common)
```

### 修复 P1: Mock API 缺失

上游代码使用了 mock 中不存在的类型或方法。

**案例 1: `AtmToolsParamInfo`**

在 `mock/innerkits/access_token/libaccesstoken_sdk/include/accesstoken_kit.h` 中：

```cpp
// 注意：结构体必须定义在 AccessTokenKit 类之前！
struct AtmToolsParamInfo {
    std::string processName;
};

class AccessTokenKit {
    // ... 现有方法 ...
    static void DumpTokenInfo(const AtmToolsParamInfo& info, std::string& dumpInfo);
};
```

同时在 `mock/src/mock_access_token.cpp` 中添加实现。

**案例 2: `ConfigFactory` 缺少方法**

在 `datamgr_service/.../service/test/mock/config_factory_mock.cpp` 中添加：

```cpp
std::vector<AutoSyncAppConfig> *ConfigFactory::GetAutoSyncAppConfig() { return nullptr; }
AppAccessCheckConfig *ConfigFactory::GetSyncAppsConfig() { return nullptr; }
```

**案例 3: 在 `mock/src/` 中创建补充 mock 文件**

如果上游 mock 声明了方法但没有实现，可以在 `mock/src/` 下创建补充文件（如 `mock_config_factory.cpp`），使用前向声明提供空实现。这些文件会被 `aux_source_directory` 自动选中加入 mock 库，避免修改上游 mock 文件。

### 修复 P2: 符号重定义

**问题**: mock 头文件中有 inline 定义，测试 mock 的 `.cpp` 又有 out-of-line 定义。

**修复方法 A**（优先）: 删除测试 mock `.cpp` 中的重复定义。

**修复方法 B**: 如果不能删除（其他测试依赖），用 `__attribute__((weak))`：

```cpp
// meta_data_manager_mock.cpp 中
template<>
__attribute__((weak)) bool OHOS::DistributedData::MetaDataManager::LoadMeta(
    const std::string &prefix, std::vector<StoreMetaData> &values, bool isLocal)
{
    return BMetaData<StoreMetaData>::metaDataManager->LoadMeta(prefix, values, isLocal);
}
```

**修复方法 C**: 在测试目标的 CMake 中添加链接器标志：

```cmake
set_target_properties(TargetName PROPERTIES LINK_FLAGS "-Wl,--allow-multiple-definition")
```

此方法适用于真实源文件和 mock 文件都定义了相同模板实例化的情况（如 `MetaDataManager::LoadMeta`），避免修改上游代码。

### 修复 P2: 链接失败

**问题**: 编译成功但链接时找不到符号定义。

**诊断方法**:

```bash
# 查看具体缺失的符号
../ninja.exe bin/TargetName 2>&1 | grep "undefined reference"
```

**常见原因与修复**:

| 缺失符号 | 原因 | 修复 |
|----------|------|------|
| `QueryHelper::*` | 源文件未加入 target | 添加 `query_helper.cpp` 到 add_executable |
| `Bootstrap::GetInstance` | 同上 | 添加 `bootstrap.cpp` |
| `vtable for NetworkDelegateMock` | mock 类有虚函数但没实现 | 添加 `network_delegate_mock.cpp` |
| `vtable for DBStoreMock` | 同上 | 添加 `db_store_mock.cpp` + `db_change_data_mock.cpp` |
| `vtable for CursorMock` | 同上 | 添加 `cursor_mock.cpp` |
| `ConfigFactory::GetAutoSyncAppConfig` | 上游 mock 声明未实现 | 在 `mock/src/` 创建补充 mock 文件 |

### 修复 P3: C++ 标准版本

```cmake
# 在目标的 cmake 中覆盖全局 C++14 设置
target_compile_features(TestName PRIVATE cxx_std_17)
```

### 修复 P3: 系统头文件缺失

```cpp
// 在测试 .cpp 文件顶部添加
#include <sys/wait.h>
```

### 修复 P4: 源码适配

当上游接口变更导致测试代码不兼容时，修改测试源文件。

例如：`ValueObject` 初始化歧义

```cpp
// 旧代码（歧义）
ValueObject({asset1, asset2})

// 修复（显式类型）
ValueObject(Assets{asset1, asset2})
```

---

## 步骤 4: 迭代验证

### 4.1 每轮修复后验证

```bash
cd /d/Projects/ClionProjects/mock/appdata_master_mock/cmake-build-debug

# 重新配置（如果改了 CMake 文件）
cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_MAKE_PROGRAM="../ninja.exe" ..

# 构建
../ninja.exe -k0 -j4 2>&1 | tee ../tmp/build_output.log

# 统计失败数
cat ../tmp/build_output.log | grep "FAILED: bin/" | sort -u | wc -l
```

### 4.2 只关注可执行文件失败

中间 `.o` 文件编译失败可以忽略，只要最终 `bin/` 目录下的可执行文件都成功：

```bash
# 只看 bin/ 下的失败
cat ../tmp/build_output.log | grep "FAILED: bin/" | sort -u

# 对比 .o 和 bin 失败
echo "中间 .o 失败数:"
cat ../tmp/build_output.log | grep "FAILED:" | grep -v "bin/" | sort -u | wc -l

echo "可执行文件失败数:"
cat ../tmp/build_output.log | grep "FAILED: bin/" | sort -u | wc -l
```

### 4.3 历史进度参考

| 阶段 | 失败数 | 操作 |
|------|--------|------|
| 初始 | 83 | 应用 -fno-access-control 和条件编译 |
| 第一轮 | 41 | 修复 include 路径和简单编译错误 |
| 第二轮 | 36 | 修复 XCollie、waitpid 等 |
| 第三轮 | 20 | 详细分类，逐模式修复 |
| 第四轮 | 0 (executable) | 所有可执行文件编译通过 |

---

## 高级修复模式

### 模式 A: 内联编译（Inline Compilation）

**场景**: 测试需要使用自己的 mock 版本，而全局库中的 mock 是 stub。

**做法**: 不链接全局库，而是将需要的 `.cpp` 文件直接编译进测试目标。

```cmake
# ScreenLockTest: 需要 mock 的 CommonEventManager（有订阅者追踪）
# 而不是 adapter 库中的 stub CommonEventManager

add_executable(ScreenLockTest
    ${ADAPTER_PATH}/screenlock/test/screen_lock_test.cpp
    ${ADAPTER_PATH}/screenlock/screen_lock.cpp           # 内联编译
    ${ADAPTER_PATH}/test/mock/mock_common_event.cpp      # 内联编译
)
target_include_directories(ScreenLockTest BEFORE PRIVATE
    ${ADAPTER_PATH}/test/mock   # mock_common_event.h 优先
    ${ADAPTER_PATH}
)
target_link_libraries(ScreenLockTest PRIVATE svcFwk mock gtest_main)
# 注意：不链接 adapter 库
```

### 模式 B: BEFORE Include 优先级

**场景**: 多个目录有同名头文件，需要控制搜索顺序。

```cmake
# BEFORE 使得目标特定路径在全局 include_directories 之前搜索
target_include_directories(TestName BEFORE PRIVATE
    ${SERVICE_PATH}/backup/include     # 优先找服务层的 backup_manager.h
)
```

### 模式 C: 弱符号解决模板冲突

**场景**: 模板显式特化在两个翻译单元中都有定义。

```cpp
// mock 文件中用 weak 属性
template<>
__attribute__((weak)) bool MetaDataManager::LoadMeta(
    const std::string &prefix, std::vector<StoreMetaData> &values, bool isLocal)
{
    // ...
}
```

### 模式 D: 在 `mock/src/` 创建补充实现文件

**场景**: 上游 mock 头文件声明了方法（前向声明），但对应的 `.cpp` 未实现，导致链接时 `undefined reference` 或 `vtable` 错误。

**做法**: 在 `mock/src/` 目录下创建新文件（如 `mock_config_factory.cpp`、`mock_auth_handler.cpp`），使用上游头文件中的前向声明，提供空实现。这些文件会被 mock 库的 `aux_source_directory` 自动选中，无需修改 CMake 或上游代码。

**适用条件**:
- 上游头文件已声明了类/方法（前向声明或类声明可访问）
- 仅需提供空/默认实现即可满足链接
- 不需要向上游 mock 目录添加 include 路径

### 模式 E: 上游移除方法后 mock 文件过时（同步后常见）

**场景**: 上游头文件移除了某个方法声明（如 `SetSearchTrigger`），但 `mock/src/` 中仍有该方法的实现文件。编译报错 `no declaration matches`。

**诊断**:
```bash
# 搜索上游头文件是否仍有该方法声明
grep -rn "MethodName" relational_store/ kv_store/ datamgr_service/
# 如果没有结果，说明上游已移除该方法

# 搜索是否有其他代码引用
grep -rn "MethodName" --include="*.cpp" --include="*.h" . | grep -v "mock/src/mock_xxx.cpp"
# 如果没有其他引用，说明 mock 文件是死代码
```

**做法**: 直接删除过时的 mock 文件。`mock/src/` 使用 `aux_source_directory` 自动收集 `.cpp`，删除文件后无需修改 CMake。

**典型案例**: 2026-09-13 同步后，上游从 `rdb_store.h` 移除了 `SetSearchTrigger(bool)`，`mock/src/mock_rdb_store.cpp` 报 `no declaration matches` 错误。删除该文件即可。

**规律**: 每次上游同步后，如果上游移除了虚方法或接口方法，检查 `mock/src/` 中是否有对应的补充实现文件。这类文件通常是为了提供 linker symbol 而创建的，方法被移除后就变成了死代码。

---

## 关键文件索引

### CMake 配置文件

| 文件 | 职责 |
|------|------|
| `CMakeLists.txt` | 根配置，全局编译选项 |
| `test/CMakeLists.txt` | 测试全局配置，include_directories |
| `test/datamgr_service/CMakeLists.txt` | datamgr_service 测试入口 |
| `test/datamgr_service/adapter/*.cmake` | adapter 层测试目标 |
| `test/datamgr_service/app/*.cmake` | app 层测试目标 |
| `test/datamgr_service/service/*.cmake` | service 层测试目标 |
| `test/datamgr_service/framework/*.cmake` | framework 层测试目标 |

### Mock 文件

| 文件 | 职责 |
|------|------|
| `mock/innerkits/access_token/libaccesstoken_sdk/include/accesstoken_kit.h` | AccessToken mock（含 AtmToolsParamInfo） |
| `mock/src/mock_access_token.cpp` | AccessToken mock 实现 |
| `mock/src/mock_notification.cpp` | CommonEventManager 全局 stub |
| `mock/src/mock_config_factory.cpp` | ConfigFactory 补充实现（mock/src 新建） |
| `mock/src/mock_auth_handler.cpp` | AuthHandler vtable 补充实现（mock/src 新建） |
| `datamgr_service/.../service/test/mock/config_factory_mock.cpp` | ConfigFactory mock（上游） |
| `datamgr_service/.../service/test/mock/meta_data_manager_mock.cpp` | MetaDataManager mock |
| `datamgr_service/.../adapter/test/mock/mock_common_event.h` | 测试用 CommonEventManager |

### 公共库链接

| 库名 | CMake target | 提供内容 |
|------|-------------|---------|
| `svcFwk` | framework 库 | 框架层接口和实现 |
| `service` | 服务层库 | 服务层接口和实现 |
| `adapter` | 适配器库 | 适配器实现（含全局 stub） |
| `mock` | mock 库 | 全局 mock（IPC, 安全, 通知等） |
| `distributeddb` | 分布式数据库 | DistributedDB |
| `gtest_main` | Google Test | 测试框架主函数 |
| `gmock_main` | Google Mock | Mock 框架主函数 |

---

## 快速启动命令（给 AI Agent 的 Prompt）

下次同步后，可以直接给 AI Agent 以下指令：

```
上游代码已同步完成，请执行以下编译修复流程：

1. 全量构建并收集失败列表：
   cd /d/Projects/ClionProjects/mock/appdata_master_mock
   "D:/Projects/ClionProjects/mock/appdata_master_mock/ninja.exe" -C cmake-build-debug -k0 -j4 2>&1 | tee build_output.log

2. 统计失败数：
   grep "FAILED:" build_output.log | sort -u | wc -l
   grep "FAILED: bin/" build_output.log | sort -u

3. 对每个失败目标收集详细错误：
   cd cmake-build-debug
   ../ninja.exe bin/TargetName 2>&1 | grep -E "error:|undefined reference"

4. 按以下模式分类修复（参考本文件）：
   P0: Feature 隔离（BUILD_UDMF 等）
   P0: Include 路径缺失
   P1: 头文件遮蔽冲突（BEFORE include）
   P1: Mock API 缺失
   P1: 上游移除方法后 mock 文件过时（模式 E）
   P2: 符号重定义
   P2: 链接失败（添加 .cpp 源文件）
   P3: C++ 标准版本 / 系统头文件
   P4: 源码适配

5. 每轮修复后重新构建验证，直到 bin/ 下 0 个失败。

6. 构建成功后运行测试：
   cd cmake-build-debug
   # 确保测试环境目录存在
   mkdir -p ../data/service/el1/public/database/distributeddata/meta/backup
   mkdir -p ../data/service/el1/public/database/distributeddata/kvdb
   mkdir -p ../data/service/el2/100/SingleStoreImplTest
   mkdir -p ../data/test ../system/etc/distributeddata/conf
   cp ../datamgr_service/conf/config.json ../system/etc/distributeddata/conf/
   ctest --output-on-failure -j1
```

### 约束提醒

- **不允许修改上游代码**。修复只能通过 `mock/`、`test/`、`CMakeLists.txt` 进行。
- **编译单元尽量与上游 GN 保持一致**。CMake 配置应映射上游 GN 的 `sources` 列表。
- **优先使用 mock_compat.h**。缺失标准库头文件时，在 `mock/include/mock_compat.h` 中添加（全局 force-include），而非逐文件修改。
- **使用 -fno-access-control**。需要访问私有成员时用此编译选项，不用 `-Dprivate=public` 宏。

---

## 注意事项

1. **不要修改上游源文件**（除非是测试文件适配）。优先修改 CMake 配置和 mock 文件。
2. **保持 mock 和测试目录在同步时受保护**。`bin/update/update_config.json` 已配置。
3. **修复顺序很重要**。高优先级修复可能一次解决多个目标。
4. **小心 `BEFORE` 的副作用**。改变 include 搜索顺序可能影响其他头文件的解析。
5. **mock 头文件修改影响全局**。修改 `accesstoken_kit.h` 等全局 mock 头文件会影响所有依赖它的目标，确保结构体定义在类使用它之前。
6. **中间 .o 失败可以忽略**。只要 `bin/` 下可执行文件全部成功，中间 .o 的编译失败不影响测试运行。

---

## 补充经验：实际踩坑与技巧

### 1. 全局 mock 头文件修改的致命陷阱

**案例**: 修改 `accesstoken_kit.h` 添加 `AtmToolsParamInfo` 结构体时，将其放在了 `AccessTokenKit` 类**之后**。

**后果**: 类方法声明使用了尚未定义的类型，导致 **所有链接 mock 库的目标全部失败**（从 20 个失败暴涨到 ~100 个）。

**规则**: 在 mock 头文件中添加新类型时，**必须在类定义之前声明**。修改全局 mock 头文件后立即执行全量构建验证。

**验证命令**:
```bash
# 修改全局 mock 后，立即检查影响面
../ninja.exe -k0 -j4 2>&1 | grep "FAILED:" | sort -u | wc -l
# 如果数量暴增，回滚全局 mock 修改
```

### 2. Mock 有两层：全局 stub vs 测试专用 mock

项目中存在两套 mock，容易混淆：

| Mock 类型 | 位置 | 特点 | 示例 |
|-----------|------|------|------|
| **全局 mock (stub)** | `mock/src/` | 所有方法返回 false/空，最小实现 | `mock/src/mock_notification.cpp` 中的 `CommonEventManager` |
| **测试 mock (完整)** | `*/test/mock/` | 有完整状态追踪、可编程行为 | `adapter/test/mock/mock_common_event.h` 中的 `CommonEventManager` |

**关键区别**: 全局 mock 的 `CommonEventManager` 所有方法返回 false（订阅永远失败），测试 mock 有 `subscribers_` 列表和事件发布功能。

**如何选择**:
- 大多数测试：链接全局 mock（通过 `mock` 库）即可
- 需要完整 mock 行为的测试：**内联编译**测试 mock 的 `.cpp`，不链接包含全局 stub 的库

### 3. 同名头文件遮蔽的完整清单

以下是已知的同名头文件冲突，新测试目标如果同时引用了这些头文件，需要用 `BEFORE`：

| 头文件名 | 全局 mock 版本（命名空间） | 服务层版本（命名空间） | 需要优先的版本 |
|----------|--------------------------|---------------------|--------------|
| `backup_manager.h` | `kv_store/.../backup_manager.h` (`OHOS::DistributedKv`) | `service/backup/include/backup_manager.h` (`OHOS::DistributedData`) | 服务层 |
| `device_manager.h` | mock 版本（缺 `Online/Offline` 等方法） | `adapter/communicator/test/mock/device_manager/device_manager.h` | 测试 mock |
| `xcollie.h` | mock 的 `xcollie/xcollie.h` (`OHOS::HiviewDFX::XCollie`) | `service/common/xcollie.h` (`OHOS::DistributedData::XCollie`) | 服务层（用 BEFORE） |
| `softbus_error_code.h` | mock 版本 | adapter test mock 版本 | 用 BEFORE 或 include guard |

### 4. 常见 vtable 链接失败的根因和依赖链

当看到 `vtable for XXXMock` 未定义错误时，说明 mock 类声明了虚函数但没有实现。

**已知的 mock vtable 依赖链**:

```
DBStoreMock（需要 db_store_mock.cpp）
  └── 依赖 DBChangeDataMock（需要 db_change_data_mock.cpp）

NetworkDelegateMock（需要 network_delegate_mock.cpp）
  └── 可能也依赖 db_store_mock.cpp

CursorMock（需要 cursor_mock.cpp）
  └── 独立，无额外依赖
```

**规律**: `db_store_mock.cpp` 和 `db_change_data_mock.cpp` 经常需要成对添加。

### 5. Feature Flag 在 CMake 和测试中的对应关系

| GN Flag | CMake 变量 | 影响的测试文件 |
|---------|-----------|--------------|
| `datamgr_service_udmf` | `BUILD_UDMF` | `service_udmf_tests.cmake`，`service_misc_tests.cmake` 中的 Utd 测试 |
| `datamgr_service_data_share` | `BUILD_DATA_SHARE` | `service_data_share_tests.cmake`，`CloudTest` |
| `datamgr_service_object` | `BUILD_DATA_OBJECT` | `service_object_tests.cmake`，`NativeRdbTest` |
| - | `BUILD_ALL` | 启用以上所有 |

**用法**: 在 `service/CMakeLists.txt` 中用 `if(BUILD_UDMF OR BUILD_ALL)` 包裹可选 feature 的测试。

### 6. 代码重构后的目录迁移处理

上游可能将代码从一层移到另一层（如 clone 从 `app/src/clone/` 移到 `service/clone/`）。这种情况下：

1. **服务层 CMakeLists.txt** 需要添加新的 `aux_source_directory` 和 `include_directories`
2. **App 层 CMakeLists.txt** 需要注释掉旧的引用（如 `distributeddata_clone`）
3. **Git 状态** 会显示 `R`（rename）标记，如 `RM app/src/clone/clone_backup_info.cpp -> service/clone/clone_backup_info.cpp`
4. **Include 路径** 需要从 `${APP_PATH}/src/clone` 改为 `${SERVICE_PATH}/clone`

### 7. `test/CMakeLists.txt` 的遗留代码和排除列表

`test/CMakeLists.txt` 包含一些遗留的大型测试（`DataMgrServiceTest` 等），使用 `aux_source_directory` 收集源文件。其中有排除列表：

```cmake
# 这些 mock 文件有特殊依赖，不能被 aux_source_directory 盲目收集
list(REMOVE_ITEM DataMgrTestSrc ".../preprocess_utils_mock.cpp")
list(REMOVE_ITEM DataMgrTestSrc ".../distributed_file_daemon_manager_mock.cpp")
list(REMOVE_ITEM DataMgrTestSrc ".../access_token_mock.cpp")  # 与全局 mock 冲突
list(REMOVE_ITEM DataMgrTestSrc ".../data_share_sa_config_info_manager_mock.cpp")
```

**注意**: 如果上游新增了 mock 文件到 `service/test/mock/` 目录，这些文件会被 `aux_source_directory` 自动收集。如果新文件与全局 mock 冲突，需要添加到排除列表。

### 8. 诊断编译错误的高效方法

**第一步: 区分编译错误 vs 链接错误**

```bash
# 编译错误（.cpp → .o 失败）
../ninja.exe bin/TargetName 2>&1 | grep "error:"

# 链接错误（.o → 可执行文件失败）
../ninja.exe bin/TargetName 2>&1 | grep "undefined reference"
```

**第二步: 查找缺失符号的来源**

```bash
# 在代码库中搜索符号定义
grep -r "void ClassName::MethodName" --include="*.cpp" .
# 或用 Grep 工具搜索 "class MockName"
```

**第三步: 确认头文件搜索路径**

```bash
# 查看 CMake 实际的 include 路径（编译命令中）
../ninja.exe -t commands bin/TargetName | grep "\-I" | tr ' ' '\n' | grep "^-I" | sort -u
```

### 9. 编译选项 `-fno-access-control` 的位置

全局 `-fno-access-control` 已设置在 `test/CMakeLists.txt`:
```cmake
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-access-control")
```

**不需要**在单个测试 target 中重复设置。如果看到 `private member access` 错误，说明该 target 没有继承全局 flags（比如没有 `add_executable` 在 `test/` 的子目录中），此时才需要单独添加。

### 10. 同步后需要检查的新文件类型

上游同步可能新增以下类型的文件，每种都有对应的处理方式：

| 新增文件类型 | 位置 | 需要的操作 |
|-------------|------|-----------|
| 新 `.cpp` 在 service 层 | `service/*/` | 检查是否被 `aux_source_directory` 自动包含 |
| 新 `.cpp` 在 app 层 | `app/src/` | 检查是否需要加入 `appSrc` 列表 |
| 新 mock 文件 | `service/test/mock/` | 检查是否需要加入排除列表（与全局冲突） |
| 新 BUILD.gn 测试 | `*/test/BUILD.gn` | 需要创建对应的 `.cmake` 文件 |
| 新头文件引用 | 任何位置 | 确认 include 路径已在 CMake 中配置 |
| 新 shared library | `service/clone/BUILD.gn` | 需要创建对应的 CMake target |

---

## 全局 Include 路径速查

以下路径已在各层 CMakeLists.txt 中全局配置，**不需要**在每个 target 中重复添加：

### test/CMakeLists.txt（所有测试继承）

```cmake
include_directories(${CMAKE_SOURCE_DIR}/utils_native/base/include)
include_directories(${CMAKE_SOURCE_DIR}/utils_native/safwk/native/include)
include_directories(${MOCK_DIR}/src/)
include_directories(${MOCK_DIR}/sqlite/include)
include_directories(${KV_STORE_DIR}/frameworks/common)
include_directories(${KV_STORE_DIR}/interfaces/innerkits/distributeddata/include)  # executor_pool.h
include_directories(${CMAKE_SOURCE_DIR}/googletest/googletest/include)
include_directories(${CMAKE_SOURCE_DIR}/googletest/googlemock/include)
```

### test/datamgr_service/service/CMakeLists.txt（service 测试继承）

```cmake
# ikvstore_data_service.h
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../../kv_store/frameworks/innerkitsimpl/distributeddatasvc/include)
# XCollie 本地定义（BEFORE mock）
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/../../../datamgr_service/services/distributeddataservice/service/common)
```

### test/datamgr_service/app/CMakeLists.txt（app 测试继承）

```cmake
# 同上两个全局 include
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../../kv_store/frameworks/innerkitsimpl/distributeddatasvc/include)
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/../../../datamgr_service/services/distributeddataservice/service/common)
```

### service 库（链接时自动获得 PUBLIC include）

```cmake
target_include_directories(service PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/kvdb
    ${CMAKE_CURRENT_SOURCE_DIR}/rdb
    ${CMAKE_CURRENT_SOURCE_DIR}            # service/ 根目录
    ${CMAKE_CURRENT_SOURCE_DIR}/dumper/include
    ${CMAKE_CURRENT_SOURCE_DIR}/network
    ${CMAKE_CURRENT_SOURCE_DIR}/permission/include
)
```

### mock 库（链接时自动获得 PUBLIC include）

包含 `mock/src/`, `mock/include/`, 以及所有 `mock/innerkits/*/include` 路径。

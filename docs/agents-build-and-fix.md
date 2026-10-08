# 本地编译及编译修复

## 前置条件

- CMake 3.11.2 或更高版本
- C++17 兼容的编译器（测试需要 C++20）
- Cygwin 环境（Windows）
- Google Test 框架（已包含在仓库中）

## 构建项目

**强制要求：**
1. **始终使用 `cmake-build-debug` 作为调试构建目录名称。** 禁止使用 `build` 或其他名称。
2. **CMake 配置必须使用 Ninja 生成器（`-G Ninja`）。**
3. **所有构建必须使用项目根目录的 `ninja.exe`。**

```bash
# 创建调试构建目录并配置（仅首次执行）
mkdir -p cmake-build-debug
cd cmake-build-debug
cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_MAKE_PROGRAM="D:/Projects/ClionProjects/mock/appdata_master_mock/ninja.exe" \
  ..

# 构建所有组件（方式一：在 build 目录中）
cd cmake-build-debug
../ninja.exe -j16

# 构建所有组件（方式二：从项目根目录，推荐）
./ninja.exe -C cmake-build-debug -j16

# 构建特定目标
./ninja.exe -C cmake-build-debug -j16 <target_name>
```

> **注意：**
> - `CMAKE_MAKE_PROGRAM` 必须使用 Windows 风格绝对路径，不能使用相对路径或 Cygwin 路径（`/cygdrive/d/...`）。
> - `-C cmake-build-debug` 等效于先 `cd cmake-build-debug` 再执行，无需改变工作目录。
> - 首次配置后，后续增量构建只需 `./ninja.exe -C cmake-build-debug -j16`。
> - **并行度选择**：默认使用 `RelWithDebInfo` 构建类型（`-O2 -g -DNDEBUG`），每个编译进程消耗 ~300MB 内存，16 核机器可安全使用 `-j16`。若切换为 `Debug` 构建类型（`-g` 无优化），每进程消耗 300-800MB，需降至 `-j4` 避免 OOM（exit code 137）。

## 使用项目根目录 Ninja

**强制要求：所有构建（CLion IDE 和命令行）必须使用项目根目录中的 `ninja.exe`：**

```
D:\Projects\ClionProjects\mock\appdata_master_mock\ninja.exe
```

**版本一致性要求（关键）：** 项目根目录的 `ninja.exe` 必须与 CLion 自带的 Ninja 完全相同的版本（当前 1.12.1），否则 `cmake-build-debug` 目录无法在 IDE 和命令行之间共用，出现 `build.ninja version mismatch` 告警。每次升级 CLion 后必须重新复制：

```bash
# Cygwin shell:
cp "/cygdrive/c/Program Files/JetBrains/CLion 2025.3.2/bin/ninja/cygwin/x64/ninja.exe" \
   /cygdrive/d/Projects/ClionProjects/mock/appdata_master_mock/ninja.exe

# Git Bash 等效命令:
cp "/c/Program Files/JetBrains/CLion 2025.3.2/bin/ninja/cygwin/x64/ninja.exe" \
   /d/Projects/ClionProjects/mock/appdata_master_mock/ninja.exe

# 验证版本一致性
./ninja.exe --version          # 应输出 1.12.1
```

<details>
<summary>CLion IDE 配置（点击展开）</summary>

CLion 默认自动使用 Ninja，打开项目即可。如需手动配置 CMake options：

```
-DCMAKE_MAKE_PROGRAM=${ProjectFileDir}/ninja.exe
-G Ninja
```

设置路径：`File → Settings (Ctrl+Alt+S) → Build, Execution, Deployment → CMake`

重新加载后验证 `cmake-build-debug/CMakeCache.txt`：

```bash
grep CMAKE_MAKE_PROGRAM CMakeCache.txt   # 应显示 ninja.exe 路径
grep CMAKE_GENERATOR CMakeCache.txt      # 应显示 Ninja
```

> **注意**：如果 CLion 自动配置了项目（未手动运行上述 `cmake` 命令），`CMAKE_MAKE_PROGRAM` 会显示 CLion 自带的 ninja 路径（如 `/cygdrive/c/Program Files/JetBrains/CLion.../ninja.exe`）。只要版本与项目根目录的 `ninja.exe` 一致（当前 1.12.1），构建即可正常工作。若出现 `build.ninja version mismatch` 告警，按上方说明重新复制 ninja.exe。

</details>

## 全量构建与失败收集

同步上游代码后，需要全量构建收集所有编译失败：

```bash
# 从项目根目录构建（推荐）
./ninja.exe -C cmake-build-debug -k0 -j16 2>&1 | tee tmp/build_output.log

# 或从 build 目录构建
cd cmake-build-debug
../ninja.exe -k0 -j16 2>&1 | tee ../tmp/build_output.log
```

`-k0` 表示即使有失败也继续构建，收集所有失败目标。然后提取失败列表：

```bash
# 提取所有失败的目标
grep "FAILED:" tmp/build_output.log | sort -u

# 只看可执行文件失败
grep "FAILED: bin/" tmp/build_output.log | sort -u

# 统计失败数量
grep "FAILED:" tmp/build_output.log | sort -u | wc -l

# 对每个失败目标收集详细错误
./ninja.exe -C cmake-build-debug bin/<TargetName> 2>&1 | grep -E "error:|undefined reference" | head -20
```

> 同步后如果构建失败，只能通过修改 `mock/` 目录来适配，**不能修改上游源码**。完整的编译失败分类与修复流程见 [编译修复流程](./build_and_fix_workflow.md)，历史记录见 [编译失败历史记录](./build_failures.md)。

## 编译单元结构

详细编译单元总览（模块层次、依赖关系、目标清单）见 [编译单元结构](./build_structure.md)。

### 构建输出

- 主可执行文件：`cmake-build-debug/bin/LDBProj`
- 测试可执行文件：`cmake-build-debug/bin/*.exe`（例如 NativeRdbTest.exe, RdbServiceTest.exe）。Windows 下所有可执行文件带 `.exe` 后缀。ninja 目标名不带后缀（如 `ninja NativeRdbTest`）。
- 库文件：`cmake-build-debug/lib/`
- 覆盖率报告：启用覆盖率时在 cmake-build-debug 目录中生成

### 可选模块编译开关

| 选项 | 默认 | 说明 |
|------|------|------|
| `BUILD_DATA_SHARE` | OFF | 数据共享组件 |
| `BUILD_PREFERENCES` | OFF | 首选项数据库 |
| `BUILD_DATA_OBJECT` | OFF | 分布式数据对象 |
| `BUILD_UDMF` | OFF | 用户数据管理框架 |
| `BUILD_INTERFACE_SDK` | OFF | interface_sdk 模块 |
| `BUILD_DATA_MINING` | OFF | Data Mining 客户端 SDK + 服务 |
| `BUILD_ALL` | OFF | 一键开启所有可选模块 |
| `BUILD_TESTS` | ON | 编译测试目标（ctest）。关闭后仅编译库，不编译测试可执行文件，显著缩短构建时间 |

始终编译的模块：`utils_native`、`mock`、`kv_store`、`relational_store`、`datamgr_service`。

### 构建调优选项

| 选项 | 默认 | 说明 |
|------|------|------|
| `COMPILE_JOBS` | 0 | 最大并发编译任务数（0 = 不限制，由 ninja `-j` 控制） |
| `LINK_JOBS` | 3 | 最大并发链接任务数。2→3 提速约 16%，3→4 提速约 7-12%（收益递减） |
| `ENABLE_STRIP_DEBUG` | OFF | 链接时 `-Wl,--strip-debug`，提速 40-44%，DLL 体积减少 70-85%。关闭后无法在 DLL 中设断点 |
| `ENABLE_COVERAGE` | OFF | 启用代码覆盖率插桩（`-ftest-coverage -fprofile-arcs`），仅在需要覆盖率报告时开启 |
| `ENABLE_PCH` | OFF | 启用预编译头（实验性），当前未在所有目标上验证 |

cmake 配置示例：

```bash
cmake -S . -B cmake-build-debug -DLINK_JOBS=3 -DENABLE_STRIP_DEBUG=OFF -DBUILD_TESTS=ON
```

## 编译修复原则

**核心约束：不能修改上游代码（`datamgr_service/`、`data_share/`、`relational_store/`、`kv_store/`、`data_object/`、`preferences/`、`udmf/`、`interface_sdk/`、`utils_native/` 中的非受保护文件）。** 只能通过以下方式修复编译问题：

1. **修改 `mock/` 目录** — 添加 mock 实现、头文件覆盖
2. **修改 `CMakeLists.txt`** — 调整编译选项、链接库
3. **修改 `test/` 目录** — 调整测试编译配置

### 常见编译失败模式

| 模式 | 症状 | 修复方式 |
|------|------|----------|
| 缺少头文件 | `fatal error: xxx.h: No such file` | 在 `mock/include/` 添加 mock 头文件 |
| 缺少符号实现 | `undefined reference to ...` | 在 `mock/src/` 添加 mock 实现 |
| 上游移除方法 | `no declaration matches ...` | 删除过时的 mock 文件（如 `mock_rdb_store.cpp`） |
| 私有成员访问 | `error: 'xxx' is private within this context` | 编译选项添加 `-fno-access-control` |
| 缺少标准库头 | `error: 'variant' not found` | `mock/include/mock_compat.h` 全局 force-include 补充 |

## GN 到 CMake 转换原则

**核心原则：CMake 配置必须与 GN 配置保持一致，便于后续同步和修改。** 完整的转换操作手册、检查清单和示例见 [`.skills/gn-to-cmake-test-converter/SKILL.md`](../.skills/gn-to-cmake-test-converter/SKILL.md)。

转换时必须遵守：

1. **禁止用 GLOB 自动收集源文件** — 必须手动列出所有 `.cpp`，与 GN `sources` 列表逐行对应。
2. **禁止用 `-Dprivate=public -Dprotected=public` 绕过访问控制** — 必须用 `-fno-access-control`。宏定义方式会导致 C++ 标准库内部类型（如 `std::basic_stringbuf::__xfer_bufptrs`）在不同翻译单元出现可访问性冲突，产生大量编译错误。
3. **禁止依赖 CMake 隐式依赖推断** — 必须显式 `target_link_libraries(... PRIVATE ...)` 声明所有依赖。
4. **保持源文件列表顺序与 GN 一致**，并添加注释说明 GN 来源（文件名、行号、优先级）。

### GN 到 CMake 关键映射

| GN 概念 | CMake 等价 | 说明 |
|---|---|---|
| `ohos_unittest` | `add_executable` + `add_test` | 测试目标 |
| `module_private_config` | `-fno-access-control` | 私有成员访问 |
| `distributeddatasvcfwk` | `svcFwk` | 框架库 |
| `external_deps`（大多数） | `mock` 库 | 外部依赖 |
| `ohos_source_set` | `OBJECT` 库 | 全局注册 |

### 常见测试场景

- **Framework 测试**：仅依赖 `svcFwk + mock`
- **带 checker 依赖**：用 `OBJECT` 库
- **带 distributeddb**：链接其库
- **带 mock**：建 `STATIC` 库

### OBJECT 库优化模式与 Mock 覆盖冲突

多个测试目标内联相同的实现源文件时，会重复编译相同的 .cpp 文件。使用 OBJECT 库（`add_library(... OBJECT ...)`）编译一次、链接多次，可消除冗余编译。

**基本模式：**

```cmake
# 编译一次，链接到所有需要实现源码的测试目标
add_library(rdb_impl_objs OBJECT ${RDB_COMMON_IMPL_SOURCES})
target_compile_options(rdb_impl_objs PRIVATE ${RDB_COMMON_COMPILE_OPTIONS})
# ... 各目标在 target_link_libraries 中链接 rdb_impl_objs
```

**Mock 覆盖冲突：** 当测试目标提供 mock 文件（如 `mock_global_resource.cpp`）覆盖 OBJECT 库中的真实实现（如 `global_resource.cpp`）时，两者定义相同符号，链接报 `multiple definition` 错误。

**⚠️ `--allow-multiple-definition` 不适用此场景：** OBJECT 库的 .o 文件在链接行中排在目标自身 .o 文件之前，链接器取第一个定义，会使用真实实现而非 mock，导致 mock 被静默忽略。该标志仅适用于 OBJECT 库与共享库共存的场景（如 `NativeRdbTest` 同时链接 `rdb_impl_objs` 和 `relational_store.dll`）。

**正确解法——拆分 per-file OBJECT 库：** 将被 mock 覆盖的文件从主 OBJECT 库中拆出，放入独立的 per-file OBJECT 库。各目标按需链接，提供 mock 的目标不链接对应的 per-file 库。

```cmake
# 主库：排除被 mock 覆盖的文件
set(RDB_IMPL_BASE_SOURCES ${RDB_COMMON_IMPL_SOURCES})
list(REMOVE_ITEM RDB_IMPL_BASE_SOURCES
    ${RELATIONAL_STORE_NATIVE_DIR}/rdb/src/global_resource.cpp  # 被 mock_global_resource.cpp 覆盖
    ${RELATIONAL_STORE_NATIVE_DIR}/rdb/src/share_block.cpp      # 被 mock_shared_block_test.cpp 覆盖
)
add_library(rdb_impl_objs OBJECT ${RDB_IMPL_BASE_SOURCES})

# 被覆盖文件各自一个 per-file 库，目标可选择性链接
add_library(rdb_impl_global_resource_obj OBJECT
    ${RELATIONAL_STORE_NATIVE_DIR}/rdb/src/global_resource.cpp)
add_library(rdb_impl_share_block_obj OBJECT
    ${RELATIONAL_STORE_NATIVE_DIR}/rdb/src/share_block.cpp)

# 不提供 mock 的目标 → 链接全部
target_link_libraries(NormalTest PRIVATE rdb_impl_objs rdb_impl_global_resource_obj rdb_impl_share_block_obj)

# 提供 mock 的目标 → 不链接被覆盖的 per-file 库
target_link_libraries(GlobalResourceTest PRIVATE rdb_impl_objs rdb_impl_share_block_obj)
#                                          ↑ 不链接 rdb_impl_global_resource_obj
```

**GN 对应关系：** GN 的 `sources -= [ "..." ]` 表示该测试用 mock 替换真实源文件。转换为 CMake 时，被移除的文件应从 OBJECT 库中拆出，不要链接到提供 mock 的目标。详见 [SKILL.md](../.skills/gn-to-cmake-test-converter/SKILL.md) 场景 5。

### 测试构建常见问题

| 问题 | 解决方案 |
|------|----------|
| 私有成员访问错误 | 编译选项添加 `-fno-access-control` |
| Checker 未注册 | 使用 `OBJECT` 库而不是 `STATIC` |
| 错误的令牌类型 | 将测试进程名称添加到 `mock_access_token.cpp` 的 `NativeName` 数组 |
| 缺少 include 头文件 | 在源文件中添加 `#include <variant>`、`<cstdint>` 等 |
| Mock 覆盖与 OBJECT 库符号冲突 | 拆分 per-file OBJECT 库，提供 mock 的目标不链接被覆盖的文件（见上方小节） |
| OBJECT 库与共享库符号重复 | 目标加 `set_target_properties(... LINK_FLAGS "-Wl,--allow-multiple-definition")` |

## 编译器标志

项目全局编译器标志（在根 `CMakeLists.txt` 中设置）：

- 禁用 RTTI：`-fno-rtti`
- 可见性：`-fvisibility=default`
- GNU 扩展：`-D_GNU_SOURCE`
- 位置无关代码：`-fPIC -fpic`
- 数据/函数节：`-fdata-sections -ffunction-sections`
- 覆盖率：`-fprofile-arcs -ftest-coverage`（用于测试）
- 全局 force-include：`mock/include/mock_compat.h`（在 `add_subdirectory` 之前设置）

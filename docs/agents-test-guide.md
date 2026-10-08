# 用例运行与修复

## 环境设置

运行测试前，确保所需的目录存在：

```bash
./bin/install.bat    # 创建测试所需的目录结构（交互式，需输入 Cygwin 路径）
./bin/clear.bat      # 清理测试数据
```

> **`install.bat` 需要交互输入 Cygwin 安装路径。** 在自动化环境或无法交互时，手动创建目录：

```bash
# 非交互式创建测试所需目录
mkdir -p data/service/el1/public/database/distributeddata/meta/backup
mkdir -p data/service/el1/public/database/distributeddata/kvdb
mkdir -p data/service/el2/100/SingleStoreImplTest
mkdir -p data/test system/etc/distributeddata/conf
cp datamgr_service/conf/config.json system/etc/distributeddata/conf/
```

所需的目录结构：

| 目录 | 用途 |
|-----|------|
| `system/etc/distributeddata/conf/` | 配置文件（含 `config.json`） |
| `data/service/el1/public/database/distributeddata/meta/backup` | 元数据存储 |
| `data/service/el1/public/database/distributeddata/kvdb` | KV 数据库存储 |
| `data/service/el2/100/SingleStoreImplTest` | 单存储测试数据 |
| `data/test/` | 测试数据 |

> **不创建上述目录会导致依赖目录的测试失败。**

## 运行所有测试

```bash
cd cmake-build-debug
ctest --output-on-failure -j1
# 注意：必须使用 -j1，并行执行会导致 SQLite 文件锁冲突和 SegFault
```

> **预期测试结果**：当前约 50% 通过。通过的测试覆盖单元测试、mock 测试和核心功能测试。失败项集中在 RDB 集成测试（SEGFAULT/Timeout）和云同步测试（CloudData），这些失败是 mock 环境限制而非编译问题。

## 运行特定测试套件

```bash
# Windows 下所有可执行文件带 .exe 后缀
./bin/NativeRdbTest.exe         # RDB 原生测试
./bin/RdbInterfaceTest.exe      # RDB 接口测试
./bin/RdbServiceTest.exe         # RDB 服务测试
./bin/KVDBGeneralStoreTest.exe   # KVDB 存储测试
./bin/StoreTest.exe              # 框架存储测试
./bin/CheckerManagerTest.exe     # 框架检查器测试
```

> 使用 `ctest -L <label>` 按标签运行测试套件，可用标签：`RDB`, `SERVICE`, `FRAMEWORK`, `APP`, `ADAPTER`, `KVDB`, `CLOUD`, `NDK` 等。运行 `ctest --print-labels` 查看全部标签。

## 构建并运行单个测试

```bash
# 先构建特定测试目标（从项目根目录）
./ninja.exe -C cmake-build-debug -j4 NativeRdbTest

# 再运行
./cmake-build-debug/bin/NativeRdbTest.exe

# 使用 Google Test 过滤器运行单个用例
./cmake-build-debug/bin/NativeRdbTest.exe --gtest_filter=TestSuite.TestCaseName
```

> **注意：** 部分测试依赖 mock 命令（如 `chattr`），需通过 `bin/run_test.sh` wrapper 运行，它会将项目 `bin/` 目录加到 PATH 前部：
> ```bash
> ./bin/run_test.sh ./cmake-build-debug/bin/NativeRdbTest.exe --gtest_filter=TestSuite.TestCaseName
> ```

## 生成覆盖率报告

```bash
cd cmake-build-debug
lcov --directory . --capture --output-file coverage.info
genhtml coverage.info --output-directory coverage-report
```

## 测试框架

- Google Test (gtest) 用于单元测试
- Google Mock (gmock) 用于 mock
- `mock/` 目录中的广泛 mock 实现
- 通过 `MockStarter` 进行 mock 服务初始化

### 测试结构

- 主测试文件：`test/test_main.cpp`
- 测试工具：`test/load_service.h/cpp`
- 测试可执行文件：不同组件的多个测试二进制文件
- 用于崩溃报告的信号处理
- 错误时的堆栈跟踪打印

### 测试目录结构

**所有测试用例的 CMake 配置必须统一放在 `test/` 目录下**，不要在模块自身的 `CMakeLists.txt` 中内联定义测试目标。模块 `CMakeLists.txt` 只负责构建库和可执行文件，测试构建配置独立放在 `test/<module_name>/` 中。

**已迁移到统一 test 目录的模块：**
- `test/datamgr_service/` - datamgr_service 服务层测试
- `test/kv_store/` - KV 存储测试
- `test/relational_store/` - 关系型数据库测试
- `test/data_mining/` - Data Mining 核心类型和 ETL 客户端测试
- `test/data_mining_service/` - Data Mining 服务端运行时和组件测试

**目录组织模式：**

简单模块使用扁平 `.cmake` 文件结构：
```
test/data_mining/
├── CMakeLists.txt        # 主入口，设置路径变量，include 各 .cmake 文件
├── core_tests.cmake      # DataMiningCoreTest 定义
└── etl_tests.cmake       # DataMiningEtlTest 定义
```

复杂模块按架构层分目录：
```
test/datamgr_service/
├── CMakeLists.txt                 # 主测试配置
├── framework/                     # 框架层测试
│   ├── CMakeLists.txt
│   └── *.cmake                    # 各 feature 测试配置
├── adapter/                       # 适配器层测试
├── app/                           # 应用层测试
└── service/                       # 服务层测试
    ├── CMakeLists.txt
    └── *.cmake
```

**路径解析注意事项：**
- 使用 `${CMAKE_SOURCE_DIR}/<module>` 作为基础路径（避免 `../../` 相对路径在 Cygwin 上的解析问题）
- 使用 `BEFORE PRIVATE` 设置 include 目录，避免全局 `include_directories()` 中的同名头文件遮蔽（如 `context.h`、`service.h` 等常见文件名）

**标准 CMake 测试配置模式：**
```cmake
# 简单的框架层测试
add_executable(TestName ${FRAMEWORK_TEST_SRC_DIR}/test_file.cpp)
target_compile_options(TestName PRIVATE -fno-access-control)
target_link_libraries(TestName PRIVATE svcFwk mock gtest_main gmock)
add_test(NAME TestName COMMAND TestName)
```

## Mock 系统

仓库包含以下内容的全面 mock 实现：
- IPC/RPC 通信
- 能力运行时
- 包框架
- 安全服务
- 系统能力管理
- 事件处理器

### 动态库加载（dlopen）Mock

**位置：** `mock/src/mock_dlfcn.cpp`

项目实现了自定义的 `dlopen`/`dlsym`/`dlclose` mock，在 Cygwin 上通过 Windows `LoadLibrary`/`GetProcAddress` 加载实际共享库并自动转换 POSIX 路径。这是 `rdb_obs_adapter` 等动态加载组件能在 mock 环境运行的关键。mock 线程安全（互斥锁保护），失败时返回 `nullptr` 并通过 `dlerror()` 报错。

**已支持的库映射：**

| 请求名称 | 基本名称 | 状态 |
|---|---|---|
| `librdb_obs_mgr_adapter.z.so` | `rdb_obs_adapter` | 必需 |
| `librelational_store_icu.z.so` | `relational_store_icu` | 可选 |
| `librelational_store_crypt.z.so` | `rdb_crypt` | 可选 |

**添加新库：** 在 `mock/src/mock_dlfcn.cpp` 的 `g_libraryMappings[]` 中添加 `{请求名, 基本名, 是否可选}` 条目，然后重建 mock 库（`ninja mock`）。详细的文件搜索顺序、使用示例和错误处理见源文件注释。

## 测试构建常见问题

| 问题 | 解决方案 |
|------|----------|
| 私有成员访问错误 | 编译选项添加 `-fno-access-control` |
| Checker 未注册 | 使用 `OBJECT` 库而不是 `STATIC` |
| 错误的令牌类型 | 将测试进程名称添加到 `mock_access_token.cpp` 的 `NativeName` 数组 |
| 缺少 include 头文件 | 在源文件中添加 `#include <variant>`、`<cstdint>` 等 |

> GN 到 CMake 转换的详细规则见 [本地编译及编译修复 → GN 到 CMake 转换原则](./agents-build-and-fix.md#gn-到-cmake-转换原则)。

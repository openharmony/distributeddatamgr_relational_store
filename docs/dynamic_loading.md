# Dynamic Loading and Unloading

本文档详细说明 native_rdb 库的动态加载和卸载机制。

## 背景和约束

native_rdb 库需要支持动态卸载，这意味着：
- **依赖管理约束**: 新增外部依赖（在 BUILD.gN 中添加）必须考虑此约束
- **依赖策略**: 新增依赖尽量使用动态加载方式，减少静态依赖，避免库体积膨胀
- **默认原则**: 针对外部模块默认不允许直接依赖，需要充分评估并尽量使用动态加载和卸载的方式新增依赖

## 当前动态加载的库

| 库名 | 用途 | 加载位置 | 卸载时机 |
|------|------|----------|----------|
| `libarkdata_db_core.z.so` | GRD（通用关系数据库）内核 | `grd_api_manager.cpp` | 进程退出时自动卸载 |
| `librelational_store_icu.z.so` | ICU 国际化支持（locale 配置） | `rdb_icu_manager.cpp` | `GlobalResource::CleanUp(ICU)` |
| `librdb_obs_mgr_adapter.z.so` | 观察者管理器适配器 | `rdb_obs_manager.cpp` | `GlobalResource::CleanUp(OBS)` |
| `libaip_knowledge_processor.z.so` | 知识图谱数据处理器 | `knowledge_schema_helper.cpp` | 析构时自动卸载 |
| `librelational_store_crypt.z.so` | 加密适配器（内部使用 HUKS） | `rdb_security_manager.cpp` | 析构时自动卸载 |

## 动态加载管理器

### GlobalResource 类

**文件**: `frameworks/native/rdb/src/global_resource.cpp`

**职责**:
- 统一管理所有动态加载库的生命周期
- 提供清理函数注册机制
- 支持按类型触发清理操作

**关键接口**:
```cpp
// 注册清理函数
void RegisterClean(CleanType type, Cleaner cleaner)

// 触发清理
void CleanUp(CleanType type)
```

**清理类型**:
- `DB_CLIENT`: 数据库客户端清理
- `OPEN_SSL`: OpenSSL 资源清理
- `ICU`: ICU 库清理
- `OBS`: 观察者管理器清理
- `IPC`: IPC 资源清理

## 各动态库详细说明

### 1. GRD 内核 (libarkdata_db_core.z.so)

**管理器**: `GrdApiManager`
**文件**: `frameworks/native/rdb/src/grd_api_manager.cpp`

**加载机制**:
- 使用 `dlopen` 动态加载 GRD 内核库
- 通过 `dlsym` 获取 GRD API 函数指针
- 支持多种数据库内核的动态切换

**关键代码**:
```cpp
// grd_api_manager.cpp
GrdApiManager& GrdApiManager::GetInstance()
{
    static GrdApiManager instance;
    return instance;
}

bool GrdApiManager::LoadGrdLibrary()
{
    // dlopen 加载库
    handle_ = dlopen("libarkdata_db_core.z.so", RTLD_LAZY);
    if (handle_ == nullptr) {
        HiLog::Error(LABEL, "Failed to load grd library: %{public}s", dlerror());
        return false;
    }

    // dlsym 获取函数指针
    grd_create_fn_ = reinterpret_cast<GrdCreateFunc>(dlsym(handle_, "GrdCreate"));
    // ... 其他函数指针

    return true;
}
```

**卸载时机**: 进程退出时自动卸载（通过 `dlclose`）

### 2. ICU 国际化 (librelational_store_icu.z.so)

**管理器**: `RdbIcuManager`
**文件**: `frameworks/native/rdb/src/rdb_icu_manager.cpp`

**加载机制**:
- 动态加载 ICU 库以支持 locale 配置
- 提供数据库国际化功能（排序、大小写转换等）

**卸载机制**:
- 通过 `GlobalResource::RegisterClean(ICU, cleaner)` 注册清理函数
- 调用 `RdbHelper::Clean()` 或 `GlobalResource::CleanUp(ICU)` 触发卸载

**关键代码**:
```cpp
// rdb_icu_manager.cpp
RdbIcuManager::~RdbIcuManager()
{
    if (icuHandle_ != nullptr) {
        dlclose(icuHandle_);
        icuHandle_ = nullptr;
    }
}

void RdbIcuManager::ReleaseIcuLibrary()
{
    if (icuHandle_ != nullptr) {
        dlclose(icuHandle_);
        icuHandle_ = nullptr;
    }
}
```

### 3. 观察者管理器 (librdb_obs_mgr_adapter.z.so)

**管理器**: `RdbObsManager`
**文件**: `frameworks/native/rdb/src/rdb_obs_manager.cpp`

**加载机制**:
- 动态加载观察者管理器适配器
- 支持数据库变更观察者模式

**卸载机制**:
- 通过 `GlobalResource::RegisterClean(OBS, cleaner)` 注册清理函数
- 在数据库关闭或应用退出时卸载

**关键代码**:
```cpp
// rdb_obs_manager.cpp
int RdbObsManager::Release()
{
    if (obsMgrHandle_ != nullptr) {
        dlclose(obsMgrHandle_);
        obsMgrHandle_ = nullptr;
    }
    return E_OK;
}
```

### 4. 知识图谱处理器 (libaip_knowledge_processor.z.so)

**管理器**: `KnowledgeSchemaHelper`
**文件**: `frameworks/native/rdb/src/knowledge_schema_helper.cpp`

**加载机制**:
- 动态加载知识图谱数据处理器
- 支持知识图谱相关的数据类型和操作

**卸载时机**: 析构时自动卸载

**关键代码**:
```cpp
// knowledge_schema_helper.cpp
KnowledgeSchemaHelper::~KnowledgeSchemaHelper()
{
    if (knowledgeHandle_ != nullptr) {
        dlclose(knowledgeHandle_);
        knowledgeHandle_ = nullptr;
    }
}
```

### 5. 加密适配器 (librelational_store_crypt.z.so)

**管理器**: `RdbSecurityManager`
**文件**: `frameworks/native/rdb/src/rdb_security_manager.cpp`

**加载机制**:
- 动态加载加密适配器库
- 内部静态依赖 HUKS SDK（`huks:libhukssdk`）
- 提供数据库加密/解密功能

**卸载时机**: 析构时自动卸载

**关键代码**:
```cpp
// rdb_security_manager.cpp
RdbSecurityManager::~RdbSecurityManager()
{
    if (cryptHandle_ != nullptr) {
        dlclose(cryptHandle_);
        cryptHandle_ = nullptr;
    }
}

bool RdbSecurityManager::LoadCryptLibrary()
{
    cryptHandle_ = dlopen("librelational_store_crypt.z.so", RTLD_LAZY);
    if (cryptHandle_ == nullptr) {
        HiLog::Error(LABEL, "Failed to load crypt library: %{public}s", dlerror());
        return false;
    }

    // 获取加密函数指针
    cryptInit_ = reinterpret_cast<CryptInitFunc>(dlsym(cryptHandle_, "RdbCryptInit"));
    // ... 其他函数

    return true;
}
```

**重要说明**: 此库内部静态依赖 HUKS SDK，因此 native_rdb 通过动态加载间接使用 HUKS，避免静态依赖导致的库体积膨胀。

## 动态卸载流程

### 触发卸载的场景

1. **应用退出**: 进程退出时自动卸载所有动态库
2. **数据库关闭**: 调用 `RdbHelper::DeleteRdbStore()` 时触发相关资源清理
3. **显式清理**: 调用 `RdbHelper::Clean()` 清理所有可清理资源

### 清理流程

```
应用退出/调用Clean()
    ↓
GlobalResource::CleanUp(type)
    ↓
调用已注册的 Cleaner 函数
    ↓
执行 dlclose() 卸载动态库
    ↓
释放资源
```

### 关键代码示例

```cpp
// global_resource.cpp
std::map<CleanType, std::vector<Cleaner>> GlobalResource::cleaners_;

void GlobalResource::RegisterClean(CleanType type, Cleaner cleaner)
{
    cleaners_[type].push_back(cleaner);
}

void GlobalResource::CleanUp(CleanType type)
{
    auto it = cleaners_.find(type);
    if (it != cleaners_.end()) {
        for (auto& cleaner : it->second) {
            if (cleaner != nullptr) {
                cleaner();
            }
        }
        cleaners_.erase(it);
    }
}
```

## 新增动态依赖的指导原则

### 评估流程

在新增外部依赖时，必须遵循以下评估流程：

1. **必要性评估**: 是否真的需要此依赖？能否通过现有功能实现？
2. **动态加载可行性**: 该依赖是否支持动态加载？是否提供 C API？
3. **性能影响**: 动态加载是否会影响性能？加载频率如何？
4. **依赖管理**: 该依赖是否还有其他依赖？是否需要级联加载？

### 实施建议

**优先使用动态加载的场景**:
- 功能可选，不是核心路径必需
- 依赖库体积较大
- 依赖库只在特定场景下使用
- 依赖库可能在不同平台有不同的实现

**可以静态依赖的场景**:
- 核心功能必需，无条件使用
- 依赖库体积很小（几KB级别）
- 依赖库非常稳定，不需要动态切换

### 动态加载模板代码

```cpp
// template_dynamic_loader.cpp
class MyDynamicLoader {
public:
    bool LoadLibrary() {
        handle_ = dlopen("libmy_dependency.z.so", RTLD_LAZY);
        if (handle_ == nullptr) {
            HiLog::Error(LABEL, "Failed to load library: %{public}s", dlerror());
            return false;
        }

        // 获取函数指针
        myFunction_ = reinterpret_cast<MyFunctionType>(dlsym(handle_, "MyFunction"));
        if (myFunction_ == nullptr) {
            HiLog::Error(LABEL, "Failed to find symbol: %{public}s", dlerror());
            dlclose(handle_);
            handle_ = nullptr;
            return false;
        }

        return true;
    }

    void UnloadLibrary() {
        if (handle_ != nullptr) {
            dlclose(handle_);
            handle_ = nullptr;
        }
    }

    ~MyDynamicLoader() {
        UnloadLibrary();
    }

private:
    void* handle_ = nullptr;
    MyFunctionType myFunction_ = nullptr;
};
```

## 调试动态加载问题

### 常见问题

1. **库加载失败**: 检查库路径、库是否存在、依赖是否满足
2. **符号查找失败**: 检查符号名称是否正确、库是否导出该符号
3. **段错误**: 检查函数指针是否为空、调用方式是否正确
4. **内存泄漏**: 确保在不需要时调用 `dlclose()` 卸载库

### 调试技巧

```cpp
// 检查加载错误
if (handle_ == nullptr) {
    const char* error = dlerror();
    HiLog::Error(LABEL, "dlopen failed: %{public}s", error);
    // 记录详细错误信息
}

// 检查符号错误
if (myFunction_ == nullptr) {
    const char* error = dlerror();
    HiLog::Error(LABEL, "dlsym failed: %{public}s", error);
    // 记录符号查找失败信息
}

// 使用 nm 命令检查库中的符号
// nm -D libmy_library.z.so | grep MyFunction
```

### 日志输出

动态加载过程中的关键日志：
- 加载开始/结束
- 符号查找结果
- 卸载时机
- 错误信息（`dlerror()`）

## 总结

动态加载和卸载机制是 native_rdb 库支持灵活依赖管理的关键特性。通过合理使用动态加载，可以：
- 减少库的静态依赖体积
- 支持可选功能的按需加载
- 提高模块化和可维护性
- 支持不同平台的差异化实现

在新增依赖时，必须充分评估并优先考虑动态加载方式，以保持 native_rdb 库的轻量化和灵活性。

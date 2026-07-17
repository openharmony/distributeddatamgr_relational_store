# DevEco Studio IDE 数据库健壮性规范检查插件

## 项目概述

本项目是为 **DevEco Studio** 开发的代码扫描插件，用于检测应用程序中的数据库使用规范问题。插件基于《数据库健壮性规范 Checklist 1.0》标准，通过静态代码分析技术自动检测JavaScript代码中违反数据库使用推荐规范的情况。

### 主要特性

- ✅ **检查规则覆盖**：实现了数据库健壮性规范中的 10 条核心规则
- ✅ **实时代码检查**：在编码过程中即时发现潜在问题
- ✅ **精准定位**：准确标记出问题代码的具体位置
- ✅ **详细的问题说明**：为每个检测到的问题提供清晰的解释和建议
- ✅ **兼容性**：支持 IntelliJ IDEA、DevEco Studio 等 JetBrains 系列 IDE

## 技术架构

### 开发环境

- **编程语言**：使用 1.9.25 版本的编程语言
- **构建工具**：Gradle 8.x (使用KotlinDSL)
- **Java 版本**：JDK 17
- **目标平台**：IntelliJ Platform 2023.3.6+
- **插件框架**：IntelliJ Platform Plugin SDK 1.17.3
- **插件类型**：LocalInspection（本地代码检查）

### 项目结构

```
DatabaseCheck_Release/
├── src/main/com/example/databasecheck/
│   ├── inspections/           # 规则检查实现
│   │   ├── BaseDatabaseInspection.kt              # 基础检查类
│   │   ├── Rule1NonRdbInterfaceInspection.kt   # 规则1：禁止使用非RDB接口
│   │   ├── Rule2DatabaseCopyInspection.kt         # 规则2：数据库文件拷贝操作
│   │   ├── Rule3TransactionUsageInspection.kt     # 规则3：事务使用优化
│   │   ├── Rule4TransactionCommitInspection.kt    # 规则4：事务提交和回滚
│   │   ├── Rule5TransactionNestingInspection.kt   # 规则5：事务嵌套和线程安全
│   │   ├── Rule6DatabaseDeletionInspection.kt     # 规则6：数据库删除句柄关闭
│   │   ├── Rule7DatabasePermissionInspection.kt   # 规则7：数据库权限验证
│   │   ├── Rule9DatabaseErrorHandlingInspection.kt # 规则9：错误码处理和重试
│   │   ├── Rule12PragmaRestrictionInspection.kt   # 规则12：SQLite Pragma限制
│   │   └── Rule14DatabaseConfigConsistencyInspection.kt # 规则14：配置一致性
│   └── utils/                 # 工具类
│       ├── DatabaseConstants.kt    # 数据库相关常量定义
│       ├── DatabasePathMatcher.kt  # 数据库路径匹配工具
│       └── JavaScriptAnalyzer.kt   # JavaScript代码分析工具
├── src/main/resources/META-INF/
│   └── plugin.xml             # 插件配置文件
├── src/test/com/example/databasecheck/
│   └── testdata/              # 测试数据（正例和反例）
│       ├── Rule1/             # 规则1 测试文件
│       ├── Rule2/             # 规则2 测试文件
│       ├── Rule3/             # 规则3 测试文件
│       ├── Rule4/             # 规则4 测试文件
│       ├── Rule5/             # 规则5 测试文件
│       ├── Rule6/             # 规则6 测试文件
│       ├── Rule7/             # 规则7 测试文件
│       ├── Rule9/             # 规则9 测试文件
│       ├── Rule12/            # 规则12 测试文件
│       └── Rule14/            # 规则14 测试文件
├── Doc/                       # 规则文档与参考文档
├── build.gradle.kts           # Gradle 构建配置
└── README.md                  # 本文件
```

## 规则说明

### 已实现的检查规则

| 规则编号 | 规则名称 | 检查内容 | 严重级别 |
|---------|---------|---------|----------|
| **Rule 1** | 禁止使用非RDB接口 | 检测对数据库文件路径使用 `fileIo.open`、`fopen`、`fcntl` 等文件操作接口 | WARNING |
| **Rule 2** | 数据库文件拷贝操作 | 检测不安全的数据库文件拷贝操作，建议使用 RDB 提供的备份/恢复接口 | WARNING |
| **Rule 3** | 事务使用优化 | 检测事务中包含耗时操作（如网络请求、IPC等），确保事务只包含原子性数据库操作 | WARNING |
| **Rule 4** | 事务提交和回滚 | 确保每个事务都有正确的提交或回滚处理 | WARNING |
| **Rule 5** | 事务嵌套和线程安全 | 防止事务嵌套，确保事务的线程安全性 | WARNING |
| **Rule 6** | 数据库删除句柄关闭 | 在删除数据库前确保所有数据库句柄已关闭 | WARNING |
| **Rule 7** | 数据库权限验证 | 确保数据库目录和文件具有正确的权限设置（DAC/ACL） | WARNING |
| **Rule 9** | 错误码处理和重试 | 检测特定数据库错误码（14800047、14800024等）的正确处理和重试逻辑 | WARNING |
| **Rule 12** | SQLite Pragma限制 | 禁止修改 SQLite 的 `synchronous` 等敏感 pragma 设置 | WARNING |
| **Rule 14** | 配置一致性检查 | 确保同一 HAP 包内相同数据库名称的配置参数保持一致 | WARNING |

### 检查原理

插件通过以下方式进行代码分析：

1. **文本模式匹配**：使用正则表达式识别数据库代码 API 调用模式
2. **上下文分析**：分析代码上下文，理解数据库操作的意图
3. **路径识别**：识别特定的数据库路径模式（如 `/data/storage/el[1-5]/database/`）
4. **配置追踪**：跨文件追踪数据库配置参数，确保一致性

## 快速开始

### 环境要求

- **JDK**：17 或更高版本
- **Gradle**：8.x（项目自带 Gradle Wrapper）
- **IDE**：IntelliJ IDEA 2023.3+ 或 DevEco Studio

### 构建插件

```bash
# 编译插件
./gradlew build

# 构建插件发布包（推荐）
./gradlew buildPlugin
```

构建完成后，插件安装包位于：
```
build/distributions/DatabaseCheck-1.0.0.zip
```

**注意**：该 `.zip` 文件即为可直接安装的插件包，可以通过 IDE 的 "Install Plugin from Disk" 功能进行安装。

### 本地测试

```bash
# 源码编译
./gradlew compileKotlin

# 在沙箱环境中运行 IDE 测试插件
./gradlew runIde
```

执行 `runIde` 后会启动一个带有插件的 IntelliJ IDEA 实例，可以在其中测试插件功能。

### 安装插件

#### 方法一：从磁盘安装（推荐用于开发测试）

1. 构建插件：`./gradlew buildPlugin`
2. 在 DevEco Studio 中打开：`File` → `Settings` → `Plugins`
3. 点击齿轮图标 → `Install Plugin from Disk...`
4. 选择 `build/distributions/DatabaseCheck-1.0.0.zip`
5. 重启 IDE

#### 方法二：发布到 JetBrains Marketplace（生产环境）

```bash
# 验证插件兼容性
./gradlew verifyPlugin

# 发布插件（需要配置 token）
./gradlew publishPlugin
```

**关于验证警告**：执行 `verifyPlugin` 可能会出现以下警告，这些**不影响插件功能**：

- ⚠️ Plugin ID 使用了 `com.example` 前缀（示例前缀）
- ⚠️ Vendor 信息为默认值 "YourCompany"

这些警告仅影响发布到 JetBrains Marketplace 的规范性检查。对于内部使用或定制交付，不影响可用性。如需发布到 Marketplace，需要在 `plugin.xml` 中修改为正式的公司信息和插件 ID。

### 使用插件

安装插件后，代码检查会自动运行：

1. **实时检查**：在编辑器中打开 JavaScript/TypeScript 文件时，违规代码会以黄色波浪线标记
2. **查看详情**：将鼠标悬停在警告上，可以查看详细的违规说明

#### 示例：Rule 1 检测效果

**违规代码**（会被标记）：
```javascript
import fileIo from '@ohos.file.fs';

// ❌ 警告：禁止使用非RDB接口操作数据库文件
let dbPath = "/data/storage/el1/database/mydb.db";
let file = fileIo.openSync(dbPath, fileIo.OpenMode.READ_WRITE);
```

**正确代码**（不会被标记）：
```javascript
import relationalStore from '@ohos.data.relationalStore';

// ✅ 正确：使用 RDB 接口
const STORE_CONFIG = {
  name: 'mydb.db',
  securityLevel: relationalStore.SecurityLevel.S1
};
relationalStore.getRdbStore(context, STORE_CONFIG);
```

## 开发指南

### 添加新规则

1. 在 `src/main/com/example/databasecheck/inspections/` 目录下新增检查类，用于实现具体的数据库规则检测逻辑。
2. 继承 `BaseDatabaseInspection` 基类
3. 实现 `buildVisitor()` 方法，定义检查逻辑
4. 在 `plugin.xml` 中注册新的 `localInspection`

示例：
```
class RuleXXXInspection : BaseDatabaseInspection() {
    override fun buildVisitor(holder: ProblemsHolder, isOnTheFly: Boolean): PsiElementVisitor {
        return object : PsiElementVisitor() {
            override fun visitElement(element: PsiElement) {
                // 实现检查逻辑
            }
        }
    }
}
```

### 测试文件说明

项目包含完整的测试用例，位于 `src/test/com/example/databasecheck/testdata/` 目录：

**测试文件结构**：
- 每个规则都有独立的测试目录（Rule1/ ~ Rule14/）
- 每个目录包含：
  - `test-ruleX-violations.js` - **反例**（应触发警告的代码）
  - `test-ruleX-correct.js` - **正例**（不应触发警告的代码）

**示例**：
```
src/test/com/example/databasecheck/testdata/
├── Rule1/
│   ├── test-rule1-violations.js    # 反例：使用非RDB接口
│   └── test-rule1-correct.js       # 正例：使用RDB接口
├── Rule2/
│   ├── test-rule2-violations.js    # 反例：不安全的文件拷贝
│   └── test-rule2-correct.js       # 正例：使用RDB备份接口
└── ...（其余规则类似）
```

**测试文件设计说明**：

测试文件（正例和反例）主要基于《数据库健壮性规范 Checklist 1.0》指导文件中的示例设计。由于指导文件中的示例主要关注单个规则的演示，**同一示例代码可能在演示某个规则的正例时，违反了其余规则**。

**重要提示**：
- 在测试某个规则的正例文件（`test-ruleX-correct.js`）时，可能会看到来自不同规则的警告，**这是正常现象**
- 例如：Rule 6 的正例代码可能违反 Rule 9（错误处理），因为 Rule 6 的示例重点在于删除句柄检查，而不是错位处理
- 每个测试文件应该关注对应规则是否正确检测，忽略其余规则的警告

**测试文件用途**：
1. 验证特定规则的检测功能是否正常工作
2. 作为开发者理解各规则检测场景的参考示例
3. 了解每条规则的具体违规模式和正确实践
4. 验证插件对不同代码模式的识别能力

### 调试方法

1. 使用 `./gradlew runIde` 启动调试实例
2. 在调试实例中打开 `src/test/com/example/databasecheck/testdata/` 目录下的测试文件
3. 观察 IDE 中是否正确显示警告标记（黄色波浪线）
4. 使用 IDE 的 `Analyze` → `Inspect Code` 功能查看完整检查结果
5. 对比正例和反例文件，验证检测的准确性


## 配置说明

### plugin.xml 关键配置

```xml
<idea-plugin>
    <id>com.example.DatabaseCheck</id>
    <name>DatabaseCheck</name>

    <!-- 平台依赖 -->
    <depends>com.intellij.modules.platform</depends>

    <!-- 注册检查规则 -->
    <extensions defaultExtensionNs="com.intellij">
        <localInspection
            displayName="规则名称"
            groupName="Database Robustness Rules"
            shortName="规则短名称"
            enabledByDefault="true"
            level="WARNING"
            implementationClass="完整类名"/>
    </extensions>
</idea-plugin>
```

## 常见问题

### Q: 插件安装后没有生效？
A: 请确保：
1. IDE 版本符合要求（IDEA 2023.3+， DevEco-Studio 5.0+）
2. 已重启 IDE
3. 在 Settings → Editor → Inspections 中启用了 "Database Robustness Rules" 分组

### Q: 如何禁用某个规则？
A: 在 Settings → Editor → Inspections → Database Robustness Rules 中取消勾选对应规则。

### Q: 插件支持哪些文件类型？
A: 目前支持 `.js`、`.ts`、`.ets` 等 JavaScript/TypeScript 相关文件。

## 参考文档

### 规则文档（Doc/ 目录）
每条规则都有详细的中文文档说明，包含检测方法、正例和反例：

- `Rule1_数据库非RDB接口使用禁止检测.md`
- `Rule2_数据库文件拷贝操作检测.md`
- `Rule3_事务使用优化检测.md`
- `Rule4_事务提交回滚检测.md`
- `Rule5_事务嵌套线程安全检测.md`
- `Rule6_数据库删除句柄关闭检测.md`
- `Rule7_数据库目录文件权限检测.md`
- `Rule9_数据库错误码处理检测.md`
- `Rule12_SQLite_Pragma限制检测.md`
- `Rule14_数据库配置一致性检测.md`

### 其余文档
- `Doc/《数据库健壮性规范Checklist1.0》工具化：检测方法、正例、反例.pdf` - 规范总文档

### 插件标识信息

- **Plugin ID**：`com.example.DatabaseCheck`
- **Plugin Name**：DatabaseCheck
- **Version**：1.0.0
- **Vendor**：YourCompany
- **Compatibility**：IntelliJ Build 233 ~ 242.*

## 版本历史

### v1.0.0 (当前版本)
- ✅ 实现全部 10 条数据库健壮性规则
- ✅ 支持 JavaScript/TypeScript 代码分析（.js, .ts, .jsx, .tsx）
- ✅ 提供精确的问题定位（使用 TextRange 技术）
- ✅ 智能过滤注释中的代码
- ✅ 支持跨文件配置一致性检查（Rule 14）
- ✅ 兼容 DevEco Studio 和 IntelliJ IDEA

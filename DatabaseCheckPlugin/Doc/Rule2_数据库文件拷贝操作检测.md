# Rule2: 数据库文件拷贝操作检测

## 1. 规则描述

Rule2用于检测基于 OpenHarmony 平台的应用中不安全的数据库文件拷贝操作，确保数据库备份和恢复操作的安全性。该规则检测文件接口复制数据库文件的行为，并验证相关的配置文件设置，推荐使用RDB接口进行数据库备份和恢复操作。

**规则要求**：
- 如果使用文件接口复制数据库文件，必须确保所有数据库句柄已关闭
- 复制整个目录内容，而不是单个文件
- 优先使用RDB接口进行备份/恢复操作
- 在`module.json`中正确配置`allowToBackupRestore`相关设置

## 2. 规则配置

在`plugin.xml`中的配置如下：

```xml
<localInspection 
    displayName="Rule 2: Database File Copy Operations"
    groupName="Database Robustness Rules"
    shortName="DatabaseRule2"
    enabledByDefault="true"
    level="WARNING"
    implementationClass="com.example.databasecheck.inspections.Rule2DatabaseCopyInspection"/>
```

**配置说明**：
- **displayName**: 规则在IDE中显示的名称
- **groupName**: 归属的检查组
- **shortName**: 规则的短名称标识符
- **enabledByDefault**: 默认启用状态（true表示默认开启）
- **level**: 警告级别（WARNING）
- **implementationClass**: 实现类`Rule2DatabaseCopyInspection`

## 3. 检测方法

### 3.1 检测架构
Rule2采用双重检测机制：

- **JavaScript代码分析**: 检测文件拷贝操作代码
- **配置文件分析**: 检测`module.json`中的备份配置

### 3.2 检测流程

#### JavaScript代码检测
1. **预处理**: 移除代码注释
2. **AST解析**: 提取函数调用和变量赋值（带作用域信息）
3. **文件拷贝检测**: `findFileCopyViolations()` - 查找对数据库路径的文件拷贝操作
4. **变量解析**: 支持通过变量引用解析数据库路径
5. **违规报告**: 生成JavaScript代码违规信息

#### 配置文件检测
1. **配置文件识别**: 检测`resources/module.json`文件
2. **配置内容分析**: `analyzeModuleJsonConfig()` - 分析备份配置
3. **不安全配置检测**: 识别可能导致数据库损坏的配置
4. **配置违规报告**: 生成配置相关的违规信息

### 3.3 核心检测逻辑

#### 文件拷贝操作检测
- **检测操作**: `fileIo.copyFile`、`fs.copyFileSync`等文件拷贝接口
- **路径验证**: 检查拷贝操作是否针对数据库路径
- **变量解析**: 支持函数作用域内的变量引用解析

#### 配置安全检验
- **allowToBackupRestore**: 检测是否启用备份恢复
- **fullBackupOnly**: 检测是否设置为完整备份模式
- **excludes**: 检测是否排除了数据库路径
- **配置一致性**: 确保配置项之间的逻辑一致性

### 3.4 违规类型
- **UNSAFE_FILE_COPY**: 直接文件拷贝操作在数据库路径上
- **RECOMMEND_RDB_INTERFACE**: 推荐使用RDB接口代替文件操作
- **UNSAFE_BACKUP_CONFIG**: `module.json`中的不安全备份配置
- **CONFIG_CHECK_NEEDED**: 需要验证配置的情况

## 4. 正确与错误示例

### 4.1 错误示例

#### 不安全的文件拷贝操作
```javascript
// ✗ 错误：直接拷贝数据库文件
async function badCopyDatabase() {
    await fileIo.copyFile(context.databaseDir + '/store.db', '/backup/store.db');
}

// ✗ 错误：使用变量拷贝数据库路径
async function badCopyWithVariable() {
    let dbPath = '/data/storage/el1/database/app.db';
    let backupPath = '/backup/app.db';
    await fileIo.copyFile(dbPath, backupPath);
}
```

#### 不安全的备份配置
```json
// ✗ 错误：module.json配置
{
    "app": {
        "allowToBackupRestore": true,
        "fullBackupOnly": false    // 不安全：未设置为完整备份
        // 缺少excludes配置排除数据库路径
    }
}
```

### 4.2 正确示例

#### 使用RDB接口备份
```javascript
// ✓ 正确：使用RDB接口备份数据库
async function correctDatabaseBackup() {
    const config = {
        name: 'userStore',
        securityLevel: relationalStore.SecurityLevel.S1
    };
    
    let store = await relationalStore.getRdbStore(context, config);
    
    // 使用RDB备份接口
    await store.backup('backup_database_name');
    
    // 或使用恢复接口
    await store.restore('backup_database_name');
    
    store.close();
}

// ✓ 正确：拷贝非数据库文件
async function correctFileCopy() {
    // 拷贝非数据库路径的文件不会触发警告
    await fileIo.copyFile('/data/storage/el1/config/app.json', '/backup/app.json');
    await fileIo.copyFile('/data/storage/el1/logs/app.log', '/backup/app.log');
}
```

#### 安全的备份配置
```json
// ✓ 正确：安全的module.json配置
{
    "app": {
        "allowToBackupRestore": true,
        "fullBackupOnly": true,    // 安全：设置为完整备份
        "excludes": [
            "data/storage/el1/database/",
            "data/storage/el2/database/"
        ]
    }
}
```

## 5. 修复建议

### 5.1 基本修复原则
1. **优先使用RDB接口**: 使用`store.backup()`和`store.restore()`进行数据库备份恢复
2. **确保数据库句柄关闭**: 如果必须使用文件接口，先关闭所有数据库连接
3. **配置安全设置**: 在`module.json`中正确配置备份参数
4. **完整性保证**: 复制整个数据库目录而不是单个文件

### 5.2 修复步骤
1. **替换文件拷贝操作**: 将`fileIo.copyFile`替换为RDB的`backup()`/`restore()`方法
2. **添加数据库句柄管理**: 确保在文件操作前正确关闭数据库连接
3. **修正配置文件**: 设置正确的`fullBackupOnly`和`excludes`参数
4. **实现错误处理**: 为备份恢复操作添加适当的异常处理

### 5.3 推荐实践
- **使用RDB原生接口**: 利用数据库引擎的内置备份恢复机制
- **原子性操作**: 确保备份恢复操作的原子性和一致性
- **资源管理**: 正确管理数据库连接和文件句柄的生命周期
- **配置验证**: 定期检查和验证备份配置的正确性
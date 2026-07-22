# Rule12: SQLite Pragma限制检测

## 1. 规则描述

Rule12用于检测基于 OpenHarmony 平台的应用中对危险SQLite Pragma语句的使用，防止修改可能影响数据库完整性、性能或安全性的关键设置。该规则确保应用不会执行可能破坏数据库稳定性的Pragma操作。

**规则要求**：
禁止以下SQLite pragma操作：
- `PRAGMA journal_mode = OFF` - 禁用日志记录，存在数据损坏风险
- `PRAGMA schema_version = xxxx` - 手动操作模式版本
- `PRAGMA synchronous = OFF` - 禁用同步，存在数据丢失风险
- `PRAGMA journal_mode = MEMORY` - 仅内存日志记录，非崩溃安全
- `PRAGMA writable_schema = ON` - 允许危险的模式修改

## 2. 规则配置

```xml
<localInspection 
    displayName="Rule 12: SQLite Pragma Restriction"
    groupName="Database Robustness Rules"
    shortName="DatabaseRule12"
    enabledByDefault="true"
    level="WARNING"
    implementationClass="com.example.databasecheck.inspections.Rule12PragmaRestrictionInspection"/>
```

## 3. 检测方法

### 3.1 检测架构
- **SQL执行检测**: 检测`execute()`和`executeSql()`调用
- **Pragma语句识别**: 识别SQL字符串中的PRAGMA语句
- **禁用设置匹配**: 匹配特定的危险pragma设置
- **字符串和变量分析**: 分析字符串字面量和变量内容

### 3.2 检测流程
1. **数据库执行调用扫描**: 查找所有数据库SQL执行调用
2. **SQL语句提取**: 提取SQL参数字符串
3. **Pragma模式匹配**: 使用正则表达式匹配禁用的pragma语句
4. **变量引用解析**: 解析包含pragma语句的变量
5. **违规报告**: 标记所有检测到的危险pragma使用

### 3.3 检测范围
**监控的数据库操作**：
- `rdbStore.execute()`
- `rdbStore.executeSql()`
- `database.exec()`
- `connection.run()`

**禁用的Pragma设置**：
- `journal_mode = OFF`
- `journal_mode = MEMORY`
- `synchronous = OFF`
- `schema_version = *`
- `writable_schema = ON`

## 4. 正确与错误示例

### 4.1 错误示例

```javascript
// ✗ 错误：直接执行危险的pragma
async function dangerousPragmaUsage() {
    await rdbStore?.execute('PRAGMA journal_mode = OFF');
    await rdbStore?.execute('PRAGMA synchronous = OFF');
    await rdbStore?.execute('PRAGMA writable_schema = ON');
}

// ✗ 错误：通过变量执行危险pragma
async function variablePragmaUsage() {
    const disableJournal = 'PRAGMA journal_mode = OFF';
    const disableSync = 'PRAGMA synchronous = OFF';
    
    await rdbStore?.execute(disableJournal);
    await rdbStore?.execute(disableSync);
}

// ✗ 错误：在配置中包含危险设置
async function configPragmaUsage() {
    const dbConfig = {
        pragmas: [
            'PRAGMA journal_mode = MEMORY',
            'PRAGMA schema_version = 1'
        ]
    };
    
    for (let pragma of dbConfig.pragmas) {
        await rdbStore?.execute(pragma);
    }
}
```

### 4.2 正确示例

```javascript
// ✓ 正确：使用安全的数据库配置
async function safeDatabaseConfig() {
    const config = {
        "name": STORE_NAME,
        securityLevel: relationalStore.SecurityLevel.S3,
        // 不手动设置危险的pragma
    };
    
    const rdbStore = await relationalStore.getRdbStore(context, config);
    return rdbStore;
}

// ✓ 正确：执行安全的pragma操作
async function safePragmaUsage() {
    // 这些pragma操作是安全的
    await rdbStore?.execute('PRAGMA table_info(users)');
    await rdbStore?.execute('PRAGMA foreign_key_check');
    await rdbStore?.execute('PRAGMA integrity_check');
    await rdbStore?.execute('PRAGMA cache_size = 10000');
}

// ✓ 正确：查询pragma信息而不修改
async function queryPragmaInfo() {
    // 查询当前设置（不修改）
    let result1 = await rdbStore?.execute('PRAGMA journal_mode');
    let result2 = await rdbStore?.execute('PRAGMA synchronous');
    let result3 = await rdbStore?.execute('PRAGMA schema_version');
    
    console.log('Current journal mode:', result1);
    console.log('Current synchronous setting:', result2);
    console.log('Current schema version:', result3);
}

// ✓ 正确：使用OpenHarmony平台的应用中推荐的数据库设置
async function recommendedDatabaseSetup() {
    const config = {
        name: 'MyDatabase',
        securityLevel: relationalStore.SecurityLevel.S1,
        encrypt: false,
        isReadOnly: false
        // 依赖系统默认的安全pragma设置
    };
    
    const store = await relationalStore.getRdbStore(context, config);
    
    // 执行业务逻辑，不修改底层pragma设置
    await store.insert('users', userData);
    
    return store;
}
```

## 5. 修复建议

### 5.1 基本修复原则
1. **移除危险pragma**: 删除所有禁用的pragma语句
2. **使用系统默认**: 依赖OpenHarmony平台的应用中的默认数据库配置
3. **替换为安全操作**: 用安全的数据库操作替换危险的pragma修改
4. **配置文件管理**: 通过应用配置而不是pragma来管理数据库行为

### 5.2 修复步骤
1. **识别危险pragma**: 搜索代码中所有被禁用的pragma语句
2. **评估必要性**: 确定是否真的需要这些pragma设置
3. **寻找替代方案**: 使用OpenHarmony平台的应用中推荐的方式实现相同功能
4. **移除或替换**: 删除危险语句或替换为安全的替代方案

### 5.3 替代方案指南

#### journal_mode = OFF 的替代
- **问题**: 禁用日志记录存在数据损坏风险
- **替代**: 使用默认的WAL模式或DELETE模式
- **建议**: 依赖系统默认设置，不手动修改

#### synchronous = OFF 的替代
- **问题**: 禁用同步存在数据丢失风险
- **替代**: 使用NORMAL或FULL同步模式
- **建议**: 为重要数据保持同步，为临时数据可以适当降低

#### writable_schema = ON 的替代
- **问题**: 允许直接修改系统表，极其危险
- **替代**: 使用标准的ALTER TABLE语句
- **建议**: 通过正常的DDL操作进行模式变更

### 5.4 推荐实践
- **系统默认**: 信任OpenHarmony平台的应用中的默认数据库配置
- **性能优化**: 通过索引和查询优化而不是危险的pragma来提升性能
- **数据安全**: 优先保证数据完整性和一致性
- **渐进式变更**: 对于必要的配置变更，使用渐进式和可逆的方法
- **监控验证**: 在变更前后监控数据库性能和稳定性
# Rule1: 数据库非RDB接口使用禁止检测

## 1. 规则描述

Rule1 用于检测基于 OpenHarmony 平台的应用中，禁止使用非 RDB 接口直接操作数据库文件的违规行为。  
该规则要求所有数据库操作均通过系统提供的 RDB 接口（`relationalStore`）完成，避免使用文件 I/O 接口（如 `fileIo`、`fopen`、`fcntl` 等）直接访问数据库文件，以降低数据一致性和安全风险。

**规则要求**：
- 禁止使用`fileIo.open`、`fileIo.close`等文件IO接口操作数据库路径
- 禁止使用C风格文件接口如`fopen`、`fclose`、`fcntl`、`flock`等操作数据库文件
- 禁止使用系统级文件接口如`open`、`close`等操作数据库路径
- 必须使用`relationalStore.getRdbStore()`等RDB接口进行数据库操作

## 2. 规则配置

在`plugin.xml`中的配置如下：

```xml
<localInspection 
    displayName="Rule 1: Prohibit Non-RDB Interface Usage"
    groupName="Database Robustness Rules"
    shortName="DatabaseRule1"
    enabledByDefault="true"
    level="WARNING"
    implementationClass="com.example.databasecheck.inspections.Rule1NonRdbInterfaceInspection"/>
```

**配置说明**：
- **displayName**: 规则在IDE中显示的名称
- **groupName**: 归属的检查组，所有数据库规则都归属于"Database Robustness Rules"
- **shortName**: 规则的短名称标识符
- **enabledByDefault**: 默认启用状态（true表示默认开启）
- **level**: 警告级别（WARNING）
- **implementationClass**: 实现类，使用V2增强版本

## 3. 检测方法

### 3.1 检测架构
Rule1采用基于AST（抽象语法树）的增强分析方法，主要由以下组件构成：

- **主分析引擎**: `analyzeJavaScriptFile()` - 协调整个检测流程
- **直接违规检测**: `findDirectDatabasePathViolations()` - 检测直接在数据库路径上的禁止操作
- **数据库变量跟踪**: `trackDatabaseVariables()` - 跟踪从数据库操作分配的变量（支持函数作用域）
- **间接违规检测**: `findIndirectViolations()` - 检测对跟踪变量的后续操作
- **回退分析**: `fallbackStringAnalysis()` - 当AST分析失败时的字符串模式匹配

### 3.2 检测流程
1. **预处理**: 移除代码注释，避免解析干扰
2. **AST解析**: 使用`JavaScriptAnalyzer`提取函数调用和变量赋值，包含函数作用域信息
3. **直接检测**: 识别直接对数据库路径执行的禁止操作
4. **变量跟踪**: 标记从数据库文件操作返回的变量，按函数作用域分组
5. **间接检测**: 检测对标记变量的后续文件操作
6. **违规报告**: 生成详细的违规信息并在IDE中显示

### 3.3 核心特性
- **函数作用域感知**: 避免跨函数变量污染，确保检测准确性
- **精确匹配算法**: 使用`isExactMatchForDatabaseOperation()`确保变量赋值和数据库操作的精确关联
- **双重检测机制**: 既检测直接违规也检测间接违规（数据流分析）
- **容错设计**: 提供字符串匹配作为AST分析的回退方案

### 3.4 检测范围
- **禁止操作**: `fileIo.open/close`、`fopen/fclose`、`fcntl/flock`、`open/close`等
- **数据库路径**: `context.databaseDir`、`/data/storage/el*/database/`、`/data/app/el*/database/`等
- **检测类型**: 直接路径操作和通过变量的间接操作

## 4. 正确与错误示例

### 4.1 错误示例

#### 直接违规
```javascript
// ✗ 错误：直接使用fileIo操作数据库路径
async function badExample1() {
    let file = await fileIo.open(context.databaseDir + '/user.db');
    let data = await fileIo.read(file, buffer);
    await fileIo.close(file);
}

// ✗ 错误：使用C风格文件接口操作数据库
function badExample2() {
    let file = fopen('/data/storage/el1/database/app.db', 'r');
    fclose(file);
}
```

#### 间接违规（数据流分析检测）
```javascript
// ✗ 错误：间接操作数据库文件描述符
async function badExample3() {
    // 第一步：从数据库路径获取文件描述符
    let dbFd = await fileIo.open(context.databaseDir + '/test.db');
    
    // 第二步：对数据库文件描述符执行后续操作（违规）
    await fileIo.write(dbFd, buffer);      // 违规：写入数据库文件描述符
    await fileIo.close(dbFd);              // 违规：关闭数据库文件描述符
}
```

### 4.2 正确示例

```javascript
// ✓ 正确：使用relationalStore接口操作数据库
async function goodExample1() {
    const config = {
        name: 'userStore',
        securityLevel: relationalStore.SecurityLevel.S1
    };
    
    let store = await relationalStore.getRdbStore(context, config);
    
    // 使用RDB接口进行数据库操作
    await store.insert('users', {name: 'John', age: 30});
    let resultSet = await store.query('SELECT * FROM users WHERE age > ?', [25]);
    
    store.close();
}

// ✓ 正确：操作普通文件不会被误报
async function goodExample2() {
    // 这些操作不会触发Rule1警告，因为不是数据库路径
    let configFile = await fileIo.open('/data/storage/el1/config/app.json');
    await fileIo.write(configFile, configData);
    await fileIo.close(configFile);
}
```

## 5. 修复建议

### 5.1 基本修复原则
1. **使用RDB接口替代文件接口**：将所有`fileIo`、`fopen`等文件操作替换为`relationalStore`接口
2. **正确配置数据库**：使用适当的`securityLevel`和其余配置参数
3. **实现事务处理**：对需要原子性的操作使用RDB事务接口
4. **正确错误处理**：使用RDB接口的错误处理机制

### 5.2 修复步骤
1. **替换文件打开操作**：使用`relationalStore.getRdbStore()`替代`fileIo.open()`等操作
2. **替换数据操作**：使用`insert()`、`query()`、`update()`、`delete()`替代文件读写操作
3. **替换文件关闭操作**：使用`store.close()`替代`fileIo.close()`等操作
4. **添加事务支持**：使用`beginTransaction()`、`commit()`、`rollback()`确保数据一致性

### 5.3 推荐实践
- **资源管理**：确保数据库连接在finally块中正确关闭
- **事务处理**：将相关操作放在同一事务中保证数据一致性
- **错误处理**：捕获数据库操作异常并进行适当处理
- **性能优化**：复用数据库连接，使用批量操作提高效率
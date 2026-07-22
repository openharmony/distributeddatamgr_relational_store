# Rule6: 数据库删除句柄关闭检测

## 1. 规则描述

Rule6用于检测基于 OpenHarmony 平台的应用中数据库删除操作前是否正确关闭数据库句柄。该规则确保在调用`deleteRdbStore`之前，所有相关的数据库连接和ResultSet都被正确关闭，防止资源泄露和删除失败。

**规则要求**：
- 在调用`deleteRdbStore`之前必须调用`rdbStore.close()`
- 确保所有相关的ResultSet都被关闭
- 采用简单的时序分析：close操作必须在delete操作之前出现

## 2. 规则配置

```xml
<localInspection 
    displayName="Rule 6: Database Deletion with Handle Closure"
    groupName="Database Robustness Rules"
    shortName="DatabaseRule6"
    enabledByDefault="true"
    level="WARNING"
    implementationClass="com.example.databasecheck.inspections.Rule6DatabaseDeletionInspection"/>
```

## 3. 检测方法

### 3.1 检测架构
- **删除操作识别**: 检测`deleteRdbStore`调用
- **关闭操作验证**: 检查对应的`close()`调用
- **时序分析**: 确保关闭操作在删除操作之前
- **作用域分析**: 支持跨函数的句柄跟踪

### 3.2 检测流程
1. **删除调用检测**: 识别所有`deleteRdbStore`调用
2. **句柄跟踪**: 跟踪相关的数据库句柄变量
3. **关闭验证**: 检查每个删除操作前是否有对应的关闭操作
4. **ResultSet检查**: 验证ResultSet的正确关闭
5. **违规报告**: 标记缺少关闭操作的删除调用

## 4. 正确与错误示例

### 4.1 错误示例

```javascript
// ✗ 错误：删除前未关闭数据库
async function badDeletion() {
    let store = await relationalStore.getRdbStore(context, config);
    await store.insert("users", userData);
    
    // 直接删除，未先关闭
    await relationalStore.deleteRdbStore(context, "userStore");
}

// ✗ 错误：ResultSet未关闭
async function badResultSetHandling() {
    let store = await relationalStore.getRdbStore(context, config);
    let resultSet = await store.query("SELECT * FROM users");
    
    // ResultSet未关闭就删除数据库
    store.close();
    await relationalStore.deleteRdbStore(context, "userStore");
}
```

### 4.2 正确示例

```javascript
// ✓ 正确：删除前正确关闭数据库
async function correctDeletion() {
    let store = await relationalStore.getRdbStore(context, config);
    await store.insert("users", userData);
    
    // 先关闭数据库
    store.close();
    
    // 然后删除
    await relationalStore.deleteRdbStore(context, "userStore");
}

// ✓ 正确：正确的ResultSet处理
async function correctResultSetHandling() {
    let store = await relationalStore.getRdbStore(context, config);
    let resultSet = await store.query("SELECT * FROM users");
    
    // 处理数据
    while (!resultSet.isAtLastRow) {
        // 处理行数据
        resultSet.goToNextRow();
    }
    
    // 先关闭ResultSet
    resultSet.close();
    
    // 然后关闭数据库
    store.close();
    
    // 最后删除
    await relationalStore.deleteRdbStore(context, "userStore");
}
```

## 5. 修复建议

### 5.1 基本修复原则
1. **顺序执行**: 按照ResultSet关闭 → 数据库关闭 → 数据库删除的顺序
2. **资源管理**: 确保所有数据库相关资源都被正确释放
3. **异常处理**: 在finally块中进行资源清理
4. **状态检查**: 删除前验证数据库和ResultSet的状态

### 5.2 修复步骤
1. **添加ResultSet关闭**: 在所有ResultSet使用后调用`resultSet.close()`
2. **添加数据库关闭**: 在删除前调用`store.close()`
3. **调整操作顺序**: 确保关闭操作在删除操作之前
4. **异常安全**: 使用try-finally确保资源清理

### 5.3 推荐实践
- **及时关闭**: ResultSet使用完毕后立即关闭
- **统一清理**: 使用统一的资源清理模式
- **状态验证**: 在操作前检查资源状态
- **文档记录**: 在代码中清楚标注资源管理的意图
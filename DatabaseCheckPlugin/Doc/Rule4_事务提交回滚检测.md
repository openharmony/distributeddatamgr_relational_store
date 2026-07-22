# Rule4: 事务提交回滚检测

## 1. 规则描述

Rule4用于检测基于 OpenHarmony 平台的应用中事务的正确提交和回滚处理，确保每个事务都有适当的生命周期管理。该规则防止事务资源泄露和数据不一致问题。

**规则要求**：
- 每个事务创建都必须有对应的提交操作
- 异常处理必须包含回滚操作进行事务清理
- 事务不应该在没有适当关闭的情况下被丢弃

## 2. 规则配置

```xml
<localInspection 
    displayName="Rule 4: Transaction Commit and Rollback"
    groupName="Database Robustness Rules"
    shortName="DatabaseRule4"
    enabledByDefault="true"
    level="WARNING"
    implementationClass="com.example.databasecheck.inspections.Rule4TransactionCommitInspection"/>
```

## 3. 检测方法

### 3.1 检测架构
- **事务生命周期跟踪**: 从创建到提交/回滚的完整跟踪
- **异常处理分析**: 检查catch块中的回滚操作
- **作用域感知**: 基于函数作用域进行精确的变量跟踪

### 3.2 检测流程
1. **事务创建识别**: 检测`createTransaction()`调用
2. **变量跟踪**: 跟踪事务变量的赋值和使用
3. **提交检测**: 验证每个事务是否有对应的`commit()`调用
4. **回滚检测**: 检查异常处理中的`rollback()`调用
5. **违规报告**: 标记缺失提交或回滚的事务

## 4. 正确与错误示例

### 4.1 错误示例

```javascript
// ✗ 错误：缺少提交操作
async function missingCommit() {
    let trans = await rdbStore.createTransaction();
    await trans.insert("users", {name: "test"});
    // 缺少 await trans.commit();
    return "done";
}

// ✗ 错误：异常处理缺少回滚
async function missingRollback() {
    try {
        let trans = await rdbStore.createTransaction();
        await trans.insert("users", {name: "test"});
        await trans.commit();
    } catch (err) {
        console.error("Error:", err);
        // 缺少 trans.rollback();
    }
}
```

### 4.2 正确示例

```javascript
// ✓ 正确：完整的事务处理
async function correctTransaction() {
    let trans;
    try {
        trans = await rdbStore.createTransaction();
        await trans.insert("users", {name: "test"});
        await trans.commit();
    } catch (err) {
        if (trans) {
            await trans.rollback();
        }
        throw err;
    }
}
```

## 5. 修复建议

### 5.1 基本修复原则
1. **确保提交**: 每个事务创建后必须调用`commit()`
2. **异常回滚**: 在catch块中添加`rollback()`调用
3. **资源管理**: 使用try-catch-finally模式确保事务正确关闭
4. **变量检查**: 在回滚前检查事务变量是否存在

### 5.2 推荐实践
- **统一模式**: 使用一致的事务处理模式
- **错误传播**: 在回滚后重新抛出异常
- **资源清理**: 确保所有事务资源都被正确释放
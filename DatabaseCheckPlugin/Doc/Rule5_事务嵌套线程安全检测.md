# Rule5: 事务嵌套线程安全检测

## 1. 规则描述

Rule5用于检测基于 OpenHarmony 平台的应用中已弃用的事务API使用，防止事务嵌套和线程安全问题。该规则确保应用使用新的线程安全事务接口，避免使用可能导致线程安全问题的旧式API。

**规则要求**：
- 检测旧式`rdbStore.beginTransaction()`API的使用（已弃用）
- 检测旧式`rdbStore.commit()`API的使用（已弃用）
- 检测旧式`rdbStore.rollback()`API的使用（已弃用）
- 防止事务嵌套，确保适当的事务可见性

## 2. 规则配置

```xml
<localInspection 
    displayName="Rule 5: Transaction Nesting and Thread Safety"
    groupName="Database Robustness Rules"
    shortName="DatabaseRule5"
    enabledByDefault="true"
    level="WARNING"
    implementationClass="com.example.databasecheck.inspections.Rule5TransactionNestingInspection"/>
```

## 3. 检测方法

### 3.1 检测架构
- **弃用API识别**: 检测旧式事务API的使用模式
- **调用链分析**: 跟踪事务相关的函数调用
- **线程安全验证**: 确保使用线程安全的新API

### 3.2 检测流程
1. **旧API识别**: 检测`rdbStore.beginTransaction()`等弃用方法
2. **调用模式分析**: 分析事务API的调用序列
3. **替换建议**: 提供新API的使用建议
4. **违规报告**: 标记所有弃用API的使用

## 4. 正确与错误示例

### 4.1 错误示例

```javascript
// ✗ 错误：使用弃用的beginTransaction API
async function oldStyleTransaction() {
    await rdbStore.beginTransaction();  // 弃用API
    try {
        await rdbStore.insert("users", userData);
        await rdbStore.commit();         // 弃用API
    } catch (err) {
        await rdbStore.rollback();      // 弃用API
    }
}
```

### 4.2 正确示例

```javascript
// ✓ 正确：使用新的createTransaction API
async function newStyleTransaction() {
    let transaction = await rdbStore.createTransaction();
    try {
        await transaction.insert("users", userData);
        await transaction.commit();
    } catch (err) {
        await transaction.rollback();
    }
}
```

## 5. 修复建议

### 5.1 基本修复原则
1. **API升级**: 将`beginTransaction()`替换为`createTransaction()`
2. **对象化操作**: 使用事务对象而不是直接在store上操作
3. **线程安全**: 确保每个线程使用独立的事务对象
4. **一致性**: 统一使用新的事务API模式

### 5.2 修复步骤
1. **替换事务创建**: `rdbStore.beginTransaction()` → `rdbStore.createTransaction()`
2. **替换提交操作**: `rdbStore.commit()` → `transaction.commit()`
3. **替换回滚操作**: `rdbStore.rollback()` → `transaction.rollback()`
4. **更新事务操作**: 在事务对象上执行数据库操作

### 5.3 推荐实践
- **对象生命周期**: 正确管理事务对象的生命周期
- **异常安全**: 确保异常情况下事务对象被正确清理
- **避免共享**: 不在多个线程间共享事务对象
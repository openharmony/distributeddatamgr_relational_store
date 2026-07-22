# Rule9: 数据库错误码处理检测

## 1. 规则描述

Rule9用于检测基于 OpenHarmony 平台的应用中数据库错误码的正确处理和重试逻辑实现。该规则确保应用能够正确处理特定的数据库错误码，并实现适当的重试机制以提高数据库操作的健壮性。

**规则要求**：
- **14800047**: 关闭ResultSet并执行检查点操作（PRAGMA wal_checkpoint(TRUNCATE)）
- **14800024, 14800025, 14800028**: 实现重试逻辑并延迟处理忙碌的数据库
- **14800029**: 清理磁盘空间并重试处理磁盘满错误

## 2. 规则配置

```xml
<localInspection 
    displayName="Rule 9: Database Error Code Handling and Retry Logic"
    groupName="Database Robustness Rules"
    shortName="DatabaseRule9"
    enabledByDefault="false"
    level="WARNING"
    implementationClass="com.example.databasecheck.inspections.Rule9DatabaseErrorHandlingInspection"/>
```

**注意**: 该规则默认禁用，需要手动启用。

## 3. 检测方法

### 3.1 检测架构
- **数据库操作识别**: 检测被try-catch包围的数据库CRUD操作
- **异常处理分析**: 分析catch块中的错误处理逻辑
- **特定错误码检测**: 查找特定数据库错误码的处理
- **重试逻辑验证**: 检查是否实现了适当的重试机制

### 3.2 检测流程
1. **数据库操作扫描**: 识别所有数据库CRUD操作
2. **异常处理检测**: 查找包含数据库操作的try-catch块
3. **错误码分析**: 检查是否处理了特定的数据库错误码
4. **重试逻辑检验**: 验证重试机制的实现
5. **违规报告**: 标记缺少错误处理的数据库操作

### 3.3 核心检测逻辑
- **平凡catch块识别**: 检测只包含简单日志记录的catch块
- **错误码匹配**: 查找特定错误码的处理逻辑
- **重试模式识别**: 检测重试逻辑的实现模式

## 4. 正确与错误示例

### 4.1 错误示例

```javascript
// ✗ 错误：没有错误处理
async function noErrorHandling() {
    await rdbStore?.insert("test", valueBucket);  // 没有try-catch
}

// ✗ 错误：平凡的异常处理
async function trivialErrorHandling() {
    try {
        await rdbStore?.insert("test", valueBucket);
    } catch (err) {
        console.log("Error occurred");  // 只有简单日志
    }
}

// ✗ 错误：没有特定错误码处理
async function genericErrorHandling() {
    try {
        await rdbStore?.insert("test", valueBucket);
    } catch (err) {
        console.error("Database error:", err);
        throw err;  // 没有处理特定错误码
    }
}
```

### 4.2 正确示例

```javascript
// ✓ 正确：处理14800047错误码
async function handleResultSetError() {
    try {
        await rdbStore?.insert("test", valueBucket);
    } catch (err) {
        if (err.code == 14800047) {
            resultSet?.close();
            await rdbStore?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        }
        throw err;
    }
}

// ✓ 正确：处理忙碌数据库错误并重试
async function handleBusyDatabaseError() {
    try {
        await rdbStore?.insert("test", valueBucket);
    } catch (err) {
        if ((err.code == 14800024 || err.code == 14800025 || err.code == 14800028) && needRetry) {
            await sleep(1000);  // 延迟1秒
            await retryForBusy(false);
        }
        throw err;
    }
}

// ✓ 正确：处理磁盘满错误
async function handleDiskFullError() {
    try {
        await rdbStore?.insert("test", valueBucket);
    } catch (err) {
        if (err.code == 14800029) {
            await cleanupDiskSpace();
            await retryOperation();
        }
        throw err;
    }
}

// ✓ 正确：综合错误处理
async function comprehensiveErrorHandling() {
    try {
        await rdbStore?.insert("test", valueBucket);
    } catch (err) {
        switch (err.code) {
            case 14800047:
                resultSet?.close();
                await rdbStore?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
                break;
            case 14800024:
            case 14800025:
            case 14800028:
                if (needRetry) {
                    await sleep(1000);
                    await retryForBusy(false);
                }
                break;
            case 14800029:
                await cleanupDiskSpace();
                await retryOperation();
                break;
            default:
                console.error("Unhandled database error:", err);
        }
        throw err;
    }
}
```

## 5. 修复建议

### 5.1 基本修复原则
1. **特定错误处理**: 为重要的数据库错误码实现特定处理逻辑
2. **重试机制**: 为临时性错误实现重试逻辑
3. **资源清理**: 在错误处理中正确清理资源
4. **错误传播**: 在处理后适当地重新抛出异常

### 5.2 修复步骤
1. **添加try-catch**: 为所有数据库操作添加异常处理
2. **实现错误码检查**: 添加特定错误码的条件判断
3. **实现重试逻辑**: 为临时错误添加重试机制
4. **添加资源清理**: 确保错误情况下的资源清理

### 5.3 错误码处理指南

#### 14800047 - ResultSet相关错误
- 立即关闭所有打开的ResultSet
- 执行WAL检查点操作清理写前日志
- 考虑重启数据库连接

#### 14800024/25/28 - 数据库忙碌错误
- 实现指数退避重试策略
- 设置合理的重试次数限制
- 在重试间隔中释放CPU资源

#### 14800029 - 磁盘空间不足
- 清理临时文件和缓存
- 压缩或删除过期数据
- 通知用户清理存储空间

### 5.4 推荐实践
- **错误分类**: 区分临时错误和永久错误
- **监控日志**: 记录错误处理的执行情况
- **用户友好**: 为用户提供有意义的错误信息
- **性能考虑**: 避免过度重试影响性能
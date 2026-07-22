# Rule7: 数据库目录文件权限检测

## 1. 规则描述

Rule7用于检测基于 OpenHarmony 平台的应用中对数据库目录和文件权限的不当修改操作。该规则确保数据库目录和文件的权限（DAC/ACL）正确配置和继承，防止权限修改导致的数据库访问问题。

**规则要求**：
- 禁止使用`chmod`、`fileIo.chmod`、`fileIo.chmodSync`操作数据库路径
- 确保数据库文件和新创建文件的读写权限正确
- 保护OpenHarmony平台的应用中数据库存储路径的权限设置

## 2. 规则配置

```xml
<localInspection 
    displayName="Rule 7: Database Directory and File Permission Validation"
    groupName="Database Robustness Rules"
    shortName="DatabaseRule7"
    enabledByDefault="true"
    level="WARNING"
    implementationClass="com.example.databasecheck.inspections.Rule7DatabasePermissionInspection"/>
```

## 3. 检测方法

### 3.1 检测架构
- **权限修改操作识别**: 检测chmod相关的函数调用
- **数据库路径验证**: 验证操作目标是否为数据库路径
- **路径模式匹配**: 使用与Rule1相同的逻辑确保一致性

### 3.2 检测范围
**数据库路径模式**：
- `context.databaseDir`
- `/data/storage/el1~el5/database`
- `/data/storage/el1~el5/database/<hap-name-xxx>`
- `/data/app/el1~el5/<userId>/database/<packagename-xxx>`
- `/data/service/el1~el4/public/database/<serviceability-xxx>`

**禁止的权限修改操作**：
- `fileIo.chmod()`
- `fileIo.chmodSync()`
- `chmod()`

## 4. 正确与错误示例

### 4.1 错误示例

```javascript
// ✗ 错误：修改数据库目录权限
async function badPermissionChange() {
    await fileIo.chmod(context.databaseDir + '/store.db', 0o771);
    await fileIo.chmod('/data/storage/el1/database/', 0o755);
}

// ✗ 错误：同步方式修改数据库权限
function badSyncPermissionChange() {
    fileIo.chmodSync('/data/storage/el2/database/app/', 0o644);
}

// ✗ 错误：使用系统chmod
async function badSystemChmod() {
    chmod('/data/app/el1/database/myapp/', 0o777);
}
```

### 4.2 正确示例

```javascript
// ✓ 正确：检查路径后跳过数据库目录
async function correctPermissionCheck() {
    if (path.search('/database/') >= 0) {
        return; // 跳过数据库路径
    }
    await fileIo.chmod(path, 0o771);
}

// ✓ 正确：只修改非数据库路径的权限
async function correctNonDbPermission() {
    // 修改配置文件权限（不是数据库路径）
    await fileIo.chmod('/data/storage/el1/config/app.json', 0o644);
    
    // 修改日志文件权限（不是数据库路径）
    await fileIo.chmod('/data/storage/el1/logs/', 0o755);
}
```

## 5. 修复建议

### 5.1 基本修复原则
1. **路径检查**: 在修改权限前检查路径是否为数据库相关
2. **权限继承**: 依赖系统的默认权限继承机制
3. **避免手动修改**: 不手动修改数据库目录和文件的权限
4. **使用系统API**: 依赖OpenHarmony平台的应用中的数据库API进行权限管理

### 5.2 修复步骤
1. **添加路径检查**: 在权限修改操作前检查是否为数据库路径
2. **移除数据库权限修改**: 删除对数据库路径的chmod操作
3. **使用条件判断**: 添加条件判断跳过数据库路径
4. **依赖默认设置**: 信任系统的默认权限配置

### 5.3 推荐实践
- **权限继承**: 让数据库文件继承目录的默认权限
- **最小权限**: 避免给数据库文件设置过宽泛的权限
- **系统管理**: 依赖OpenHarmony平台的应用中系统进行数据库权限管理
- **安全检查**: 定期检查数据库文件的权限设置
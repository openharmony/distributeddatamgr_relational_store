# Rule14: 数据库配置一致性检测

## 1. 规则描述

Rule14用于检测基于 OpenHarmony 平台的应用中同一数据库名称的配置参数一致性问题。该规则确保在HAP包内，所有对同一数据库名称的`getRdbStore`调用都使用完全一致的配置参数，防止配置不一致导致的数据库行为异常。

**规则要求**：
对于相同的数据库名称，所有`getRdbStore`调用必须使用相同的配置参数：
- `name` - 数据库名称（必须相同）
- `securityLevel` - 安全等级设置
- `encrypt` - 加密设置
- `isReadOnly` - 只读模式设置
- `customDir` - 自定义目录设置

## 2. 规则配置

```xml
<localInspection 
    displayName="Rule 14: Database Configuration Consistency"
    groupName="Database Robustness Rules"
    shortName="DatabaseRule14"
    enabledByDefault="true"
    level="WARNING"
    implementationClass="com.example.databasecheck.inspections.Rule14DatabaseConfigConsistencyInspection"/>
```

## 3. 检测方法

### 3.1 检测架构
- **getRdbStore调用提取**: 查找所有数据库获取调用
- **配置参数解析**: 解析对象字面量和变量引用的配置
- **数据库名称分组**: 按数据库名称对配置进行分组
- **配置一致性验证**: 检查同名数据库的配置一致性

### 3.2 检测流程
1. **预处理**: 移除注释避免解析干扰
2. **调用提取**: 使用正则表达式提取所有`getRdbStore`调用
3. **配置解析**: 解析每个调用的配置参数（支持对象字面量和变量引用）
4. **分组分析**: 按数据库名称对配置进行分组
5. **一致性检测**: 比较同一数据库名称的所有配置参数
6. **违规报告**: 标记配置不一致的调用

### 3.3 核心检测逻辑

#### 配置参数提取
- **对象字面量解析**: 直接解析`{name: "db", securityLevel: S1}`形式的配置
- **变量引用解析**: 跟踪变量定义，解析`const config = {...}`形式的配置
- **参数完整性**: 提取所有配置参数，包括未知参数

#### 一致性比较
- **参数存在性检查**: 确保相同数据库的所有配置包含相同的参数
- **参数值比较**: 对比每个参数的具体值
- **缺失参数处理**: 将缺失参数视为与存在参数不一致

## 4. 正确与错误示例

### 4.1 错误示例

#### 配置参数不一致
```javascript
// ✗ 错误：同一数据库名称使用不同的安全等级
async function CreateRdbStore(context) {
    const config = {
        "name": STORE_NAME,
        securityLevel: relationalStore.SecurityLevel.S3
    };
    return await relationalStore.getRdbStore(context, config);
}

async function GetActiveRdbStore(context) {
    const config = {
        "name": STORE_NAME,
        securityLevel: relationalStore.SecurityLevel.S1,  // 不一致：不同的安全等级
        encrypt: true,        // 不一致：额外的加密参数
        isReadOnly: true      // 不一致：额外的只读参数
    };
    return await relationalStore.getRdbStore(context, config);
}
```

#### 参数缺失不一致
```javascript
// ✗ 错误：配置参数的存在性不一致
async function FirstAccess(context) {
    const config = {
        "name": "userStore",
        securityLevel: relationalStore.SecurityLevel.S2
    };
    return await relationalStore.getRdbStore(context, config);
}

async function SecondAccess(context) {
    const config = {
        "name": "userStore",
        securityLevel: relationalStore.SecurityLevel.S2,
        encrypt: false,       // 额外参数：第一个调用中没有
        customDir: "/custom"  // 额外参数：第一个调用中没有
    };
    return await relationalStore.getRdbStore(context, config);
}
```

### 4.2 正确示例

#### 一致的配置使用
```javascript
// ✓ 正确：使用相同的配置常量
const CONFIG = {
    "name": STORE_NAME,
    securityLevel: relationalStore.SecurityLevel.S3,
    encrypt: false,
    isReadOnly: false
};

async function CreateRdbStore(context) {
    return await relationalStore.getRdbStore(context, CONFIG);
}

async function GetActiveRdbStore(context) {
    return await relationalStore.getRdbStore(context, CONFIG);
}

async function GetBackupRdbStore(context) {
    return await relationalStore.getRdbStore(context, CONFIG);
}
```

#### 完全一致的内联配置
```javascript
// ✓ 正确：每次调用使用完全相同的配置
async function AccessDatabase1(context) {
    const config = {
        "name": "appDatabase",
        securityLevel: relationalStore.SecurityLevel.S1,
        encrypt: true,
        isReadOnly: false,
        customDir: "/data/custom"
    };
    return await relationalStore.getRdbStore(context, config);
}

async function AccessDatabase2(context) {
    const config = {
        "name": "appDatabase",
        securityLevel: relationalStore.SecurityLevel.S1,
        encrypt: true,
        isReadOnly: false,
        customDir: "/data/custom"
    };
    return await relationalStore.getRdbStore(context, config);
}
```

#### 不同数据库使用不同配置（正确）
```javascript
// ✓ 正确：不同数据库名称可以使用不同配置
async function getUserStore(context) {
    const config = {
        "name": "userStore",
        securityLevel: relationalStore.SecurityLevel.S3
    };
    return await relationalStore.getRdbStore(context, config);
}

async function getLogStore(context) {
    const config = {
        "name": "logStore",           // 不同的数据库名称
        securityLevel: relationalStore.SecurityLevel.S1,  // 可以有不同的配置
        encrypt: false
    };
    return await relationalStore.getRdbStore(context, config);
}
```

## 5. 修复建议

### 5.1 基本修复原则
1. **配置统一**: 为同一数据库名称使用完全一致的配置参数
2. **配置复用**: 使用共享的配置常量或对象
3. **参数完整性**: 确保所有调用包含相同的参数集合
4. **值一致性**: 确保相同参数具有相同的值

### 5.2 修复步骤
1. **识别同名数据库**: 找出所有使用相同数据库名称的`getRdbStore`调用
2. **统一配置定义**: 创建共享的配置对象或常量
3. **替换内联配置**: 将内联配置替换为共享配置的引用
4. **验证一致性**: 确认所有配置参数的名称和值都完全一致

### 5.3 推荐的配置管理模式

#### 模式1：全局配置常量
```javascript
// 定义全局配置
const DATABASE_CONFIGS = {
    userStore: {
        name: "userStore",
        securityLevel: relationalStore.SecurityLevel.S3,
        encrypt: true,
        isReadOnly: false
    },
    logStore: {
        name: "logStore", 
        securityLevel: relationalStore.SecurityLevel.S1,
        encrypt: false,
        isReadOnly: true
    }
};

// 在所有地方使用相同的配置
async function getUserDatabase(context) {
    return await relationalStore.getRdbStore(context, DATABASE_CONFIGS.userStore);
}
```

#### 模式2：配置工厂函数
```javascript
// 配置生成函数
function getDatabaseConfig(databaseName) {
    const baseConfig = {
        name: databaseName,
        securityLevel: relationalStore.SecurityLevel.S2,
        encrypt: false,
        isReadOnly: false
    };
    
    // 根据数据库名称定制配置
    switch (databaseName) {
        case "sensitiveData":
            baseConfig.securityLevel = relationalStore.SecurityLevel.S3;
            baseConfig.encrypt = true;
            break;
        case "readOnlyCache":
            baseConfig.isReadOnly = true;
            break;
    }
    
    return baseConfig;
}

// 使用一致的配置生成方式
async function accessDatabase(context, dbName) {
    return await relationalStore.getRdbStore(context, getDatabaseConfig(dbName));
}
```

### 5.4 推荐实践
- **配置集中管理**: 将数据库配置集中在一个地方定义
- **类型安全**: 使用TypeScript等工具确保配置类型一致
- **文档记录**: 为每个配置参数添加清晰的注释说明
- **版本管理**: 对配置变更进行版本控制和影响分析
- **测试验证**: 编写测试确保配置一致性
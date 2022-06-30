# 数据共享（DataShare）<a name="ZH-CN_TOPIC_0000001124534865"></a>

-   [本地数据管理组件](../README_zh.md)
-   [简介](#section11660541593)
    -   [数据共享（DataShare）](#section1287582752720)
-   [目录](#section161941989596)
-   [数据共享（DataShare）](#section762641474721)
    -   [约束](#section1944481420489)
-   [相关仓](#section1371113476307)

## 简介<a name="section11660541593"></a>

**数据共享（DataShare）** 主要用于应用管理其自身数据，同时支持同个设备上不同应用间的数据共享

### 数据共享（DataShare）<a name="section1287582752720"></a>

> 主要用于应用管理其自身数据，同时支持同个设备上不同应用间的数据共享

## 目录<a name="section161941989596"></a>

```
//foundation/distributeddatamgr/appdatamgr
├── data_share                # 数据共享（DataShare）
│   ├── frameworks            # 框架层代码
│   │   └── js                # JS API的实现
│   │   │   └── napi          # napi代码实现
│   │   └── native            # 内部接口实现
│   ├── interfaces            # 接口代码
│   │   └── inner_api         # 内部接口声明
│   │       └── native        # C/C++接口
│   └── test                  # 测试用例
│       ├── js                # js用例
│       └── native            # C++用例
```

## 数据共享（DataShare）<a name="section762641474721"></a>

以下是几个基本概念：

-   **Key-Value数据库**

    一种以键值对存储数据的一种数据库。Key是关键字，Value是值。

-   **非关系型数据库**

    区别于关系数据库，不保证遵循ACID（Atomic、Consistency、Isolation及Durability）特性，不采用关系模型来组织数据，数据之间无关系，扩展性好。

-   **偏好数据**

    用户经常访问和使用的数据。

### 约束<a name="section1944481420489"></a>

Key键为String类型，要求非空且长度不超过80个字符。

如果Value值为String类型，可以为空但是长度不超过8192个字符。

存储的数据量应该是轻量级的，建议存储的数据不超过一万条，否则会在内存方面产生较大的开销。

## 相关仓<a name="section1371113476307"></a>

分布式数据管理子系统

- [distributeddatamgr\_appdatamgr](https://gitee.com/openharmony/distributeddatamgr_appdatamgr)
- [third\_party\_sqlite](https://gitee.com/openharmony/third_party_sqlite)
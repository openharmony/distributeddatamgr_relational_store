# 本地数据管理组件<a name="ZH-CN_TOPIC_0000001124534865"></a>

-   [简介](#section11660541593)
    -   [关系型数据库（RDB）](relational_store/README_zh.md)
    -   [首选项（Preferences）](preferences/README_zh.md)
    -   [数据共享（DataShare）](data_share/README_zh.md)
    -   [轻量系统KV数据库（Lightweight KV store）](kv_store/README_zh.md)
-   [目录](#section161941989596)
-   [相关仓](#section1371113476307)

## 简介<a name="section11660541593"></a>

**关系型数据库（Relational Database，RDB）** 是一种基于关系模型来管理数据的数据库。OpenHarmony关系型数据库基于SQLite组件提供了一套完整的对本地数据库进行管理的机制。

**首选项（Preferences）** 主要提供轻量级Key-Value操作，支持本地应用存储少量数据，数据存储在本地文件中，同时也加载在内存中，所以访问速度更快，效率更高。首选项提供非关系型数据存储，不宜存储大量数据，经常用于操作键值对形式数据的场景。

**数据共享（DataShare）** 主要用于应用管理其自身数据，同时支持同个设备上不同应用间的数据共享。

**轻量系统KV数据库（Lightweight KV store）** 依托当前公共基础库提供的KV存储能力开发，为轻量系统设备应用提供键值对数据管理能力。在有进程的平台上，KV存储提供的参数管理，供单进程访问不能被其他进程使用。在此类平台上，KV存储作为基础库加载在应用进程，以保障不被其他进程访问。

## 目录<a name="section161941989596"></a>

```
//foundation/distributeddatamgr/appdatamgr
├── relational_store          # 关系型数据库（RDB）
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
│
├── preferences               # 首选项（Preferences）
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
├── kv_store                  # 轻量系统KV数据库（Lightweight KV store）
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


## 相关仓<a name="section1371113476307"></a>

- [分布式数据管理子系统](https://gitee.com/openharmony/docs/blob/master/zh-cn/readme/%E5%88%86%E5%B8%83%E5%BC%8F%E6%95%B0%E6%8D%AE%E7%AE%A1%E7%90%86%E5%AD%90%E7%B3%BB%E7%BB%9F.md)

- **distributeddatamgr\_appdatamgr**

- [third\_party\_sqlite](https://gitee.com/openharmony/third_party_sqlite)
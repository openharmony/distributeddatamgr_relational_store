# 轻量系统KV数据库（Lightweight KV store）<a name="ZH-CN_TOPIC_0000001124534865"></a>

-   [本地数据管理组件](../README_zh.md)
-   [简介](#section11660541593)
    -   [轻量系统KV数据库（Lightweight KV store）](#section762641474721)
-   [目录](#section161941989596)
-   [轻量系统KV数据库（Lightweight KV store）](#section762641474722)
    -   [说明](#section1944481420489)
    -   [约束](#section1944481420490)
-   [相关仓](#section1371113476307)

## 简介<a name="section11660541593"></a>

**轻量系统KV数据库（Lightweight KV store）** 依托当前公共基础库提供的KV存储能力开发，为轻量系统设备应用提供键值对数据管理能力。在有进程的平台上，KV存储提供的参数管理，供单进程访问不能被其他进程使用。在此类平台上，KV存储作为基础库加载在应用进程，以保障不被其他进程访问。

### 轻量系统KV数据库（Lightweight KV store）<a name="section762641474721"></a>

> 当前先支持轻量键值（KV）本地数据存储能力，后续会逐步支持其他更丰富的数据类型。
>
> 轻量键值（KV）数据：数据有结构，文件轻量，具有简易事务性，单独提供一套专用的键值对接口

分布式数据管理服务在不同平台上，将数据操作接口形成抽象层用来统一进行文件操作，使厂商不需要关注不同芯片平台文件系统的差异。

**目前，在轻量系统上默认关闭该特性，需要使用时请用户修改vendor_hisilicon仓配置以开启。**

## 目录<a name="section161941989596"></a>

```
//foundation/distributeddatamgr/appdatamgr
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

## 轻量系统KV数据库（Lightweight KV store）<a name="section762641474722"></a>

### 说明<a name="section1944481420489"></a>

KV存储能力继承自公共基础库原始设计，在原有能力基础上进行增强，新增提供数据删除及二进制value读写能力的同时，保证操作的原子性；

>- 轻量系统普遍性能有限，内存及计算能力不足，对于数据管理的场景大多读多写少，且内存占用敏感；
>- 平台使用的文件操作接口是由文件系统提供，一般来说文件操作接口本身并不是进程安全的，请格外注意；
>- 轻量系统，存在不具备锁能力的情况，不提供锁的机制，并发由业务保证，若需要提供有锁机制，则需要提供hook，由业务进行注册。
### 约束<a name="section1944481420490"></a>

- KV大小及可存储条目数在平台可承受内可修改配置，轻量系统默认为小于Key(32byte)，Value(512byte)，通过修改编译宏修改；

- 依赖平台具有正常的文件创建、读写删除修改、锁等能力，针对不同平台（如LiteOS-M内核、LiteOS-A内核等）尽可能表现接口语义功能的不变；

- 由于平台能力差异数据库能力需要做相应裁剪，其中不同平台内部实现可能不同；

- 对于指定路径仅支持创建数据库单例，不支持同一路径创建多数据库实例对象。

## 相关仓<a name="section1371113476307"></a>

分布式数据管理子系统

- [distributeddatamgr\_appdatamgr](https://gitee.com/openharmony/distributeddatamgr_appdatamgr)
- [third\_party\_sqlite](https://gitee.com/openharmony/third_party_sqlite)
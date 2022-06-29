# 数据共享

## 简介<a name="section11660541593"></a>

**数据共享（Data Share）** 用于应用管理其自身数据，也提供了向其他应用共享以及管理其数据的方法，支持同个设备上不同应用之间的数据共享。

**图 1**  逻辑架构图<a name="fig4166312527"></a>  

![](../figures/zh-cn_dataShare逻辑架构图.png)

DataShareHelper模块为数据访问者提供操作DataShareExtAbility即数据提供者模块的接口。

ResultSet模块提供跨应用操作或访问查询出的结果集的接口。

DataShareExtAbility模块实现跨应用数据共享的相关业务。

## 目录

```
/foundation/distributeddatamgr/appdatamgr/data_share
├── frameworks                                   # 框架代码
│   ├── js
│   │   └── napi                                 # NAPI代码存放目录
│   │       ├── common                           # 公用NAPI代码存放目录
│   │       ├── dataShare                        # 客户端NAPI代码存放目录
│   │       ├── datashare_ext_ability            # DataShareExtentionAbility模块JS代码存放目录
│   │       └── datashare_ext_ability_context    # DataShareExtentionAbilityContext模块JS代码存放目录
│   └── native
│       ├── common
│       ├── consumer
│       └── provider
└── interfaces                                   # 对外接口存放目录
    └── inner_api                                # 对内部子系统暴露的头文件存放目录
        ├── common                               # 公用对内部子系统暴露的头文件存放目录
        ├── consumer                             # 客户端对内部子系统暴露的头文件存放目录
        └── provider                             # 服务端对内部子系统暴露的头文件存放目录
```




## 约束<a name="section119744591305"></a>

**数据共享（Data Share）** 受到所使用数据库或IPC通信的约束与限制，例如支持的数据模型，Key的长度、Value的长度、每个应用程序最多支持同时打开数据库数量、针对每个应用程序的流控等。

## 相关仓<a name="section1371113476307"></a>

分布式数据管理子系统

[distributeddatamgr_datamgr](https://gitee.com/openharmony/distributeddatamgr_datamgr/blob/master/README_zh.md)

[**distributeddatamgr_appdatamgr**](https://gitee.com/openharmony/distributeddatamgr_appdatamgr/blob/master/README_zh.md)
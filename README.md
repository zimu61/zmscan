# 漏洞扫描器

一个基于Go和Python开发的安全漏洞检测工具，支持自定义POC、批量扫描、图形化界面等功能。

## 功能特性

- **图形化界面**: 使用PyQt5开发的友好用户界面
- **POC管理**: 独立的POC库，支持YAML格式定义，可自定义POC
- **POC分类**: 支持CVE、厂商漏洞、其他等分类管理
- **导入导出**: 支持按分类导入导出POC
- **批量扫描**: 支持批量IP和端口扫描
- **可配置**: 扫描并发数、超时时间等参数可配置
- **实时进度**: 实时显示扫描进度和结果
- **结果导出**: 支持将扫描结果导出为JSON格式

## 项目结构

```
漏洞扫描器/
├── backend/           # Go后端
│   ├── api/           # API服务层
│   ├── poc/           # POC管理模块
│   ├── scanner/       # 扫描引擎模块
│   ├── main.go        # 程序入口
│   └── go.mod         # Go模块依赖
├── frontend/          # Python前端
│   └── main.py        # 图形化界面
├── pocs/              # POC库目录
│   ├── cve/           # CVE漏洞POC
│   ├── vendor/        # 厂商漏洞POC
│   └── others/        # 其他POC
└── docs/              # 文档目录
    ├── 开发文档.md    # 开发文档和API接口说明
    └── POC编写规则.md # POC编写规则
```

## 技术栈

### 后端 (Go)
- Go 1.21+
- net/http (Web框架)
- gopkg.in/yaml.v3 (YAML解析)

### 前端 (Python)
- Python 3.8+
- PyQt5 (GUI框架)
- requests (HTTP客户端)

## 快速开始

### 环境要求

- Go 1.21+
- Python 3.8+

### 安装依赖

**后端依赖:**
```bash
cd backend
go mod download
```

**前端依赖:**
```bash
pip install PyQt5 requests
```

### 运行程序

1. **启动后端服务**
```bash
cd backend
go run main.go
```

2. **启动前端界面**
```bash
cd frontend
python main.py
```

### 命令行参数

后端服务支持的参数：
```
-port int      API服务器端口 (默认 8080)
-pocs string   POC目录路径 (默认 ../pocs)
-workers int    最大扫描并发数 (默认 50)
-timeout int    默认超时时间(秒) (默认 10)
-version        显示版本信息
```

## 使用说明

### 扫描流程

1. **配置目标**
   - 在"扫描"标签页输入IP地址或域名
   - 配置端口（支持单个端口、端口范围如8000-9000、多端口如80,443）

2. **选择POC**
   - 按分类筛选POC
   - 勾选需要使用的POC

3. **配置扫描参数**
   - 设置并发数（1-200）
   - 设置超时时间（1-60秒）

4. **开始扫描**
   - 点击"开始扫描"按钮
   - 在"扫描结果"标签页查看进度和结果

5. **结果处理**
   - 查看存在漏洞的目标
   - 导出扫描结果

### POC管理

- **导入POC**: 在"POC管理"标签页点击"导入POC"
- **导出POC**: 选中POC后点击"导出POC"
- **重新加载**: 点击"重新加载POC"刷新POC库

## 文档

- [开发文档](docs/开发文档.md) - 包含API接口文档、系统架构等
- [POC编写规则](docs/POC编写规则.md) - POC格式规范和编写指南

## API接口

基础URL: `http://localhost:8080/api`

| 接口 | 方法 | 说明 |
|------|------|------|
| /pocs | GET | 获取POC列表 |
| /pocs/{id} | GET | 获取单个POC |
| /pocs/upload | POST | 上传POC |
| /pocs/export | POST | 导出POC |
| /pocs/{id} | DELETE | 删除POC |
| /pocs/reload | POST | 重新加载POC |
| /scan/start | POST | 开始扫描 |
| /scan/stop | POST | 停止扫描 |
| /scan/status | GET | 获取扫描状态 |
| /scan/results | GET | 获取扫描结果 |
| /categories | GET | 获取分类列表 |
| /stats | GET | 获取统计信息 |
| /health | GET | 健康检查 |

详细的API接口说明请参考 [开发文档](docs/开发文档.md)。

## POC编写

POC采用YAML格式定义，基本结构如下：

```yaml
name: "POC名称"
id: "poc-unique-id"
category: "cve"
severity: "Critical"
description: "漏洞描述"
author: "作者"
version: "1.0.0"
references:
  - "参考链接"
tags:
  - "标签"
target:
  protocol: "http"
  path: "/path"
  method: "GET"
  headers: {...}
  body: ""
  timeout: 10
conditions:
  - type: "status"
    operator: "equals"
    value: 200
```

详细的POC编写规则请参考 [POC编写规则.md](docs/POC编写规则.md)。

## 许可证

本项目仅供学习交流使用。

## 免责声明

本工具仅用于安全研究和授权的渗透测试。使用本工具进行的任何未授权测试均为非法行为，使用者需自行承担相应法律责任。

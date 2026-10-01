# NSEC3 NXDOMAIN 离线证明审计服务

面向离线控制网（卫星任务域名）的 NSEC3 “名称不存在”证明审计台。值班员提交
稳定审计标识、规范域名、目标名称、NSEC3 盐值与迭代次数，以及含 owner 哈希、
next 哈希与类型位图的 NSEC3 记录组；服务精确复算 SHA-1 迭代哈希，验证一条
NXDOMAIN 证明是否成立，并把结论**冻结**供后续按标识重新打开复核。

> 仅支持 **SHA-1（算法 1）且无 Opt-Out** 的 NSEC3（RFC 5155）。

## 判定规则（RFC 5155 §8.9）

结论为“通过”必须**同时**满足：

1. **最近存在祖先（Closest Encloser, CE）**：目标祖先链（目标自身逐层到区域
   顶点）中最深的、其 NSEC3 owner 哈希确实出现在记录组中的名称；
2. **下一层名称（Next Closer Name, NC）**：CE 之下、通往目标路径上的第一层
   名称，其哈希必须落入某条记录的**环形半开区间** `(owner, next)`；
3. **通配符名 `*.<CE>`**：其哈希也必须落入某条记录的半开区间，以排除通配符
   展开。

半开区间在哈希环上判定：`owner < h < next` 为非环绕；`owner > next` 时
`h > owner 或 h < next` 为**环绕（wrap）**。owner==next 为退化空区间，拒绝。

下列情况一律 **rejected，绝不给出通过结论**：

- 重复 owner（无论断言是否一致）；同 owner 但 next/位图/Opt-Out 冲突；
- 区间与其他 owner 存在性断言冲突（伪造 next、错误环绕区间等）；
- 非法 Base32hex、非法盐值/迭代次数/域名/类型位图；
- 任何记录带 Opt-Out；非 SHA-1 输入；
- 缺少 CE、缺少 NC 覆盖（截断证据）、缺少通配符覆盖（无法排除通配符）；
- 目标或通配符的 owner 哈希实际存在、目标在区外、目标即顶点；
- 审计标识复用但载荷改变（HTTP 409，原冻结结论不被覆盖）；
- 记录组为空等证据不足情形。

页面与读取结果**并列展示**：最近存在祖先、两项被覆盖名称（NC 与 `*.CE`）、
所用记录及各自环绕方向/覆盖标记，并列出每个祖先的复算哈希，供审查员复算。

## 目录结构

```
app/nsec3.py     NSEC3 参数解析、Base32hex、RFC5155 迭代哈希
app/verifier.py  证明审计核心（CE/NC/通配符、环形区间、冲突检测、可复用纯函数）
app/packages.py  多目标共同记录证据包引擎（候选子集逐目标重算、最少化+稳定裁决）
app/storage.py   冻结结论持久化、审计/证据包标识复用与篡改检测
app/server.py    标准库 HTTP 服务（页面 + JSON API + 健康检查）
app/templates/   审计页面
tests/           哈希/判定/证据包/HTTP 共 60 项测试
verify           一次性验收可执行文件（构建检查+测试+场景+HTTP 冒烟）
```

运行只依赖 Python 3.11 标准库，无需联网安装包。

## 本地运行

```bash
python3 -m app.server            # 默认 0.0.0.0:8080，数据 /data/audits.json
PORT=8080 AUDIT_DB=./audits.json python3 -m app.server
```

- 健康地址：`GET /healthz`
- 审计页面：`GET /`
- 提交冻结：`POST /api/audits`
- 按标识重开：`GET /api/audits?id=<audit_id>`
- 全部标识：`GET /api/audits`

### 提交载荷示例

```json
{
  "audit_id": "SAT-NSEC3-20260929-001",
  "zone": "example.cn",
  "target": "host.offline.example.cn",
  "salt": "-",
  "iterations": 0,
  "records": [
    {"owner_hash": "…", "next_hash": "…", "types": "NS SOA RRSIG", "opt_out": false}
  ]
}
```

`types` 也接受数组。HTTP 状态：通过 `200`，拒绝 `422`，标识复用冲突 `409`。

## 多目标共同记录证据包

值班员打开一份**已通过**的冻结审计后，可提交稳定证据包标识与 **2–6 个**
同一区域的规范目标名称，服务从**来源审计冻结的完整记录组**中抽出一组共同
记录，使每个目标在该子集上同时构成完整 RFC 5155 不存在证明。

- 证据包把来源审计的 **zone、salt、iterations 与完整记录组**原样冻结进
  包体；出具证据包**绝不改写来源审计**。
- 明确拒绝（`422`）：来源审计不存在或结论非通过、目标越区、目标即顶点、
  重复目标（大小写归一后相同也算）、目标数不在 2–6、任一目标在来源完整
  记录组上即不可证明。
- 证据包标识复用但改换**来源或目标**：`409`，原冻结结论保持不变。

### 候选子集如何裁决

- 对每个候选子集，每个目标都**重新调用**核心判定，重算最近存在祖先（CE）、
  下一层名称（NC）与 `*.CE` 通配符覆盖；任何一个目标不再通过，候选即失效。
- **不能**把各目标在完整记录组上各自的单条证明简单拼接：增删一条记录都可能
  移动 CE（例如加入某个中层祖先 owner 后，CE 下移、新的下一层名称失去覆盖），
  引擎会枚举 CE 层级组合并逐目标复算筛选。
- 最优裁决是**先最少化记录数**；记录数相同时，按所选记录 **owner 哈希升序
  序列**做字典序稳定裁决（测试中以 2ⁿ 全子集暴力枚举作为对照预言机）。

页面与 `GET /api/packages?id=…` 的结果**并列**给出：

- 每个目标的三项证明角色（CE 记录、NC 覆盖记录、`*.CE` 覆盖记录）与祖先
  哈希复算；
- 每条选用记录的**共享归属**（服务于哪些目标、扮演什么角色）；
- **未被选用**的来源记录清单；
- “共同子集条数 vs 各目标单条证明简单拼接条数”的减少量。

### 证据包接口

- 提交冻结：`POST /api/packages`
- 按包标识重开：`GET /api/packages?id=<package_id>`
- 全部包标识：`GET /api/packages`

```json
{
  "package_id": "SAT-PKG-20261001-001",
  "source_audit_id": "SAT-NSEC3-20260929-001",
  "targets": ["host-a.offline.example.cn", "host-b.offline.example.cn"]
}
```

返回体中关键字段：`selected`（按 owner 哈希升序的最优共同记录，含 `serves`
共享归属）、`unused`（未选用记录）、`shared`（多目标共享记录）、
`targets_detail`（每目标 CE/NC/WC 三角色与祖先复算）、
`selected_count` 与 `stitched_single_proof_count`（减少总数对照）、
`candidate_stats`（逐目标复算的候选数/通过数）。

## Docker Compose

宿主机端口由 `HOST_PORT` 配置（默认 8080）：

```bash
HOST_PORT=18080 docker compose up -d --build web
# 健康地址  http://<宿主机>:18080/healthz
# 审计页面  http://<宿主机>:18080/
```

### 一次性验收服务 `verify`

名为 `verify` 的可执行一次性验收服务会等待 `web` 健康，然后：

- 字节码构建检查；
- 穿插执行全部单元/集成/API 测试；
- 验证**合法不存在证明与环绕覆盖可通过**；
- 验证**遗漏通配符覆盖、非法记录（及 Opt-Out、重复 owner）被拒绝**；
- 对 Compose 中的 `web` 做 API/HTTP 冒烟（健康、页面、提交、重开、复用冲突）；
- 完成后退出，**退出码即验收结果**（0 通过，非零失败）。

```bash
docker compose run --rm verify     # 前台查看报告
echo $?                            # 0 表示验收通过
```

不使用容器时可直接运行同一可执行文件：

```bash
./verify            # 自包含（就地拉起临时 HTTP 服务冒烟）
BASE_URL=http://127.0.0.1:8080 ./verify
```

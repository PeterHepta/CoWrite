# 详细设计二：CRDT 协同编辑业务流程

## 1. 概述

CoWrite 的协同编辑核心基于 **CRDT（Conflict-free Replicated Data Type）** 思想，以"位置无关唯一 ID"标识每个字符，通过字符串字典序保证多端插入的全局排序一致性，无需中央仲裁。

本文描述涉及该业务的全部函数及其调用关系。

---

## 2. 核心数据结构

### 2.1 文档状态（客户端）

```javascript
docState = [
    { id: "leftPos@siteId", char: "H", attributes: { bold: true } },
    { id: "midPos@siteId",  char: "i", attributes: {} },
    ...
]
```

- `id`：格式为 `"位置串@站点ID"`，**全局唯一**，字典序即为文档顺序。
- `char`：单个字形（grapheme cluster），或 embed 对象（如 emoji）。
- `attributes`：富文本格式（bold、italic、color 等）。

### 2.2 数据库存储（服务端）

`events` 表中每条记录为一个操作 JSON：

```json
{ "type": "insert", "id": "abc@2", "char": "H", "attributes": {} }
{ "type": "delete", "id": "abc@2" }
{ "type": "format", "id": "abc@2", "key": "bold", "value": true }
```

新客户端加入时，服务端重放全部 events 重建文档。

---

## 3. 函数调用关系总览

```
【本地编辑】
quill.on('text-change')
    └── 处理 delta.ops
            ├── insert → generatePosBetween() → 生成 absoluteId
            │              └── docState.splice(insert)
            │              └── batchOps.push({type:"insert",...})
            ├── delete → docState.splice(remove)
            │              └── batchOps.push({type:"delete",...})
            └── retain+attributes → 遍历 docState 更新 attributes
                             └── batchOps.push({type:"format",...})
    └── ws.send(ops_batch 或单条)

【远端编辑接收】
handleMessage(data)
    ├── type=="insert"    → docState.push → docState.sort → quill.insertText
    ├── type=="delete"    → docState.splice → quill.deleteText
    ├── type=="format"    → 更新 attributes → quill.formatText
    └── type=="ops_batch" → applyOpsToDocState(data.ops) → sort → rebuildQuill

【历史回放（新用户加入）】
handleMessage("history_batch")
    └── applyOpsToDocState(events)
            ├── insert  → docState.push
            ├── delete  → docState.splice
            └── format  → attributes 更新
    └── docState.sort → rebuildQuill

【快照加载】
handleMessage("snapshot_init") 或 handleMessage("load_save_applied")
    └── applySnapshot({docState, shapes})
            ├── docState.length = 0 → 用 snap.docState 填充
            ├── rebuildQuill(docState)
            ├── shapes.length = 0 → 清除所有 shape DOM
            └── snap.shapes.forEach → syncShapeEl
```

---

## 4. 核心函数详细描述

### 4.1 `generatePosBetween(left, right)` — 位置 ID 生成算法

**职责**：在 `left` 和 `right` 两个位置串之间生成一个新的位置串，使得 `left < newPos < right`（字典序）。

**算法流程**：

```
输入：left = "abc", right = "abd"

逐字符对比：
  i=0: l='a'(97), r='a'(97) → 相等，追加'a'，继续
  i=1: l='b'(98), r='b'(98) → 相等，追加'b'，继续
  i=2: l='c'(99), r='d'(100) → r-l=1，不足2，追加'c'，继续
  i=3: l=96(默认左边界), r=123(默认右边界) → r-l>1 → pos += chr(floor((96+123)/2)) = chr(109) = 'm'
  返回 "abcm"

验证: "abc" < "abcm" < "abd" ✓
```

**边界值约定**：
- 无左邻居时，`l = 96`（字符 `` ` ``，ASCII 96，低于所有可见字符）
- 无右邻居时，`r = 123`（字符 `{`，ASCII 123，高于所有小写字母）

**特殊情况**：若 `r - l == 1`（无中间值），则当前字符取 `l` 并向下一位继续，直到找到可以插入中间值的位置。

```javascript
// client.html:956-965
function generatePosBetween(left, right) {
    let pos = ""; let i = 0;
    while (true) {
        let l = i < left.length  ? left.charCodeAt(i)  : 96;
        let r = i < right.length ? right.charCodeAt(i) : 123;
        if (r - l > 1) {
            pos += String.fromCharCode(Math.floor((l + r) / 2));
            return pos;
        } else {
            pos += String.fromCharCode(l);
        }
        i++;
    }
}
```

### 4.2 `quill.on('text-change', ...)` — 本地编辑转换为 CRDT 操作

**职责**：将 Quill 的增量格式（Delta）转换为 CRDT 操作并广播。

**处理流程**：

```
delta.ops 中可能包含三种原语：
  retain N           → 跳过 N 个字符（可选带 attributes → 格式化）
  insert "字符串"     → 插入字符
  delete N           → 删除 N 个字符

遍历 delta.ops，维护 currentIndex（docState 中的当前位置指针）：

  retain:
    若无 attributes → currentIndex += N，不产生操作
    若有 attributes → 遍历 [currentIndex, currentIndex+N)，对每个字符
                       生成 format 操作，更新本地 attributes

  insert:
    用 Intl.Segmenter 按 grapheme cluster 切分多字节字符
    对每个 grapheme：
      leftId  = docState[currentIndex-1].id 的位置串部分（"@"前）
      rightId = docState[currentIndex].id 的位置串部分（"@"前）
      newPos  = generatePosBetween(leftId, rightId)
      absoluteId = newPos + "@" + mySiteId
      docState.splice(currentIndex, 0, {id, char, attributes})
      batchOps.push({type:"insert", id, char, attributes})
      currentIndex++

  delete:
    对 N 个字符，取 docState[currentIndex].id，splice 移除
    batchOps.push({type:"delete", id})
    （currentIndex 不变，因为元素已删除）

发送：
  batchOps.length == 1 → ws.send(JSON.stringify(batchOps[0]))
  batchOps.length > 1  → ws.send(JSON.stringify({type:"ops_batch", ops:batchOps}))
```

**关键设计**：`absoluteId = 位置串@站点ID` 保证不同站点同时在同一位置插入时，最终排序由 `id` 字典序决定，无冲突。

### 4.3 `applyOpsToDocState(evList)` — 操作应用函数

**职责**：将操作列表（来自远端广播或历史回放）应用到本地 `docState`。

```javascript
// client.html:993-1010
function applyOpsToDocState(evList) {
    for (const e of evList) {
        if (e.type === "insert") {
            docState.push({ id: e.id, char: e.char, attributes: e.attributes || {} });
            // 注意：push 后不立即 sort，批量处理完再 sort 一次
        } else if (e.type === "delete") {
            const idx = docState.findIndex(item => item.id === e.id);
            if (idx !== -1) docState.splice(idx, 1);
        } else if (e.type === "format") {
            const item = docState.find(item => item.id === e.id);
            if (item) {
                if (e.value === null || e.value === false) delete item.attributes[e.key];
                else item.attributes[e.key] = e.value;
            }
        } else if (["shape_add","shape_move","shape_delete"].includes(e.type)) {
            applyRemoteShape(e);
        }
    }
}
```

**关键设计**：insert 使用 `push` 而非 `splice`，批量操作完后调用一次 `docState.sort(id字典序)` 整体排序，比每次 insert 都 splice 性能更好。

### 4.4 `rebuildQuill(state)` — 全量重建编辑器

**职责**：将 `docState` 数组转换为 Quill Delta 并一次性刷新编辑器，避免逐条操作带来的性能开销。

```javascript
// client.html:974-990
function rebuildQuill(state) {
    const ops = [];
    for (const item of state) {
        const op = { insert: item.char };
        if (Object.keys(item.attributes).length > 0) op.attributes = item.attributes;
        ops.push(op);
    }
    if (ops.length > 0) quill.setContents({ ops }, 'silent');
    // 'silent' 表示此次变更不触发 text-change 事件，避免循环广播
}
```

**调用场景**：
- `history_batch` 接收后（新用户加入时）
- `ops_batch` 接收后（批量远端操作）
- `applySnapshot` 后（快照加载）

### 4.5 `handleMessage` 中的单条远端操作应用

对于单条实时操作（非批量），直接操作 Quill 以获得最低延迟：

```
收到 insert:
  docState.push({id, char, attributes})
  docState.sort(id字典序)
  relativeIndex = docState.findIndex(item => item.id === data.id)
  quill.insertText(relativeIndex, char, attributes, 'silent')

收到 delete:
  targetIndex = docState.findIndex(item => item.id === data.id)
  deletedItem = docState.splice(targetIndex, 1)[0]
  quill.deleteText(targetIndex, len, 'silent')

收到 format:
  targetIndex = docState.findIndex(item => item.id === data.id)
  更新 attributes
  quill.formatText(targetIndex, len, key, value, 'silent')
```

---

## 5. 自动快照压缩流程（跨函数协作）

当 `events` 表过大时，通过自动快照压缩历史，涉及服务端与客户端多个函数协作：

```
【触发端：服务端 Room::save_event()】
  每收到一条 event → event_count_++
  → maybe_request_auto_snapshot()
        若 event_count_ >= 500 且 !snapshot_requested_ 且 sessions_ 非空：
            snapshot_requested_ = true
            target->send({"type":"request_auto_snapshot"})

【客户端响应：handleMessage("request_auto_snapshot")】
  captureSnapshot()
      → 深拷贝 docState 和 shapes
  ws.send({type:"submit_auto_snapshot",
           doc_state: JSON.stringify(snap.docState),
           shapes: JSON.stringify(snap.shapes)})

【服务端接收：on_read() 处理 "submit_auto_snapshot"】
  db_task:
    INSERT INTO saves (is_auto=1, doc_state, shapes)     ← 插入自动快照
    DELETE FROM events WHERE doc_id=?                     ← 清空 events 表
    DELETE old auto snaps (保留最新一条)
    net::post(io) → room_ref->reset_snapshot_state()     ← 重置计数器和锁

【新用户加入时：Room::send_history()】
  db_task:
    SELECT latest auto_snap (is_auto=1)
    若存在：
      发送 snapshot_init {doc_state, shapes}              ← 先发快照基线
      SELECT events WHERE id > snap_rowid                 ← 再发增量
      若有增量 → 发送 history_batch {events}
    若不存在：
      SELECT all events                                   ← 全量回放
      发送 history_batch {events}
```

**关键不变式**：
1. `event_count_` 仅在 io 线程（`save_event`）中递增，`snapshot_requested_` 有互斥锁保护，保证每次只请求一次快照。
2. `reset_snapshot_state()` 必须在快照写入完成后才回到 io 线程调用，确保顺序性。
3. 快照存储在 `saves` 表中（`is_auto=1`），与用户手动存档共表，通过 `id` 字段追踪增量起点。

---

## 6. 并发冲突场景示例

### 场景：A 和 B 同时在同一位置插入字符

```
初始文档：["H"@1, "i"@1]

A（site=1）在 "H" 后插入 "e"：
  leftId = "H_pos"，rightId = "i_pos"
  newId = generatePosBetween("H_pos", "i_pos") + "@1" = "H_mid@1"
  本地 docState: ["H"@1, "He@1", "i"@1]
  广播: {type:"insert", id:"H_mid@1", char:"e"}

B（site=2）同时在 "H" 后插入 "o"：
  leftId = "H_pos"，rightId = "i_pos"（相同区间）
  newId = generatePosBetween("H_pos", "i_pos") + "@2" = "H_mid@2"
  本地 docState: ["H"@1, "Ho@2", "i"@1]
  广播: {type:"insert", id:"H_mid@2", char:"o"}

A 收到 B 的 insert：
  docState.push({"H_mid@2", "o"})
  sort 后：["H_pos@1", "H_mid@1", "H_mid@2", "i_pos@1"]
  → 因为 "H_mid@1" < "H_mid@2"（字典序），A 端显示 "Heoi"

B 收到 A 的 insert：
  docState.push({"H_mid@1", "e"})
  sort 后：["H_pos@1", "H_mid@1", "H_mid@2", "i_pos@1"]
  → B 端同样显示 "Heoi"

两端收敛为同一状态 ✓
```

位置串中嵌入 `@siteId` 后缀，保证即使两端生成相同的位置前缀，最终排序也由站点 ID 决定，实现无需通信的冲突解决。

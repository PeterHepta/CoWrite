#!/usr/bin/env python3
"""
冒烟测试：覆盖后端关键 WebSocket 协议流程。
重构前后都应通过，作为等价性基线。

用法:
    1. 先启动服务: ./tests/run_server.sh
    2. 另开终端: python3 tests/smoke_test.py
"""
import asyncio
import json
import sys
import time
import uuid

import websockets

URL = "ws://127.0.0.1:9002"
TIMEOUT = 5.0


class Client:
    def __init__(self, ws):
        self.ws = ws

    @classmethod
    async def connect(cls):
        ws = await websockets.connect(URL)
        return cls(ws)

    async def send(self, obj):
        await self.ws.send(json.dumps(obj))

    async def recv(self):
        raw = await asyncio.wait_for(self.ws.recv(), timeout=TIMEOUT)
        return json.loads(raw)

    async def recv_until(self, predicate, max_msgs=20):
        """支持 batch: 自动展开 {"type":"batch","msgs":[...]}"""
        seen = []
        for _ in range(max_msgs):
            msg = await self.recv()
            candidates = msg.get("msgs", []) if msg.get("type") == "batch" else [msg]
            for m in candidates:
                seen.append(m)
                if predicate(m):
                    return m
        raise AssertionError(f"未在 {max_msgs} 条消息内收到匹配消息，已收: {[s.get('type') for s in seen]}")

    async def close(self):
        await self.ws.close()


def assert_eq(actual, expected, label):
    if actual != expected:
        raise AssertionError(f"{label}: 期望 {expected!r}, 实际 {actual!r}")


def assert_truthy(v, label):
    if not v:
        raise AssertionError(f"{label}: 期望真值, 实际 {v!r}")


async def run_test(name, coro):
    print(f"  [..] {name}", flush=True)
    t0 = time.time()
    try:
        await coro
    except Exception as e:
        print(f"  [FAIL] {name}: {e}", flush=True)
        return False
    print(f"  [OK]   {name}  ({(time.time()-t0)*1000:.0f}ms)", flush=True)
    return True


# ---------- 测试用例 ----------

async def t_register_login():
    c = await Client.connect()
    user = "u_" + uuid.uuid4().hex[:8]
    pwd = "pw_" + uuid.uuid4().hex[:6]

    await c.send({"type": "register", "username": user, "password": pwd})
    res = await c.recv_until(lambda m: m.get("type") == "register_res")
    assert_truthy(res.get("success"), "register 应成功")

    # 重复注册应失败
    await c.send({"type": "register", "username": user, "password": pwd})
    res = await c.recv_until(lambda m: m.get("type") == "register_res")
    assert_eq(res.get("success"), False, "重复注册应失败")

    # 错误密码登录
    await c.send({"type": "login", "username": user, "password": "wrong"})
    res = await c.recv_until(lambda m: m.get("type") == "login_res")
    assert_eq(res.get("success"), False, "错密码应失败")

    # 正确登录
    await c.send({"type": "login", "username": user, "password": pwd})
    res = await c.recv_until(lambda m: m.get("type") == "login_res")
    assert_truthy(res.get("success"), "正确登录应成功")
    assert_eq(res.get("username"), user, "用户名应回显")

    await c.close()
    return user, pwd


async def t_create_and_join_room():
    # owner 创建房间
    owner = await Client.connect()
    u_owner = "owner_" + uuid.uuid4().hex[:8]
    await owner.send({"type": "register", "username": u_owner, "password": "p"})
    await owner.recv_until(lambda m: m.get("type") == "register_res")
    await owner.send({"type": "login", "username": u_owner, "password": "p"})
    await owner.recv_until(lambda m: m.get("type") == "login_res")

    await owner.send({"type": "create_room", "room_name": "测试房", "invite_type": "once"})
    res = await owner.recv_until(lambda m: m.get("type") == "create_room_res")
    assert_truthy(res.get("success"), "create_room 应成功")
    code = res["code"]
    doc_id = res["doc_id"]
    assert_eq(res.get("room_name"), "测试房", "房间名")

    # guest 加入
    guest = await Client.connect()
    u_guest = "guest_" + uuid.uuid4().hex[:8]
    await guest.send({"type": "register", "username": u_guest, "password": "p"})
    await guest.recv_until(lambda m: m.get("type") == "register_res")
    await guest.send({"type": "login", "username": u_guest, "password": "p"})
    await guest.recv_until(lambda m: m.get("type") == "login_res")

    await guest.send({"type": "join_with_code", "code": code})
    res = await guest.recv_until(lambda m: m.get("type") == "join_with_code_res")
    assert_truthy(res.get("success"), "join_with_code 应成功")
    assert_eq(res.get("doc_id"), doc_id, "doc_id 一致")

    # 第二次使用 once 邀请码应失败
    again = await Client.connect()
    u3 = "user3_" + uuid.uuid4().hex[:8]
    await again.send({"type": "register", "username": u3, "password": "p"})
    await again.recv_until(lambda m: m.get("type") == "register_res")
    await again.send({"type": "login", "username": u3, "password": "p"})
    await again.recv_until(lambda m: m.get("type") == "login_res")
    await again.send({"type": "join_with_code", "code": code})
    res = await again.recv_until(lambda m: m.get("type") == "join_with_code_res")
    assert_eq(res.get("success"), False, "once 邀请码二次使用应失败")
    await again.close()

    # owner 与 guest 同时进入房间
    await owner.send({"type": "join", "doc_id": doc_id})
    await guest.send({"type": "join", "doc_id": doc_id})

    init1 = await owner.recv_until(lambda m: m.get("type") == "init")
    init2 = await guest.recv_until(lambda m: m.get("type") == "init")
    assert_truthy(init1.get("site_id"), "owner site_id")
    assert_truthy(init2.get("site_id"), "guest site_id")

    return owner, guest, doc_id, u_owner, u_guest, init1["site_id"], init2["site_id"]


async def t_broadcast_insert():
    owner, guest, doc_id, u_owner, u_guest, sid_o, sid_g = await t_create_and_join_room()

    # owner 发一个 insert，guest 应收到（recv_until 会自动展开 batch）
    payload = {
        "type": "insert", "id": "evt_1",
        "char": "A", "pos": "M", "site_id": sid_o
    }
    await owner.send(payload)

    msg = await guest.recv_until(lambda m: m.get("type") == "insert" and m.get("id") == "evt_1")
    assert_eq(msg.get("char"), "A", "insert.char")

    await owner.close()
    await guest.close()


async def t_my_rooms_and_rejoin():
    # Session 是单房间的状态机：一旦 join 后再发 get_my_rooms 不会被响应。
    # 所以每次查询用新连接。

    async def login_as(client, u, pwd="p"):
        await client.send({"type": "login", "username": u, "password": pwd})
        await client.recv_until(lambda m: m.get("type") == "login_res")

    async def register_user(u):
        c = await Client.connect()
        await c.send({"type": "register", "username": u, "password": "p"})
        await c.recv_until(lambda m: m.get("type") == "register_res")
        await c.close()

    u = "myrooms_" + uuid.uuid4().hex[:8]
    await register_user(u)

    # 创建并 join R1（join 是 owner 进入 room_members 的唯一路径）
    c1 = await Client.connect()
    await login_as(c1, u)
    await c1.send({"type": "create_room", "room_name": "R1", "invite_type": "permanent"})
    r1 = await c1.recv_until(lambda m: m.get("type") == "create_room_res")
    await c1.send({"type": "join", "doc_id": r1["doc_id"]})
    await c1.recv_until(lambda m: m.get("type") == "init")
    await c1.close()

    # 创建并 join R2
    c2 = await Client.connect()
    await login_as(c2, u)
    await c2.send({"type": "create_room", "room_name": "R2", "invite_type": "permanent"})
    r2 = await c2.recv_until(lambda m: m.get("type") == "create_room_res")
    await c2.send({"type": "join", "doc_id": r2["doc_id"]})
    await c2.recv_until(lambda m: m.get("type") == "init")
    await c2.close()

    # 新连接：get_my_rooms 必须在 join 之前
    c3 = await Client.connect()
    await login_as(c3, u)
    await c3.send({"type": "get_my_rooms"})
    res = await c3.recv_until(lambda m: m.get("type") == "get_my_rooms_res")
    assert_truthy(res.get("success"), "get_my_rooms 应成功")
    rooms = res.get("rooms", [])
    doc_ids = {r.get("doc_id") for r in rooms}
    assert_truthy(r1["doc_id"] in doc_ids, f"R1 在 my_rooms (got {doc_ids})")
    assert_truthy(r2["doc_id"] in doc_ids, f"R2 在 my_rooms (got {doc_ids})")
    await c3.close()

    # rejoin_room 测试：必须用新连接
    c4 = await Client.connect()
    await login_as(c4, u)
    await c4.send({"type": "rejoin_room", "doc_id": r1["doc_id"]})
    init_msg = await c4.recv_until(lambda m: m.get("type") == "init")
    assert_truthy(init_msg.get("site_id"), "rejoin 后应收到 init")
    await c4.close()


async def t_rename_and_members():
    owner = await Client.connect()
    u_o = "ow_" + uuid.uuid4().hex[:8]
    await owner.send({"type": "register", "username": u_o, "password": "p"})
    await owner.recv_until(lambda m: m.get("type") == "register_res")
    await owner.send({"type": "login", "username": u_o, "password": "p"})
    await owner.recv_until(lambda m: m.get("type") == "login_res")
    await owner.send({"type": "create_room", "room_name": "原名", "invite_type": "permanent"})
    r = await owner.recv_until(lambda m: m.get("type") == "create_room_res")
    doc_id = r["doc_id"]

    await owner.send({"type": "join", "doc_id": doc_id})
    await owner.recv_until(lambda m: m.get("type") == "init")

    await owner.send({"type": "rename_room", "room_name": "新名"})
    res = await owner.recv_until(lambda m: m.get("type") == "rename_room_res")
    assert_truthy(res.get("success"), "rename 应成功")
    assert_eq(res.get("room_name"), "新名", "新房名")

    await owner.send({"type": "get_room_members"})
    res = await owner.recv_until(lambda m: m.get("type") == "get_room_members_res")
    assert_truthy(res.get("success"), "get_members 应成功")
    members = res.get("members", [])
    usernames = [m.get("username") for m in members]
    assert_truthy(u_o in usernames, "owner 在成员列表中")

    await owner.close()


async def t_save_load_delete():
    owner = await Client.connect()
    u = "sv_" + uuid.uuid4().hex[:8]
    await owner.send({"type": "register", "username": u, "password": "p"})
    await owner.recv_until(lambda m: m.get("type") == "register_res")
    await owner.send({"type": "login", "username": u, "password": "p"})
    await owner.recv_until(lambda m: m.get("type") == "login_res")
    await owner.send({"type": "create_room", "room_name": "存档房", "invite_type": "permanent"})
    r = await owner.recv_until(lambda m: m.get("type") == "create_room_res")
    doc_id = r["doc_id"]
    await owner.send({"type": "join", "doc_id": doc_id})
    await owner.recv_until(lambda m: m.get("type") == "init")

    await owner.send({
        "type": "save_snapshot", "name": "存档1",
        "doc_state": "[]", "shapes": "[]"
    })
    res = await owner.recv_until(lambda m: m.get("type") == "save_snapshot_res")
    assert_truthy(res.get("success"), "save_snapshot 应成功")
    save_id = res["id"]

    await owner.send({"type": "get_saves"})
    res = await owner.recv_until(lambda m: m.get("type") == "get_saves_res")
    assert_truthy(res.get("success"), "get_saves 应成功")
    saves = res.get("saves", [])
    assert_truthy(any(s.get("id") == save_id for s in saves), "存档应在列表中")

    await owner.send({"type": "delete_save", "save_id": save_id})
    res = await owner.recv_until(lambda m: m.get("type") in ("delete_save_res", "save_deleted"))
    assert_truthy(res.get("save_id") == save_id, "delete_save 返回正确 id")

    await owner.close()


async def t_gen_invite():
    owner = await Client.connect()
    u = "gi_" + uuid.uuid4().hex[:8]
    await owner.send({"type": "register", "username": u, "password": "p"})
    await owner.recv_until(lambda m: m.get("type") == "register_res")
    await owner.send({"type": "login", "username": u, "password": "p"})
    await owner.recv_until(lambda m: m.get("type") == "login_res")
    await owner.send({"type": "create_room", "room_name": "GI", "invite_type": "once"})
    r = await owner.recv_until(lambda m: m.get("type") == "create_room_res")
    await owner.send({"type": "join", "doc_id": r["doc_id"]})
    await owner.recv_until(lambda m: m.get("type") == "init")

    await owner.send({"type": "gen_invite", "invite_type": "permanent"})
    res = await owner.recv_until(lambda m: m.get("type") == "gen_invite_res")
    assert_truthy(res.get("success"), "gen_invite 应成功")
    assert_truthy(res.get("code"), "返回邀请码")
    await owner.close()


async def main():
    print(f"连接 {URL} ...", flush=True)
    try:
        c = await Client.connect()
        await c.close()
    except Exception as e:
        print(f"无法连接服务器: {e}", flush=True)
        sys.exit(2)

    tests = [
        ("register/login", t_register_login()),
        ("create + join_with_code + once 邀请码限制", t_create_and_join_room()),
        ("insert 广播", t_broadcast_insert()),
        ("get_my_rooms + rejoin_room", t_my_rooms_and_rejoin()),
        ("rename_room + get_room_members", t_rename_and_members()),
        ("save/get/delete snapshot", t_save_load_delete()),
        ("gen_invite", t_gen_invite()),
    ]

    passed = 0
    for name, coro in tests:
        if await run_test(name, coro):
            passed += 1

    print(f"\n{passed}/{len(tests)} 通过", flush=True)
    sys.exit(0 if passed == len(tests) else 1)


if __name__ == "__main__":
    asyncio.run(main())

function onKicked(data) {
    alert(data.msg);
    localStorage.clear();
    location.reload();
}

function onRegisterRes(data) {
    showToast(data.msg, data.success !== false ? 'success' : 'error');
    if (data.success !== false) switchTab('login');
}

function onLoginRes(data) {
    if (data.success) {
        authOverlay.style.display = 'none';
        btnLogout.style.display = 'inline-block';
        localStorage.setItem('myUsername', myUsername);
        localStorage.setItem('myPassword', myPassword);
        siteDisplay.innerText = `${myUsername}`;
        addLog(`登录成功！欢迎回来，${myUsername}！`, true);
        if (currentRoom) {
            statusSpan.innerText = "重新加入房间中";
            ws.send(JSON.stringify({ type: "join", doc_id: currentRoom.doc_id, requested_site_id: mySiteId || 0 }));
        } else {
            statusSpan.innerText = "已登录，选择房间";
            roomChoiceOverlay.style.display = 'flex';
        }
    } else {
        showToast(data.msg, 'error');
        authOverlay.style.display = 'flex';
        localStorage.clear();
    }
}

function onCreateRoomRes(data) {
    if (data.success) {
        currentRoom = { doc_id: data.doc_id, code: data.code, room_name: data.room_name };
        localStorage.setItem('currentRoom', JSON.stringify(currentRoom));
        roomChoiceOverlay.style.display = 'none';
        inviteTypeOverlay.style.display = 'none';
        inviteCodeDisplay.innerText = data.code;
        inviteTypeHint.innerText = inviteTypeHintText(data.invite_type, data.expires_at);
        roomCreatedOverlay.style.display = 'flex';
        addLog(`房间「${data.room_name}」已创建，邀请码: ${data.code}`, true);
    } else {
        showToast(data.msg, 'error');
    }
}

function onGenInviteRes(data) {
    if (data.success) {
        genInviteCodeDisplay.innerText = data.code;
        genInviteTypeHint.innerText = inviteTypeHintText(data.invite_type, data.expires_at);
        genInviteOverlay.style.display = 'flex';
        addLog(`新邀请码已生成: ${data.code}`, true);
    } else {
        showToast(data.msg || '生成邀请码失败', 'error');
    }
}

function onJoinWithCodeRes(data) {
    if (data.success) {
        currentRoom = { doc_id: data.doc_id, room_name: data.room_name };
        localStorage.setItem('currentRoom', JSON.stringify(currentRoom));
        joinRoomOverlay.style.display = 'none';
        statusSpan.innerText = "进入房间中";
        docDisplay.innerText = `${data.room_name || data.doc_id}`;
        ws.send(JSON.stringify({ type: "join", doc_id: currentRoom.doc_id, requested_site_id: mySiteId || 0 }));
    } else {
        showToast(data.msg, 'error');
        inputInviteCode.value = '';
    }
}

function onGetMyRoomsRes(data) {
    myRoomsLoading.style.display = 'none';
    if (!data.success) {
        myRoomsList.innerHTML = `<p class="flow-hint" style="color:#ff3b30;">${escapeHtml(data.msg || '加载失败')}</p>`;
        return;
    }
    if (!data.rooms || data.rooms.length === 0) {
        myRoomsList.innerHTML = '<p class="flow-hint">暂无历史房间记录</p>';
        return;
    }
    const nameCount = {};
    const nameIndex = {};
    data.rooms.forEach(r => { nameCount[r.room_name] = (nameCount[r.room_name] || 0) + 1; });
    data.rooms.forEach(room => {
        let displayName = room.room_name;
        if (nameCount[room.room_name] > 1) {
            nameIndex[room.room_name] = (nameIndex[room.room_name] || 0) + 1;
            displayName = `${room.room_name}(${nameIndex[room.room_name]})`;
        }
        const card = document.createElement('div');
        card.className = 'room-card';
        const joinedDate  = room.joined_at  ? new Date(room.joined_at  * 1000).toLocaleDateString('zh-CN') : '未知';
        const createdDate = room.created_at && room.created_at > 0
            ? new Date(room.created_at * 1000).toLocaleDateString('zh-CN') : '未知';
        card.innerHTML = `
            <div class="room-card-name">${escapeHtml(displayName)}</div>
            <div class="room-card-meta">
                <span>创建者: ${escapeHtml(room.created_by || '未知')}</span>
                <span>创建于: ${createdDate}</span>
                <span>你加入于: ${joinedDate}</span>
            </div>`;
        card.onclick = () => {
            myRoomsOverlay.style.display = 'none';
            currentRoom = { doc_id: room.doc_id, room_name: room.room_name };
            localStorage.setItem('currentRoom', JSON.stringify(currentRoom));
            statusSpan.innerText = "进入房间中";
            docDisplay.innerText = `${room.room_name || room.doc_id}`;
            ws.send(JSON.stringify({ type: "rejoin_room", doc_id: room.doc_id, requested_site_id: mySiteId || 0 }));
        };
        myRoomsList.appendChild(card);
    });
}

function onRejoinRoomRes(data) {
    showToast(data.msg || '重新加入房间失败', 'error');
    myRoomsOverlay.style.display = 'flex';
}

function onRenameRoomRes(data) {
    if (data.success) {
        currentRoom.room_name = data.room_name;
        localStorage.setItem('currentRoom', JSON.stringify(currentRoom));
        docDisplay.innerText = `${data.room_name}`;
        addLog(`房间已重命名为「${data.room_name}」`, true);
    } else {
        showToast(data.msg, 'error');
    }
}

function onGetRoomMembersRes(data) {
    const list = document.getElementById('members-list');
    if (!data.success || !data.members || data.members.length === 0) {
        list.innerHTML = '<div class="member-item" style="color:#8a8a9a;">暂无成员记录</div>';
        return;
    }
    const statusOrder = { in_room: 0, online: 1, offline: 2 };
    const statusLabel = { in_room: '在本房间', online: '在线', offline: '离线' };
    const statusClass = { in_room: 'in-room', online: 'online', offline: 'offline' };
    const owner = data.members.find(m => m.is_owner);
    const others = data.members.filter(m => !m.is_owner)
        .sort((a, b) => (statusOrder[a.status] ?? 3) - (statusOrder[b.status] ?? 3));
    const sorted = owner ? [owner, ...others] : others;
    list.innerHTML = sorted.map(m => `
        <div class="member-item">
            <span class="member-dot ${statusClass[m.status] || 'offline'}"></span>
            <span>${escapeHtml(m.username)}${m.is_owner ? ' <span class="member-owner-tag">创建者</span>' : ''}</span>
            <span class="member-status-label">${statusLabel[m.status] || '离线'}</span>
        </div>`).join('');
}

function onSaveSnapshotRes(data) {
    if (data.success) {
        const label = data.is_quick ? '快速存档已更新' : `已保存存档「${data.name}」`;
        addLog(label, true);
    }
}

function onGetSavesRes(data) {
    if (!data.success) return;
    cachedSaves = data.saves || [];
    if (pendingSaveAfterList) {
        pendingSaveAfterList = false;
        doSaveWithPrompt();
    } else {
        openLoadModal(cachedSaves);
    }
}

function onLoadSaveApplied(data) {
    applySnapshot({ docState: data.doc_state, shapes: data.shapes });
    document.getElementById('load-save-overlay').classList.remove('open');
    addLog(`存档「${data.name}」已被 ${escapeHtml(data.applied_by)} 读取并应用`, true);
}

function onDeleteSaveRes(data) {
    if (data.success) removeSaveCard(data.save_id);
}

function onSaveDeleted(data) {
    removeSaveCard(data.save_id);
}

function onInit(data) {
    mySiteId = data.site_id;
    localStorage.setItem('mySiteId', mySiteId);
    if (data.room_name && currentRoom) {
        currentRoom.room_name = data.room_name;
        localStorage.setItem('currentRoom', JSON.stringify(currentRoom));
    }
    statusSpan.innerText = "已进入房间";
    statusSpan.classList.remove('waiting');
    statusSpan.classList.add('online');
    if (currentRoom) docDisplay.innerText = `${currentRoom.room_name || currentRoom.doc_id}`;
    siteDisplay.innerText = `${myUsername} (Site: ${mySiteId})`;
    btnGenInvite.style.display = 'inline-flex';
    btnRenameRoom.style.display = 'inline-flex';
    document.getElementById('btn-leave-room').style.display = 'inline-flex';
    document.getElementById('btn-members').style.display = 'inline-flex';
    document.getElementById('btn-ai-panel').style.display = 'inline-flex';
    resizeCanvas();
    showSaveBtn();
}

function onSnapshotInit(data) {
    applySnapshot({ docState: data.doc_state || [], shapes: data.shapes || [] });
}

function onRequestAutoSnapshot() {
    const snap = captureSnapshot();
    ws.send(JSON.stringify({
        type: "submit_auto_snapshot",
        doc_state: JSON.stringify(snap.docState),
        shapes: JSON.stringify(snap.shapes)
    }));
}

function onHistoryBatch(data) {
    isApplyingRemoteChange = true;
    for (const ev of data.events) {
        const evList = ev.type === "ops_batch" ? ev.ops : [ev];
        applyOpsToDocState(evList);
    }
    docState.sort((a, b) => a.id.localeCompare(b.id));
    rebuildQuill(docState);
    isApplyingRemoteChange = false;
}

function onOpsBatch(data) {
    isApplyingRemoteChange = true;
    applyOpsToDocState(data.ops);
    docState.sort((a, b) => a.id.localeCompare(b.id));
    rebuildQuill(docState);
    isApplyingRemoteChange = false;
}

function onPresence(data) {
    showToast(`${data.username || ('用户' + data.site_id)} 进入了文档`, 'info', 2500);
}

function onCursor(data) {
    if (data.site_id === mySiteId) return;
    let relativeIndex = 0;
    if (data.anchorId !== "start") {
        const foundIndex = docState.findIndex(item => item.id === data.anchorId);
        if (foundIndex !== -1) relativeIndex = foundIndex + 1;
    }
    const remoteName = data.username ? data.username : `神秘人 ${data.site_id}`;
    cursorsModule.createCursor(data.site_id.toString(), remoteName, getUserColor(data.site_id));
    cursorsModule.moveCursor(data.site_id.toString(), { index: relativeIndex, length: data.length });
}

function onInsert(data) {
    isApplyingRemoteChange = true;
    docState.push({ id: data.id, char: data.char, attributes: data.attributes || {} });
    docState.sort((a, b) => a.id.localeCompare(b.id));
    const relativeIndex = docState.findIndex(item => item.id === data.id);
    if (typeof data.char === 'string') {
        if (data.char.length > 0) quill.insertText(relativeIndex, data.char, data.attributes || {}, 'silent');
    } else {
        const embedType = Object.keys(data.char)[0];
        const embedValue = data.char[embedType];
        quill.insertEmbed(relativeIndex, embedType, embedValue, 'silent');
    }
    isApplyingRemoteChange = false;
}

function onDelete(data) {
    isApplyingRemoteChange = true;
    const targetIndex = docState.findIndex(item => item.id === data.id);
    if (targetIndex !== -1) {
        const deletedItem = docState.splice(targetIndex, 1)[0];
        const delLen = typeof deletedItem.char === 'string' ? deletedItem.char.length : 1;
        if (delLen > 0) quill.deleteText(targetIndex, delLen, 'silent');
    }
    isApplyingRemoteChange = false;
}

function onFormat(data) {
    isApplyingRemoteChange = true;
    const targetIndex = docState.findIndex(item => item.id === data.id);
    if (targetIndex !== -1) {
        const formatItem = docState[targetIndex];
        if (data.value === null || data.value === false) delete formatItem.attributes[data.key];
        else formatItem.attributes[data.key] = data.value;
        const formatLen = typeof formatItem.char === 'string' ? formatItem.char.length : 1;
        if (formatLen > 0) quill.formatText(targetIndex, formatLen, data.key, data.value, 'silent');
    }
    isApplyingRemoteChange = false;
}

const messageHandlers = {
    kicked: onKicked,
    register_res: onRegisterRes,
    login_res: onLoginRes,
    create_room_res: onCreateRoomRes,
    gen_invite_res: onGenInviteRes,
    join_with_code_res: onJoinWithCodeRes,
    get_my_rooms_res: onGetMyRoomsRes,
    rejoin_room_res: onRejoinRoomRes,
    rename_room_res: onRenameRoomRes,
    get_room_members_res: onGetRoomMembersRes,
    save_snapshot_res: onSaveSnapshotRes,
    get_saves_res: onGetSavesRes,
    load_save_applied: onLoadSaveApplied,
    delete_save_res: onDeleteSaveRes,
    save_deleted: onSaveDeleted,
    init: onInit,
    snapshot_init: onSnapshotInit,
    request_auto_snapshot: onRequestAutoSnapshot,
    history_batch: onHistoryBatch,
    ops_batch: onOpsBatch,
    presence: onPresence,
    cursor: onCursor,
    insert: onInsert,
    delete: onDelete,
    format: onFormat,
    shape_add: applyRemoteShape,
    shape_move: applyRemoteShape,
    shape_delete: applyRemoteShape,
};

function handleMessage(data) {
    const fn = messageHandlers[data.type];
    if (fn) fn(data);
}

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.type === "batch") {
        for (const msg of data.msgs) handleMessage(msg);
    } else {
        handleMessage(data);
    }
};

const roomNameOverlay = document.getElementById('room-name-overlay');
const inviteTypeOverlay = document.getElementById('invite-type-overlay');
const inviteTypeHint = document.getElementById('invite-type-hint');
const genInviteOverlay = document.getElementById('gen-invite-overlay');
const genInviteCodeDisplay = document.getElementById('gen-invite-code-display');
const genInviteTypeHint = document.getElementById('gen-invite-type-hint');
const btnGenInvite = document.getElementById('btn-gen-invite');
const btnRenameRoom = document.getElementById('btn-rename-room');

btnRenameRoom.onclick = () => {
    const current = currentRoom ? (currentRoom.room_name || '') : '';
    showPrompt('请输入新的房间名称：', current, (newName) => {
        if (newName === null || newName === undefined) return;
        if (!newName.trim()) return showToast('房间名称不能为空！', 'warn');
        ws.send(JSON.stringify({ type: "rename_room", room_name: newName.trim() }));
    });
};

let isGenInviteMode = false;

document.getElementById('btn-create-room').onclick = () => {
    roomChoiceOverlay.style.display = 'none';
    roomNameOverlay.style.display = 'flex';
    document.getElementById('input-room-name').value = '';
};

document.getElementById('btn-confirm-room-name').onclick = () => {
    const name = document.getElementById('input-room-name').value.trim();
    if (!name) return showToast('请输入房间名称！', 'warn');
    roomNameOverlay.dataset.roomName = name;
    roomNameOverlay.style.display = 'none';
    isGenInviteMode = false;
    inviteTypeOverlay.style.display = 'flex';
    document.getElementById('timed-options').style.display = 'none';
};

document.getElementById('btn-back-from-name').onclick = () => {
    roomNameOverlay.style.display = 'none';
    roomChoiceOverlay.style.display = 'flex';
};

btnGenInvite.onclick = () => {
    isGenInviteMode = true;
    inviteTypeOverlay.style.display = 'flex';
    document.getElementById('timed-options').style.display = 'none';
};

function sendCreateOrGenInvite(invite_type, extra) {
    if (isGenInviteMode) {
        ws.send(JSON.stringify({ type: "gen_invite", invite_type, ...extra }));
    } else {
        const room_name = roomNameOverlay.dataset.roomName || '未命名房间';
        ws.send(JSON.stringify({ type: "create_room", room_name, invite_type, ...extra }));
    }
}

document.getElementById('btn-invite-once').onclick = () => {
    inviteTypeOverlay.style.display = 'none';
    sendCreateOrGenInvite("once", {});
};

document.getElementById('btn-invite-timed').onclick = () => {
    const timedOpts = document.getElementById('timed-options');
    timedOpts.style.display = timedOpts.style.display === 'none' ? 'flex' : 'none';
    timedOpts.style.flexDirection = 'column';
    timedOpts.style.gap = '10px';
};

document.getElementById('btn-confirm-timed').onclick = () => {
    const hours = parseInt(document.getElementById('select-hours').value);
    inviteTypeOverlay.style.display = 'none';
    sendCreateOrGenInvite("timed", { expire_hours: hours });
};

document.getElementById('btn-invite-permanent').onclick = () => {
    inviteTypeOverlay.style.display = 'none';
    sendCreateOrGenInvite("permanent", {});
};

document.getElementById('btn-back-room-choice').onclick = () => {
    inviteTypeOverlay.style.display = 'none';
    if (isGenInviteMode) return;
    roomNameOverlay.style.display = 'flex';
};

document.getElementById('btn-go-back-login').onclick = () => {
    roomChoiceOverlay.style.display = 'none';
    authOverlay.style.display = 'flex';
};

document.getElementById('btn-copy-code').onclick = () => {
    navigator.clipboard.writeText(inviteCodeDisplay.innerText).then(() => showToast('邀请码已复制！', 'success'));
};

document.getElementById('btn-enter-room').onclick = () => {
    roomCreatedOverlay.style.display = 'none';
    statusSpan.innerText = "进入房间中";
    docDisplay.innerText = `${currentRoom.room_name || currentRoom.doc_id}`;
    ws.send(JSON.stringify({ type: "join", doc_id: currentRoom.doc_id, requested_site_id: mySiteId || 0 }));
};

document.getElementById('btn-copy-gen-code').onclick = () => {
    navigator.clipboard.writeText(genInviteCodeDisplay.innerText).then(() => showToast('邀请码已复制！', 'success'));
};

document.getElementById('btn-close-gen-invite').onclick = () => {
    genInviteOverlay.style.display = 'none';
};

document.getElementById('btn-new-room').onclick = () => {
    roomCreatedOverlay.style.display = 'none';
    inviteTypeOverlay.style.display = 'flex';
    document.getElementById('timed-options').style.display = 'none';
};

document.getElementById('btn-join-room').onclick = () => {
    roomChoiceOverlay.style.display = 'none';
    joinRoomOverlay.style.display = 'flex';
    inputInviteCode.focus();
};

document.getElementById('btn-my-rooms').onclick = () => {
    roomChoiceOverlay.style.display = 'none';
    myRoomsOverlay.style.display = 'flex';
    myRoomsList.innerHTML = '';
    myRoomsLoading.style.display = 'block';
    ws.send(JSON.stringify({ type: "get_my_rooms" }));
};

document.getElementById('btn-back-from-my-rooms').onclick = () => {
    myRoomsOverlay.style.display = 'none';
    roomChoiceOverlay.style.display = 'flex';
};

document.getElementById('btn-back-choice').onclick = () => {
    joinRoomOverlay.style.display = 'none';
    roomChoiceOverlay.style.display = 'flex';
    inputInviteCode.value = '';
};

document.getElementById('btn-join-with-code').onclick = () => {
    const code = inputInviteCode.value.trim().toUpperCase();
    if (code.length !== 6) return showToast('请输入 6 位邀请码！', 'warn');
    ws.send(JSON.stringify({ type: "join_with_code", code: code }));
};

const statusSpan = document.getElementById('status');
const siteDisplay = document.getElementById('site-display');
const docDisplay = document.getElementById('doc-display');
const authOverlay = document.getElementById('auth-overlay');
const btnLogout = document.getElementById('btn-logout');
const roomChoiceOverlay = document.getElementById('room-choice-overlay');
const roomCreatedOverlay = document.getElementById('room-created-overlay');
const joinRoomOverlay = document.getElementById('join-room-overlay');
const myRoomsOverlay = document.getElementById('my-rooms-overlay');
const myRoomsList    = document.getElementById('my-rooms-list');
const myRoomsLoading = document.getElementById('my-rooms-loading');
const inviteCodeDisplay = document.getElementById('invite-code-display');
const inputInviteCode = document.getElementById('input-invite-code');

let currentRoom = JSON.parse(localStorage.getItem('currentRoom') || 'null');

let mySiteId = localStorage.getItem('mySiteId') ? parseInt(localStorage.getItem('mySiteId')) : null;
let myUsername = localStorage.getItem('myUsername') || null;
let myPassword = localStorage.getItem('myPassword') || null;

let docState = [{ id: "p@0", char: "\n", attributes: {} }];
let isApplyingRemoteChange = false;

function addLog(text, isOwn = false) {
    const type = isOwn ? 'success' : 'info';
    showToast(text, type, 4000);
}

function inviteTypeHintText(inviteType, expiresAt) {
    const hints = {
        once: '仅限一次使用，用完即失效',
        timed: expiresAt ? `有效至 ${new Date(expiresAt * 1000).toLocaleString()}` : '限时有效',
        permanent: '永久有效，可无限次使用'
    };
    return hints[inviteType] || '';
}

function removeSaveCard(saveId) {
    const card = document.querySelector(`.save-slot-card[data-save-id="${saveId}"]`);
    if (card) card.remove();
    const list = document.getElementById('load-save-list');
    if (list && !list.querySelector('.save-slot-card'))
        list.innerHTML = '<div class="load-save-empty">暂无存档</div>';
}

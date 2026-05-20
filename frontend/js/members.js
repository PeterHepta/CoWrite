const btnMembers = document.getElementById('btn-members');
const membersPanel = document.getElementById('members-panel');
const membersList = document.getElementById('members-list');

btnMembers.onclick = (e) => {
    e.stopPropagation();
    const isOpen = membersPanel.classList.contains('open');
    if (isOpen) {
        membersPanel.classList.remove('open');
    } else {
        const rect = btnMembers.getBoundingClientRect();
        membersPanel.style.top = (rect.bottom + 6) + 'px';
        membersPanel.style.left = rect.left + 'px';
        membersList.innerHTML = '<div class="member-item" style="color:#8a8a9a;">加载中...</div>';
        membersPanel.classList.add('open');
        ws.send(JSON.stringify({ type: "get_room_members" }));
    }
};

document.addEventListener('click', (e) => {
    if (!membersPanel.contains(e.target) && e.target !== btnMembers) {
        membersPanel.classList.remove('open');
    }
});

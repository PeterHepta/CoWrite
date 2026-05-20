function captureSnapshot() {
    return {
        docState: JSON.parse(JSON.stringify(docState)),
        shapes:   JSON.parse(JSON.stringify(shapes))
    };
}

function applySnapshot(snap) {
    docState.length = 0;
    (snap.docState || []).forEach(item => docState.push(item));

    isApplyingRemoteChange = true;
    if (docState.length > 0) rebuildQuill(docState);
    else quill.setContents({ ops: [{ insert: '\n' }] }, 'silent');
    isApplyingRemoteChange = false;

    shapes.length = 0;
    document.getElementById('editor-wrap').querySelectorAll('.shape-el').forEach(el => el.remove());
    (snap.shapes || []).forEach(s => { shapes.push(s); syncShapeEl(s); });
}

let cachedSaves = [];
let pendingSaveAfterList = false;

function uniqueSaveName(baseName) {
    const existing = new Set(cachedSaves.filter(s => !s.is_quick).map(s => s.name));
    if (!existing.has(baseName)) return baseName;
    let i = 1;
    while (existing.has(`${baseName}(${i})`)) i++;
    return `${baseName}(${i})`;
}

document.getElementById('menu-save').onclick = () => {
    closeSaveDropdown();
    ws.send(JSON.stringify({ type: "get_saves" }));
    pendingSaveAfterList = true;
};

function doSaveWithPrompt() {
    showPrompt('请输入存档名称（留空则使用"默认存档"）：', '', (input) => {
        if (input === null || input === undefined) return;
        const baseName = input.trim() || '默认存档';
        const name = uniqueSaveName(baseName);
        const snap = captureSnapshot();
        ws.send(JSON.stringify({
            type: "save_snapshot",
            name,
            doc_state: JSON.stringify(snap.docState),
            shapes: JSON.stringify(snap.shapes)
        }));
    });
}

document.getElementById('menu-quicksave').onclick = () => {
    closeSaveDropdown();
    const snap = captureSnapshot();
    ws.send(JSON.stringify({
        type: "quicksave_snapshot",
        doc_state: JSON.stringify(snap.docState),
        shapes: JSON.stringify(snap.shapes)
    }));
};

document.getElementById('menu-load').onclick = () => {
    closeSaveDropdown();
    ws.send(JSON.stringify({ type: "get_saves" }));
};

function openLoadModal(saves) {
    const overlay = document.getElementById('load-save-overlay');
    const list = document.getElementById('load-save-list');
    list.innerHTML = '';
    if (!saves || !saves.length) {
        list.innerHTML = '<div class="load-save-empty">暂无存档</div>';
        overlay.classList.add('open');
        return;
    }
    saves.forEach(save => {
        const card = document.createElement('div');
        card.className = 'save-slot-card' + (save.is_quick ? ' quick-save' : '');
        card.dataset.saveId = save.id;

        const dateStr = new Date(save.created_at * 1000).toLocaleString('zh-CN', {
            month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit'
        });

        card.innerHTML = `
            <div class="save-slot-info">
                <div class="save-slot-name">${escapeHtml(save.name)}${save.is_quick ? ' [Q]' : ''}</div>
                <div class="save-slot-meta">保存于 ${dateStr}，由 ${escapeHtml(save.created_by)} 创建</div>
            </div>
            <button class="save-slot-del">删除</button>`;

        card.addEventListener('click', (e) => {
            if (e.target.classList.contains('save-slot-del')) return;
            showConfirm(`确认读取存档「${save.name}」？\n当前未保存的进度将永久丢失，且房间内所有人的内容都将被覆盖。`, () => {
                ws.send(JSON.stringify({ type: "load_save", save_id: save.id }));
            }, null, true);
        });

        card.querySelector('.save-slot-del').onclick = (e) => {
            e.stopPropagation();
            showConfirm(`确认删除存档「${save.name}」？`, () => {
                ws.send(JSON.stringify({ type: "delete_save", save_id: save.id }));
            }, null, true);
        };

        list.appendChild(card);
    });
    overlay.classList.add('open');
}

document.getElementById('btn-close-load-save').onclick = () => {
    document.getElementById('load-save-overlay').classList.remove('open');
};
document.getElementById('load-save-overlay').addEventListener('click', (e) => {
    if (e.target === document.getElementById('load-save-overlay'))
        document.getElementById('load-save-overlay').classList.remove('open');
});

const saveDropdownMenu = document.getElementById('save-dropdown-menu');
document.getElementById('btn-save-menu').onclick = (e) => {
    e.stopPropagation();
    saveDropdownMenu.classList.toggle('open');
};
function closeSaveDropdown() { saveDropdownMenu.classList.remove('open'); }
document.addEventListener('click', (e) => {
    if (!document.getElementById('save-dropdown-wrap').contains(e.target)) closeSaveDropdown();
});

function showSaveBtn() {
    document.getElementById('save-dropdown-wrap').classList.add('visible');
}

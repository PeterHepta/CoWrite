function showToast(msg, type = 'info', duration = 3500) {
    const icons = { info: '[i]', success: '[ok]', warn: '[!]', error: '[x]' };
    const container = document.getElementById('toast-container');
    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.innerHTML = `<span class="toast-icon">${icons[type]}</span>
        <span class="toast-body"><span class="toast-msg">${msg}</span></span>
        <button class="toast-close" onclick="dismissToast(this.closest('.toast'))">✕</button>`;
    container.appendChild(el);
    const timer = setTimeout(() => dismissToast(el), duration);
    el._timer = timer;
}
function dismissToast(el) {
    if (!el || el._dismissed) return;
    el._dismissed = true;
    clearTimeout(el._timer);
    el.classList.add('toast-out');
    el.addEventListener('animationend', () => el.remove(), { once: true });
}

function showConfirm(msg, onOk, onCancel, danger = false) {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `<div class="modal-box">
        <p class="modal-msg">${msg}</p>
        <div class="modal-btns">
            <button class="modal-btn modal-btn-cancel" id="_mc">取消</button>
            <button class="modal-btn modal-btn-ok${danger ? ' danger' : ''}" id="_mo">确认</button>
        </div>
    </div>`;
    document.body.appendChild(overlay);
    const close = () => overlay.remove();
    overlay.querySelector('#_mc').onclick = () => { close(); onCancel && onCancel(); };
    overlay.querySelector('#_mo').onclick = () => { close(); onOk && onOk(); };
    overlay.addEventListener('click', e => { if (e.target === overlay) { close(); onCancel && onCancel(); } });
    setTimeout(() => overlay.querySelector('#_mo').focus(), 50);
}

function showPrompt(msg, defaultVal, onOk, onCancel) {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `<div class="modal-box">
        <p class="modal-msg">${msg}</p>
        <input class="modal-input" id="_mp" type="text" value="${defaultVal || ''}">
        <div class="modal-btns">
            <button class="modal-btn modal-btn-cancel" id="_mpc">取消</button>
            <button class="modal-btn modal-btn-ok" id="_mpo">确认</button>
        </div>
    </div>`;
    document.body.appendChild(overlay);
    const input = overlay.querySelector('#_mp');
    const close = () => overlay.remove();
    const confirm = () => { const v = input.value; close(); onOk && onOk(v); };
    overlay.querySelector('#_mpc').onclick = () => { close(); onCancel && onCancel(); };
    overlay.querySelector('#_mpo').onclick = confirm;
    input.addEventListener('keydown', e => { if (e.key === 'Enter') confirm(); if (e.key === 'Escape') { close(); onCancel && onCancel(); } });
    overlay.addEventListener('click', e => { if (e.target === overlay) { close(); onCancel && onCancel(); } });
    setTimeout(() => { input.focus(); input.select(); }, 50);
}

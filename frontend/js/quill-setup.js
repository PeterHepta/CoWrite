Quill.register('modules/cursors', QuillCursors);

var quill = new Quill('#editor-container', {
    modules: {
        toolbar: {
            container: '#quill-toolbar',
            handlers: { 'emoji': function() {} }
        },
        "emoji-toolbar": true, "emoji-shortname": true,
        cursors: { transformOnTextChange: true, hideDelayMs: 5000, hideSpeedMs: 300 }
    },
    placeholder: '', theme: 'snow'
});

const cursorsModule = quill.getModule('cursors');

const editorEl = document.querySelector('#editor-container .ql-editor');
const placeholderEl = document.createElement('div');
placeholderEl.id = 'ql-custom-placeholder';
placeholderEl.innerText = '在这里开始协同创作...';
editorEl.parentElement.style.position = 'relative';
editorEl.parentElement.appendChild(placeholderEl);

function updatePlaceholder() {
    const len = quill.getLength();
    placeholderEl.style.display = len <= 1 ? 'block' : 'none';
}
function updatePlaceholderDeferred() { setTimeout(updatePlaceholder, 0); }
quill.on('text-change', updatePlaceholderDeferred);
editorEl.addEventListener('compositionstart', () => { placeholderEl.style.display = 'none'; });
editorEl.addEventListener('compositionend', updatePlaceholder);
editorEl.addEventListener('input', updatePlaceholder);
new MutationObserver(updatePlaceholderDeferred).observe(editorEl, { childList: true, subtree: true, characterData: true });
updatePlaceholder();

function rebuildQuill(state) {
    const ops = [];
    for (const item of state) {
        if (typeof item.char === 'string' && item.char.length === 0) continue;
        const op = { insert: item.char };
        if (Object.keys(item.attributes).length > 0) op.attributes = item.attributes;
        ops.push(op);
    }
    if (ops.length > 0) quill.setContents({ ops }, 'silent');
}

function applyOpsToDocState(evList) {
    for (const e of evList) {
        if (e.type === "insert") {
            docState.push({ id: e.id, char: e.char, attributes: e.attributes || {} });
        } else if (e.type === "delete") {
            const idx = docState.findIndex(item => item.id === e.id);
            if (idx !== -1) docState.splice(idx, 1);
        } else if (e.type === "format") {
            const item = docState.find(item => item.id === e.id);
            if (item) {
                if (e.value === null || e.value === false) delete item.attributes[e.key];
                else item.attributes[e.key] = e.value;
            }
        } else if (e.type === "shape_add" || e.type === "shape_move" || e.type === "shape_delete") {
            applyRemoteShape(e);
        }
    }
}

// shapes: { id, type, x, y, w, h, siteId }
let shapes = [];
let selectedShapeId = null;
let currentTool = null;

// { shapeId, mode: 'move'|'resize', corner, startMX, startMY, origX, origY, origW, origH }
let activeDragShape = null;

const canvas = document.getElementById('shape-canvas');
const ctx = canvas.getContext('2d');
const shapeHint = document.getElementById('shape-hint');

function resizeCanvas() {
    const wrap = document.getElementById('editor-wrap');
    canvas.width = wrap.clientWidth;
    canvas.height = wrap.clientHeight;
}
new ResizeObserver(resizeCanvas).observe(document.getElementById('editor-wrap'));

function generateShapeId() {
    return `sh_${Date.now()}_${mySiteId || 0}_${Math.floor(Math.random()*9999)}`;
}
function getShapeColor(siteId) { return colorPalette[(siteId || 0) % colorPalette.length]; }
function setShapeHint(msg) {
    shapeHint.style.display = msg ? 'block' : 'none';
    shapeHint.innerText = msg || '';
}

function drawShapeOnEl(s) {
    const el = document.getElementById('shape-dom-' + s.id);
    if (!el) return;
    const cv = el.querySelector('canvas');
    if (!cv) return;
    const w = s.w, h = s.h;
    if (!w || !h) return;
    cv.width = w; cv.height = h;
    const c = cv.getContext('2d');
    c.clearRect(0, 0, w, h);
    const color = getShapeColor(s.siteId);
    c.strokeStyle = color;
    c.lineWidth = 2;
    c.setLineDash([]);
    c.beginPath();
    if (s.type === 'rect') {
        c.rect(1, 1, w - 2, h - 2);
    } else if (s.type === 'circle') {
        c.ellipse(w/2, h/2, w/2 - 1, h/2 - 1, 0, 0, Math.PI*2);
    } else if (s.type === 'triangle') {
        c.moveTo(w/2, 1); c.lineTo(w - 1, h - 1); c.lineTo(1, h - 1); c.closePath();
    } else if (s.type === 'star') {
        const cx = w/2, cy = h/2;
        const R = Math.min(w, h) / 2 - 2;
        const r = R / 2.4;
        let rot = -Math.PI / 2;
        const step = Math.PI / 5;
        c.moveTo(cx + R * Math.cos(rot), cy + R * Math.sin(rot));
        for (let i = 0; i < 5; i++) {
            rot += step; c.lineTo(cx + r * Math.cos(rot), cy + r * Math.sin(rot));
            rot += step; c.lineTo(cx + R * Math.cos(rot), cy + R * Math.sin(rot));
        }
        c.closePath();
    }
    c.stroke();
}

function getOrCreateShapeEl(s) {
    let el = document.getElementById('shape-dom-' + s.id);
    if (!el) {
        el = document.createElement('div');
        el.id = 'shape-dom-' + s.id;
        el.className = 'shape-el';
        el.innerHTML = `<canvas></canvas>
            <div class="shape-handle tl" data-corner="tl"></div>
            <div class="shape-handle tr" data-corner="tr"></div>
            <div class="shape-handle bl" data-corner="bl"></div>
            <div class="shape-handle br" data-corner="br"></div>`;

        el.addEventListener('mousedown', (e) => {
            if (e.target.classList.contains('shape-handle')) return;
            if (currentTool) return;
            e.preventDefault();
            e.stopPropagation();
            selectShape(s.id);
            activeDragShape = { shapeId: s.id, mode: 'move',
                startMX: e.clientX, startMY: e.clientY,
                origX: s.x, origY: s.y, origW: s.w, origH: s.h };
            el.style.cursor = 'grabbing';
        });
        el.addEventListener('dblclick', (e) => {
            if (e.target.classList.contains('shape-handle')) return;
            e.stopPropagation();
            removeShape(s.id, true);
        });
        el.querySelectorAll('.shape-handle').forEach(handle => {
            handle.addEventListener('mousedown', (e) => {
                e.preventDefault();
                e.stopPropagation();
                activeDragShape = { shapeId: s.id, mode: 'resize',
                    corner: handle.dataset.corner,
                    startMX: e.clientX, startMY: e.clientY,
                    origX: s.x, origY: s.y, origW: s.w, origH: s.h };
            });
        });

        document.getElementById('editor-wrap').appendChild(el);
    }
    el.style.left = s.x + 'px';
    el.style.top  = (s.y - editorEl.scrollTop) + 'px';
    el.style.width  = s.w + 'px';
    el.style.height = s.h + 'px';
    return el;
}

function syncShapeEl(s) {
    const el = getOrCreateShapeEl(s);
    drawShapeOnEl(s);
    return el;
}

function removeShapeEl(id) {
    const el = document.getElementById('shape-dom-' + id);
    if (el) el.remove();
}

function selectShape(id) {
    if (selectedShapeId && selectedShapeId !== id) {
        const prev = document.getElementById('shape-dom-' + selectedShapeId);
        if (prev) prev.classList.remove('selected');
    }
    selectedShapeId = id;
    if (id) {
        const el = document.getElementById('shape-dom-' + id);
        if (el) { el.classList.add('selected'); el.style.cursor = 'grab'; }
        setShapeHint('拖动移动 · 拖角点缩放 · 双击删除');
    } else {
        setShapeHint('');
    }
}

function deselectShape() {
    if (selectedShapeId) {
        const el = document.getElementById('shape-dom-' + selectedShapeId);
        if (el) el.classList.remove('selected');
    }
    selectedShapeId = null;
    setShapeHint('');
}

function removeShape(id, broadcast) {
    const idx = shapes.findIndex(s => s.id === id);
    if (idx !== -1) {
        const type = shapes[idx].type;
        shapes.splice(idx, 1);
        removeShapeEl(id);
        if (id === selectedShapeId) deselectShape();
        if (broadcast) {
            ws.send(JSON.stringify({ type: "shape_delete", id }));
            addLog(`删除图形 [${type}]`, true);
        }
        updateTextWrap();
    }
}

document.addEventListener('mousemove', (e) => {
    if (!activeDragShape) return;
    const { shapeId, mode, corner, startMX, startMY, origX, origY, origW, origH } = activeDragShape;
    const s = shapes.find(s => s.id === shapeId);
    if (!s) return;
    const dx = e.clientX - startMX;
    const dy = e.clientY - startMY;
    if (mode === 'move') {
        s.x = origX + dx;
        s.y = origY + dy;
    } else {
        if (corner === 'br') { s.w = Math.max(30, origW + dx); s.h = Math.max(30, origH + dy); }
        else if (corner === 'tr') { s.w = Math.max(30, origW + dx); s.y = origY + dy; s.h = Math.max(30, origH - dy); }
        else if (corner === 'bl') { s.x = origX + dx; s.w = Math.max(30, origW - dx); s.h = Math.max(30, origH + dy); }
        else if (corner === 'tl') { s.x = origX + dx; s.y = origY + dy; s.w = Math.max(30, origW - dx); s.h = Math.max(30, origH - dy); }
    }
    syncShapeEl(s);
    requestAnimationFrame(updateTextWrap);
});

document.addEventListener('mouseup', (e) => {
    if (!activeDragShape) return;
    const { shapeId } = activeDragShape;
    const s = shapes.find(s => s.id === shapeId);
    if (s) {
        ws.send(JSON.stringify({ type: "shape_move", id: s.id, x: s.x, y: s.y, w: s.w, h: s.h }));
        updateTextWrap();
    }
    activeDragShape = null;
    const el = document.getElementById('shape-dom-' + shapeId);
    if (el) el.style.cursor = 'grab';
});

document.getElementById('editor-wrap').addEventListener('mousedown', (e) => {
    if (e.target.closest('.shape-el')) return;
    if (currentTool) return;
    deselectShape();
});

canvas.addEventListener('click', (e) => {
    if (!currentTool) return;
    const wrapRect = document.getElementById('editor-wrap').getBoundingClientRect();
    const editorRect = editorEl.getBoundingClientRect();
    const ex = e.clientX - wrapRect.left;
    const ey = e.clientY - wrapRect.top;

    const s = {
        id: generateShapeId(), type: currentTool,
        x: Math.round(ex - 60),
        y: Math.round(ey - 40 + editorEl.scrollTop),
        w: 120, h: 80,
        siteId: mySiteId || 0
    };
    shapes.push(s);
    syncShapeEl(s);
    ws.send(JSON.stringify({ type: "shape_add", shape: s }));
    addLog(`插入图形 [${s.type}]`, true);
    cancelShapeTool();
    selectShape(s.id);
    updateTextWrap();
});

function selectShapeTool(type) {
    deselectShape();
    currentTool = type;
    ['rect','circle','triangle','star'].forEach(t =>
        document.getElementById('stb-'+t)?.classList.toggle('active', t === type));
    document.getElementById('stb-cancel').style.display = 'flex';
    document.getElementById('shape-mode-hint').style.display = 'inline';
    document.getElementById('shape-mode-hint').innerText = '点击编辑器放置图形';
    canvas.classList.add('placing');
    resizeCanvas();
    setShapeHint('点击编辑器放置图形');
}

function cancelShapeTool() {
    currentTool = null;
    ['rect','circle','triangle','star'].forEach(t =>
        document.getElementById('stb-'+t)?.classList.remove('active'));
    document.getElementById('stb-cancel').style.display = 'none';
    document.getElementById('shape-mode-hint').style.display = 'none';
    canvas.classList.remove('placing');
    setShapeHint('');
}

function applyRemoteShape(data) {
    if (data.type === 'shape_add') {
        if (!shapes.find(s => s.id === data.shape.id)) {
            shapes.push(data.shape);
            syncShapeEl(data.shape);
            updateTextWrap();
        }
    } else if (data.type === 'shape_move') {
        const s = shapes.find(s => s.id === data.id);
        if (s) { s.x = data.x; s.y = data.y; s.w = data.w; s.h = data.h; syncShapeEl(s); updateTextWrap(); }
    } else if (data.type === 'shape_delete') {
        const idx = shapes.findIndex(s => s.id === data.id);
        if (idx !== -1) {
            removeShapeEl(data.id);
            shapes.splice(idx, 1);
            updateTextWrap();
        }
    }
}

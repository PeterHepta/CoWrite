function updateTextWrap() {
    const lines = editorEl.querySelectorAll('p, h1, h2, h3, li');
    if (!shapes.length) {
        lines.forEach(line => {
            line.style.paddingLeft = '';
            line.style.paddingRight = '';
        });
        return;
    }

    const editorRect = editorEl.getBoundingClientRect();
    const editorL = editorRect.left;
    const editorR = editorRect.right;
    const editorW = editorEl.clientWidth;
    const editorMidX = editorL + editorW / 2;
    const MARGIN = 8;

    const shapeViewRects = shapes.map(s => {
        const el = document.getElementById('shape-dom-' + s.id);
        if (!el) return null;
        const r = el.getBoundingClientRect();
        return { top: r.top, bottom: r.bottom, left: r.left, right: r.right,
                 centerX: (r.left + r.right) / 2 };
    }).filter(Boolean);

    if (!shapeViewRects.length) return;

    lines.forEach(line => { line.style.paddingLeft = ''; line.style.paddingRight = ''; });
    void editorEl.offsetHeight;

    lines.forEach(line => {
        const lr = line.getBoundingClientRect();
        let leftBlock = 0, rightBlock = 0;

        shapeViewRects.forEach(sr => {
            if (lr.bottom <= sr.top || lr.top >= sr.bottom) return;

            if (sr.centerX <= editorMidX) {
                const needed = sr.right - editorL + MARGIN;
                if (needed > leftBlock) leftBlock = needed;
            } else {
                const needed = editorR - sr.left + MARGIN;
                if (needed > rightBlock) rightBlock = needed;
            }
        });

        line.style.paddingLeft  = leftBlock  > 0 ? leftBlock  + 'px' : '';
        line.style.paddingRight = rightBlock > 0 ? rightBlock + 'px' : '';
    });
}

function syncAllShapePositions() {
    shapes.forEach(s => {
        const el = document.getElementById('shape-dom-' + s.id);
        if (el) el.style.top = (s.y - editorEl.scrollTop) + 'px';
    });
}

quill.on('text-change', () => { requestAnimationFrame(updateTextWrap); });
editorEl.addEventListener('scroll', () => {
    syncAllShapePositions();
    updateTextWrap();
});

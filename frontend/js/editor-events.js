quill.on('selection-change', (range, oldRange, source) => {
    if (range && mySiteId) {
        let anchorId = "start";
        if (range.index > 0 && range.index <= docState.length) anchorId = docState[range.index - 1].id;
        ws.send(JSON.stringify({ type: "cursor", site_id: mySiteId, username: myUsername, anchorId: anchorId, length: range.length }));
    }
});

quill.on('text-change', (delta, oldDelta, source) => {
    if (source === 'silent' || !mySiteId || isApplyingRemoteChange) return;
    let currentIndex = 0;
    const batchOps = [];
    delta.ops.forEach(op => {
        if (op.retain) {
            if (op.attributes) {
                const attrKeys = Object.keys(op.attributes);
                for (let i = 0; i < op.retain; i++) {
                    const targetRelIndex = currentIndex + i; if (targetRelIndex >= docState.length) break;
                    const charItem = docState[targetRelIndex];
                    attrKeys.forEach(key => {
                        const val = op.attributes[key];
                        if (val === null || val === false) delete charItem.attributes[key]; else charItem.attributes[key] = val;
                        batchOps.push({ type: "format", id: charItem.id, key: key, value: val });
                    });
                }
            }
            currentIndex += op.retain;
        } else if (op.insert) {
            let itemsToInsert = [];
            if (typeof op.insert === 'string') {
                const segmenter = new Intl.Segmenter('zh-CN', { granularity: 'grapheme' });
                const chars = Array.from(segmenter.segment(op.insert)).map(s => s.segment);
                chars.forEach(c => { itemsToInsert.push(c); for(let i = 1; i < c.length; i++) itemsToInsert.push(""); });
            } else { itemsToInsert = [op.insert]; }

            for (let i = 0; i < itemsToInsert.length; i++) {
                const item = itemsToInsert[i];
                const leftId = currentIndex > 0 ? docState[currentIndex - 1].id.split('@')[0] : "";
                const rightId = currentIndex < docState.length ? docState[currentIndex].id.split('@')[0] : "";
                const absoluteId = `${generatePosBetween(leftId, rightId)}@${mySiteId}`;
                const attrs = op.attributes || {};
                docState.splice(currentIndex, 0, { id: absoluteId, char: item, attributes: attrs });
                batchOps.push({ type: "insert", id: absoluteId, char: item, attributes: attrs });
                currentIndex++;
            }
        } else if (op.delete) {
            for (let i = 0; i < op.delete; i++) {
                if (currentIndex < docState.length) {
                    const delId = docState[currentIndex].id; docState.splice(currentIndex, 1);
                    batchOps.push({ type: "delete", id: delId });
                }
            }
        }
    });
    if (batchOps.length === 1) {
        ws.send(JSON.stringify(batchOps[0]));
    } else if (batchOps.length > 1) {
        ws.send(JSON.stringify({ type: "ops_batch", ops: batchOps }));
    }
});

const colorPalette = ['#f56223', '#ffc107', '#00a8ff', '#00b894', '#9b59b6', '#e84393'];
function getUserColor(siteId) { return colorPalette[siteId % colorPalette.length]; }

function generatePosBetween(left, right) {
    let pos = ""; let i = 0;
    while (true) {
        let l = i < left.length ? left.charCodeAt(i) : 96;
        let r = i < right.length ? right.charCodeAt(i) : 123;
        if (r - l > 1) { pos += String.fromCharCode(Math.floor((l + r) / 2)); return pos; }
        else { pos += String.fromCharCode(l); }
        i++;
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
              .replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}

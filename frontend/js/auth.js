function switchTab(tab) {
    const isLogin = tab === 'login';
    document.getElementById('tab-login').classList.toggle('active', isLogin);
    document.getElementById('tab-register').classList.toggle('active', !isLogin);
    document.getElementById('form-login').style.display = isLogin ? 'flex' : 'none';
    document.getElementById('form-register').style.display = isLogin ? 'none' : 'flex';
}

document.getElementById('btn-register').onclick = () => {
    myUsername = document.getElementById('input-username-reg').value;
    myPassword = document.getElementById('input-password-reg').value;
    if(!myUsername || !myPassword) return showToast('用户名和密码不能为空！', 'warn');
    ws.send(JSON.stringify({ type: "register", username: myUsername, password: myPassword }));
};

document.getElementById('btn-login').onclick = () => {
    myUsername = document.getElementById('input-username').value;
    myPassword = document.getElementById('input-password').value;
    if(!myUsername || !myPassword) return showToast('用户名和密码不能为空！', 'warn');
    ws.send(JSON.stringify({ type: "login", username: myUsername, password: myPassword }));
};

btnLogout.onclick = () => {
    showConfirm('确定要退出登录吗？', () => { localStorage.clear(); location.reload(); }, null, false);
};

document.getElementById('btn-leave-room').onclick = () => {
    localStorage.removeItem('currentRoom');
    localStorage.removeItem('mySiteId');
    location.reload();
};

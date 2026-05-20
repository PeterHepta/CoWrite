const ws = new WebSocket("ws://39.102.113.202:9002");

ws.onopen = () => {
    if (myUsername && myPassword) {
        authOverlay.style.display = 'none';
        statusSpan.innerText = "自动登录中";
        ws.send(JSON.stringify({ type: "login", username: myUsername, password: myPassword }));
    } else {
        statusSpan.innerText = "已连网，请登录";
    }
};

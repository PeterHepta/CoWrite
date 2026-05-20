(function() {
    const panel        = document.getElementById('ai-panel');
    const btnOpen      = document.getElementById('btn-ai-panel');
    const btnClose     = document.getElementById('btn-close-ai');
    const btnSummarize = document.getElementById('btn-ai-summarize');
    const btnStop      = document.getElementById('btn-ai-stop');
    const modelSel     = document.getElementById('ai-model-select');
    const progressWrap = document.getElementById('ai-progress-wrap');
    const progressFill = document.getElementById('ai-progress-bar-fill');
    const progressLabel= document.getElementById('ai-progress-label');
    const resultWrap   = document.getElementById('ai-result-wrap');
    const resultBox    = document.getElementById('ai-result-box');
    const statusLine   = document.getElementById('ai-status-line');
    const promptInput  = document.getElementById('ai-prompt-input');
    const badge        = document.getElementById('ai-backend-badge');
    const webgpuOptgroup = document.getElementById('ai-optgroup-webgpu');

    let webgpuAvailable = false;
    let activeEngine = null;
    let aiWorker = null;
    let loadedModelKey = null;
    let generating = false;
    let stopRequested = false;

    btnOpen.onclick  = () => panel.classList.add('open');
    btnClose.onclick = () => panel.classList.remove('open');

    function setStatus(msg) { statusLine.textContent = msg; }

    async function detectWebGPU() {
        try {
            if (!navigator.gpu) return false;
            const adapter = await navigator.gpu.requestAdapter();
            return !!adapter;
        } catch { return false; }
    }

    async function init() {
        webgpuAvailable = await detectWebGPU();
        if (webgpuAvailable) {
            badge.textContent = 'WebGPU 可用';
            badge.className = 'webgpu';
            modelSel.value = 'webgpu:Qwen2.5-3B-Instruct-q4f16_1-MLC';
        } else {
            badge.textContent = 'WASM 模式';
            badge.className = 'wasm';
            webgpuOptgroup.label = 'WebGPU（当前设备不支持）';
            modelSel.value = 'wasm:onnx-community/Qwen2.5-0.5B-Instruct';
        }
    }
    init();

    function parseModel(val) {
        const idx = val.indexOf(':');
        return { backend: val.slice(0, idx), modelId: val.slice(idx + 1) };
    }

    async function loadModel() {
        const val = modelSel.value;
        if (loadedModelKey === val && (activeEngine || aiWorker)) return true;

        activeEngine = null;
        if (aiWorker) { aiWorker.terminate(); aiWorker = null; }
        loadedModelKey = null;
        progressWrap.classList.add('visible');
        progressFill.style.width = '0%';
        progressLabel.textContent = '正在初始化...';
        btnSummarize.disabled = true;
        setStatus('');

        const { backend, modelId } = parseModel(val);

        try {
            if (backend === 'webgpu') {
                setStatus('正在加载 WebLLM...');
                const webllm = await window._loadWebLLM();
                activeEngine = await webllm.CreateMLCEngine(modelId, {
                    initProgressCallback: (p) => {
                        const pct = Math.round((p.progress || 0) * 100);
                        progressFill.style.width = pct + '%';
                        progressLabel.textContent = p.text || `加载中 ${pct}%`;
                    }
                });
                badge.textContent = 'WebGPU';
                badge.className = 'webgpu';
                loadedModelKey = val;
                progressFill.style.width = '100%';
                progressLabel.textContent = '模型已就绪';
                setTimeout(() => progressWrap.classList.remove('visible'), 1500);
                btnSummarize.disabled = false;
                setStatus('模型加载完成');
                return true;
            } else {
                badge.textContent = 'WASM';
                badge.className = 'wasm';
                setStatus('正在后台加载模型...');

                return await new Promise((resolve) => {
                    aiWorker = new Worker('/ai-worker.js', { type: 'module' });
                    aiWorker.postMessage({ type: 'load', payload: { modelId } });
                    aiWorker.onmessage = (e) => {
                        const { type, payload } = e.data;
                        if (type === 'progress') {
                            if (payload.status === 'progress') {
                                const pct = Math.round(payload.progress || 0);
                                progressFill.style.width = pct + '%';
                                progressLabel.textContent = `下载 ${payload.file || ''} ${pct}%`;
                            } else if (payload.status === 'done') {
                                progressLabel.textContent = `已加载 ${payload.file || ''}`;
                            } else if (payload.status === 'initiate') {
                                progressLabel.textContent = `准备 ${payload.file || ''}...`;
                            }
                        } else if (type === 'load_done') {
                            loadedModelKey = val;
                            progressFill.style.width = '100%';
                            progressLabel.textContent = '模型已就绪';
                            setTimeout(() => progressWrap.classList.remove('visible'), 1500);
                            btnSummarize.disabled = false;
                            setStatus('模型加载完成');
                            resolve(true);
                        } else if (type === 'load_error') {
                            progressWrap.classList.remove('visible');
                            btnSummarize.disabled = false;
                            setStatus('加载失败：' + payload);
                            showToast('AI 模型加载失败：' + payload, 'error');
                            aiWorker.terminate(); aiWorker = null;
                            resolve(false);
                        }
                    };
                    aiWorker.onerror = (err) => {
                        progressWrap.classList.remove('visible');
                        btnSummarize.disabled = false;
                        setStatus('加载失败：' + err.message);
                        showToast('AI Worker 错误：' + err.message, 'error');
                        aiWorker = null;
                        resolve(false);
                    };
                });
            }
        } catch (e) {
            progressWrap.classList.remove('visible');
            btnSummarize.disabled = false;
            setStatus('加载失败：' + e.message);
            showToast('AI 模型加载失败：' + e.message, 'error');
            activeEngine = null;
            aiWorker = null;
            return false;
        }
    }

    function getDocText() {
        return docState.filter(c => c.char && c.char !== '\x00').map(c => c.char).join('');
    }

    btnSummarize.onclick = async () => {
        if (generating) return;
        const ok = await loadModel();
        if (!ok) return;

        const text = getDocText().trim();
        if (!text) { setStatus('文档内容为空，无法总结'); return; }

        const userPrompt = promptInput.value.trim() ||
            '请用中文对以下文档内容进行简洁的结构化总结，包括主要主题、关键要点和结论（如有）。';
        const maxChars = 4000;
        const docSnippet = text.length > maxChars
            ? text.slice(0, maxChars) + '\n\n[…内容过长，已截断]' : text;
        const messages = [
            { role: 'system', content: '你是一个专业的文档助手，擅长提炼要点并给出清晰的总结。' },
            { role: 'user',   content: userPrompt + '\n\n---\n' + docSnippet }
        ];

        generating = true;
        stopRequested = false;
        btnSummarize.disabled = true;
        btnStop.classList.add('visible');
        resultBox.textContent = '';
        resultWrap.classList.add('visible');
        setStatus('生成中…');

        try {
            if (activeEngine) {
                const stream = await activeEngine.chat.completions.create({
                    messages, stream: true, temperature: 0.6, max_tokens: 800,
                });
                for await (const chunk of stream) {
                    if (stopRequested) { await activeEngine.interruptGenerate(); break; }
                    const delta = chunk.choices[0]?.delta?.content || '';
                    resultBox.textContent += delta;
                    resultBox.scrollTop = resultBox.scrollHeight;
                }
            } else {
                await new Promise((resolve, reject) => {
                    stopRequested = false;
                    aiWorker.onmessage = (e) => {
                        const { type, payload } = e.data;
                        if (type === 'token') {
                            if (stopRequested) return;
                            resultBox.textContent += payload;
                            resultBox.scrollTop = resultBox.scrollHeight;
                        } else if (type === 'generate_done' || type === 'stopped') {
                            resolve();
                        } else if (type === 'generate_error') {
                            reject(new Error(payload));
                        }
                    };
                    aiWorker.postMessage({ type: 'generate', payload: { messages, max_new_tokens: 600 } });
                });
            }
            setStatus(stopRequested ? '已停止' : '生成完成');
        } catch (e) {
            setStatus('生成出错：' + e.message);
            showToast('AI 生成出错：' + e.message, 'error');
        } finally {
            generating = false;
            btnSummarize.disabled = false;
            btnStop.classList.remove('visible');
        }
    };

    btnStop.onclick = () => {
        stopRequested = true;
        if (aiWorker) aiWorker.postMessage({ type: 'stop' });
    };

    modelSel.onchange = () => {
        activeEngine = null;
        if (aiWorker) { aiWorker.terminate(); aiWorker = null; }
        loadedModelKey = null;
        const { backend } = parseModel(modelSel.value);
        setStatus('已选择新模型，点击按钮时将重新加载');
        badge.textContent = backend === 'webgpu' ? 'WebGPU' : 'WASM';
        badge.className   = backend;
    };
})();

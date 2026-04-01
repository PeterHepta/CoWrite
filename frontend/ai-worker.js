let pipeline, TextStreamer, env;
let activePipe = null;
let loadedModelKey = null;
let stopFlag = false;

self.postMessage({ type: 'worker_ready' });

self.onmessage = async (e) => {
    const { type, payload } = e.data;

    if (type === 'load') {
        const { modelId } = payload;
        const key = 'wasm:' + modelId;

        if (loadedModelKey === key && activePipe) {
            self.postMessage({ type: 'load_done' });
            return;
        }

        try {
            if (!pipeline) {
                self.postMessage({ type: 'progress', payload: { status: 'initiate', file: 'transformers.js' } });
                const mod = await import('/transformers.browser.mjs');
                pipeline = mod.pipeline;
                TextStreamer = mod.TextStreamer;
                env = mod.env;
            }

            env.allowRemoteModels = true;
            env.remoteHost = 'https://modelscope.cn/models/';
            env.remotePathTemplate = '{model}/resolve/master/';

            activePipe = await pipeline('text-generation', modelId, {
                dtype: 'q4',
                progress_callback: (p) => {
                    self.postMessage({ type: 'progress', payload: p });
                }
            });
            loadedModelKey = key;
            self.postMessage({ type: 'load_done' });
        } catch (err) {
            self.postMessage({ type: 'load_error', payload: err.message });
        }
    }

    if (type === 'generate') {
        const { messages, max_new_tokens } = payload;
        stopFlag = false;
        try {
            const streamer = new TextStreamer(activePipe.tokenizer, {
                skip_prompt: true,
                skip_special_tokens: true,
                callback_function: (token) => {
                    if (stopFlag) return;
                    self.postMessage({ type: 'token', payload: token });
                }
            });
            await activePipe(messages, { max_new_tokens: max_new_tokens || 600, do_sample: false, streamer });
            self.postMessage({ type: 'generate_done' });
        } catch (err) {
            self.postMessage({ type: 'generate_error', payload: err.message });
        }
    }

    if (type === 'stop') {
        stopFlag = true;
        self.postMessage({ type: 'stopped' });
    }
};

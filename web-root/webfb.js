const webfbBinding = {
    env: {
        js_log_int: a => console.log(`DEBUG: ${a}`),
        js_assert_fail: len => {
            const dec = new TextDecoder();
            const msg = dec.decode(tempPage().subarray(0, len));
            console.assert(false, msg);
        },
        js_warn: len => {
            const dec = new TextDecoder();
            const msg = dec.decode(tempPage().subarray(0, len));
            console.warn(msg);
        },
        js_ws_send: len => ws.send(sendBuf.subarray(0, len)),
    }
};

const webfb = (await WebAssembly.instantiateStreaming(fetch("webfb.wasm"), webfbBinding)).instance.exports;
webfb.initTempPage(); // init debug output early (e.g. assert())
// typed array is not stored, because wasm memory might be reallocated (grow)
const tempPage = () => new Uint8Array(webfb.memory.buffer, webfb.tempPageAdr(), 1 << 16);
webfb.init();

const canvas = document.getElementById("canvas");
canvas.width = webfb.frameWidth();
canvas.height = webfb.frameHeight();

canvas.addEventListener("contextmenu", e => e.preventDefault(), { passive: false });
canvas.addEventListener("mousemove", e => {
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    webfb.setInputPosition(x, y);
});
canvas.addEventListener("mousedown", e => {
    if (e.button == 0)
        webfb.setInputPressed(true);
    else if (e.button == 1)
        webfb.setWheelPressed(true);
});
canvas.addEventListener("mouseup", e => {
    if (e.button == 0)
        webfb.setInputPressed(false);
    else if (e.button == 1)
        webfb.setWheelPressed(false);
});
canvas.addEventListener("mouseleave", e => webfb.setInputPressed(false));
canvas.addEventListener("wheel", e => webfb.setWheelDelta(e.deltaY));

const bufAdrLen = new Uint32Array(webfb.memory.buffer, webfb.tempPageAdr(), webfb.writeBufferAdrLen());
const frameBuf = new Uint8ClampedArray(webfb.memory.buffer, bufAdrLen[0], bufAdrLen[1]);
const recvBuf = new Uint8Array(webfb.memory.buffer, bufAdrLen[2], bufAdrLen[3]);
const sendBuf = new Uint8Array(webfb.memory.buffer, bufAdrLen[4], bufAdrLen[5]);

const imageData = new ImageData(frameBuf, webfb.frameWidth(), webfb.frameHeight());
const ctx = canvas.getContext("bitmaprenderer");

const ws = new WebSocket("ws://" + window.location.host);
ws.addEventListener("open", e => webfb.setConnected(true));
ws.addEventListener("close", e => webfb.setConnected(false));
ws.onmessage = a => a.data.arrayBuffer().then(buf => {
    recvBuf.set(new Uint8Array(buf));
    webfb.pushReceived(buf.byteLength);
});

animate();

function animate() {
    webfb.update(performance.now());
    if (webfb.popShouldRender())
        createImageBitmap(imageData).then((a) => { ctx.transferFromImageBitmap(a); });

    const maxFps = 30; // rough approximate target
    setTimeout(() => { requestAnimationFrame(animate); }, 1000 / maxFps);
}

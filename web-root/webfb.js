const webfbBinding = {
    env: {
        js_log_int: (a) => { console.log(`debug: ${a}`); },
        js_assert_fail: (exprAdr, exprLen, fileAdr, fileLen, line, funcAdr, funcLen) => {
            const dec = new TextDecoder();
            const expr = dec.decode(new Uint8Array(webfb.memory.buffer, exprAdr, exprLen));
            const file = dec.decode(new Uint8Array(webfb.memory.buffer, fileAdr, fileLen));
            const func = dec.decode(new Uint8Array(webfb.memory.buffer, funcAdr, funcLen));
            console.assert(false, `${file}:${line}: ${func}: Assertion '${expr}' failed.`);
        },
    }
};

const webfb = (await WebAssembly.instantiateStreaming(fetch("webfb.wasm"), webfbBinding)).instance.exports;
webfb.init();

const canvas = document.getElementById("canvas");
canvas.width = webfb.imageWidth();
canvas.height = webfb.imageHeight();

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

const frameBuffer = new Uint8ClampedArray(webfb.memory.buffer, webfb.bufferAddress(), webfb.bufferSize());
const imageData = new ImageData(frameBuffer, webfb.imageWidth(), webfb.imageHeight());
const ctx = canvas.getContext("bitmaprenderer");

const ws = new WebSocket("ws://" + window.location.host);

animate();

function animate() {
    webfb.update(performance.now());
    if (webfb.popShouldDraw())
        createImageBitmap(imageData).then((a) => { ctx.transferFromImageBitmap(a); });

    const maxFps = 30; // rough approximate target
    setTimeout(() => { requestAnimationFrame(animate); }, 1000 / maxFps);
}

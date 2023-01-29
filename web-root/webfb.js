const webfbBinding = {
    env: {
        js_log_int: (a) => { console.log(`debug: ${a}`); },
        js_assert_failure: (filenameAddr, filenameLen, line) => {
            const rawFilename = new Uint8Array(webfb.memory.buffer, filenameAddr, filenameLen);
            const filename = new TextDecoder().decode(rawFilename);
            console.assert(false, filename, ":", line);
        },
    }
};

const webfb = (await WebAssembly.instantiateStreaming(fetch("webfb.wasm"), webfbBinding)).instance.exports;
webfb.init();

const canvas = document.getElementById("canvas");
canvas.width = webfb.imageWidth();
canvas.height = webfb.imageHeight();

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

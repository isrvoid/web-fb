const webfbBinding = {
    env: {
        print: (a) => { console.log(`result: ${a}`); }
    }
};

const webfb = (await WebAssembly.instantiateStreaming(fetch("webfb.wasm"), webfbBinding)).instance.exports;
webfb.init();

const canvas = document.getElementById("canvas");
canvas.width = webfb.imageWidth();
canvas.height = webfb.imageHeight();

const frameBuffer = new Uint8ClampedArray(webfb.memory.buffer, webfb.bufferOffset(), webfb.bufferSize());
const imageData = new ImageData(frameBuffer, webfb.imageWidth(), webfb.imageHeight());
const ctx = canvas.getContext("bitmaprenderer");

animate();

function animate() {
    webfb.testTransitionStep();
    window.createImageBitmap(imageData).then((a) => { ctx.transferFromImageBitmap(a); });

    const maxFps = 30; // rough approximate target
    setTimeout(() => { window.requestAnimationFrame(animate); }, 1000 / maxFps);
}

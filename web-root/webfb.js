window.addEventListener("load", initModule, false);

let gl;
let program;
let locations;
let isGlReady = false;
// TODO get buffer size from wasm code
const width = 800;
const height = 480;

function initModule(evt) {
    window.removeEventListener(evt.type, initModule, false);
    const webfbFut = WebAssembly.instantiateStreaming(fetch("webfb.wasm"), webfbBinding);

    gl = getRenderingContext();
    if (!gl) {
        console.log(gl, "Failed to get WebGL context");
        return;
    }
    gl.viewport(0, 0, gl.drawingBufferWidth, gl.drawingBufferHeight);
    gl.clearColor(0.0, 0.0, 0.0, 1.0);
    gl.clear(gl.COLOR_BUFFER_BIT);

    const vertexShader = gl.createShader(gl.VERTEX_SHADER);
    gl.shaderSource(vertexShader, vsSource);
    gl.compileShader(vertexShader);

    const fragmentShader = gl.createShader(gl.FRAGMENT_SHADER);
    gl.shaderSource(fragmentShader, fsSource);
    gl.compileShader(fragmentShader);

    program = gl.createProgram();
    gl.attachShader(program, vertexShader);
    gl.attachShader(program, fragmentShader);
    gl.linkProgram(program);

    gl.detachShader(program, vertexShader);
    gl.detachShader(program, fragmentShader);
    gl.deleteShader(vertexShader);
    gl.deleteShader(fragmentShader);

    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
        const errorLog = gl.getProgramInfoLog(program);
        cleanup();
        console.log(`Link error: ${errorLog}`);
        return;
    }
    gl.useProgram(program);

    locations = {
        vertexPosition: gl.getAttribLocation(program, "aVertexPosition"),
        textureCoord: gl.getAttribLocation(program, "aTextureCoord"),
        uSampler: gl.getUniformLocation(program, "uSampler"),
    };

    initAttributes();
    isGlReady = true;

    webfbFut.then(initWebfbAndRun);
}

const webfbBinding = {
    env: {
        print: (a) => { console.log(`result: ${a}`); }
    }
};

let webfb;
let frameBuffer;

function initWebfbAndRun(obj) {
    webfb = obj.instance.exports;
    webfb.init();
    frameBuffer = new Uint8Array(webfb.memory.buffer, webfb.bufferOffset(), webfb.bufferSize());
    window.requestAnimationFrame(animate);
}

function animate() {
    if (!isGlReady) return;

    webfb.testTransitionStep();
    gl.texSubImage2D(gl.TEXTURE_2D, 0, 0, 0, width, height, gl.RGBA, gl.UNSIGNED_BYTE, frameBuffer);
    gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);

    const fps = 20;
    setTimeout(() => {
        window.requestAnimationFrame(animate);
    }, 1000 / fps);
}

let positionBuffer;
let coordBuffer;
let texture;

function initAttributes() {
    const positions = [1.0, 1.0, -1.0, 1.0, 1.0, -1.0, -1.0, -1.0];
    const coords = [1.0, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0];
    positionBuffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, positionBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(positions), gl.STATIC_DRAW);
    gl.vertexAttribPointer(locations.vertexPositions, 2, gl.FLOAT, false, 0, 0);
    gl.enableVertexAttribArray(locations.vertexPosition);

    coordBuffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, coordBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(coords), gl.STATIC_DRAW);
    gl.vertexAttribPointer(locations.textureCoord, 2, gl.FLOAT, false, 0, 0);
    gl.enableVertexAttribArray(locations.textureCoord);

    gl.activeTexture(gl.TEXTURE0);
    texture = gl.createTexture();
    gl.bindTexture(gl.TEXTURE_2D, texture);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, width, height, 0, gl.RGBA, gl.UNSIGNED_BYTE, null);
    gl.uniform1i(locations.uSampler, 0);
}

window.addEventListener("beforeunload", cleanup, true);
function cleanup() {
    isGlReady = false;
    gl.useProgram(null);
    if (positionBuffer)
        gl.deleteBuffer(positionBuffer);
    if (coordBuffer)
        gl.deleteBuffer(coordBuffer);
    if (texture)
        gl.deleteTexture(texture);
    if (program)
        gl.deleteProgram(program);
}

function getRenderingContext() {
    const canvas = document.getElementById("canvas");
    return canvas.getContext("webgl", { alpha: false, depth: false, antialias: false, desynchronized: true });
}

const vsSource = `
    attribute vec2 aVertexPosition;
    attribute vec2 aTextureCoord;

    varying highp vec2 vTextureCoord;

    void main() {
        gl_Position = vec4(aVertexPosition, 0.0, 1.0);
        vTextureCoord = aTextureCoord;
    }
`;

const fsSource = `
    varying highp vec2 vTextureCoord;
    uniform sampler2D uSampler;

    void main() {
        gl_FragColor = texture2D(uSampler, vTextureCoord);
    }
`;

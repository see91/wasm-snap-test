import { initWasm } from './nucypher_core_wasm.js';

(async function() {
    await initWasm()
}());

export * from "./nucypher_core_wasm.js";

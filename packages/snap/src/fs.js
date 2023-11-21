const fs = require('fs');
// let imports = {};
// imports['__wbindgen_placeholder__'] = module.exports;


function arrayBufferToString (buffer, encoding = 'utf-8') {
  const decoder = new TextDecoder(encoding);
  return decoder.decode(buffer);
}

// function str2ab (str) {
//   var buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
//   var bufView = new Uint16Array(buf);
//   for (var i = 0, strLen = str.length; i < strLen; i++) {
//     bufView[i] = str.charCodeAt(i);
//   }
//   return buf;
// }

// const path = require('path').join(__dirname, 'nucypher_core_wasm_bg.wasm');
const path = require('path').join(__dirname, 'wasmNew/nucypher_core_wasm_bg.wasm');
const bytes = require('fs').readFileSync(path);
// const res = arrayBufferToString(Buffer.from(bytes), 'gb2312')
fs.writeFileSync('res.json', JSON.stringify(bytes));

// const wasmModule = new WebAssembly.Module(bytes);
// const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
// console.log(11111, '-----------', wasmInstance.exports);

import { OnRpcRequestHandler } from '@metamask/snaps-types';
import { panel, text } from '@metamask/snaps-ui';
import nucypher_core_wasm_bg from './wasmNew/nucypher_core_wasm_bg.wasm';
// import nucypher_core_wasm_bg from '@nucypher/nucypher-core/pkg-bundler/nucypher_core_wasm_bg.wasm';

let imports: any = {};
imports['__wbindgen_placeholder__'] = module.exports;
// const wasmFile = require('@nucypher/nucypher-core/pkg-node/nucypher_core_wasm.js');
// import * as wasmFile from './nucypher_core_wasm_bg.wasm';
// import { MessageKit } from './pkg-bundler/nucypher_core_wasm';
// const wasmFile = require('./pkg-bundler/nucypher_core_wasm_bg.js');
// import { SecretKey, MessageKit } from './pkg-bundler/nucypher_core_wasm';
// import { SecretKey, MessageKit } from '@nucypher/nucypher-core';

// const wasm: any = wasmFile;

// async function fetchAndInstantiate() {
//   try {
//     const response = await fetch(
//       'http://localhost:8089/nucypher_core_wasm_bg.wasm',
//     );
//     const buffer = await response.arrayBuffer();

//     const module = new WebAssembly.Module(buffer);
//     const instance = new WebAssembly.Instance(module);
//     // const instance = await WebAssembly.instantiate(buffer, {});
//   } catch (error) {
//     console.log('[error]', error);
//   }
// }

/**
 * Handle incoming JSON-RPC requests, sent through `wallet_invokeSnap`.
 *
 * @param args - The request handler args as object.
 * @param args.origin - The origin of the request, e.g., the website that
 * invoked the snap.
 * @param args.request - A validated JSON-RPC request object.
 * @returns The result of `snap_dialog`.
 * @throws If the request method is not valid for this snap.
 */
export const onRpcRequest: OnRpcRequestHandler = async ({
  origin,
  request,
}) => {
  switch (request.method) {
    case 'hello':
      return snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: panel([
            text(`Hello, **${origin}**!`),
            text('This custom confirmation is just for display purposes.'),
            text(
              'But you can edit the snap source code to make it do something, if you want to!',
            ),
          ]),
        },
      });
    case 'multi_test_run':
      console.log('log 1');
      // const response = await fetch(
      //   'http://localhost:8089/nucypher_core_wasm_bg.wasm',
      // );
      // const buffer = await response.arrayBuffer();
      console.log(nucypher_core_wasm_bg, '----');

      const wasmModule = new WebAssembly.Module(nucypher_core_wasm_bg);
      const wasmInstance = new WebAssembly.Instance(wasmModule, imports);

      console.log(wasmInstance.exports, '****************');

      // wasm = wasmInstance.exports;
      // const entropy = await snap.request({
      //   method: 'snap_getEntropy',
      //   params: {
      //     version: 1,
      //     salt: '0x5359e1dcd4db3002d28f9ca90b3022672f4423f0',
      //   },
      // });

      // const module = new WebAssembly.Module(bytes);
      // const instance = new WebAssembly.Instance(module, {});

      // fetchAndInstantiate();
      // let importObject = {
      //   imports: {
      //     imported_func: (arg: any) => console.log(arg),
      //   },
      // };

      // WebAssembly.instantiate(
      //   fetch(wasm),
      //   // fetch('http://localhost:8089/nucypher_core_wasm_bg.wasm'),
      //   {},
      // )
      //   .then((obj) => {
      //     console.log(obj, '----');
      //     // obj.instance.exports.exported_func()
      //   })
      //   .catch((error) => {
      //     console.log(error, '报错');
      //   });

      // fetch('http://localhost:8089/simple.wasm')
      // fetch('http://localhost:8089/nucypher_core_wasm_bg.wasm')
      //   .then(async (res) => {
      //     console.log(await res.json());
      //   })
      //   // .then((res) => res.arrayBuffer())
      //   // .then((bytes) => WebAssembly.instantiateStreaming(bytes, {}))
      //   // .then((bytes) => WebAssembly.instantiate(bytes, {}))
      //   .then((results: any) => {
      //     console.log(results.instance, '结果 ~ ');
      //     // results.instance.exports.exported_func();
      //   })
      //   .catch((error) => {
      //     console.log(error, '报错');
      //   });

      // fetch('https://dev-api-nft.interworld.io/api/v1/ping')
      //   .then((x) => x.json())
      //   .then((n) => {
      //     console.log(n, '结果');
      //   });
      return snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: panel([
            text(`Hello, **${origin}**!`),
            text('This custom confirmation is just for display purposes.'),
            text(
              'But you can edit the snap source code to make it do something, if you want to!',
            ),
          ]),
        },
      });
    default:
      throw new Error('Method not found.');
  }
};

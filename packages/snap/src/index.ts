import { OnRpcRequestHandler } from '@metamask/snaps-types';
import { panel, text } from '@metamask/snaps-ui';
let imports: any = {};
imports['__wbindgen_placeholder__'] = module.exports;

module.exports.__wbindgen_object_drop_ref = function () {};

module.exports.__wbg_verifiedkeyfrag_new = function () {};

module.exports.__wbg_getRandomValues_37fa2ca9e4e07fab = function () {};

module.exports.__wbg_randomFillSync_dc1e9a60c158336d = function () {};

module.exports.__wbg_crypto_c48a774b022d20ac = function () {};

module.exports.__wbindgen_is_object = function () {};

module.exports.__wbg_process_298734cf255a885d = function () {};

module.exports.__wbg_versions_e2e78e134e3e5d01 = function () {};

module.exports.__wbg_node_1cd7a5d853dbea79 = function () {};

module.exports.__wbindgen_is_string = function () {};

module.exports.__wbg_msCrypto_bcb970640f50a1e8 = function () {};

module.exports.__wbg_require_8f08ceecec0f4fee = function () {};

module.exports.__wbindgen_is_function = function () {};

module.exports.__wbindgen_string_new = function () {};

module.exports.__wbg_newnoargs_ccdcae30fd002262 = function () {};

module.exports.__wbg_call_669127b9d730c650 = function () {};

module.exports.__wbindgen_object_clone_ref = function () {};

module.exports.__wbg_self_3fad056edded10bd = function () {};

module.exports.__wbg_window_a4f46c98a61d4089 = function () {};

module.exports.__wbg_globalThis_17eff828815f7d84 = function () {};

module.exports.__wbg_global_46f939f6541643c5 = function () {};

module.exports.__wbindgen_is_undefined = function () {};

module.exports.__wbg_new_ab87fd305ed9004b = function () {};

module.exports.__wbg_call_53fc3abd42e24ec8 = function () {};

module.exports.__wbg_buffer_344d9b41efe96da7 = function () {};

module.exports.__wbg_newwithbyteoffsetandlength_2dc04d99088b15e3 =
  function () {};

module.exports.__wbg_new_d8a000788389a31e = function () {};

module.exports.__wbg_set_dcfd613a3420f908 = function () {};

module.exports.__wbg_newwithlength_13b5319ab422dcf6 = function () {};

module.exports.__wbg_subarray_6ca5cfa7fbb9abbe = function () {};

module.exports.__wbindgen_throw = function () {};

module.exports.__wbindgen_memory = function () {};

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
      const response = await fetch(
        'http://localhost:8089/nucypher_core_wasm_bg.wasm',
      );
      const buffer = await response.arrayBuffer();
      const wasmModule = new WebAssembly.Module(buffer);
      const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
      const wasm: any = wasmInstance.exports;
      console.log(wasm, '****************', wasm.secretkey_random());

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

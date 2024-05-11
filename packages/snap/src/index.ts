import { OnRpcRequestHandler } from '@metamask/snaps-types';
import { panel, text } from '@metamask/snaps-ui';
import { SecretKey } from './nulink-nucypher-snap';
import { hdkey } from 'ethereumjs-wallet/dist.browser'
import * as bip39 from "bip39"; //"bip39": "^3.0.4",
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
      const mnemonic = bip39.generateMnemonic();
      console.log(mnemonic, '助记词');
      const seed = await bip39.mnemonicToSeed(mnemonic);
      // console.log(seed, '助记词的 seed');
      try {
        console.log(hdkey, '打扫房间肯定是');
        // const __hdkey = new hdkey()
        console.log(hdkey.fromMasterSeed(seed), '发的设计费活动结束');

        hdkey.fromMasterSeed(seed);
      } catch (error) {
        console.log(error, '地方技术开发进度款圣诞节开发');
      }

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
      console.log('[SecretKey.random]', SecretKey.random());
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

import { OnRpcRequestHandler } from '@metamask/snaps-types';
import { panel, text } from '@metamask/snaps-ui';
import { TextDecoder } from '@polkadot/x-textdecoder';
// const decoder = new TextDecoder('utf-8');
let imports: any = {};
imports['__wbindgen_placeholder__'] = module.exports;
let wasm: any;
// const { TextDecoder } = require(`util`);

const heap = new Array(128).fill(undefined);

heap.push(undefined, null, true, false);

function getObject(idx: any) {
  return heap[idx];
}

let heap_next = heap.length;

function dropObject(idx: any) {
  if (idx < 132) return;
  heap[idx] = heap_next;
  heap_next = idx;
}

function takeObject(idx: any) {
  const ret = getObject(idx);
  dropObject(idx);
  return ret;
}

let cachedTextDecoder = new TextDecoder('utf-8', {
  ignoreBOM: true,
  fatal: true,
});

cachedTextDecoder.decode();

let cachedUint8Memory0: any = null;

function getUint8Memory0() {
  if (cachedUint8Memory0 === null || cachedUint8Memory0.byteLength === 0) {
    cachedUint8Memory0 = new Uint8Array(wasm.memory.buffer);
  }
  return cachedUint8Memory0;
}

function getStringFromWasm0(ptr: any, len: any) {
  ptr = ptr >>> 0;
  return cachedTextDecoder.decode(getUint8Memory0().subarray(ptr, ptr + len));
}

function addHeapObject(obj: any) {
  if (heap_next === heap.length) heap.push(heap.length + 1);
  const idx = heap_next;
  heap_next = heap[idx];

  heap[idx] = obj;
  return idx;
}

function _assertClass(instance: any, klass: any) {
  if (!(instance instanceof klass)) {
    throw new Error(`expected instance of ${klass.name}`);
  }
  return instance.ptr;
}

let WASM_VECTOR_LEN = 0;

function passArray8ToWasm0(arg: any, malloc: any) {
  const ptr = malloc(arg.length * 1, 1) >>> 0;
  getUint8Memory0().set(arg, ptr / 1);
  WASM_VECTOR_LEN = arg.length;
  return ptr;
}

let cachedInt32Memory0: any = null;

function getInt32Memory0() {
  if (cachedInt32Memory0 === null || cachedInt32Memory0.byteLength === 0) {
    cachedInt32Memory0 = new Int32Array(wasm.memory.buffer);
  }
  return cachedInt32Memory0;
}

function getArrayU8FromWasm0(ptr: any, len: any) {
  ptr = ptr >>> 0;
  return getUint8Memory0().subarray(ptr / 1, ptr / 1 + len);
}
/**
 * @param {PublicKey} delegating_pk
 * @param {Uint8Array} plaintext
 * @returns {EncryptionResult}
 */
module.exports.encrypt = function (delegating_pk: any, plaintext: any) {
  try {
    const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
    _assertClass(delegating_pk, PublicKey);
    const ptr0 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    wasm.encrypt(retptr, delegating_pk.__wbg_ptr, ptr0, len0);
    var r0 = getInt32Memory0()[retptr / 4 + 0];
    var r1 = getInt32Memory0()[retptr / 4 + 1];
    var r2 = getInt32Memory0()[retptr / 4 + 2];
    if (r2) {
      throw takeObject(r1);
    }
    return EncryptionResult.__wrap(r0);
  } finally {
    wasm.__wbindgen_add_to_stack_pointer(16);
  }
};

/**
 * @param {SecretKey} delegating_sk
 * @param {Capsule} capsule
 * @param {Uint8Array} ciphertext
 * @returns {Uint8Array}
 */
module.exports.decryptOriginal = function (
  delegating_sk: any,
  capsule: any,
  ciphertext: any,
) {
  try {
    const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
    _assertClass(delegating_sk, SecretKey);
    _assertClass(capsule, Capsule);
    const ptr0 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    wasm.decryptOriginal(
      retptr,
      delegating_sk.__wbg_ptr,
      capsule.__wbg_ptr,
      ptr0,
      len0,
    );
    var r0 = getInt32Memory0()[retptr / 4 + 0];
    var r1 = getInt32Memory0()[retptr / 4 + 1];
    var r2 = getInt32Memory0()[retptr / 4 + 2];
    var r3 = getInt32Memory0()[retptr / 4 + 3];
    if (r3) {
      throw takeObject(r2);
    }
    var v2 = getArrayU8FromWasm0(r0, r1).slice();
    wasm.__wbindgen_free(r0, r1 * 1, 1);
    return v2;
  } finally {
    wasm.__wbindgen_add_to_stack_pointer(16);
  }
};

let cachedUint32Memory0: any = null;

function getUint32Memory0() {
  if (cachedUint32Memory0 === null || cachedUint32Memory0.byteLength === 0) {
    cachedUint32Memory0 = new Uint32Array(wasm.memory.buffer);
  }
  return cachedUint32Memory0;
}

function getArrayJsValueFromWasm0(ptr: any, len: any) {
  ptr = ptr >>> 0;
  const mem = getUint32Memory0();
  const slice = mem.subarray(ptr / 4, ptr / 4 + len);
  const result = [];
  for (let i = 0; i < slice.length; i++) {
    result.push(takeObject(slice[i]));
  }
  return result;
}
/**
 * @param {SecretKey} delegating_sk
 * @param {PublicKey} receiving_pk
 * @param {Signer} signer
 * @param {number} threshold
 * @param {number} shares
 * @param {boolean} sign_delegating_key
 * @param {boolean} sign_receiving_key
 * @returns {any[]}
 */
module.exports.generateKFrags = function (
  delegating_sk: any,
  receiving_pk: any,
  signer: any,
  threshold: any,
  shares: any,
  sign_delegating_key: any,
  sign_receiving_key: any,
) {
  try {
    const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
    _assertClass(delegating_sk, SecretKey);
    _assertClass(receiving_pk, PublicKey);
    _assertClass(signer, Signer);
    wasm.generateKFrags(
      retptr,
      delegating_sk.__wbg_ptr,
      receiving_pk.__wbg_ptr,
      signer.__wbg_ptr,
      threshold,
      shares,
      sign_delegating_key,
      sign_receiving_key,
    );
    var r0 = getInt32Memory0()[retptr / 4 + 0];
    var r1 = getInt32Memory0()[retptr / 4 + 1];
    var v1 = getArrayJsValueFromWasm0(r0, r1).slice();
    wasm.__wbindgen_free(r0, r1 * 4, 4);
    return v1;
  } finally {
    wasm.__wbindgen_add_to_stack_pointer(16);
  }
};

/**
 * @param {Capsule} capsule
 * @param {VerifiedKeyFrag} kfrag
 * @returns {VerifiedCapsuleFrag}
 */
module.exports.reencrypt = function (capsule: any, kfrag: any) {
  _assertClass(capsule, Capsule);
  _assertClass(kfrag, VerifiedKeyFrag);
  const ret = wasm.reencrypt(capsule.__wbg_ptr, kfrag.__wbg_ptr);
  return VerifiedCapsuleFrag.__wrap(ret);
};

function handleError(this: any, f: any, args: any) {
  try {
    return f.apply(this, args);
  } catch (e) {
    wasm.__wbindgen_exn_store(addHeapObject(e));
  }
}
/**
 */
class Capsule {
  private __wbg_ptr: any;
  static __wrap(ptr: any) {
    ptr = ptr >>> 0;
    const obj = Object.create(Capsule.prototype);
    obj.__wbg_ptr = ptr;

    return obj;
  }

  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;

    return ptr;
  }

  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_capsule_free(ptr);
  }
  /**
   * @param {VerifiedCapsuleFrag} cfrag
   * @returns {CapsuleWithFrags}
   */
  withCFrag(cfrag: any) {
    _assertClass(cfrag, VerifiedCapsuleFrag);
    const ret = wasm.capsule_withCFrag(this.__wbg_ptr, cfrag.__wbg_ptr);
    return CapsuleWithFrags.__wrap(ret);
  }
  /**
   * @returns {Uint8Array}
   */
  toBytes() {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.capsule_toBytes(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var v1 = getArrayU8FromWasm0(r0, r1).slice();
      wasm.__wbindgen_free(r0, r1 * 1, 1);
      return v1;
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @param {Uint8Array} data
   * @returns {Capsule}
   */
  static fromBytes(data: any) {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
      const len0 = WASM_VECTOR_LEN;
      wasm.capsule_fromBytes(retptr, ptr0, len0);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var r2 = getInt32Memory0()[retptr / 4 + 2];
      if (r2) {
        throw takeObject(r1);
      }
      return Capsule.__wrap(r0);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @returns {string}
   */
  toString() {
    let deferred1_0;
    let deferred1_1;
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.capsule_toString(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      deferred1_0 = r0;
      deferred1_1 = r1;
      return getStringFromWasm0(r0, r1);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * @param {Capsule} other
   * @returns {boolean}
   */
  equals(other: any) {
    _assertClass(other, Capsule);
    const ret = wasm.capsule_equals(this.__wbg_ptr, other.__wbg_ptr);
    return ret !== 0;
  }
}
module.exports.Capsule = Capsule;
/**
 */
class CapsuleFrag {
  private __wbg_ptr: any;
  static __wrap(ptr: any) {
    ptr = ptr >>> 0;
    const obj = Object.create(CapsuleFrag.prototype);
    obj.__wbg_ptr = ptr;

    return obj;
  }

  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;

    return ptr;
  }

  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_capsulefrag_free(ptr);
  }
  /**
   * @param {Capsule} capsule
   * @param {PublicKey} verifying_pk
   * @param {PublicKey} delegating_pk
   * @param {PublicKey} receiving_pk
   * @returns {VerifiedCapsuleFrag}
   */
  verify(
    capsule: any,
    verifying_pk: any,
    delegating_pk: any,
    receiving_pk: any,
  ) {
    try {
      const ptr = this.__destroy_into_raw();
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      _assertClass(capsule, Capsule);
      _assertClass(verifying_pk, PublicKey);
      _assertClass(delegating_pk, PublicKey);
      _assertClass(receiving_pk, PublicKey);
      wasm.capsulefrag_verify(
        retptr,
        ptr,
        capsule.__wbg_ptr,
        verifying_pk.__wbg_ptr,
        delegating_pk.__wbg_ptr,
        receiving_pk.__wbg_ptr,
      );
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var r2 = getInt32Memory0()[retptr / 4 + 2];
      if (r2) {
        throw takeObject(r1);
      }
      return VerifiedCapsuleFrag.__wrap(r0);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @returns {Uint8Array}
   */
  toBytes() {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.capsulefrag_toBytes(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var v1 = getArrayU8FromWasm0(r0, r1).slice();
      wasm.__wbindgen_free(r0, r1 * 1, 1);
      return v1;
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @param {Uint8Array} data
   * @returns {CapsuleFrag}
   */
  static fromBytes(data: any) {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
      const len0 = WASM_VECTOR_LEN;
      wasm.capsulefrag_fromBytes(retptr, ptr0, len0);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var r2 = getInt32Memory0()[retptr / 4 + 2];
      if (r2) {
        throw takeObject(r1);
      }
      return CapsuleFrag.__wrap(r0);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @returns {string}
   */
  toString() {
    let deferred1_0;
    let deferred1_1;
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.capsulefrag_toString(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      deferred1_0 = r0;
      deferred1_1 = r1;
      return getStringFromWasm0(r0, r1);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * @param {CapsuleFrag} other
   * @returns {boolean}
   */
  equals(other: any) {
    _assertClass(other, CapsuleFrag);
    const ret = wasm.capsulefrag_equals(this.__wbg_ptr, other.__wbg_ptr);
    return ret !== 0;
  }
}
module.exports.CapsuleFrag = CapsuleFrag;
/**
 */
class CapsuleWithFrags {
  private __wbg_ptr: any;
  static __wrap(ptr: any) {
    ptr = ptr >>> 0;
    const obj = Object.create(CapsuleWithFrags.prototype);
    obj.__wbg_ptr = ptr;

    return obj;
  }

  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;

    return ptr;
  }

  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_capsulewithfrags_free(ptr);
  }
  /**
   * @param {VerifiedCapsuleFrag} cfrag
   * @returns {CapsuleWithFrags}
   */
  withCFrag(cfrag: any) {
    _assertClass(cfrag, VerifiedCapsuleFrag);
    const ret = wasm.capsulewithfrags_withCFrag(
      this.__wbg_ptr,
      cfrag.__wbg_ptr,
    );
    return CapsuleWithFrags.__wrap(ret);
  }
  /**
   * @param {SecretKey} receiving_sk
   * @param {PublicKey} delegating_pk
   * @param {Uint8Array} ciphertext
   * @returns {Uint8Array}
   */
  decryptReencrypted(receiving_sk: any, delegating_pk: any, ciphertext: any) {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      _assertClass(receiving_sk, SecretKey);
      _assertClass(delegating_pk, PublicKey);
      const ptr0 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
      const len0 = WASM_VECTOR_LEN;
      wasm.capsulewithfrags_decryptReencrypted(
        retptr,
        this.__wbg_ptr,
        receiving_sk.__wbg_ptr,
        delegating_pk.__wbg_ptr,
        ptr0,
        len0,
      );
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var r2 = getInt32Memory0()[retptr / 4 + 2];
      var r3 = getInt32Memory0()[retptr / 4 + 3];
      if (r3) {
        throw takeObject(r2);
      }
      var v2 = getArrayU8FromWasm0(r0, r1).slice();
      wasm.__wbindgen_free(r0, r1 * 1, 1);
      return v2;
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
}
module.exports.CapsuleWithFrags = CapsuleWithFrags;
/**
 */
class EncryptedKeyFrag {
  private __wbg_ptr: any;
  static __wrap(ptr: any) {
    ptr = ptr >>> 0;
    const obj = Object.create(EncryptedKeyFrag.prototype);
    obj.__wbg_ptr = ptr;

    return obj;
  }

  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;

    return ptr;
  }

  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_encryptedkeyfrag_free(ptr);
  }
  /**
   * @param {Signer} signer
   * @param {PublicKey} recipient_key
   * @param {HRAC} hrac
   * @param {VerifiedKeyFrag} verified_kfrag
   */
  constructor(signer: any, recipient_key: any, hrac: any, verified_kfrag: any) {
    _assertClass(signer, Signer);
    _assertClass(recipient_key, PublicKey);
    _assertClass(hrac, HRAC);
    _assertClass(verified_kfrag, VerifiedKeyFrag);
    const ret = wasm.encryptedkeyfrag_new(
      signer.__wbg_ptr,
      recipient_key.__wbg_ptr,
      hrac.__wbg_ptr,
      verified_kfrag.__wbg_ptr,
    );
    this.__wbg_ptr = ret >>> 0;
    return this;
  }
  /**
   * @param {SecretKey} sk
   * @param {HRAC} hrac
   * @param {PublicKey} publisher_verifying_key
   * @returns {VerifiedKeyFrag}
   */
  decrypt(sk: any, hrac: any, publisher_verifying_key: any) {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      _assertClass(sk, SecretKey);
      _assertClass(hrac, HRAC);
      _assertClass(publisher_verifying_key, PublicKey);
      wasm.encryptedkeyfrag_decrypt(
        retptr,
        this.__wbg_ptr,
        sk.__wbg_ptr,
        hrac.__wbg_ptr,
        publisher_verifying_key.__wbg_ptr,
      );
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var r2 = getInt32Memory0()[retptr / 4 + 2];
      if (r2) {
        throw takeObject(r1);
      }
      return VerifiedKeyFrag.__wrap(r0);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @param {Uint8Array} data
   * @returns {EncryptedKeyFrag}
   */
  static fromBytes(data: any) {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
      const len0 = WASM_VECTOR_LEN;
      wasm.encryptedkeyfrag_fromBytes(retptr, ptr0, len0);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var r2 = getInt32Memory0()[retptr / 4 + 2];
      if (r2) {
        throw takeObject(r1);
      }
      return EncryptedKeyFrag.__wrap(r0);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @returns {Uint8Array}
   */
  toBytes() {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.encryptedkeyfrag_toBytes(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var v1 = getArrayU8FromWasm0(r0, r1).slice();
      wasm.__wbindgen_free(r0, r1 * 1, 1);
      return v1;
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
}
module.exports.EncryptedKeyFrag = EncryptedKeyFrag;
/**
 */
class EncryptionResult {
  private __wbg_ptr: any;
  static __wrap(ptr: any) {
    ptr = ptr >>> 0;
    const obj = Object.create(EncryptionResult.prototype);
    obj.__wbg_ptr = ptr;

    return obj;
  }

  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;

    return ptr;
  }

  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_encryptionresult_free(ptr);
  }
  /**
   * @returns {Capsule}
   */
  get capsule() {
    const ret = wasm.__wbg_get_encryptionresult_capsule(this.__wbg_ptr);
    return Capsule.__wrap(ret);
  }
  /**
   * @param {Capsule} arg0
   */
  set capsule(arg0) {
    _assertClass(arg0, Capsule);
    var ptr0 = arg0.__destroy_into_raw();
    wasm.__wbg_set_encryptionresult_capsule(this.__wbg_ptr, ptr0);
  }
  /**
   * @returns {Uint8Array}
   */
  get ciphertext() {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.encryptionresult_ciphertext(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var v1 = getArrayU8FromWasm0(r0, r1).slice();
      wasm.__wbindgen_free(r0, r1 * 1, 1);
      return v1;
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
}
module.exports.EncryptionResult = EncryptionResult;
/**
 */
class HRAC {
  private __wbg_ptr: any;
  static __wrap(ptr: any) {
    ptr = ptr >>> 0;
    const obj = Object.create(HRAC.prototype);
    obj.__wbg_ptr = ptr;

    return obj;
  }

  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;

    return ptr;
  }

  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_hrac_free(ptr);
  }
  /**
   * @param {PublicKey} publisher_verifying_key
   * @param {PublicKey} bob_verifying_key
   * @param {Uint8Array} label
   */
  constructor(
    publisher_verifying_key: any,
    bob_verifying_key: any,
    label: any,
  ) {
    _assertClass(publisher_verifying_key, PublicKey);
    _assertClass(bob_verifying_key, PublicKey);
    const ptr0 = passArray8ToWasm0(label, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.hrac_new(
      publisher_verifying_key.__wbg_ptr,
      bob_verifying_key.__wbg_ptr,
      ptr0,
      len0,
    );
    this.__wbg_ptr = ret >>> 0;
    return this;
  }
  /**
   * @param {Uint8Array} bytes
   * @returns {HRAC}
   */
  static fromBytes(bytes: any) {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
      const len0 = WASM_VECTOR_LEN;
      wasm.hrac_fromBytes(retptr, ptr0, len0);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var r2 = getInt32Memory0()[retptr / 4 + 2];
      if (r2) {
        throw takeObject(r1);
      }
      return HRAC.__wrap(r0);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @returns {Uint8Array}
   */
  toBytes() {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.hrac_toBytes(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var v1 = getArrayU8FromWasm0(r0, r1).slice();
      wasm.__wbindgen_free(r0, r1 * 1, 1);
      return v1;
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
}
module.exports.HRAC = HRAC;
/**
 */
class KeyFrag {
  private __wbg_ptr: any;
  static __wrap(ptr: any) {
    ptr = ptr >>> 0;
    const obj = Object.create(KeyFrag.prototype);
    obj.__wbg_ptr = ptr;

    return obj;
  }

  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;

    return ptr;
  }

  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_keyfrag_free(ptr);
  }
  /**
   * @param {PublicKey} verifying_pk
   * @returns {VerifiedKeyFrag}
   */
  verify(verifying_pk: any) {
    try {
      const ptr = this.__destroy_into_raw();
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      _assertClass(verifying_pk, PublicKey);
      wasm.keyfrag_verify(retptr, ptr, verifying_pk.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var r2 = getInt32Memory0()[retptr / 4 + 2];
      if (r2) {
        throw takeObject(r1);
      }
      return VerifiedKeyFrag.__wrap(r0);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @param {PublicKey} verifying_pk
   * @param {PublicKey} delegating_pk
   * @returns {VerifiedKeyFrag}
   */
  verifyWithDelegatingKey(verifying_pk: any, delegating_pk: any) {
    try {
      const ptr = this.__destroy_into_raw();
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      _assertClass(verifying_pk, PublicKey);
      _assertClass(delegating_pk, PublicKey);
      wasm.keyfrag_verifyWithDelegatingKey(
        retptr,
        ptr,
        verifying_pk.__wbg_ptr,
        delegating_pk.__wbg_ptr,
      );
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var r2 = getInt32Memory0()[retptr / 4 + 2];
      if (r2) {
        throw takeObject(r1);
      }
      return VerifiedKeyFrag.__wrap(r0);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @param {PublicKey} verifying_pk
   * @param {PublicKey} receiving_pk
   * @returns {VerifiedKeyFrag}
   */
  verifyWithReceivingKey(verifying_pk: any, receiving_pk: any) {
    try {
      const ptr = this.__destroy_into_raw();
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      _assertClass(verifying_pk, PublicKey);
      _assertClass(receiving_pk, PublicKey);
      wasm.keyfrag_verifyWithReceivingKey(
        retptr,
        ptr,
        verifying_pk.__wbg_ptr,
        receiving_pk.__wbg_ptr,
      );
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var r2 = getInt32Memory0()[retptr / 4 + 2];
      if (r2) {
        throw takeObject(r1);
      }
      return VerifiedKeyFrag.__wrap(r0);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @param {PublicKey} verifying_pk
   * @param {PublicKey} delegating_pk
   * @param {PublicKey} receiving_pk
   * @returns {VerifiedKeyFrag}
   */
  verifyWithDelegatingAndReceivingKeys(
    verifying_pk: any,
    delegating_pk: any,
    receiving_pk: any,
  ) {
    try {
      const ptr = this.__destroy_into_raw();
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      _assertClass(verifying_pk, PublicKey);
      _assertClass(delegating_pk, PublicKey);
      _assertClass(receiving_pk, PublicKey);
      wasm.keyfrag_verifyWithDelegatingAndReceivingKeys(
        retptr,
        ptr,
        verifying_pk.__wbg_ptr,
        delegating_pk.__wbg_ptr,
        receiving_pk.__wbg_ptr,
      );
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var r2 = getInt32Memory0()[retptr / 4 + 2];
      if (r2) {
        throw takeObject(r1);
      }
      return VerifiedKeyFrag.__wrap(r0);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @returns {Uint8Array}
   */
  toBytes() {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.keyfrag_toBytes(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var v1 = getArrayU8FromWasm0(r0, r1).slice();
      wasm.__wbindgen_free(r0, r1 * 1, 1);
      return v1;
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @param {Uint8Array} data
   * @returns {KeyFrag}
   */
  static fromBytes(data: any) {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
      const len0 = WASM_VECTOR_LEN;
      wasm.keyfrag_fromBytes(retptr, ptr0, len0);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var r2 = getInt32Memory0()[retptr / 4 + 2];
      if (r2) {
        throw takeObject(r1);
      }
      return KeyFrag.__wrap(r0);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @returns {string}
   */
  toString() {
    let deferred1_0;
    let deferred1_1;
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.keyfrag_toString(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      deferred1_0 = r0;
      deferred1_1 = r1;
      return getStringFromWasm0(r0, r1);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * @param {KeyFrag} other
   * @returns {boolean}
   */
  equals(other: any) {
    _assertClass(other, KeyFrag);
    const ret = wasm.keyfrag_equals(this.__wbg_ptr, other.__wbg_ptr);
    return ret !== 0;
  }
}
module.exports.KeyFrag = KeyFrag;
/**
 */
class PublicKey {
  private __wbg_ptr: any;
  static __wrap(ptr: any) {
    ptr = ptr >>> 0;
    const obj = Object.create(PublicKey.prototype);
    obj.__wbg_ptr = ptr;

    return obj;
  }

  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;

    return ptr;
  }

  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_publickey_free(ptr);
  }
  /**
   * @returns {Uint8Array}
   */
  toBytes() {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.publickey_toBytes(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var v1 = getArrayU8FromWasm0(r0, r1).slice();
      wasm.__wbindgen_free(r0, r1 * 1, 1);
      return v1;
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @param {Uint8Array} data
   * @returns {PublicKey}
   */
  static fromBytes(data: any) {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
      const len0 = WASM_VECTOR_LEN;
      wasm.publickey_fromBytes(retptr, ptr0, len0);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var r2 = getInt32Memory0()[retptr / 4 + 2];
      if (r2) {
        throw takeObject(r1);
      }
      return PublicKey.__wrap(r0);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @returns {string}
   */
  toString() {
    let deferred1_0;
    let deferred1_1;
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.publickey_toString(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      deferred1_0 = r0;
      deferred1_1 = r1;
      return getStringFromWasm0(r0, r1);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * @param {PublicKey} other
   * @returns {boolean}
   */
  equals(other: any) {
    _assertClass(other, PublicKey);
    const ret = wasm.publickey_equals(this.__wbg_ptr, other.__wbg_ptr);
    return ret !== 0;
  }
}
module.exports.PublicKey = PublicKey;
/**
 */
class SecretKey {
  private __wbg_ptr: any;
  static __wrap(ptr: any) {
    ptr = ptr >>> 0;
    const obj = Object.create(SecretKey.prototype);
    obj.__wbg_ptr = ptr;

    return obj;
  }

  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;

    return ptr;
  }

  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_secretkey_free(ptr);
  }
  /**
   * Generates a secret key using the default RNG and returns it.
   * @returns {SecretKey}
   */
  static random() {
    const ret = wasm.secretkey_random();
    return SecretKey.__wrap(ret);
  }
  /**
   * Generates a secret key using the default RNG and returns it.
   * @returns {PublicKey}
   */
  publicKey() {
    const ret = wasm.secretkey_publicKey(this.__wbg_ptr);
    return PublicKey.__wrap(ret);
  }
  /**
   * @returns {Uint8Array}
   */
  toSecretBytes() {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.secretkey_toSecretBytes(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var v1 = getArrayU8FromWasm0(r0, r1).slice();
      wasm.__wbindgen_free(r0, r1 * 1, 1);
      return v1;
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @param {Uint8Array} data
   * @returns {SecretKey}
   */
  static fromBytes(data: any) {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
      const len0 = WASM_VECTOR_LEN;
      wasm.secretkey_fromBytes(retptr, ptr0, len0);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var r2 = getInt32Memory0()[retptr / 4 + 2];
      if (r2) {
        throw takeObject(r1);
      }
      return SecretKey.__wrap(r0);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @returns {string}
   */
  toString() {
    let deferred1_0;
    let deferred1_1;
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.secretkey_toString(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      deferred1_0 = r0;
      deferred1_1 = r1;
      return getStringFromWasm0(r0, r1);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
}
module.exports.SecretKey = SecretKey;
/**
 */
class SecretKeyFactory {
  private __wbg_ptr: any;
  static __wrap(ptr: any) {
    ptr = ptr >>> 0;
    const obj = Object.create(SecretKeyFactory.prototype);
    obj.__wbg_ptr = ptr;

    return obj;
  }

  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;

    return ptr;
  }

  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_secretkeyfactory_free(ptr);
  }
  /**
   * Generates a secret key factory using the default RNG and returns it.
   * @returns {SecretKeyFactory}
   */
  static random() {
    const ret = wasm.secretkeyfactory_random();
    return SecretKeyFactory.__wrap(ret);
  }
  /**
   * @returns {number}
   */
  static seedSize() {
    const ret = wasm.secretkeyfactory_seedSize();
    return ret >>> 0;
  }
  /**
   * @param {Uint8Array} seed
   * @returns {SecretKeyFactory}
   */
  static fromSecureRandomness(seed: any) {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
      const len0 = WASM_VECTOR_LEN;
      wasm.secretkeyfactory_fromSecureRandomness(retptr, ptr0, len0);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var r2 = getInt32Memory0()[retptr / 4 + 2];
      if (r2) {
        throw takeObject(r1);
      }
      return SecretKeyFactory.__wrap(r0);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @param {Uint8Array} label
   * @returns {SecretKey}
   */
  makeKey(label: any) {
    const ptr0 = passArray8ToWasm0(label, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.secretkeyfactory_makeKey(this.__wbg_ptr, ptr0, len0);
    return SecretKey.__wrap(ret);
  }
  /**
   * @param {Uint8Array} label
   * @returns {SecretKeyFactory}
   */
  makeFactory(label: any) {
    const ptr0 = passArray8ToWasm0(label, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.secretkeyfactory_makeFactory(this.__wbg_ptr, ptr0, len0);
    return SecretKeyFactory.__wrap(ret);
  }
  /**
   * @returns {Uint8Array}
   */
  toSecretBytes() {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.secretkeyfactory_toSecretBytes(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var v1 = getArrayU8FromWasm0(r0, r1).slice();
      wasm.__wbindgen_free(r0, r1 * 1, 1);
      return v1;
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @param {Uint8Array} data
   * @returns {SecretKeyFactory}
   */
  static fromBytes(data: any) {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
      const len0 = WASM_VECTOR_LEN;
      wasm.secretkeyfactory_fromBytes(retptr, ptr0, len0);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var r2 = getInt32Memory0()[retptr / 4 + 2];
      if (r2) {
        throw takeObject(r1);
      }
      return SecretKeyFactory.__wrap(r0);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @returns {string}
   */
  toString() {
    let deferred1_0;
    let deferred1_1;
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.secretkeyfactory_toString(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      deferred1_0 = r0;
      deferred1_1 = r1;
      return getStringFromWasm0(r0, r1);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
}
module.exports.SecretKeyFactory = SecretKeyFactory;
/**
 */
class Signature {
  private __wbg_ptr: any;
  static __wrap(ptr: any) {
    ptr = ptr >>> 0;
    const obj = Object.create(Signature.prototype);
    obj.__wbg_ptr = ptr;

    return obj;
  }

  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;

    return ptr;
  }

  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_signature_free(ptr);
  }
  /**
   * @param {PublicKey} verifying_pk
   * @param {Uint8Array} message
   * @returns {boolean}
   */
  verify(verifying_pk: any, message: any) {
    _assertClass(verifying_pk, PublicKey);
    const ptr0 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.signature_verify(
      this.__wbg_ptr,
      verifying_pk.__wbg_ptr,
      ptr0,
      len0,
    );
    return ret !== 0;
  }
  /**
   * @returns {Uint8Array}
   */
  toBytes() {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.signature_toBytes(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var v1 = getArrayU8FromWasm0(r0, r1).slice();
      wasm.__wbindgen_free(r0, r1 * 1, 1);
      return v1;
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @param {Uint8Array} data
   * @returns {Signature}
   */
  static fromBytes(data: any) {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
      const len0 = WASM_VECTOR_LEN;
      wasm.signature_fromBytes(retptr, ptr0, len0);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var r2 = getInt32Memory0()[retptr / 4 + 2];
      if (r2) {
        throw takeObject(r1);
      }
      return Signature.__wrap(r0);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @returns {string}
   */
  toString() {
    let deferred1_0;
    let deferred1_1;
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.signature_toString(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      deferred1_0 = r0;
      deferred1_1 = r1;
      return getStringFromWasm0(r0, r1);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * @param {Signature} other
   * @returns {boolean}
   */
  equals(other: any) {
    _assertClass(other, Signature);
    const ret = wasm.signature_equals(this.__wbg_ptr, other.__wbg_ptr);
    return ret !== 0;
  }
}
module.exports.Signature = Signature;
/**
 */
class Signer {
  private __wbg_ptr: any;
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;

    return ptr;
  }

  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_signer_free(ptr);
  }
  /**
   * @param {SecretKey} secret_key
   */
  constructor(secret_key: any) {
    _assertClass(secret_key, SecretKey);
    const ret = wasm.signer_new(secret_key.__wbg_ptr);
    this.__wbg_ptr = ret >>> 0;
    return this;
  }
  /**
   * @param {Uint8Array} message
   * @returns {Signature}
   */
  sign(message: any) {
    const ptr0 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.signer_sign(this.__wbg_ptr, ptr0, len0);
    return Signature.__wrap(ret);
  }
  /**
   * @returns {PublicKey}
   */
  verifyingKey() {
    const ret = wasm.signer_verifyingKey(this.__wbg_ptr);
    return PublicKey.__wrap(ret);
  }
  /**
   * @returns {string}
   */
  toString() {
    let deferred1_0;
    let deferred1_1;
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.signer_toString(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      deferred1_0 = r0;
      deferred1_1 = r1;
      return getStringFromWasm0(r0, r1);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
}
module.exports.Signer = Signer;
/**
 */
class VerifiedCapsuleFrag {
  private __wbg_ptr: any;
  static __wrap(ptr: any) {
    ptr = ptr >>> 0;
    const obj = Object.create(VerifiedCapsuleFrag.prototype);
    obj.__wbg_ptr = ptr;

    return obj;
  }

  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;

    return ptr;
  }

  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_verifiedcapsulefrag_free(ptr);
  }
  /**
   * @param {Uint8Array} bytes
   * @returns {VerifiedCapsuleFrag}
   */
  static fromVerifiedBytes(bytes: any) {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
      const len0 = WASM_VECTOR_LEN;
      wasm.verifiedcapsulefrag_fromVerifiedBytes(retptr, ptr0, len0);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var r2 = getInt32Memory0()[retptr / 4 + 2];
      if (r2) {
        throw takeObject(r1);
      }
      return VerifiedCapsuleFrag.__wrap(r0);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @returns {Uint8Array}
   */
  toBytes() {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.capsulefrag_toBytes(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var v1 = getArrayU8FromWasm0(r0, r1).slice();
      wasm.__wbindgen_free(r0, r1 * 1, 1);
      return v1;
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @returns {string}
   */
  toString() {
    let deferred1_0;
    let deferred1_1;
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.verifiedcapsulefrag_toString(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      deferred1_0 = r0;
      deferred1_1 = r1;
      return getStringFromWasm0(r0, r1);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * @param {VerifiedCapsuleFrag} other
   * @returns {boolean}
   */
  equals(other: any) {
    _assertClass(other, VerifiedCapsuleFrag);
    const ret = wasm.capsulefrag_equals(this.__wbg_ptr, other.__wbg_ptr);
    return ret !== 0;
  }
}
module.exports.VerifiedCapsuleFrag = VerifiedCapsuleFrag;
/**
 */
class VerifiedKeyFrag {
  private __wbg_ptr: any;
  static __wrap(ptr: any) {
    ptr = ptr >>> 0;
    const obj = Object.create(VerifiedKeyFrag.prototype);
    obj.__wbg_ptr = ptr;

    return obj;
  }

  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;

    return ptr;
  }

  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_verifiedkeyfrag_free(ptr);
  }
  /**
   * @param {Uint8Array} bytes
   * @returns {VerifiedKeyFrag}
   */
  static fromVerifiedBytes(bytes: any) {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
      const len0 = WASM_VECTOR_LEN;
      wasm.verifiedkeyfrag_fromVerifiedBytes(retptr, ptr0, len0);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var r2 = getInt32Memory0()[retptr / 4 + 2];
      if (r2) {
        throw takeObject(r1);
      }
      return VerifiedKeyFrag.__wrap(r0);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @returns {Uint8Array}
   */
  toBytes() {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.verifiedkeyfrag_toBytes(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var v1 = getArrayU8FromWasm0(r0, r1).slice();
      wasm.__wbindgen_free(r0, r1 * 1, 1);
      return v1;
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @returns {string}
   */
  toString() {
    let deferred1_0;
    let deferred1_1;
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.verifiedkeyfrag_toString(retptr, this.__wbg_ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      deferred1_0 = r0;
      deferred1_1 = r1;
      return getStringFromWasm0(r0, r1);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
      wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
  }
  /**
   * @param {VerifiedKeyFrag} other
   * @returns {boolean}
   */
  equals(other: any) {
    _assertClass(other, VerifiedKeyFrag);
    const ret = wasm.keyfrag_equals(this.__wbg_ptr, other.__wbg_ptr);
    return ret !== 0;
  }
}
module.exports.VerifiedKeyFrag = VerifiedKeyFrag;

module.exports.__wbindgen_object_drop_ref = function (arg0: any) {
  takeObject(arg0);
};

module.exports.__wbg_verifiedkeyfrag_new = function (arg0: any) {
  const ret = VerifiedKeyFrag.__wrap(arg0);
  return addHeapObject(ret);
};

module.exports.__wbg_getRandomValues_37fa2ca9e4e07fab = function () {
  return handleError(function (arg0: any, arg1: any) {
    getObject(arg0).getRandomValues(getObject(arg1));
  }, arguments);
};

module.exports.__wbg_randomFillSync_dc1e9a60c158336d = function () {
  return handleError(function (arg0: any, arg1: any) {
    getObject(arg0).randomFillSync(takeObject(arg1));
  }, arguments);
};

module.exports.__wbg_crypto_c48a774b022d20ac = function (arg0: any) {
  const ret = getObject(arg0).crypto;
  return addHeapObject(ret);
};

module.exports.__wbindgen_is_object = function (arg0: any) {
  const val = getObject(arg0);
  const ret = typeof val === 'object' && val !== null;
  return ret;
};

module.exports.__wbg_process_298734cf255a885d = function (arg0: any) {
  const ret = getObject(arg0).process;
  return addHeapObject(ret);
};

module.exports.__wbg_versions_e2e78e134e3e5d01 = function (arg0: any) {
  const ret = getObject(arg0).versions;
  return addHeapObject(ret);
};

module.exports.__wbg_node_1cd7a5d853dbea79 = function (arg0: any) {
  const ret = getObject(arg0).node;
  return addHeapObject(ret);
};

module.exports.__wbindgen_is_string = function (arg0: any) {
  const ret = typeof getObject(arg0) === 'string';
  return ret;
};

module.exports.__wbg_msCrypto_bcb970640f50a1e8 = function (arg0: any) {
  const ret = getObject(arg0).msCrypto;
  return addHeapObject(ret);
};

module.exports.__wbg_require_8f08ceecec0f4fee = function () {
  return handleError(function () {
    const ret = module.require;
    return addHeapObject(ret);
  }, arguments);
};

module.exports.__wbindgen_is_function = function (arg0: any) {
  const ret = typeof getObject(arg0) === 'function';
  return ret;
};

module.exports.__wbindgen_string_new = function (arg0: any, arg1: any) {
  const ret = getStringFromWasm0(arg0, arg1);
  return addHeapObject(ret);
};

module.exports.__wbg_newnoargs_ccdcae30fd002262 = function (
  arg0: any,
  arg1: any,
) {
  const ret = new Function(getStringFromWasm0(arg0, arg1));
  return addHeapObject(ret);
};

module.exports.__wbg_call_669127b9d730c650 = function () {
  return handleError(function (arg0: any, arg1: any) {
    const ret = getObject(arg0).call(getObject(arg1));
    return addHeapObject(ret);
  }, arguments);
};

module.exports.__wbindgen_object_clone_ref = function (arg0: any) {
  const ret = getObject(arg0);
  return addHeapObject(ret);
};

module.exports.__wbg_self_3fad056edded10bd = function () {
  return handleError(function () {
    const ret = self.self;
    return addHeapObject(ret);
  }, arguments);
};

module.exports.__wbg_window_a4f46c98a61d4089 = function () {
  return handleError(function () {
    const ret = window.window;
    return addHeapObject(ret);
  }, arguments);
};

module.exports.__wbg_globalThis_17eff828815f7d84 = function () {
  return handleError(function () {
    const ret = globalThis.globalThis;
    return addHeapObject(ret);
  }, arguments);
};

module.exports.__wbg_global_46f939f6541643c5 = function () {
  return handleError(function () {
    const ret = global.global;
    return addHeapObject(ret);
  }, arguments);
};

module.exports.__wbindgen_is_undefined = function (arg0: any) {
  const ret = getObject(arg0) === undefined;
  return ret;
};

module.exports.__wbg_new_ab87fd305ed9004b = function (arg0: any, arg1: any) {
  const ret = new Error(getStringFromWasm0(arg0, arg1));
  return addHeapObject(ret);
};

module.exports.__wbg_call_53fc3abd42e24ec8 = function () {
  return handleError(function (arg0: any, arg1: any, arg2: any) {
    const ret = getObject(arg0).call(getObject(arg1), getObject(arg2));
    return addHeapObject(ret);
  }, arguments);
};

module.exports.__wbg_buffer_344d9b41efe96da7 = function (arg0: any) {
  const ret = getObject(arg0).buffer;
  return addHeapObject(ret);
};

module.exports.__wbg_newwithbyteoffsetandlength_2dc04d99088b15e3 = function (
  arg0: any,
  arg1: any,
  arg2: any,
) {
  const ret = new Uint8Array(getObject(arg0), arg1 >>> 0, arg2 >>> 0);
  return addHeapObject(ret);
};

module.exports.__wbg_new_d8a000788389a31e = function (arg0: any) {
  const ret = new Uint8Array(getObject(arg0));
  return addHeapObject(ret);
};

module.exports.__wbg_set_dcfd613a3420f908 = function (
  arg0: any,
  arg1: any,
  arg2: any,
) {
  getObject(arg0).set(getObject(arg1), arg2 >>> 0);
};

module.exports.__wbg_newwithlength_13b5319ab422dcf6 = function (arg0: any) {
  const ret = new Uint8Array(arg0 >>> 0);
  return addHeapObject(ret);
};

module.exports.__wbg_subarray_6ca5cfa7fbb9abbe = function (
  arg0: any,
  arg1: any,
  arg2: any,
) {
  const ret = getObject(arg0).subarray(arg1 >>> 0, arg2 >>> 0);
  return addHeapObject(ret);
};

module.exports.__wbindgen_throw = function (arg0: any, arg1: any) {
  throw new Error(getStringFromWasm0(arg0, arg1));
};

module.exports.__wbindgen_memory = function () {
  const ret = wasm.memory;
  return addHeapObject(ret);
};

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
      // const wasmModule = new WebAssembly.Module(buffer);
      // const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
      // const wasm: any = wasmInstance.exports;
      // console.log(wasm, '****************', wasm.secretkey_random());
      // **********************************************************
      // const path = require('path').join(
      //   __dirname,
      //   'nucypher_core_wasm_bg.wasm',
      // );
      // const buffer = require('fs').readFileSync(path);
      const wasmModule = new WebAssembly.Module(buffer);
      const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
      wasm = wasmInstance.exports;

      // const secretKey = wasm.secretkey_fromBytes.fromBytes(
      //   Buffer.from(
      //     '0x2ed04b34a0001676360813ee958cde47b233cfc13a2c62f4157964701e06836e'.substring(
      //       2,
      //       66,
      //     ),
      //     'hex',
      //   ),
      // );

      // console.log(secretKey, '================');

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

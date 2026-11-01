/**
 * favicon 指纹哈希工具(fofa / shodan 风格 icon_hash)。
 *
 * MurmurHash3 x86 32-bit 实现已对公开测试向量逐一校验(见 test/faviconHash.test.js:
 * ("",1)=0x514e28b7、("",0xffffffff)=0x81f16f39、("test")=0xba6bd213 等),可信。
 *
 * 注:本文件只负责"字节/ base64 → 哈希"的纯计算。抓取 favicon、接入指纹结果与 UI
 * 展示需在真实扩展里验证,属后续集成步骤(见 roadmap 记忆 ⑥)。
 */

function mul32(a, b) { return Math.imul(a, b) >>> 0; }
function rotl32(x, r) { return ((x << r) | (x >>> (32 - r))) >>> 0; }

/**
 * MurmurHash3 x86 32-bit。
 * @param {string|Uint8Array} input - 字符串(按 UTF-8 取字节)或字节数组
 * @param {number} [seed=0]
 * @returns {number} 无符号 32 位哈希
 */
export function mmh3_x86_32(input, seed = 0) {
  const data = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  const len = data.length;
  let h1 = seed >>> 0;
  const c1 = 0xcc9e2d51, c2 = 0x1b873593;
  const nblocks = len >> 2;

  for (let i = 0; i < nblocks; i++) {
    const o = i * 4;
    let k1 = (data[o] | (data[o + 1] << 8) | (data[o + 2] << 16) | (data[o + 3] << 24)) >>> 0;
    k1 = mul32(k1, c1);
    k1 = rotl32(k1, 15);
    k1 = mul32(k1, c2);
    h1 ^= k1;
    h1 = rotl32(h1, 13);
    h1 = (mul32(h1, 5) + 0xe6546b64) >>> 0;
  }

  let k1 = 0;
  const tail = nblocks * 4;
  switch (len & 3) {
    case 3: k1 ^= data[tail + 2] << 16; // falls through
    case 2: k1 ^= data[tail + 1] << 8;  // falls through
    case 1:
      k1 ^= data[tail];
      k1 = mul32(k1 >>> 0, c1);
      k1 = rotl32(k1, 15);
      k1 = mul32(k1, c2);
      h1 ^= k1;
  }

  h1 ^= len;
  h1 ^= h1 >>> 16;
  h1 = mul32(h1, 0x85ebca6b);
  h1 ^= h1 >>> 13;
  h1 = mul32(h1, 0xc2b2ae35);
  h1 ^= h1 >>> 16;
  return h1 >>> 0;
}

/**
 * 把 base64 串按 Python base64.encodebytes 的方式折行:每 76 字符一行、
 * 每行(含末行)后跟 \n。fofa 的 favicon 哈希就是对这种折行文本取 mmh3。
 * @param {string} b64 - 无换行的 base64 串
 * @returns {string}
 */
export function base64EncodeBytesFormat(b64) {
  const lines = b64.match(/.{1,76}/g) || [];
  return lines.join('\n') + '\n';
}

/**
 * fofa / shodan 风格 favicon 哈希:对 base64(favicon) 折行后取 mmh3,输出有符号
 * 32 位(与 fofa `icon_hash=` 查询值对齐)。
 * @param {string} faviconBase64 - favicon 字节的 base64(无换行)
 * @returns {number} 有符号 32 位哈希
 */
export function fofaFaviconHash(faviconBase64) {
  const formatted = base64EncodeBytesFormat(faviconBase64);
  const h = mmh3_x86_32(formatted, 0);
  return h > 0x7fffffff ? h - 0x100000000 : h;
}

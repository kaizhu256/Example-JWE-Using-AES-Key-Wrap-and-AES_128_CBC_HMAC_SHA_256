/* jslint utility2:true */
/* istanbul ignore next */
// run shared js-env code - init-local
(function () {
    "use strict";
    let consoleError;
    let local;
    // init debugInline
    if (!globalThis.debugInline) {
        consoleError = console.error;
        globalThis.debugInline = function (...argList) {
        /*
         * this function will both print <argList> to stderr
         * and return <argList>[0]
         */
            consoleError("\n\ndebugInline");
            consoleError(...argList);
            consoleError("\n");
            return argList[0];
        };
    }
    // init local
    local = {};
    local.local = local;
    globalThis.globalLocal = local;
    // init isBrowser
    local.isBrowser = (
        typeof globalThis.XMLHttpRequest === "function"
        && globalThis.navigator
        && typeof globalThis.navigator.userAgent === "string"
    );
    // init isWebWorker
    local.isWebWorker = (
        local.isBrowser && typeof globalThis.importScripts === "function"
    );
    // init function
    local.assertJsonEqual = function (aa, bb) {
    /*
     * this function will assert JSON.stringify(<aa>) === JSON.stringify(<bb>)
     */
        let objectDeepCopyWithKeysSorted;
        objectDeepCopyWithKeysSorted = function (obj) {
        /*
         * this function will recursively deep-copy <obj> with keys sorted
         */
            let sorted;
            if (typeof obj !== "object" || !obj) {
                return obj;
            }
            // recursively deep-copy list with child-keys sorted
            if (Array.isArray(obj)) {
                return obj.map(objectDeepCopyWithKeysSorted);
            }
            // recursively deep-copy obj with keys sorted
            sorted = {};
            Object.keys(obj).sort().forEach(function (key) {
                sorted[key] = objectDeepCopyWithKeysSorted(obj[key]);
            });
            return sorted;
        };
        aa = JSON.stringify(objectDeepCopyWithKeysSorted(aa));
        bb = JSON.stringify(objectDeepCopyWithKeysSorted(bb));
        if (aa !== bb) {
            throw new Error(JSON.stringify(aa) + " !== " + JSON.stringify(bb));
        }
    };
    local.assertOrThrow = function (passed, msg) {
    /*
     * this function will throw <msg> if <passed> is falsy
     */
        if (passed) {
            return;
        }
        throw (
            (
                msg
                && typeof msg.message === "string"
                && typeof msg.stack === "string"
            )
            // if msg is err, then leave as is
            ? msg
            : new Error(
                typeof msg === "string"
                // if msg is string, then leave as is
                ? msg
                // else JSON.stringify(msg)
                : JSON.stringify(msg, undefined, 4)
            )
        );
    };
    local.coalesce = function (...argList) {
    /*
     * this function will coalesce null, undefined, or "" in <argList>
     */
        let arg;
        let ii;
        ii = 0;
        while (ii < argList.length) {
            arg = argList[ii];
            if (arg !== undefined && arg !== null && arg !== "") {
                return arg;
            }
            ii += 1;
        }
        return arg;
    };
    local.identity = function (val) {
    /*
     * this function will return <val>
     */
        return val;
    };
    local.nop = function () {
    /*
     * this function will do nothing
     */
        return;
    };
    local.objectAssignDefault = function (tgt = {}, src = {}, depth = 0) {
    /*
     * this function will if items from <tgt> are null, undefined, or "",
     * then overwrite them with items from <src>
     */
        let recurse;
        recurse = function (tgt, src, depth) {
            Object.entries(src).forEach(function ([
                key, bb
            ]) {
                let aa;
                aa = tgt[key];
                if (aa === undefined || aa === null || aa === "") {
                    tgt[key] = bb;
                    return;
                }
                if (
                    depth !== 0
                    && typeof aa === "object" && aa && !Array.isArray(aa)
                    && typeof bb === "object" && bb && !Array.isArray(bb)
                ) {
                    recurse(aa, bb, depth - 1);
                }
            });
        };
        recurse(tgt, src, depth | 0);
        return tgt;
    };
    local.onErrorThrow = function (err) {
    /*
     * this function will throw <err> if exists
     */
        if (err) {
            throw err;
        }
    };
    // bug-workaround - throw unhandledRejections in node-process
    if (
        typeof process === "object" && process
        && typeof process.on === "function"
        && process.unhandledRejections !== "strict"
    ) {
        process.unhandledRejections = "strict";
        process.on("unhandledRejection", function (err) {
            throw err;
        });
    }
}());


// run shared js-env code - function
(async function () {
    "use strict";
    let assertEqual;
    let assertOrThrow;
    let bufferFromBase64url;
    let bufferFromHex;
    let bufferRandom;
    let bufferToBase64url;
    let bufferToHex;
    let crypto;
    let isBrowser;
    let jweDecrypt;
    let jweEncrypt;
    let jweKeyUnwrap;
    let jweKeyWrap;
    let jweValidateHeader;
    let testCase_jweEncrypt_default;
    let testCase_jweKeyWrap_default;
    crypto = globalThis.crypto;
    if (
        crypto && crypto.subtle
        && typeof crypto.subtle.wrapKey === "function"
    ) {
        isBrowser = true;
    } else {
        crypto = require("crypto");
    }
    assertEqual = function (aa, bb) {
    /*
     * this function will assert <aa> === <bb>
     */
        if (aa !== bb) {
            throw new Error(JSON.stringify(aa) + " !== " + JSON.stringify(bb));
        }
    };
    assertOrThrow = function (passed, msg) {
    /*
     * this function will throw <msg> if <passed> is falsy
     */
        if (!passed) {
            throw new Error(msg);
        }
    };
    bufferFromBase64url = function (str) {
    /*
     * this function will base64url-decode <str> to buf
     */
        // convert base64url to base64
        str = str.replace((
            /-/g
        ), "+").replace((
            /_/g
        ), "/").replace((
            /\=*?$/
        ), "");
        // env - browser
        if (typeof globalThis.atob === "function") {
            return Uint8Array.from(globalThis.atob(str), function (chr) {
                return chr.charCodeAt(0);
            });
        }
        // env - node
        return Buffer.from(str, "base64");
    };
    bufferToBase64url = function (buf) {
    /*
     * this function will base64url-encode <buf> to str
     */
        let ii;
        let str;
        // env - browser
        if (typeof globalThis.btoa === "function") {
            str = "";
            ii = 0;
            while (ii < buf.byteLength) {
                str += String.fromCharCode(buf[ii]);
                ii += 1;
            }
            str = globalThis.btoa(str);
        // env - node
        } else {
            str = Buffer.from(buf).toString("base64");
        }
        // convert base64 to base64url
        return str.replace((
            /\+/g
        ), "-").replace((
            /\//g
        ), "_").replace((
            /\=*?$/
        ), "");
    };
    bufferFromHex = function (str) {
    /*
     * this function will hex-decode <str> to buf
     */
        let buf;
        let ii;
        buf = new Uint8Array(str.length >> 1);
        ii = 0;
        while (ii < str.length) {
            buf[ii >> 1] = Number("0x" + str.slice(ii, ii + 2));
            ii += 2;
        }
        return buf;
    };
    bufferToHex = function (buf) {
    /*
     * this function will hex-encode <buf> to str
     */
        let ii;
        let str;
        str = "";
        ii = 0;
        while (ii < buf.byteLength) {
            str += buf[ii].toString(16).padStart(2, "0");
            ii += 1;
        }
        return str;
    };
    bufferRandom = function (nn, mode) {
    /*
     * this function will generate cryptographically-secure-random buf
     * with byteLength <nn>
     */
        nn = (
            (
                globalThis.crypto
                && typeof globalThis.crypto.getRandomValues === "function"
            )
            ? globalThis.crypto.getRandomValues(new Uint8Array(nn))
            : require("crypto").randomBytes(nn)
        );
        return (
            mode === "base64url"
            ? bufferToBase64url(nn)
            : nn
        );
    };
    jweDecrypt = function (kek, jwe) {
    /*
     * this function will A256KW+A256GCM-decrypt <jwe> with given <kek>
     * to plaintext
     */
        let cek;
        let cipher;
        let ciphertext;
        let header;
        let iv;
        let tag;
        let tmp;
        // validate jwe
        assertOrThrow((
            /^[\w\-]+?\.[\w\-]+?\.[\w\-]+?\.[\w\-]*?\.[\w\-]+?$/
        ).test(jwe), "jwe validation failed");
        // init var
        [
            header, cek, iv, ciphertext, tag
        ] = jwe.split(".").map(bufferFromBase64url);
        kek = bufferFromBase64url(kek);
        // validate header
        jweValidateHeader(JSON.parse(new TextDecoder().decode(
            header
        )), kek, cek, 8, iv);
        // init aad
        header = new TextEncoder().encode(bufferToBase64url(header));
        // env - node
        if (!isBrowser) {
            // key-unwrap cek
            cek = jweKeyUnwrap(kek, cek);
            // decrypt ciphertext
            cipher = crypto.createDecipheriv((
                cek.byteLength === 16
                ? "aes-128-gcm"
                : cek.byteLength === 24
                ? "aes-192-gcm"
                : "aes-256-gcm"
            ), cek, iv);
            cipher.setAuthTag(tag);
            cipher.setAAD(header);
            tmp = [
                cipher.update(Buffer.from(ciphertext))
            ];
            tmp.push(cipher.final());
            tmp = Buffer.concat(tmp).toString();
            return Promise.resolve().then(function () {
                return tmp;
            });
        }
        // env - browser
        // key-unwrap cek
        return crypto.subtle.importKey("raw", kek, "AES-KW", false, [
            "unwrapKey"
        ]).then(function (data) {
            kek = data;
            return crypto.subtle.unwrapKey("raw", cek, kek, {
                name: "AES-KW"
            }, "AES-GCM", false, [
                "decrypt"
            ]);
        // decrypt ciphertext
        }).then(function (data) {
            cek = data;
            tmp = ciphertext;
            ciphertext = new Uint8Array(tmp.length + 16);
            ciphertext.set(tmp);
            ciphertext.set(tag, tmp.length);
            return crypto.subtle.decrypt({
                additionalData: header,
                iv,
                name: "AES-GCM"
            }, cek, ciphertext);
        }).then(function (data) {
            return new TextDecoder().decode(data);
        });
    };
    jweEncrypt = function (kek, plaintext, header, cek, iv) {
    /*
     * this function will A256KW+A256GCM-encrypt <plaintext> with given <kek>
     * to jwe
     */
        let cipher;
        let ciphertext;
        let tag;
        // init var
        header = header || {
            alg: "A256KW",
            enc: "A256GCM"
        };
        cek = bufferFromBase64url(cek || bufferToBase64url(bufferRandom(
            header.enc === "A128GCM"
            ? 16
            : header.enc === "A192GCM"
            ? 24
            : 32
        )));
        iv = (
            iv
            ? bufferFromBase64url(iv)
            : header.enc === "A128CBC-HS256"
            ? bufferRandom(16)
            : bufferRandom(12)
        );
        kek = bufferFromBase64url(kek);
        plaintext = new TextEncoder().encode(plaintext);
        // validate header
        jweValidateHeader(header, kek, cek, 0, iv);
        // init aad
        header = new TextEncoder().encode(bufferToBase64url(
            new TextEncoder().encode(JSON.stringify(header))
        ));
        // env - node
        if (!isBrowser) {
            // encrypt plaintext
            cipher = crypto.createCipheriv((
                cek.byteLength === 16
                ? "aes-128-gcm"
                : cek.byteLength === 24
                ? "aes-192-gcm"
                : "aes-256-gcm"
            ), cek, iv);
            cipher.setAAD(header);
            ciphertext = [
                cipher.update(plaintext)
            ];
            ciphertext.push(cipher.final());
            ciphertext = Buffer.concat(ciphertext);
            // key-wrap cek
            cek = jweKeyWrap(kek, cek);
            tag = cipher.getAuthTag();
            // return compact-form-jwe
            return Promise.resolve().then(function () {
                return (
                    new TextDecoder().decode(header)
                    + "." + bufferToBase64url(cek)
                    + "." + bufferToBase64url(iv)
                    + "." + bufferToBase64url(ciphertext)
                    + "." + bufferToBase64url(tag)
                );
            });
        }
        // env - browser
        // encrypt plaintext
        return crypto.subtle.importKey("raw", cek, {
            name: "AES-GCM"
        }, true, [
            "encrypt"
        ]).then(function (data) {
            cek = data;
            return crypto.subtle.encrypt({
                additionalData: header,
                iv,
                name: "AES-GCM"
            }, cek, plaintext);
        }).then(function (data) {
            ciphertext = new Uint8Array(data);
            tag = ciphertext.subarray(-16);
            ciphertext = ciphertext.subarray(0, -16);
            return crypto.subtle.importKey("raw", kek, "AES-KW", false, [
                "wrapKey"
            ]);
        // key-wrap cek
        }).then(function (data) {
            kek = data;
            return crypto.subtle.wrapKey("raw", cek, kek, "AES-KW");
        // return compact-form-jwe
        }).then(function (data) {
            cek = new Uint8Array(data);
            return (
                new TextDecoder().decode(header)
                + "." + bufferToBase64url(cek)
                + "." + bufferToBase64url(iv)
                + "." + bufferToBase64url(ciphertext)
                + "." + bufferToBase64url(tag)
            );
        });
    };
    jweKeyUnwrap = function (kek, cek) {
    /*
     * this function will A256KW-key-unwrap <cek> with given <kek>
     * https://tools.ietf.org/html/rfc3394#section-2.2.2
     */
        let aa;
        let bb;
        let ii;
        let iv;
        let jj;
        let nn;
        let rr;
        let tt;
        // 2.2.2 Key Unwrap
        // Inputs: Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}, and
        // Key, K (the KEK).
        // Outputs: Plaintext, n 64-bit values {P0, P1, K, Pn}.
        // 1) Initialize variables.
        // Set A = C[0]
        // For i = 1 to n
        // R[i] = C[i]
        nn = (cek.byteLength >> 3) - 1;
        aa = Buffer.from(cek.slice(0, 16));
        iv = Buffer.alloc(16);
        rr = Buffer.from(cek.slice(8));
        // 2) Compute intermediate values.
        // For j = 5 to 0
        // For i = n to 1
        // B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
        // A = MSB(64, B)
        // R[i] = LSB(64, B)
        jj = 5;
        while (jj >= 0) {
            ii = nn - 1;
            while (ii >= 0) {
                tt = jj * nn + ii + 1;
                aa[4] ^= (tt >>> 24) & 0xff;
                aa[5] ^= (tt >> 16) & 0xff;
                aa[6] ^= (tt >> 8) & 0xff;
                aa[7] ^= tt & 0xff;
                aa[8] = rr[ii * 8];
                aa[9] = rr[ii * 8 + 1];
                aa[10] = rr[ii * 8 + 2];
                aa[11] = rr[ii * 8 + 3];
                aa[12] = rr[ii * 8 + 4];
                aa[13] = rr[ii * 8 + 5];
                aa[14] = rr[ii * 8 + 6];
                aa[15] = rr[ii * 8 + 7];
                bb = crypto.createDecipheriv((
                    kek.byteLength === 16
                    ? "aes-128-cbc"
                    : kek.byteLength === 24
                    ? "aes-192-cbc"
                    : "aes-256-cbc"
                ), kek, iv);
                bb.setAutoPadding(false);
                aa.set(bb.update(aa));
                bb = bb.final();
                aa.set(bb, 8 - bb.byteLength);
                rr[ii * 8 + 0] = aa[8];
                rr[ii * 8 + 1] = aa[9];
                rr[ii * 8 + 2] = aa[10];
                rr[ii * 8 + 3] = aa[11];
                rr[ii * 8 + 4] = aa[12];
                rr[ii * 8 + 5] = aa[13];
                rr[ii * 8 + 6] = aa[14];
                rr[ii * 8 + 7] = aa[15];
                ii -= 1;
            }
            jj -= 1;
        }
        // 3) Output results.
        // For i = 1 to n
        // P[i] = R[i]
        assertOrThrow(aa[0] === 0xa6, "key-unwrap failed");
        assertOrThrow(aa[1] === 0xa6, "key-unwrap failed");
        assertOrThrow(aa[2] === 0xa6, "key-unwrap failed");
        assertOrThrow(aa[3] === 0xa6, "key-unwrap failed");
        assertOrThrow(aa[4] === 0xa6, "key-unwrap failed");
        assertOrThrow(aa[5] === 0xa6, "key-unwrap failed");
        assertOrThrow(aa[6] === 0xa6, "key-unwrap failed");
        assertOrThrow(aa[7] === 0xa6, "key-unwrap failed");
        return rr;
    };
    jweKeyWrap = function (kek, cek) {
    /*
     * this function will A256KW-key-wrap <cek> with given <kek>
     * https://tools.ietf.org/html/rfc3394#section-2.2.1
     */
        let aa;
        let bb;
        let ii;
        let iv;
        let jj;
        let nn;
        let rr;
        let tt;
        // 2.2.1 Key Wrap
        // Inputs: Plaintext, n 64-bit values {P1, P2, ..., Pn}, and
        // Key, K (the KEK).
        // Outputs: Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}.
        // 1) Initialize variables.
        // Set A = IV, an initial value (see 2.2.3)
        // For i = 1 to n
        // R[i] = P[i]
        nn = cek.byteLength >> 3;
        aa = Buffer.alloc(16, 0xa6);
        iv = Buffer.alloc(16);
        rr = Buffer.concat([
            Buffer.alloc(8), cek
        ]);
        // 2) Calculate intermediate values.
        // For j = 0 to 5
        // For i = 1 to n
        // B = AES(K, A | R[i])
        // A = MSB(64, B) ^ t where t = (n*j)+i
        // R[i] = LSB(64, B)
        jj = 0;
        while (jj < 6) {
            ii = 1;
            while (ii <= nn) {
                tt = jj * nn + ii;
                aa[8] = rr[ii * 8];
                aa[9] = rr[ii * 8 + 1];
                aa[10] = rr[ii * 8 + 2];
                aa[11] = rr[ii * 8 + 3];
                aa[12] = rr[ii * 8 + 4];
                aa[13] = rr[ii * 8 + 5];
                aa[14] = rr[ii * 8 + 6];
                aa[15] = rr[ii * 8 + 7];
                bb = crypto.createCipheriv((
                    kek.byteLength === 16
                    ? "aes-128-cbc"
                    : kek.byteLength === 24
                    ? "aes-192-cbc"
                    : "aes-256-cbc"
                ), kek, iv);
                bb.setAutoPadding(false);
                aa.set(bb.update(aa));
                bb = bb.final();
                aa.set(bb, 8 - bb.byteLength);
                aa[4] ^= (tt >>> 24) & 0xff;
                aa[5] ^= (tt >> 16) & 0xff;
                aa[6] ^= (tt >> 8) & 0xff;
                aa[7] ^= tt & 0xff;
                rr[ii * 8 + 0] = aa[8];
                rr[ii * 8 + 1] = aa[9];
                rr[ii * 8 + 2] = aa[10];
                rr[ii * 8 + 3] = aa[11];
                rr[ii * 8 + 4] = aa[12];
                rr[ii * 8 + 5] = aa[13];
                rr[ii * 8 + 6] = aa[14];
                rr[ii * 8 + 7] = aa[15];
                ii += 1;
            }
            jj += 1;
        }
        // 3) Output the results.
        // Set C[0] = A
        // For i = 1 to n
        // C[i] = R[i]
        rr[0] = aa[0];
        rr[1] = aa[1];
        rr[2] = aa[2];
        rr[3] = aa[3];
        rr[4] = aa[4];
        rr[5] = aa[5];
        rr[6] = aa[6];
        rr[7] = aa[7];
        return rr;
    };
    jweValidateHeader = function (header, kek, cek, cekPadding, iv) {
    /*
     * this function will validate jwe <header>
     */
        let test;
        switch (header.alg + "." + kek.byteLength) {
        case "A128KW.16":
        case "A192KW.24":
        case "A256KW.32":
            break;
        default:
            assertOrThrow(test, "jwe validation failed");
        }
        switch (header.enc + "." + (cek.byteLength - cekPadding)) {
        case "A128CBC-HS256.32":
            test = iv.byteLength === 16;
            assertOrThrow(test, "jwe validation failed");
            break;
        case "A128GCM.16":
        case "A192GCM.24":
        case "A256GCM.32":
            test = iv.byteLength === 12;
            assertOrThrow(test, "jwe validation failed");
            break;
        default:
            assertOrThrow(test, "jwe validation failed");
        }
    };
    testCase_jweKeyWrap_default = function () {
    /*
     * this function will test jweKeyWrap's default handling-behavior
     */
        let cek;
        let kek;
        let tmp;
        if (isBrowser) {
            return;
        }
        // 4.1 Wrap 128 bits of Key Data with a 128-bit KEK
        cek = bufferFromHex("00112233445566778899aabbccddeeff");
        kek = bufferFromHex("000102030405060708090a0b0c0d0e0f");
        tmp = bufferToHex(jweKeyWrap(kek, cek));
        assertEqual(tmp, "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5");
        cek = bufferToHex(jweKeyUnwrap(kek, bufferFromHex(tmp)));
        assertEqual(cek, "00112233445566778899aabbccddeeff");
        // 4.2 Wrap 128 bits of Key Data with a 192-bit KEK
        cek = bufferFromHex("00112233445566778899aabbccddeeff");
        kek = bufferFromHex("000102030405060708090a0b0c0d0e0f1011121314151617");
        tmp = bufferToHex(jweKeyWrap(kek, cek));
        assertEqual(tmp, "96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d");
        cek = bufferToHex(jweKeyUnwrap(kek, bufferFromHex(tmp)));
        assertEqual(cek, "00112233445566778899aabbccddeeff");
        // 4.3 Wrap 128 bits of Key Data with a 256-bit KEK
        cek = bufferFromHex("00112233445566778899aabbccddeeff");
        kek = bufferFromHex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        tmp = bufferToHex(jweKeyWrap(kek, cek));
        assertEqual(tmp, "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7");
        cek = bufferToHex(jweKeyUnwrap(kek, bufferFromHex(tmp)));
        assertEqual(cek, "00112233445566778899aabbccddeeff");
        // 4.4 Wrap 192 bits of Key Data with a 192-bit KEK
        cek = bufferFromHex("00112233445566778899aabbccddeeff0001020304050607");
        kek = bufferFromHex("000102030405060708090a0b0c0d0e0f1011121314151617");
        tmp = bufferToHex(jweKeyWrap(kek, cek));
        assertEqual(tmp, (
            "031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2"
        ));
        cek = bufferToHex(jweKeyUnwrap(kek, bufferFromHex(tmp)));
        assertEqual(cek, "00112233445566778899aabbccddeeff0001020304050607");
        // 4.5 Wrap 192 bits of Key Data with a 256-bit KEK
        cek = bufferFromHex(
            "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f"
        );
        kek = bufferFromHex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        tmp = bufferToHex(jweKeyWrap(kek, cek));
        assertEqual(tmp, (
            "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326"
            + "cbc7f0e71a99f43bfb988b9b7a02dd21"
        ));
        cek = bufferToHex(jweKeyUnwrap(kek, bufferFromHex(tmp)));
        assertEqual(
            cek,
            "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f"
        );
    };
    testCase_jweKeyWrap_default();
    testCase_jweEncrypt_default = async function () {
        let tmp;
        // https://tools.ietf.org/id/draft-ietf-jose-cookbook-02.html#rfc.section.4.8
        // 4.8. Key Wrap using AES-KeyWrap with AES-GCM
        tmp = await jweEncrypt("GZy6sIZ6wl9NJOKB-jnmVQ", (
            "You can trust us to stick with you through thick and "
            + "thin\u2013to the bitter end. And you can trust us to "
            + "keep any secret of yours\u2013closer than you keep it "
            + "yourself. But you cannot trust us to let you face trouble "
            + "alone, and go off without a word. We are your friends, Frodo."
        ), {
            "alg": "A128KW",
            "kid": "81b20965-8332-43d9-a468-82160ad91ac8",
            "enc": "A128GCM"
        }, "aY5_Ghmk9KxWPBLu_glx1w", "Qx0pmsDa8KnJc9Jo");
        assertEqual(tmp, (
            // protectedHeader - Protected JWE header
            "eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC"
            + "04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0"
            + "."
            // cek - encrypted key
            + "CBI6oDw8MydIx1IBntf_lQcw2MmJKIQx"
            + "."
            // iv - Initialization vector/nonce
            + "Qx0pmsDa8KnJc9Jo"
            + "."
            // ciphertext
            + "AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD6"
            + "1A1hnWGetdg11c9ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfe"
            + "F0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8RE"
            + "wOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-p"
            + "uQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRa"
            + "a8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZF"
            + "."
            // tag - Authentication tag
            + "ER7MWJZ1FBI_NKvn7Zb1Lw"
        ));
        tmp = await jweDecrypt("GZy6sIZ6wl9NJOKB-jnmVQ", tmp);
        assertEqual(tmp, (
            "You can trust us to stick with you through thick and "
            + "thin\u2013to the bitter end. And you can trust us to "
            + "keep any secret of yours\u2013closer than you keep it "
            + "yourself. But you cannot trust us to let you face trouble "
            + "alone, and go off without a word. We are your friends, Frodo."
        ));
        [
            "", (
                "You can trust us to stick with you through thick and "
                + "thin\u2013to the bitter end. And you can trust us to "
                + "keep any secret of yours\u2013closer than you keep it "
                + "yourself. But you cannot trust us to let you face trouble "
                + "alone, and go off without a word. We are your friends, "
                + "Frodo."
            )
        ].forEach(function (plaintext0) {
            [
                128, 192, 256
            ].forEach(function (alg) {
                [
                    128, 192, 256
                ].forEach(async function (enc) {
                    let jwe;
                    let kek;
                    let plaintext;
                    kek = bufferRandom(alg >> 3, "base64url");
                    jwe = await jweEncrypt(kek, plaintext0, {
                        alg: "A" + alg + "KW",
                        enc: "A" + enc + "GCM"
                    });
                    plaintext = await jweDecrypt(kek, jwe);
                    assertEqual(plaintext, plaintext0);
                });
            });
        });
    };
    await testCase_jweEncrypt_default();
}());

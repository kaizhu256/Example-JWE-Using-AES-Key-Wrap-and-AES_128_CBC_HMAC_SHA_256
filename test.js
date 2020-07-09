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
    let base64urlFromBuffer;
    let base64urlToBuffer;
    let crypto;
    let cryptoDecryptBrowser;
    let cryptoEncryptBrowser;
    let cryptoKeyWrapNode;
    let cryptoValidateHeader;
    let hexFromBuffer;
    let hexToBuffer;
    let isBrowser;
    let runMe;
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
    base64urlFromBuffer = function (buf) {
    /*
     * this function will base64url-encode <buf> to str
     */
        let ii;
        let str;
        // browser
        if (typeof globalThis.btoa === "function") {
            str = "";
            ii = 0;
            while (ii < buf.byteLength) {
                str += String.fromCharCode(buf[ii]);
                ii += 1;
            }
            str = globalThis.btoa(str);
        // node
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
    base64urlToBuffer = function (str) {
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
        // browser
        if (typeof globalThis.atob === "function") {
            return Uint8Array.from(globalThis.atob(str), function (chr) {
                return chr.charCodeAt(0);
            });
        }
        // node
        return Buffer.from(str, "base64");
    };
    hexFromBuffer = function (buf) {
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
    hexToBuffer = function (str) {
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
    cryptoDecryptBrowser = async function (kek, jwe) {
        let cek;
        let ciphertext;
        let header;
        let iv;
        let tag;
        let tmp;
        // validate jwe
        assertOrThrow((
            /^[\w\-]+?\.[\w\-]+?\.[\w\-]+?\.[\w\-]*?\.[\w\-]+?$/
        ).test(jwe), "jwe failed validation");
        // init var
        [
            header, cek, iv, ciphertext, tag
        ] = jwe.split(".");
        cek = base64urlToBuffer(cek);
        kek = base64urlToBuffer(kek);
        // validate header
        cryptoValidateHeader(JSON.parse(new TextDecoder().decode(
            base64urlToBuffer(header)
        )), kek, cek, 8);
        kek = await crypto.subtle.importKey("raw", kek, "AES-KW", false, [
            "unwrapKey"
        ]);
        cek = await crypto.subtle.unwrapKey("raw", cek, kek, {
            name: "AES-KW"
        }, "AES-GCM", false, [
            "decrypt"
        ]);
        tmp = base64urlToBuffer(ciphertext);
        ciphertext = new Uint8Array(tmp.length + 16);
        ciphertext.set(tmp);
        ciphertext.set(base64urlToBuffer(tag), tmp.length);
        tmp = new Uint8Array(await crypto.subtle.decrypt({
            additionalData: new TextEncoder().encode(header),
            iv: base64urlToBuffer(iv),
            name: "AES-GCM"
        }, cek, ciphertext));
        return new TextDecoder().decode(tmp);
    };
    cryptoEncryptBrowser = async function (kek, plaintext, header, cek, iv) {
        let tmp;
        header = header || {
            "alg": "A256KW",
            "enc": "A256GCM"
        };
        kek = base64urlToBuffer(kek);
        cek = base64urlToBuffer(cek || base64urlFromBuffer(
            crypto.getRandomValues(new Uint8Array(
                header.enc !== "A256GCM"
                ? 16
                : 32
            ))
        ));
        // validate header
        cryptoValidateHeader(header, kek, cek, 0);
        kek = await crypto.subtle.importKey("raw", kek, "AES-KW", false, [
            "wrapKey"
        ]);
        header = base64urlFromBuffer(
            new TextEncoder().encode(JSON.stringify(header))
        );
        iv = iv || base64urlFromBuffer(
            crypto.getRandomValues(new Uint8Array(12))
        );
        cek = await crypto.subtle.importKey("raw", cek, {
            name: "AES-GCM"
        }, true, [
            "encrypt"
        ]);
        tmp = new Uint8Array(await crypto.subtle.encrypt({
            additionalData: new TextEncoder().encode(header),
            iv: base64urlToBuffer(iv),
            name: "AES-GCM"
        }, cek, new TextEncoder().encode(plaintext)));
        cek = base64urlFromBuffer(new Uint8Array(
            await crypto.subtle.wrapKey("raw", cek, kek, "AES-KW")
        ));
        return (
            header
            + "." + cek
            + "." + iv
            + "." + base64urlFromBuffer(tmp.subarray(0, -16))
            + "." + base64urlFromBuffer(tmp.subarray(-16))
        );
    };
    cryptoValidateHeader = function (header, kek, cek, cekPadding) {
        assertOrThrow((
            (header.alg === "A128KW" && header.enc === "A128GCM")
            || (header.alg === "A256KW" && header.enc === "A256GCM")
        ), "jwe failed validation");
        assertOrThrow(kek.byteLength === (
            header.alg !== "A256KW"
            ? 16
            : 32
        ), "jwe failed validation");
        assertOrThrow((cek.byteLength - cekPadding) === (
            header.enc !== "A256GCM"
            ? 16
            : 32
        ), "jwe failed validation");
    };
    runMe = async function () {
        if (!isBrowser) {
            return;
        }
        // 4.1 Wrap 128 bits of Key Data with a 128-bit KEK
        // https://tools.ietf.org/html/rfc3394#section-4.1
        let cek;
        let kek;
        cek = hexToBuffer("00112233445566778899AABBCCDDEEFF");
        kek = hexToBuffer("000102030405060708090A0B0C0D0E0F");
        kek = await crypto.subtle.importKey("raw", kek, "AES-KW", false, [
            "wrapKey"
        ]);
        cek = await crypto.subtle.importKey("raw", cek, {
            name: "AES-GCM"
        }, true, [
            "encrypt"
        ]);
        cek = hexFromBuffer(new Uint8Array(
            await crypto.subtle.wrapKey("raw", cek, kek, "AES-KW")
        ));
        assertEqual(
            cek,
            "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"
        );
        let myJwe;
        let myKek;
        let myPlaintext;
        myJwe = await cryptoEncryptBrowser("GZy6sIZ6wl9NJOKB-jnmVQ", (
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
        console.log("encrypted jwe - " + myJwe);
        // encrypted jwe - eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0.CBI6oDw8MydIx1IBntf_lQcw2MmJKIQx.Qx0pmsDa8KnJc9Jo.AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD61A1hnWGetdg11c9ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfeF0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8REwOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-puQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRaa8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZF.ER7MWJZ1FBI_NKvn7Zb1Lw // jslint ignore:line
        assertEqual(myJwe, (
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
        // cek = "aY5_Ghmk9KxWPBLu_glx1w";
        myPlaintext = await cryptoDecryptBrowser(
            "GZy6sIZ6wl9NJOKB-jnmVQ",
            myJwe
        );
        console.log("decrypted jwe - " + myPlaintext);
        assertEqual(myPlaintext, (
            "You can trust us to stick with you through thick and "
            + "thin\u2013to the bitter end. And you can trust us to "
            + "keep any secret of yours\u2013closer than you keep it "
            + "yourself. But you cannot trust us to let you face trouble "
            + "alone, and go off without a word. We are your friends, Frodo."
        ));
        myKek = base64urlFromBuffer(globalThis.crypto.getRandomValues(
            new Uint8Array(32)
        ));
        myJwe = await cryptoEncryptBrowser(myKek, (
            "You can trust us to stick with you through thick and "
            + "thin\u2013to the bitter end. And you can trust us to "
            + "keep any secret of yours\u2013closer than you keep it "
            + "yourself. But you cannot trust us to let you face trouble "
            + "alone, and go off without a word. We are your friends, Frodo."
        ));
        myPlaintext = await cryptoDecryptBrowser(myKek, myJwe);
        assertEqual(myPlaintext, (
            "You can trust us to stick with you through thick and "
            + "thin\u2013to the bitter end. And you can trust us to "
            + "keep any secret of yours\u2013closer than you keep it "
            + "yourself. But you cannot trust us to let you face trouble "
            + "alone, and go off without a word. We are your friends, Frodo."
        ));
        myJwe = await cryptoEncryptBrowser(myKek, "");
        myPlaintext = await cryptoDecryptBrowser(myKek, myJwe);
        assertEqual(myPlaintext, "");
    };
    await runMe();
    runMe = async function () {
        let aa;
        let bb;
        let cek;
        let ii;
        let iv;
        let jj;
        let kek;
        let nn;
        let rr;
        let tt;
        if (isBrowser) {
            return;
        }
        cek = hexToBuffer("00112233445566778899AABBCCDDEEFF");
        kek = hexToBuffer("000102030405060708090A0B0C0D0E0F");
        cek = Buffer.from(cek);
        kek = Buffer.from(kek);
        // https://tools.ietf.org/html/rfc3394#section-2.2.1
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
        debugInline({
            kek,
            cek,
            aa,
            iv,
            rr
        });
        // 2) Calculate intermediate values.
        // For j = 0 to 5
        // For i = 1 to n
        // B = AES(K, A | R[i])
        // A = MSB(64, B) ^ t where t = (n*j)+i
        // R[i] = LSB(64, B)
        jj = 0;
        while (jj < 6 * nn) {
            ii = 1;
            while (ii <= nn) {
                aa[8] = 0;
                aa[9] = 0;
                aa[10] = 0;
                aa[11] = 0;
                aa[12] = 0;
                aa[13] = 0;
                aa[14] = 0;
                aa[15] = 0;
                rr.copy(aa, 8, ii * 8, ii * 8 + 8);
                bb = crypto.createCipheriv("aes-128-cbc", kek, iv);
                bb.setAutoPadding(false);
                bb.update(aa).copy(aa);
                bb = bb.final();
                bb.copy(aa, 8 - bb.byteLength);
                aa.copy(rr, ii * 8, 8, 16);
                tt = jj + ii;
                aa[4] ^= (tt >>> 24) & 0xff;
                aa[5] ^= (tt >> 16) & 0xff;
                aa[6] ^= (tt >> 8) & 0xff;
                aa[7] ^= tt & 0xff;
                //!! debugInline(aa, "aes");
                //!! debugInline(rr, "aes");
                ii += 1;
            }
            jj += nn;
        }
        // 3) Output the results.
        // Set C[0] = A
        // For i = 1 to n
        // C[i] = R[i]
        aa.copy(rr);
        try {
            assertEqual(
                hexFromBuffer(rr),
                "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"
            );
        } catch (errCaught) {
            console.error(errCaught);
        }
        debugInline(rr);
        return;
    };
    await runMe();
}());

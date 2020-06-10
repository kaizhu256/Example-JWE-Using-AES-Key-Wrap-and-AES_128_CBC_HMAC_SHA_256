/* jslint utility2:true */
/* istanbul ignore next */
// run shared js-env code - init-local
(function (globalThis) {
    "use strict";
    let consoleError;
    let local;
    // init globalThis
    globalThis.globalThis = globalThis.globalThis || globalThis;
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
            if (!(typeof obj === "object" && obj)) {
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
     * this function will throw err.<msg> if <passed> is falsy
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
                // else JSON.stringify msg
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
    // require builtin
    if (!local.isBrowser) {
        if (process.unhandledRejections !== "strict") {
            process.unhandledRejections = "strict";
            process.on("unhandledRejection", function (err) {
                throw err;
            });
        }
        local.assert = require("assert");
        local.buffer = require("buffer");
        local.child_process = require("child_process");
        local.cluster = require("cluster");
        local.crypto = require("crypto");
        local.dgram = require("dgram");
        local.dns = require("dns");
        local.domain = require("domain");
        local.events = require("events");
        local.fs = require("fs");
        local.http = require("http");
        local.https = require("https");
        local.net = require("net");
        local.os = require("os");
        local.path = require("path");
        local.querystring = require("querystring");
        local.readline = require("readline");
        local.repl = require("repl");
        local.stream = require("stream");
        local.string_decoder = require("string_decoder");
        local.timers = require("timers");
        local.tls = require("tls");
        local.tty = require("tty");
        local.url = require("url");
        local.util = require("util");
        local.vm = require("vm");
        local.zlib = require("zlib");
    }
}((typeof globalThis === "object" && globalThis) || window));



// run shared js-env code - function
(async function (local) {
    "use strict";
    let assertJsonEqual;
    let assertOrThrow;
    let base64urlFromBuffer;
    let base64urlToBuffer;
    let cryptoDecryptBrowser;
    let cryptoDecryptNode;
    let cryptoEncryptBrowser;
    let cryptoValidateHeader;
    let runMe;
    assertJsonEqual = local.assertJsonEqual;
    assertOrThrow = local.assertOrThrow;
    base64urlFromBuffer = function (buf) {
        let base64url;
        let ii;
        base64url = "";
        ii = 0;
        while (ii < buf.byteLength) {
            base64url += String.fromCharCode(buf[ii]);
            ii += 1;
        }
        return globalThis.btoa(base64url).replace((
            /\+/g
        ), "-").replace((
            /\//g
        ), "_").replace((
            /\=*?$/
        ), "");
    };
    base64urlToBuffer = function (base64url) {
        return Uint8Array.from(globalThis.atob(base64url.replace((
            /-/g
        ), "+").replace((
            /_/g
        ), "/").replace((
            /\=*?$/
        ), "")), function (chr) {
            return chr.charCodeAt(0);
        });
    };
    cryptoDecryptBrowser = async function (kek, jwe) {
        let cek;
        let ciphertext;
        let crypto;
        let header;
        let iv;
        let tag;
        let tmp;
        crypto = globalThis.crypto;
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
        let crypto;
        let tmp;
        crypto = globalThis.crypto;
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
    cryptoDecryptNode = async function (kek, plaintext, header, cek, iv) {
        let crypto;
        let tmp;
        crypto = globalThis.crypto;
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
        debugInline("sldfkj");
        if (!local.isBrowser) {
            return;
        }
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
        assertJsonEqual(myJwe, (
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
        myPlaintext = await cryptoDecryptBrowser("GZy6sIZ6wl9NJOKB-jnmVQ", myJwe);
        console.log("decrypted jwe - " + myPlaintext);
        assertJsonEqual(myPlaintext, (
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
        console.log("encrypted jwe - " + myJwe);
        myPlaintext = await cryptoDecryptBrowser(myKek, myJwe);
        console.log("decrypted jwe - " + myPlaintext);
        assertJsonEqual(myPlaintext, (
            "You can trust us to stick with you through thick and "
            + "thin\u2013to the bitter end. And you can trust us to "
            + "keep any secret of yours\u2013closer than you keep it "
            + "yourself. But you cannot trust us to let you face trouble "
            + "alone, and go off without a word. We are your friends, Frodo."
        ));
        myJwe = await cryptoEncryptBrowser(myKek, "");
        console.log("encrypted jwe - " + myJwe);
        myPlaintext = await cryptoDecryptBrowser(myKek, myJwe);
        console.log("decrypted jwe - " + myPlaintext);
    };
    runMe();
}(globalThis.globalLocal));

/* jslint utility2:true */
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
        let objectKeysSort;
        objectKeysSort = function (obj) {
        /*
         * this function will return copy of <obj> with keys sorted recursively
         */
            let sorted;
            if (!(typeof obj === "object" && obj)) {
                return obj;
            }
            // return copy of list with child-keys sorted recursively
            if (Array.isArray(obj)) {
                return obj.map(objectKeysSort);
            }
            // return copy of obj with keys sorted recursively
            sorted = {};
            Object.keys(obj).sort().forEach(function (key) {
                sorted[key] = objectKeysSort(obj[key]);
            });
            return sorted;
        };
        aa = JSON.stringify(objectKeysSort(aa));
        bb = JSON.stringify(objectKeysSort(bb));
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
    local.base64urlFromBuffer = function (buf) {
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
    local.base64urlToBuffer = function (base64url) {
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
        [
            "assert", "buffer",
            "child_process", "cluster", "crypto",
            "dgram", "dns", "domain",
            "events", "fs",
            "http", "https",
            "net", "os", "path",
            "querystring",
            "readline", "repl",
            "stream", "string_decoder",
            "timers", "tls", "tty",
            "url", "util",
            "vm", "zlib"
        ].forEach(function (module) {
            local[module] = require(module);
        });
    }
}());



(async function () {
"use strict";
let atag;
let ciphertext;
let crypto;
let jwk;
let local;
let plaintext;
let tmp;
local = globalThis.globalLocal;
crypto = globalThis.crypto;
// https://tools.ietf.org/id/draft-ietf-jose-cookbook-02.html#jwe-dir_gcm
// 4.6. Direct Encryption using AES-GCM
// This example illustrates encrypting content using a previously exchanged key
// directly and the "A128GCM" (AES-GCM) content encryption algorithm.

// 4.6.1. Input Factors
// The following are supplied before beginning the encryption process:

// Plaintext content; this example uses the content from Figure 51.
// AES symmetric key as the Content Encryption Key (CEK); this example uses the
// key from Figure 105.
// "alg" parameter of "dir"
// "enc" parameter of "A128GCM"
// {
// "kty": "oct",
// "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a",
// "use": "enc",
// "alg": "A128GCM",
// "k": "XctOhJAkA-pD9Lh7ZgW_2A"
// }
// Figure 105: AES 128-bit key, in JWK format

// 4.6.2. Generated Factors
// The following are generated before encrypting:

// Initialization vector/nonce; this example uses the initialization
// vector/nonce from Figure 106.
// refa467QzzKx6QAB
// Figure 106: Initialization Vector, base64url-encoded

// 4.6.3. Encrypting the Content
// The following are generated before encrypting the content:

// Protected JWE Header; this example uses the header from Figure 107, encoded
// as [RFC4648] base64url to produce Figure 108.
// {
// "alg": "dir",
// "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a",
// "enc": "A128GCM"
// }
// Figure 107: Protected JWE Header JSON

// Encoded as [RFC4648] base64url:

// eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MT
// diNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0
// Figure 108: Protected JWE Header, base64url-encoded

// Performing the encryption operation on the Plaintext (Figure 51) using the
// following:

// CEK (Figure 105);
// Initialization vector/nonce (Figure 106); and
// Protected JWE header (Figure 108) as authenticated data
// produces the following:

jwk = await crypto.subtle.importKey("jwk", {
    "kty": "oct",
    "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a",
    "use": "enc",
    "alg": "A128GCM",
    "k": "XctOhJAkA-pD9Lh7ZgW_2A"
}, {
    name: "AES-GCM"
}, true, [
    "decrypt", "encrypt"
]);
plaintext = (
    "You can trust us to stick with you through thick and "
    + "thin\u2013to the bitter end. And you can trust us to "
    + "keep any secret of yours\u2013closer than you keep it "
    + "yourself. But you cannot trust us to let you face trouble "
    + "alone, and go off without a word. We are your friends, Frodo."
);
tmp = new Uint8Array(await crypto.subtle.encrypt(
    {
        additionalData: new TextEncoder().encode(
            "eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MT"
            + "diNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0"
        ),
        iv: local.base64urlToBuffer("refa467QzzKx6QAB"),
        name: "AES-GCM",
    },
    jwk,
    new TextEncoder().encode(plaintext)
));
atag = tmp.subarray(-16);
ciphertext = tmp.subarray(0, -16);
local.assertJsonEqual(local.base64urlFromBuffer(ciphertext), (
    "JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7Y"
    + "hLpT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9HRUYkshtrMmIUAyGmUnd9zM"
    + "DB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-Nceb4h3-FtBP-c_"
    + "BIwCPTjb9o0SbdcdREEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5"
    + "g-NJsUPbjk29-s7LJAGb15wEBtXphVCgyy53CoIKLHHeJHXex45Uz9aKZSRSIn"
    + "ZI-wjsY0yu3cT4_aQ3i1o-tiE-F8Ios61EKgyIQ4CWao8PFMj8TTnp"
));
local.assertJsonEqual(local.base64urlFromBuffer(atag), (
    "vbb32Xvllea2OtmHAdccRQ"
));

// Ciphertext from Figure 109.
// Authentication tag from Figure 110.
// JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7Y
// hLpT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9HRUYkshtrMmIUAyGmUnd9zM
// DB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-Nceb4h3-FtBP-c_
// BIwCPTjb9o0SbdcdREEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5
// g-NJsUPbjk29-s7LJAGb15wEBtXphVCgyy53CoIKLHHeJHXex45Uz9aKZSRSIn
// ZI-wjsY0yu3cT4_aQ3i1o-tiE-F8Ios61EKgyIQ4CWao8PFMj8TTnp
// Figure 109: Ciphertext, base64url-encoded

// vbb32Xvllea2OtmHAdccRQ
// Figure 110: Authentication Tag, base64url-encoded

// 4.6.4. Output Results
// The following compose the resulting JWE object:

// Protected JWE header (Figure 108)
// Initialization vector/nonce (Figure 106)
// Ciphertext (Figure 109)
// Authentication tag (Figure 110)
// The resulting JWE object using the Compact serialization:

// eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MT
// diNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0
// .
// .
// refa467QzzKx6QAB
// .
// JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7Y
// hLpT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9HRUYkshtrMmIUAyGmUnd9zM
// DB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-Nceb4h3-FtBP-c_
// BIwCPTjb9o0SbdcdREEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5
// g-NJsUPbjk29-s7LJAGb15wEBtXphVCgyy53CoIKLHHeJHXex45Uz9aKZSRSIn
// ZI-wjsY0yu3cT4_aQ3i1o-tiE-F8Ios61EKgyIQ4CWao8PFMj8TTnp
// .
// vbb32Xvllea2OtmHAdccRQ
// Figure 111: Compact Serialization

// The resulting JWE object using the JSON serialization:

// {
// "protected": "eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLT
// Q1Y2YtODY3Mi02MTdiNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0",
// "iv": "refa467QzzKx6QAB",
// "ciphertext": "JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJ
// oBcW29rHP8yZOZG7YhLpT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9
// HRUYkshtrMmIUAyGmUnd9zMDB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdc
// qMyiBoCO-FBdE-Nceb4h3-FtBP-c_BIwCPTjb9o0SbdcdREEMJMyZBH8
// ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5g-NJsUPbjk29-s7LJAGb1
// 5wEBtXphVCgyy53CoIKLHHeJHXex45Uz9aKZSRSInZI-wjsY0yu3cT4_
// aQ3i1o-tiE-F8Ios61EKgyIQ4CWao8PFMj8TTnp",
// "tag": "vbb32Xvllea2OtmHAdccRQ"
// }
// Figure 112: JSON Serialization

plaintext = new Uint8Array(await crypto.subtle.decrypt(
    {
        additionalData: new TextEncoder().encode(
            "eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MT"
            + "diNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0"
        ),
        iv: local.base64urlToBuffer("refa467QzzKx6QAB"),
        name: "AES-GCM",
    },
    jwk,
    tmp
));
local.assertJsonEqual(new TextDecoder().decode(plaintext), (
    "You can trust us to stick with you through thick and "
    + "thin\u2013to the bitter end. And you can trust us to "
    + "keep any secret of yours\u2013closer than you keep it "
    + "yourself. But you cannot trust us to let you face trouble "
    + "alone, and go off without a word. We are your friends, Frodo."
));
}());

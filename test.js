(async function () {
    "use strict";
    let assertJsonEqual;
    let assertOrThrow;
    let base64urlFromBuffer;
    let base64urlToBuffer;
    let cryptoDecrypt;
    let cryptoEncrypt;
    let cryptoValidateHeader;
    let myJwe;
    let myKek;
    let myPlaintext;
    assertJsonEqual = function (aa, bb) {
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
    assertOrThrow = function (passed, msg) {
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
    cryptoDecrypt = async function (kek, jwe) {
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
    cryptoEncrypt = async function (kek, plaintext, header, cek, iv) {
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
    myJwe = await cryptoEncrypt("GZy6sIZ6wl9NJOKB-jnmVQ", (
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
    myPlaintext = await cryptoDecrypt("GZy6sIZ6wl9NJOKB-jnmVQ", myJwe);
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
    myJwe = await cryptoEncrypt(myKek, (
        "You can trust us to stick with you through thick and "
        + "thin\u2013to the bitter end. And you can trust us to "
        + "keep any secret of yours\u2013closer than you keep it "
        + "yourself. But you cannot trust us to let you face trouble "
        + "alone, and go off without a word. We are your friends, Frodo."
    ));
    console.log("encrypted jwe - " + myJwe);
    myPlaintext = await cryptoDecrypt(myKek, myJwe);
    console.log("decrypted jwe - " + myPlaintext);
    assertJsonEqual(myPlaintext, (
        "You can trust us to stick with you through thick and "
        + "thin\u2013to the bitter end. And you can trust us to "
        + "keep any secret of yours\u2013closer than you keep it "
        + "yourself. But you cannot trust us to let you face trouble "
        + "alone, and go off without a word. We are your friends, Frodo."
    ));
    myJwe = await cryptoEncrypt(myKek, "");
    console.log("encrypted jwe - " + myJwe);
    myPlaintext = await cryptoDecrypt(myKek, myJwe);
    console.log("decrypted jwe - " + myPlaintext);
}());

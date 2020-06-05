/* jslint utility2:true */
// https://tools.ietf.org/html/rfc7516#appendix-A.3
(async function () {
    "use strict";
    let aad;
    let aal;
    let assertJsonEqual;
    let base64urlFromBuffer;
    let base64urlToBuffer;
    let cek;
    let ciphertext;
    let crypto;
    let enc_key;
    let header;
    let ii;
    let iv;
    let jj;
    let jwe;
    let jwk;
    let mac_key;
    let plaintext;
    let tag;
    globalThis.debugInline = function (...argList) {
    /*
     * this function will both print <argList> to stderr
     * and return <argList>[0]
     */
        console.error("\n\ndebugInline");
        console.error(...argList);
        console.error("\n");
        return argList[0];
    };
    assertJsonEqual = function (aa, bb) {
    /*
     * this function will assert JSON.stringify(<aa>) === JSON.stringify(<bb>)
     */
        aa = JSON.stringify(aa);
        bb = JSON.stringify(bb);
        if (aa !== bb) {
            throw new Error(JSON.stringify(aa) + " !== " + JSON.stringify(bb));
        }
    };
    base64urlFromBuffer = function (buf) {
        let base64url;
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
    crypto = globalThis.crypto;
    // https://tools.ietf.org/html/rfc7516#appendix-A.3
    // A.3.  Example JWE Using AES Key Wrap and AES_128_CBC_HMAC_SHA_256
    plaintext = "Live long and prosper.";
    plaintext = await new TextEncoder().encode(plaintext);
    assertJsonEqual(Array.from(plaintext), [
        76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
        112, 114, 111, 115, 112, 101, 114, 46
    ]);
    // A.3.1.  JOSE Header
    header = "{\"alg\":\"A128KW\",\"enc\":\"A128CBC-HS256\"}";
    header = globalThis.btoa(header).replace((
        /\+/g
    ), "-").replace((
        /\//g
    ), "_").replace((
        /\=*?$/
    ), "");
    assertJsonEqual(
        header,
        "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
    );
    // A.3.2.  Content Encryption Key (CEK)
    cek = Uint8Array.from([
        4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
        206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
        44, 207
    ]);
    mac_key = cek.slice(0, 16);
    enc_key = cek.slice(16);
    cek = base64urlFromBuffer(cek);
    cek = {
        "k": cek,
        "kty": "oct"
    };
    assertJsonEqual(cek, {
        "k": "BNMfxVSd_P4LZJ36P6pqzmt81C1vawnbyLEA8I-cLM8",
        "kty": "oct"
    });
    // A.3.3.  Key Encryption
    jwk = {
        "alg": "A128KW",
        "k": "GawgguFyGrWKav7AX4VKUg",
        "kty": "oct"
    };
    jwk = await crypto.subtle.importKey("jwk", jwk, {
        name: "AES-KW"
    }, false, [
        "unwrapKey", "wrapKey"
    ]);
    cek = await crypto.subtle.importKey("jwk", cek, {
        name: "AES-CBC"
    }, true, [
        "encrypt"
    ]);
    cek = await crypto.subtle.wrapKey("raw", cek, jwk, "AES-KW");
    cek = base64urlFromBuffer(new Uint8Array(cek));
    assertJsonEqual(
        cek,
        "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"
    );
    // A.3.4.  Initialization Vector
    iv = base64urlToBuffer("AxY8DCtDaGlsbGljb3RoZQ");
    assertJsonEqual(Array.from(iv), [
        3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104,
        101
    ]);
    // A.3.5.  Additional Authenticated Data
    aad = new TextEncoder().encode(header);
    assertJsonEqual(Array.from(aad), [
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52,
        83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66,
        77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73,
        110, 48
    ]);
    // A.3.6.  Content Encryption
    // Appendix B.  Example AES_128_CBC_HMAC_SHA_256 Computation
    // B.1.  Extract MAC_KEY and ENC_KEY from Key
    assertJsonEqual(Array.from(mac_key), [
        4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
        206
    ]);
    assertJsonEqual(Array.from(enc_key), [
        107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44,
        207
    ]);
    // B.2.  Encrypt Plaintext to Create Ciphertext
    enc_key = await crypto.subtle.importKey("raw", enc_key, "AES-CBC", true, [
        "encrypt"
    ]);
    ciphertext = new Uint8Array(await crypto.subtle.encrypt({
        iv,
        name: "AES-CBC"
    }, enc_key, plaintext));
    assertJsonEqual(Array.from(ciphertext), [
        40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6,
        75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143,
        112, 56, 102
    ]);
    // B.3.  64-Bit Big-Endian Representation of AAD Length
    aal = Uint8Array.from([
        0, 0, 0, 0,
        (aad.length >>> 21) & 0xff,
        (aad.length >> 13) & 0xff,
        (aad.length >> 5) & 0xff,
        (8 * aad.length) & 0xff
    ]);
    assertJsonEqual(Array.from(aal), [
        0, 0, 0, 0, 0, 0, 1, 152
    ]);
    // B.4.  Initialization Vector Value
    assertJsonEqual(Array.from(iv), [
        3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104,
        101
    ]);
    // B.5.  Create Input to HMAC Computation
    tag = new Uint8Array(aad.length + iv.length + ciphertext.length + 8);
    ii = 0;
    [
        aad, iv, ciphertext, [
            // 64-bit length of aad
            0, 0, 0, 0,
            (aad.length >>> 21) & 0xff,
            (aad.length >> 13) & 0xff,
            (aad.length >> 5) & 0xff,
            (8 * aad.length) & 0xff
        ]
    ].forEach(function (elem) {
        jj = 0;
        while (jj < elem.length) {
            tag[ii] = elem[jj];
            ii += 1;
            jj += 1;
        }
    });
    assertJsonEqual(Array.from(tag), [
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52,
        83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66,
        77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73,
        110, 48, 3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111,
        116, 104, 101, 40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24,
        152, 230, 6, 75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215,
        104, 143, 112, 56, 102, 0, 0, 0, 0, 0, 0, 1, 152
    ]);
    // B.6.  Compute HMAC Value
    mac_key = await crypto.subtle.importKey("raw", mac_key, {
        hash: "SHA-256",
        name: "HMAC"
    }, false, [
        "sign"
    ]);
    tag = new Uint8Array(await crypto.subtle.sign({
        name: "HMAC"
    }, mac_key, tag));
    assertJsonEqual(Array.from(tag), [
        83, 73, 191, 98, 104, 205, 211, 128, 201, 189, 199, 133, 32, 38,
        194, 85, 9, 84, 229, 201, 219, 135, 44, 252, 145, 102, 179, 140, 105,
        86, 229, 116
    ]);
    // B.7.  Truncate HMAC Value to Create Authentication Tag
    tag = tag.slice(0, 16);
    assertJsonEqual(Array.from(tag), [
        83, 73, 191, 98, 104, 205, 211, 128, 201, 189, 199, 133, 32, 38,
        194, 85
    ]);
    tag = base64urlFromBuffer(tag);
    ciphertext = base64urlFromBuffer(ciphertext);
    assertJsonEqual({
        ciphertext,
        tag
    }, {
        ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
        tag: "U0m_YmjN04DJvceFICbCVQ"
    });
    // A.3.7.  Complete Representation
    jwe = (
        header + "."
        + cek + "."
        + base64urlFromBuffer(iv) + "."
        + ciphertext + "."
        + tag
    );
    assertJsonEqual(jwe, (
        // header
        "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0."
        // cek
        + "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ."
        // iv
        + "AxY8DCtDaGlsbGljb3RoZQ."
        // ciphertext
        + "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY."
        // tag
        + "U0m_YmjN04DJvceFICbCVQ"
    ));
    console.error("jwe - " + jwe);
    // A.3.8.  Validation
    [
        header, cek, iv, ciphertext
    ] = jwe.split(".");
    header = new TextEncoder().encode(header);
    cek = await crypto.subtle.unwrapKey("raw", base64urlToBuffer(
        cek
    ), jwk, "AES-KW", "AES-CBC", true, [
        "decrypt"
    ]);
    cek = new Uint8Array(await crypto.subtle.exportKey("raw", cek));
    iv = base64urlToBuffer(iv);
    ciphertext = base64urlToBuffer(ciphertext);
    // B.5.  Create Input to HMAC Computation
    tag = new Uint8Array(header.length + iv.length + ciphertext.length + 8);
    ii = 0;
    [
        header, iv, ciphertext, [
            // 64-bit length of header
            0, 0, 0, 0,
            (header.length >>> 21) & 0xff,
            (header.length >> 13) & 0xff,
            (header.length >> 5) & 0xff,
            (header.length << 3) & 0xff
        ]
    ].forEach(function (elem) {
        jj = 0;
        while (jj < elem.length) {
            tag[ii] = elem[jj];
            ii += 1;
            jj += 1;
        }
    });
    // B.6.  Compute HMAC Value
    jwk = await crypto.subtle.importKey("raw", cek.slice(0, 16), {
        hash: "SHA-256",
        name: "HMAC"
    }, false, [
        "sign"
    ]);
    tag = new Uint8Array(await crypto.subtle.sign({
        name: "HMAC"
    }, jwk, tag));
    // B.7.  Truncate HMAC Value to Create Authentication Tag
    tag = tag.slice(0, 16);
    tag = base64urlFromBuffer(tag);
    assertJsonEqual(tag, "U0m_YmjN04DJvceFICbCVQ");
    // decrypt
    jwk = await crypto.subtle.importKey("raw", cek.slice(16), "AES-CBC", true, [
        "decrypt"
    ]);
    plaintext = await crypto.subtle.decrypt({
        iv,
        name: "AES-CBC"
    }, jwk, ciphertext);
    plaintext = new TextDecoder().decode(plaintext);
    assertJsonEqual(plaintext, "Live long and prosper.");
    console.error("plaintext - " + plaintext);
}());



//!! (async function () {
    //!! "use strict";
    //!! let assertJsonEqual;
    //!! let base64urlFromBuffer;
    //!! let base64urlToBuffer;
    //!! let decrypt;
    //!! let encrypt;
    //!! let jwe;
    //!! let jwk;
    //!! let sign;
    //!! assertJsonEqual = function (aa, bb) {
    //!! /*
     //!! * this function will assert JSON.stringify(<aa>) === JSON.stringify(<bb>)
     //!! */
        //!! aa = JSON.stringify(aa);
        //!! bb = JSON.stringify(bb);
        //!! if (aa !== bb) {
            //!! throw new Error(JSON.stringify(aa) + " !== " + JSON.stringify(bb));
        //!! }
    //!! };
    //!! base64urlFromBuffer = function (buf) {
        //!! let base64url;
        //!! let ii;
        //!! base64url = "";
        //!! ii = 0;
        //!! while (ii < buf.byteLength) {
            //!! base64url += String.fromCharCode(buf[ii]);
            //!! ii += 1;
        //!! }
        //!! return globalThis.btoa(base64url).replace((
            //!! /\+/g
        //!! ), "-").replace((
            //!! /\//g
        //!! ), "_").replace((
            //!! /\=*?$/
        //!! ), "");
    //!! };
    //!! base64urlToBuffer = function (base64url) {
        //!! return Uint8Array.from(globalThis.atob(base64url.replace((
            //!! /-/g
        //!! ), "+").replace((
            //!! /_/g
        //!! ), "/").replace((
            //!! /\=*?$/
        //!! ), "")), function (chr) {
            //!! return chr.charCodeAt(0);
        //!! });
    //!! };
    //!! decrypt = async function (jwk, jwe) {
        //!! let cek;
        //!! let ciphertext;
        //!! let crypto;
        //!! let header;
        //!! let iv;
        //!! let tag;
        //!! crypto = globalThis.crypto;
        //!! // A.3.8.  Validation
        //!! [
            //!! header, cek, iv, ciphertext, tag
        //!! ] = jwe.split(".");
        //!! if (typeof tag !== "string") {
            //!! throw new Error("jwe failed validation - " + jwe);
        //!! }
        //!! cek = await crypto.subtle.unwrapKey("raw", base64urlToBuffer(
            //!! cek
        //!! ), jwk, "AES-KW", "AES-CBC", true, [
            //!! "decrypt"
        //!! ]);
        //!! cek = new Uint8Array(await crypto.subtle.exportKey("raw", cek));
        //!! iv = base64urlToBuffer(iv);
        //!! ciphertext = base64urlToBuffer(ciphertext);
        //!! if (await sign(jwk, jwe) !== tag) {
            //!! throw new Error("jwe failed validation - " + jwe);
        //!! }
        //!! // decrypt
        //!! jwk = await crypto.subtle.importKey("raw", cek.subarray(
            //!! 16
        //!! ), "AES-CBC", true, [
            //!! "decrypt"
        //!! ]);
        //!! return new TextDecoder().decode(await crypto.subtle.decrypt({
            //!! iv,
            //!! name: "AES-CBC"
        //!! }, jwk, ciphertext));
    //!! };
    //!! encrypt = async function (jwk, plaintext, iv) {
        //!! let cek;
        //!! let ciphertext;
        //!! let crypto;
        //!! let tmp;
        //!! crypto = globalThis.crypto;
        //!! ciphertext = "";
        //!! // https://tools.ietf.org/html/rfc7516#appendix-A.3
        //!! // A.3.  Example JWE Using AES Key Wrap and AES_128_CBC_HMAC_SHA_256
        //!! plaintext = new TextEncoder().encode(plaintext);
        //!! // A.3.1.  JOSE Header
        //!! tmp = "{\"alg\":\"A128KW\",\"enc\":\"A128CBC-HS256\"}";
        //!! tmp = globalThis.btoa(tmp).replace((
            //!! /\+/g
        //!! ), "-").replace((
            //!! /\//g
        //!! ), "_").replace((
            //!! /\=*?$/
        //!! ), "");
        //!! // jwe BASE64URL(UTF8(JWE Protected Header) - protected
        //!! ciphertext += tmp;
        //!! // A.3.2.  Content Encryption Key (CEK)
        //!! cek = crypto.getRandomValues(new Uint8Array(32));
        //!! tmp = await crypto.subtle.importKey("raw", cek, {
            //!! name: "AES-CBC"
        //!! }, true, [
            //!! "encrypt"
        //!! ]);
        //!! tmp = await crypto.subtle.wrapKey("raw", tmp, jwk, "AES-KW");
        //!! tmp = base64urlFromBuffer(new Uint8Array(tmp));
        //!! // jwe BASE64URL(JWE Encrypted Key) - cek
        //!! ciphertext += "." + tmp;
        //!! // A.3.4.  Initialization Vector
        //!! iv = iv || crypto.getRandomValues(new Uint8Array(16));
        //!! // jwe BASE64URL(JWE Initialization Vector) - iv
        //!! ciphertext += "." + base64urlFromBuffer(iv);
        //!! // A.3.5.  Additional Authenticated Data
        //!! // A.3.6.  Content Encryption
        //!! // Appendix B.  Example AES_128_CBC_HMAC_SHA_256 Computation
        //!! // B.1.  Extract MAC_KEY and ENC_KEY from Key
        //!! // B.2.  Encrypt Plaintext to Create Ciphertext
        //!! tmp = await crypto.subtle.importKey("raw", cek.subarray(
            //!! 16
        //!! ), "AES-CBC", true, [
            //!! "encrypt"
        //!! ]);
        //!! tmp = base64urlFromBuffer(new Uint8Array(await crypto.subtle.encrypt({
            //!! iv,
            //!! name: "AES-CBC"
        //!! }, tmp, plaintext)));
        //!! // jwe BASE64URL(JWE Ciphertext) - ciphertext
        //!! ciphertext += "." + tmp;
        //!! tmp = await sign(jwk, ciphertext);
        //!! // jwe BASE64URL(JWE Authentication Tag) - tag
        //!! ciphertext += "." + tmp;
        //!! return ciphertext;
    //!! };
    //!! sign = async function (jwk, jwe) {
        //!! let cek;
        //!! let ciphertext;
        //!! let crypto;
        //!! let ii;
        //!! let iv;
        //!! let jj;
        //!! let protectedHeader;
        //!! let tag;
        //!! crypto = globalThis.crypto;
        //!! // A.3.8.  Validation
        //!! [
            //!! protectedHeader, cek, iv, ciphertext
        //!! ] = jwe.split(".");
        //!! if (typeof ciphertext !== "string") {
            //!! throw new Error("jwe failed signing - " + jwe);
        //!! }
        //!! protectedHeader = new TextEncoder().encode(protectedHeader);
        //!! cek = await crypto.subtle.unwrapKey("raw", base64urlToBuffer(
            //!! cek
        //!! ), jwk, "AES-KW", "AES-CBC", true, [
            //!! "decrypt"
        //!! ]);
        //!! cek = new Uint8Array(await crypto.subtle.exportKey("raw", cek));
        //!! iv = base64urlToBuffer(iv);
        //!! ciphertext = base64urlToBuffer(ciphertext);
        //!! // B.5.  Create Input to HMAC Computation
        //!! tag = new Uint8Array(
            //!! protectedHeader.length + iv.length + ciphertext.length + 8
        //!! );
        //!! ii = 0;
        //!! [
            //!! protectedHeader, iv, ciphertext, [
                //!! // 64-bit length of protectedHeader
                //!! 0, 0, 0, 0,
                //!! (protectedHeader.length >>> 21) & 0xff,
                //!! (protectedHeader.length >> 13) & 0xff,
                //!! (protectedHeader.length >> 5) & 0xff,
                //!! (protectedHeader.length << 3) & 0xff
            //!! ]
        //!! ].forEach(function (elem) {
            //!! jj = 0;
            //!! while (jj < elem.length) {
                //!! tag[ii] = elem[jj];
                //!! ii += 1;
                //!! jj += 1;
            //!! }
        //!! });
        //!! // B.6.  Compute HMAC Value
        //!! jwk = await crypto.subtle.importKey("raw", cek.subarray(0, 16), {
            //!! hash: "SHA-256",
            //!! name: "HMAC"
        //!! }, false, [
            //!! "sign"
        //!! ]);
        //!! tag = new Uint8Array(await crypto.subtle.sign({
            //!! name: "HMAC"
        //!! }, jwk, tag));
        //!! // B.7.  Truncate HMAC Value to Create Authentication Tag
        //!! return base64urlFromBuffer(tag.subarray(0, 16));
    //!! };
    //!! jwk = {
        //!! "alg": "A128KW",
        //!! "k": "GawgguFyGrWKav7AX4VKUg",
        //!! "kty": "oct"
    //!! };
    //!! jwk = await globalThis.crypto.subtle.importKey("jwk", jwk, {
        //!! name: "AES-KW"
    //!! }, false, [
        //!! "unwrapKey", "wrapKey"
    //!! ]);
    //!! jwe = (
        //!! // protectedHeader
        //!! "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0."
        //!! // cek
        //!! + "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ."
        //!! // iv
        //!! + "AxY8DCtDaGlsbGljb3RoZQ."
        //!! // ciphertext
        //!! + "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY."
        //!! // tag
        //!! + "U0m_YmjN04DJvceFICbCVQ"
    //!! );
    //!! assertJsonEqual(await decrypt(jwk, jwe), "Live long and prosper.");
    //!! jwe = await encrypt(jwk, "Live long and prosper.");
    //!! console.error("jwe - " + jwe);
    //!! assertJsonEqual(await decrypt(jwk, jwe), "Live long and prosper.");
//!! }());

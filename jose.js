//!! /* jslint utility2:true */
//!! (async function () {
    //!! "use strict";
    //!! let cryptoSubtle;
    //!! let header;
    //!! let plaintext;
    //!! globalThis.debugInline = function (...argList) {
    //!! /*
     //!! * this function will both print <argList> to stderr
     //!! * and return <argList>[0]
     //!! */
        //!! console.error("\n\ndebugInline");
        //!! console.error(...argList);
        //!! console.error("\n");
        //!! return argList[0];
    //!! };
    //!! function assertJsonEqual(aa, bb) {
    //!! /*
     //!! * this function will assert JSON.stringify(<aa>) === JSON.stringify(<bb>)
     //!! */
        //!! aa = JSON.stringify(aa);
        //!! bb = JSON.stringify(bb);
        //!! if (aa !== bb) {
            //!! throw new Error(JSON.stringify(aa) + " !== " + JSON.stringify(bb));
        //!! }
    //!! }
    //!! cryptoSubtle = globalThis.cryptoSubtle;
    //!! // https://tools.ietf.org/html/rfc7516#appendix-A.3
    //!! // A.3.  Example JWE Using AES Key Wrap and AES_128_CBC_HMAC_SHA_256
    //!! plaintext = "Live long and prosper.";
    //!! header = "{\"alg\":\"A128KW\",\"enc\":\"A128CBC-HS256\"}";
    //!! header = globalThis.btoa(header).replace((
        //!! /\=*?$/
    //!! ), "");
    //!! //!! debugInline(header);
    //!! assertJsonEqual(
        //!! header,
        //!! "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
    //!! );
//!! }());

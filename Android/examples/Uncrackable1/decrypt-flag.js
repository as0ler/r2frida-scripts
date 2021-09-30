function bufferToString(buf) {
    var buffer = Java.array('byte', buf);
    var result = "";
    for(var i = 0; i < buffer.length; ++i){
      result += (String.fromCharCode(buffer[i] & 0xff));
    }
    return result;
}

console.log("Having fun with Frida :D ");
Java.perform(function x() {
    console.log("Start hooking...");
    var aes_decrypt = Java.use("sg.vantagepoint.a.a");
    aes_decrypt.a.overload("[B","[B").implementation = function(var_0,var_1) {
    	console.log("sg.vantagepoint.a.a.a([B[B)[B   doFinal(enc)  // AES/ECB/PKCS7Padding");
	var retval = this.a(var_0, var_1);
	const flag = bufferToString(retval);
	console.log("Decrypted flag: " + flag);
	return retval;
    };
});


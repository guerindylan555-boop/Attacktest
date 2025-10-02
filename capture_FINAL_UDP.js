/**
 * FINAL UDP CAPTURE - Hex dump of lock/unlock packets
 * File: c:\Users\abesn\OneDrive\Bureau\analyse\capture_FINAL_UDP.js
 */

console.log('[*] FINAL UDP CAPTURE - Starting...');

Java.perform(function() {
    console.log('[+] Java ready');
    
    // SSL BYPASS
    try {
        const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        const SSLContext = Java.use('javax.net.ssl.SSLContext');
        const TrustManager = Java.registerClass({
            name: 'com.finaludp.trust',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(km, tm, sr) {
            SSLContext.init.call(this, km, [TrustManager.$new()], sr);
        };
        console.log('[+] SSL bypass OK');
    } catch (e) {}
    
    console.log('[+] Java hooks complete');
    // OKHTTP REQUEST CAPTURE - automatically log Authorization headers and discover coroutine call sites
    try {
        var Exception = Java.use('java.lang.Exception');
        var RequestBuilder = Java.use('okhttp3.Request$Builder');

        function formatStack(prefix) {
            try {
                var stack = Exception.$new().getStackTrace();
                var interesting = [];
                for (var i = 0; i < stack.length; i++) {
                    var line = stack[i].toString();
                    if (line.indexOf('mayn') !== -1 || line.indexOf('B4.') !== -1 || line.indexOf('okhttp3') !== -1) {
                        interesting.push('    at ' + line);
                        if (interesting.length >= 12) {
                            break;
                        }
                    }
                }
                if (interesting.length > 0) {
                    console.log(prefix);
                    for (var j = 0; j < interesting.length; j++) {
                        console.log(interesting[j]);
                    }
                }
            } catch (stackErr) {
                console.log('[-] Failed to capture stack: ' + stackErr);
            }
        }

        var buildOriginal = RequestBuilder.build.overload();
        RequestBuilder.build.overload().implementation = function() {
            var request = buildOriginal.call(this);
            try {
                var urlObj = request.url();
                var method = request.method();
                var urlString = urlObj ? urlObj.toString() : '<unknown>';
                var headers = request.headers();
                console.log('[HTTP] ' + method + ' ' + urlString);
                if (headers) {
                    var auth = headers.get('Authorization');
                    if (auth) {
                        console.log('  Authorization: ' + auth);
                        send({
                            type: 'http_authorization',
                            method: method,
                            url: urlString,
                            authorization: auth
                        });
                        formatStack('  Stack (filtered):');
                    }
                }
            } catch (httpErr) {
                console.log('[-] HTTP hook error: ' + httpErr);
            }
            return request;
        };

        function wrapHeader(original) {
            return function(name, value) {
                try {
                    if (name && value && name.toLowerCase() === 'authorization') {
                        console.log('[HTTP:header] ' + value);
                        send({
                            type: 'http_authorization_header_call',
                            header: value
                        });
                        formatStack('  Stack (Authorization header):');
                    }
                } catch (err) {
                    console.log('[-] header hook error: ' + err);
                }
                return original.call(this, name, value);
            };
        }

        var addHeaderOriginal = RequestBuilder.addHeader.overload('java.lang.String', 'java.lang.String');
        RequestBuilder.addHeader.overload('java.lang.String', 'java.lang.String').implementation = wrapHeader(addHeaderOriginal);
        var headerOriginal = RequestBuilder.header.overload('java.lang.String', 'java.lang.String');
        RequestBuilder.header.overload('java.lang.String', 'java.lang.String').implementation = wrapHeader(headerOriginal);

        console.log('[+] OkHttp request hooks installed');
    } catch (httpHookError) {
        console.log('[-] Failed to install OkHttp hooks: ' + httpHookError);
    }
});

// ===== NATIVE UDP PACKET CAPTURE WITH HEX DUMP =====
console.log('[*] Installing comprehensive native UDP hooks...');

setTimeout(function() {
    try {
        // Helper to create hex dump
        function hexDump(buffer, length) {
            if (length > 500) length = 500;
            
            let result = '';
            for (let i = 0; i < length; i += 16) {
                // Offset
                result += ('0000' + i.toString(16)).slice(-4) + '  ';
                
                // Hex bytes
                let hexPart = '';
                let asciiPart = '';
                for (let j = 0; j < 16 && (i + j) < length; j++) {
                    const byte = buffer.add(i + j).readU8();
                    hexPart += ('0' + byte.toString(16)).slice(-2) + ' ';
                    asciiPart += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
                }
                
                // Pad hex part
                while (hexPart.length < 48) hexPart += ' ';
                
                result += hexPart + ' |' + asciiPart + '|\n';
            }
            
            return result;
        }
        
        // HOOK 1: sendto() - Capture ALL UDP packets with HEX
        const sendtoPtr = Module.findExportByName("libc.so", "sendto");
        if (sendtoPtr) {
            Interceptor.attach(sendtoPtr, {
                onEnter: function(args) {
                    this.sockfd = args[0].toInt32();
                    this.buf = args[1];
                    this.len = args[2].toInt32();
                    this.flags = args[3].toInt32();
                    this.dest_addr = args[4];
                },
                onLeave: function(retval) {
                    // Focus on packets 100-200 bytes (lock/unlock range)
                    if (this.len > 100 && this.len < 200) {
                        console.log('');
                        console.log('='.repeat(100));
                        console.log('[🎯 UDP PACKET - LOCK/UNLOCK SIZE 🎯]');
                        console.log('Socket: ' + this.sockfd);
                        console.log('Length: ' + this.len + ' bytes');
                        console.log('Flags: ' + this.flags);
                        
                        // Try to get destination
                        try {
                            const sa_family = this.dest_addr.readU16();
                            if (sa_family === 2) {
                                const port = (this.dest_addr.add(2).readU8() << 8) | this.dest_addr.add(3).readU8();
                                const ip = this.dest_addr.add(4).readU8() + '.' + 
                                          this.dest_addr.add(5).readU8() + '.' + 
                                          this.dest_addr.add(6).readU8() + '.' + 
                                          this.dest_addr.add(7).readU8();
                                console.log('Destination: ' + ip + ':' + port);
                            }
                        } catch (e) {}
                        
                        console.log('---');
                        console.log('HEX DUMP:');
                        console.log(hexDump(this.buf, this.len));
                        console.log('='.repeat(100));
                        
                        // Try UTF-8
                        try {
                            const str = Memory.readUtf8String(this.buf, Math.min(this.len, 500));
                            if (str && str.length > 5) {
                                console.log('UTF-8 Attempt:');
                                console.log(str);
                            }
                        } catch (e) {}
                        
                        // Send hex as string
                        send({
                            type: 'udp_lock_unlock',
                            socket: this.sockfd,
                            length: this.len,
                            hex: hexDump(this.buf, this.len)
                        });
                    }
                }
            });
            console.log('[+] sendto() hooked with HEX dump');
        }
        
        // HOOK 2: recvfrom() - Capture responses
        const recvfromPtr = Module.findExportByName("libc.so", "recvfrom");
        if (recvfromPtr) {
            Interceptor.attach(recvfromPtr, {
                onEnter: function(args) {
                    this.sockfd = args[0].toInt32();
                    this.buf = args[1];
                    this.len = args[2].toInt32();
                },
                onLeave: function(retval) {
                    const bytesRead = retval.toInt32();
                    
                    // Large responses (likely lock/unlock confirmation)
                    if (bytesRead > 1000) {
                        console.log('');
                        console.log('='.repeat(100));
                        console.log('[📥 UDP RESPONSE - LARGE 📥]');
                        console.log('Socket: ' + this.sockfd);
                        console.log('Length: ' + bytesRead + ' bytes');
                        console.log('---');
                        console.log('HEX DUMP (first 500 bytes):');
                        console.log(hexDump(this.buf, Math.min(bytesRead, 500)));
                        console.log('='.repeat(100));
                    }
                }
            });
            console.log('[+] recvfrom() hooked');
        }
        
        // HOOK 3: connect() - Track connections
        const connectPtr = Module.findExportByName("libc.so", "connect");
        if (connectPtr) {
            Interceptor.attach(connectPtr, {
                onEnter: function(args) {
                    const sockfd = args[0].toInt32();
                    const addr = args[1];
                    
                    try {
                        const sa_family = addr.readU16();
                        if (sa_family === 2) {
                            const port = (addr.add(2).readU8() << 8) | addr.add(3).readU8();
                            const ip = addr.add(4).readU8() + '.' + 
                                      addr.add(5).readU8() + '.' + 
                                      addr.add(6).readU8() + '.' + 
                                      addr.add(7).readU8();
                            
                            console.log('[CONNECT] sockfd=' + sockfd + ' → ' + ip + ':' + port);
                        }
                    } catch (e) {}
                }
            });
            console.log('[+] connect() hooked');
        }
        
        console.log('');
        console.log('='.repeat(100));
        console.log('[✅ ALL UDP HOOKS INSTALLED WITH HEX DUMP]');
        console.log('='.repeat(100));
        
    } catch (e) {
        console.log('[-] Native hooks error: ' + e);
    }
}, 500);

console.log('');
console.log('='.repeat(100));
console.log('[✅ FINAL UDP CAPTURE LOADED]');
console.log('');
console.log('  WHAT THIS CAPTURES:');
console.log('    ✓ UDP packets 100-200 bytes (lock/unlock size)');
console.log('    ✓ Complete HEX dump of packet contents');
console.log('    ✓ Destination IP:port');
console.log('    ✓ Socket tracking');
console.log('    ✓ Large UDP responses (>1KB)');
console.log('');
console.log('  NOW:');
console.log('    1. Use the app');
console.log('    2. Press UNLOCK or LOCK');
console.log('    3. You will see HEX dump of the encrypted packet!');
console.log('    4. We can analyze the protocol from the hex!');
console.log('');
console.log('='.repeat(100));




/**
 * MaynDrive DTLS Decryption Script
 * Captures plaintext BEFORE DTLS encryption
 * Run this during unlock/lock to see commands
 */
'use strict';

const LOG_LINE = '='.repeat(100);

function hexdumpEnhanced(bytes, maxLen) {
    if (!bytes || bytes.length === 0) return '';
    
    var output = [];
    var len = Math.min(bytes.length, maxLen || bytes.length);
    
    for (var i = 0; i < len; i += 16) {
        var hex = [];
        var ascii = '';
        
        for (var j = 0; j < 16; j++) {
            if (i + j < len) {
                var b = bytes[i + j] & 0xFF;
                hex.push(('0' + b.toString(16)).slice(-2));
                ascii += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
            } else {
                hex.push('  ');
                ascii += ' ';
            }
        }
        
        var offset = ('0000' + i.toString(16)).slice(-4);
        output.push(offset + '  ' + hex.join(' ') + '  |' + ascii + '|');
    }
    
    return output.join('\n');
}

function tryParseAsText(bytes) {
    try {
        var text = '';
        for (var i = 0; i < Math.min(bytes.length, 2048); i++) {
            var b = bytes[i] & 0xFF;
            if (b >= 32 && b <= 126 || b === 10 || b === 13) {
                text += String.fromCharCode(b);
            }
        }
        
        // Check if it looks like text (at least 30% printable)
        var printable = text.replace(/[\s]/g, '').length;
        if (printable > bytes.length * 0.3) {
            return text;
        }
    } catch (e) {}
    return null;
}

function analyzeContent(bytes, label) {
    console.log('\n' + LOG_LINE);
    console.log('[' + label + '] ' + bytes.length + ' bytes');
    console.log(LOG_LINE);
    
    // Hex dump
    console.log(hexdumpEnhanced(bytes, 512));
    
    // Try as text
    var text = tryParseAsText(bytes);
    if (text) {
        console.log('\n[TEXT CONTENT]:');
        console.log(text.substring(0, 1000));
        
        // Check for interesting patterns
        if (text.indexOf('unlock') !== -1 || text.indexOf('lock') !== -1) {
            console.log('\n⚠️  UNLOCK/LOCK COMMAND DETECTED!');
        }
        if (text.indexOf('{') !== -1 && text.indexOf('}') !== -1) {
            console.log('\n⚠️  JSON DATA DETECTED!');
            // Try to extract JSON
            var jsonStart = text.indexOf('{');
            var jsonEnd = text.lastIndexOf('}') + 1;
            if (jsonStart !== -1 && jsonEnd > jsonStart) {
                try {
                    var jsonStr = text.substring(jsonStart, jsonEnd);
                    console.log('JSON: ' + jsonStr);
                } catch (e) {}
            }
        }
        if (text.indexOf('Bearer') !== -1 || text.indexOf('Authorization') !== -1) {
            console.log('\n⚠️  AUTHORIZATION DATA DETECTED!');
        }
    }
    
    console.log(LOG_LINE + '\n');
}

Java.perform(function() {
    console.log('[*] Enhanced DTLS Decryption - Installing hooks');
    console.log('');
    
    // === HOOK 1: Cipher operations (catches encryption before DTLS) ===
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        
        // Hook doFinal(byte[])
        var doFinalBytes = Cipher.doFinal.overload('[B');
        doFinalBytes.implementation = function(input) {
            var result = doFinalBytes.call(this, input);
            
            try {
                var algo = this.getAlgorithm ? this.getAlgorithm().toString() : 'unknown';
                
                // Get operation mode (1=ENCRYPT, 2=DECRYPT)
                var opModeField = null;
                try {
                    var CipherClass = Java.use('javax.crypto.Cipher');
                    var fields = CipherClass.class.getDeclaredFields();
                    for (var i = 0; i < fields.length; i++) {
                        if (fields[i].getName() === 'opmode') {
                            fields[i].setAccessible(true);
                            opModeField = fields[i].getInt(this);
                            break;
                        }
                    }
                } catch (e) {}
                
                var mode = opModeField === 1 ? 'ENCRYPT' : opModeField === 2 ? 'DECRYPT' : 'UNKNOWN';
                
                console.log('\n' + LOG_LINE);
                console.log('[CIPHER] Operation: ' + mode);
                console.log('  Algorithm: ' + algo);
                console.log('  Input:  ' + input.length + ' bytes ' + (mode === 'ENCRYPT' ? '(plaintext)' : '(ciphertext)'));
                console.log('  Output: ' + result.length + ' bytes ' + (mode === 'ENCRYPT' ? '(ciphertext)' : '(plaintext)'));
                console.log(LOG_LINE);
                
                // If encrypting, input is plaintext - THIS IS WHAT WE WANT!
                if (mode === 'ENCRYPT' && input && input.length > 0) {
                    var inputBytes = [];
                    for (var i = 0; i < input.length; i++) {
                        inputBytes.push(input[i] & 0xFF);
                    }
                    analyzeContent(inputBytes, 'PLAINTEXT BEFORE ENCRYPTION');
                }
                
                // If decrypting, output is plaintext
                if (mode === 'DECRYPT' && result && result.length > 0) {
                    var outputBytes = [];
                    for (var i = 0; i < result.length; i++) {
                        outputBytes.push(result[i] & 0xFF);
                    }
                    analyzeContent(outputBytes, 'PLAINTEXT AFTER DECRYPTION');
                }
                
            } catch (e) {
                console.log('[-] Cipher analysis error: ' + e);
            }
            
            return result;
        };
        
        console.log('[+] Hooked Cipher.doFinal(byte[])');
    } catch (e) {
        console.log('[-] Failed to hook Cipher: ' + e);
    }
    
    // === HOOK 2: SSLEngine (DTLS layer) ===
    try {
        var SSLEngine = Java.use('javax.net.ssl.SSLEngine');
        
        // Hook wrap (encrypts outgoing data)
        var wrap = SSLEngine.wrap.overload('[Ljava.nio.ByteBuffer;', 'int', 'int', 'java.nio.ByteBuffer');
        wrap.implementation = function(srcs, offset, length, dst) {
            var result = wrap.call(this, srcs, offset, length, dst);
            
            try {
                // Extract data from source buffers
                if (srcs && srcs.length > 0) {
                    for (var i = offset; i < offset + length && i < srcs.length; i++) {
                        var buf = srcs[i];
                        if (buf && buf.hasRemaining()) {
                            var remaining = buf.remaining();
                            if (remaining > 0 && remaining < 10000) {
                                var bytes = [];
                                var pos = buf.position();
                                for (var j = 0; j < remaining; j++) {
                                    bytes.push(buf.get(pos + j) & 0xFF);
                                }
                                analyzeContent(bytes, 'SSLEngine WRAP (outgoing plaintext)');
                            }
                        }
                    }
                }
            } catch (e) {
                console.log('[-] SSLEngine wrap error: ' + e);
            }
            
            return result;
        };
        
        // Hook unwrap (decrypts incoming data)
        var unwrap = SSLEngine.unwrap.overload('java.nio.ByteBuffer', '[Ljava.nio.ByteBuffer;', 'int', 'int');
        unwrap.implementation = function(src, dsts, offset, length) {
            var result = unwrap.call(this, src, dsts, offset, length);
            
            try {
                // Extract decrypted data from destination buffers
                if (dsts && dsts.length > 0) {
                    for (var i = offset; i < offset + length && i < dsts.length; i++) {
                        var buf = dsts[i];
                        if (buf && buf.position() > 0) {
                            var pos = buf.position();
                            if (pos > 0 && pos < 10000) {
                                var bytes = [];
                                for (var j = 0; j < pos; j++) {
                                    bytes.push(buf.get(j) & 0xFF);
                                }
                                analyzeContent(bytes, 'SSLEngine UNWRAP (incoming plaintext)');
                            }
                        }
                    }
                }
            } catch (e) {
                console.log('[-] SSLEngine unwrap error: ' + e);
            }
            
            return result;
        };
        
        console.log('[+] Hooked SSLEngine.wrap/unwrap');
    } catch (e) {
        console.log('[-] Failed to hook SSLEngine: ' + e);
    }
    
    // === HOOK 3: Native sendto/recvfrom (already in main script but add analysis) ===
    // This is backup to correlate encrypted packets
    
    console.log('');
    console.log('[*] All decryption hooks installed!');
    console.log('[*] Now unlock/lock a scooter and watch for PLAINTEXT output');
    console.log('');
});

/**
 * WORKING FINAL CAPTURE - Uses discovered coroutine classes
 * Based on automatic discovery results
 */
'use strict';

const LOG_LINE = '='.repeat(96);

function unwrapField(owner, name) {
    try {
        var field = owner[name];
        if (field === null || field === undefined) return null;
        if (typeof field === 'object' && field !== null && 'value' in field) {
            try { return field.value; } catch (e) { return field; }
        }
        return field;
    } catch (e) {
        return null;
    }
}

function toStringSafe(value) {
    if (value === null || value === undefined) {
        return null;
    }
    try {
        return value.toString();
    } catch (e) {
        return null;
    }
}

function logBlock(title, lines) {
    console.log('\n' + LOG_LINE);
    console.log(title);
    if (lines && lines.length) {
        lines.forEach(function(line) {
            console.log(line);
        });
    }
    console.log(LOG_LINE + '\n');
}

Java.perform(function() {
    console.log('[*] WORKING FINAL CAPTURE - Installing discovered hooks\n');
    
    // UNLOCK COROUTINES (with location)
    var unlockClasses = ['B4.i1', 'B4.d3'];
    
    unlockClasses.forEach(function(className) {
        try {
            var clazz = Java.use(className);
            var invokeSuspend = clazz.invokeSuspend.overload('java.lang.Object');
            invokeSuspend.implementation = function(arg) {
                var token = toStringSafe(unwrapField(this, 'Z'));
                var location = unwrapField(this, 'g0');
                var scooterId = unwrapField(this, 'f0');
                
                var lines = [];
                if (token) lines.push('  Authorization: ' + token.substring(0, 60) + '...');
                if (scooterId) lines.push('  Scooter ID: ' + scooterId);
                if (location) lines.push('  Location: ' + location);
                
                logBlock('[UNLOCK] ' + className + ' - Scooter Unlock Request', lines);
                
                // Send to Python
                send({
                    type: 'unlock_request',
                    authorization: token,
                    scooter_id: scooterId ? scooterId.toString() : null,
                    location: location ? location.toString() : null,
                    timestamp: new Date().toISOString(),
                    className: className
                });
                
                return invokeSuspend.call(this, arg);
            };
            console.log('[+] Hooked ' + className + ' (UNLOCK)');
        } catch (e) {
            console.log('[-] Failed to hook ' + className + ': ' + e);
        }
    });
    
    // LOCK COROUTINES (token only)
    var lockClasses = ['B4.P3', 'B4.x', 'B4.q2', 'B4.U4', 'B4.r1'];
    
    lockClasses.forEach(function(className) {
        try {
            var clazz = Java.use(className);
            var invokeSuspend = clazz.invokeSuspend.overload('java.lang.Object');
            invokeSuspend.implementation = function(arg) {
                var token = toStringSafe(unwrapField(this, 'Z'));
                var passId = unwrapField(this, 'k0') || unwrapField(this, 'g0') || unwrapField(this, 'f0');
                
                var lines = [];
                if (token) lines.push('  Authorization: ' + token.substring(0, 60) + '...');
                if (passId) lines.push('  Pass ID: ' + passId);
                
                logBlock('[LOCK] ' + className + ' - Scooter Lock Request', lines);
                
                // Send to Python
                send({
                    type: 'lock_request',
                    authorization: token,
                    pass_id: passId ? passId.toString() : null,
                    timestamp: new Date().toISOString(),
                    className: className
                });
                
                return invokeSuspend.call(this, arg);
            };
            console.log('[+] Hooked ' + className + ' (LOCK)');
        } catch (e) {
            console.log('[-] Failed to hook ' + className + ': ' + e);
        }
    });
    
    // UDP Cipher hooks for telemetry decryption
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        var doFinal = Cipher.doFinal.overload('[B');
        doFinal.implementation = function(input) {
            var result = doFinal.call(this, input);
            
            // Check if this looks like telemetry data
            if (input && input.length > 10) {
                try {
                    var inputStr = Java.use('java.lang.String').$new(input, 'UTF-8');
                    if (inputStr.indexOf('lat') !== -1 || inputStr.indexOf('lon') !== -1 || 
                        inputStr.indexOf('battery') !== -1 || inputStr.indexOf('speed') !== -1) {
                        
                        console.log('\n' + LOG_LINE);
                        console.log('[UDP PLAINTEXT] Decrypted telemetry data:');
                        console.log(inputStr);
                        console.log(LOG_LINE + '\n');
                        
                        send({
                            type: 'telemetry_data',
                            data: inputStr,
                            timestamp: new Date().toISOString()
                        });
                    }
                } catch (e) {
                    // Not text data, ignore
                }
            }
            
            return result;
        };
        console.log('[+] Hooked Cipher.doFinal for telemetry decryption');
    } catch (e) {
        console.log('[-] Failed to hook Cipher: ' + e);
    }
    
    // Native UDP hooks
    try {
        var sendto = Module.getExportByName(null, 'sendto');
        if (sendto) {
            Interceptor.attach(sendto, {
                onEnter: function(args) {
                    this.socket = args[0].toInt32();
                    this.buf = args[1];
                    this.len = args[2].toInt32();
                },
                onLeave: function(retval) {
                    if (this.len > 0 && this.len < 2000) {
                        var data = this.buf.readByteArray(this.len);
                        var hex = '';
                        for (var i = 0; i < Math.min(data.length, 64); i++) {
                            hex += ('0' + data[i].toString(16)).slice(-2) + ' ';
                        }
                        
                        console.log('\n' + LOG_LINE);
                        console.log('[UDP SEND] Socket: ' + this.socket + ' Length: ' + this.len + ' bytes');
                        console.log(hex);
                        console.log(LOG_LINE + '\n');
                    }
                }
            });
            console.log('[+] Hooked native sendto');
        }
    } catch (e) {
        console.log('[-] Failed to hook sendto: ' + e);
    }
    
    console.log('\n[*] ALL HOOKS INSTALLED!\n');
    console.log('[!] Ready to capture unlock/lock requests and telemetry data\n');
});

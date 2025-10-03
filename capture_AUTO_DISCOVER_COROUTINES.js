/**
 * AUTOMATIC COROUTINE DISCOVERY
 * Finds the real obfuscated coroutine classes for unlock/lock operations
 */
'use strict';

console.log('[*] AUTOMATIC COROUTINE DISCOVERY STARTING...\n');

Java.perform(function() {
    console.log('[+] Java environment ready\n');
    
    // 1. Find all classes in the B4 package (common obfuscation pattern)
    console.log('[*] Phase 1: Discovering B4.* coroutine classes...\n');
    var b4Classes = [];
    
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.startsWith('B4.') && className.length < 10) {
                b4Classes.push(className);
                console.log('[FOUND] ' + className);
            }
        },
        onComplete: function() {
            console.log('\n[*] Found ' + b4Classes.length + ' B4.* classes\n');
        }
    });
    
    // 2. Hook ALL B4 classes to see which ones get called during unlock/lock
    console.log('[*] Phase 2: Hooking all B4.* classes...\n');
    var hookedClasses = [];
    
    b4Classes.forEach(function(className) {
        try {
            var clazz = Java.use(className);
            console.log('[+] Hooking class: ' + className);
            
            // Try to hook invokeSuspend method
            try {
                var invokeSuspend = clazz.invokeSuspend.overload('java.lang.Object');
                invokeSuspend.implementation = function(arg) {
                    console.log('\n' + '='.repeat(80));
                    console.log('>>> ' + className + '.invokeSuspend CALLED <<<');
                    console.log('='.repeat(80));
                    
                    // Check if this looks like unlock/lock data
                    var hasToken = false;
                    var hasSerial = false;
                    var hasLocation = false;
                    
                    try {
                        var fields = this.getClass().getDeclaredFields();
                        console.log('Total fields: ' + fields.length);
                        
                        for (var i = 0; i < fields.length; i++) {
                            try {
                                fields[i].setAccessible(true);
                                var fieldName = fields[i].getName();
                                var value = fields[i].get(this);
                                var valueStr = value ? value.toString() : 'null';
                                
                                console.log('Field[' + i + ']: ' + fieldName + ' = ' + valueStr);
                                
                                // Check for interesting values
                                if (valueStr.indexOf('Bearer') !== -1 || valueStr.indexOf('eyJ') !== -1) {
                                    console.log('    *** TOKEN FOUND! ***');
                                    hasToken = true;
                                }
                                if (valueStr.match(/^[A-Z]{3,6}\d{3,4}$/)) {
                                    console.log('    *** SCOOTER SERIAL FOUND! ***');
                                    hasSerial = true;
                                }
                                if (valueStr.indexOf('Location') !== -1 || valueStr.indexOf('lat') !== -1) {
                                    console.log('    *** LOCATION FOUND! ***');
                                    hasLocation = true;
                                }
                                
                            } catch (e) {
                                console.log('Field[' + i + ']: ' + fields[i].getName() + ' (error)');
                            }
                        }
                        
                        // Determine if this is unlock or lock based on data
                        if (hasToken && hasSerial && hasLocation) {
                            console.log('\n*** THIS IS UNLOCK COROUTINE! ***');
                            console.log('Class: ' + className);
                            console.log('Fields contain: Token + Serial + Location');
                        } else if (hasToken && !hasLocation) {
                            console.log('\n*** THIS IS LOCK COROUTINE! ***');
                            console.log('Class: ' + className);
                            console.log('Fields contain: Token (no location)');
                        }
                        
                    } catch (e) {
                        console.log('Error inspecting fields: ' + e);
                    }
                    
                    console.log('='.repeat(80) + '\n');
                    
                    return invokeSuspend.call(this, arg);
                };
                
                hookedClasses.push(className);
                console.log('  [+] Successfully hooked ' + className + '.invokeSuspend');
                
            } catch (e) {
                console.log('  [-] No invokeSuspend in ' + className + ': ' + e);
            }
            
        } catch (e) {
            console.log('[-] Failed to hook ' + className + ': ' + e);
        }
    });
    
    // 3. Also search for other common obfuscation patterns
    console.log('\n[*] Phase 3: Searching for other obfuscation patterns...\n');
    
    var otherPatterns = ['A4.', 'C4.', 'D4.', 'E4.', 'F4.', 'G4.', 'H4.', 'I4.', 'J4.', 'K4.'];
    var foundOtherClasses = [];
    
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            for (var i = 0; i < otherPatterns.length; i++) {
                if (className.startsWith(otherPatterns[i]) && className.length < 10) {
                    foundOtherClasses.push(className);
                    console.log('[FOUND] ' + className);
                    break;
                }
            }
        },
        onComplete: function() {
            console.log('\n[*] Found ' + foundOtherClasses.length + ' other obfuscated classes\n');
        }
    });
    
    // Hook the other classes too
    foundOtherClasses.forEach(function(className) {
        try {
            var clazz = Java.use(className);
            console.log('[+] Hooking class: ' + className);
            
            try {
                var invokeSuspend = clazz.invokeSuspend.overload('java.lang.Object');
                invokeSuspend.implementation = function(arg) {
                    console.log('\n>>> ' + className + '.invokeSuspend CALLED <<<');
                    return invokeSuspend.call(this, arg);
                };
                hookedClasses.push(className);
                console.log('  [+] Successfully hooked ' + className + '.invokeSuspend');
            } catch (e) {
                console.log('  [-] No invokeSuspend in ' + className);
            }
        } catch (e) {
            console.log('[-] Failed to hook ' + className);
        }
    });
    
    console.log('\n[*] DISCOVERY COMPLETE!\n');
    console.log('[+] Successfully hooked ' + hookedClasses.length + ' coroutine classes:');
    hookedClasses.forEach(function(className) {
        console.log('    - ' + className);
    });
    
    console.log('\n[!] IMPORTANT: Use the Frida-spawned app instance only!\n');
    console.log('[!] Now unlock/lock a scooter and watch for output...\n');
    console.log('[!] Look for "THIS IS UNLOCK COROUTINE" or "THIS IS LOCK COROUTINE" messages...\n');
});

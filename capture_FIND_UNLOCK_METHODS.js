/**
 * COMPREHENSIVE UNLOCK/LOCK METHOD DISCOVERY
 * Finds the real methods used for unlock/lock operations
 */
'use strict';

console.log('[*] COMPREHENSIVE UNLOCK/LOCK DISCOVERY STARTING...\n');

Java.perform(function() {
    console.log('[+] Java environment ready\n');
    
    // 1. Search for classes containing unlock/lock
    console.log('[*] Phase 1: Searching for unlock/lock classes...\n');
    var interestingClasses = [];
    
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            var lower = className.toLowerCase();
            if ((lower.indexOf('unlock') !== -1 || lower.indexOf('lock') !== -1 || 
                 lower.indexOf('vehicle') !== -1 || lower.indexOf('scooter') !== -1) &&
                className.length < 100) {
                interestingClasses.push(className);
                console.log('[FOUND] ' + className);
            }
        },
        onComplete: function() {
            console.log('\n[*] Found ' + interestingClasses.length + ' interesting classes\n');
        }
    });
    
    // 2. Hook ALL OkHttp requests to see what's actually being called
    console.log('[*] Phase 2: Hooking ALL HTTP requests...\n');
    
    try {
        // Hook Request.Builder to catch all HTTP requests
        var RequestBuilder = Java.use('okhttp3.Request$Builder');
        var originalBuild = RequestBuilder.build;
        
        RequestBuilder.build.implementation = function() {
            var request = originalBuild.call(this);
            var url = request.url().toString();
            var method = request.method();
            
            console.log('\n' + '='.repeat(80));
            console.log('>>> HTTP REQUEST DETECTED <<<');
            console.log('='.repeat(80));
            console.log('Method: ' + method);
            console.log('URL: ' + url);
            
            // Check headers
            var headers = request.headers();
            var headerNames = headers.names();
            for (var i = 0; i < headerNames.size(); i++) {
                var name = headerNames.get(i);
                var value = headers.get(name);
                console.log('Header: ' + name + ' = ' + value);
                
                if (name.toLowerCase().indexOf('authorization') !== -1) {
                    console.log('*** BEARER TOKEN FOUND: ' + value + ' ***');
                }
            }
            
            // Check body
            var body = request.body();
            if (body !== null) {
                console.log('Body type: ' + body.getClass().getName());
                try {
                    // Try to get body content
                    var buffer = Java.use('okio.Buffer').$new();
                    body.writeTo(buffer);
                    var bodyStr = buffer.readUtf8();
                    console.log('Body: ' + bodyStr);
                } catch (e) {
                    console.log('Body: [Could not read]');
                }
            }
            
            console.log('='.repeat(80) + '\n');
            
            return request;
        };
        console.log('[+] Hooked Request.Builder.build()\n');
    } catch (e) {
        console.log('[-] Failed to hook Request.Builder: ' + e + '\n');
    }
    
    // 3. Hook Retrofit calls
    console.log('[*] Phase 3: Hooking Retrofit calls...\n');
    
    try {
        var Retrofit = Java.use('retrofit2.Retrofit');
        var originalCreate = Retrofit.create;
        
        Retrofit.create.implementation = function(serviceClass) {
            console.log('\n>>> RETROFIT SERVICE CREATED: ' + serviceClass.getName() + ' <<<\n');
            return originalCreate.call(this, serviceClass);
        };
        console.log('[+] Hooked Retrofit.create()\n');
    } catch (e) {
        console.log('[-] Failed to hook Retrofit: ' + e + '\n');
    }
    
    // 4. Hook common coroutine classes
    console.log('[*] Phase 4: Hooking common coroutine patterns...\n');
    
    var coroutineClasses = ['B4.Y4', 'B4.M4', 'B4.X4', 'B4.Z4', 'B4.A4', 'B4.B4', 'B4.C4', 'B4.D4'];
    
    coroutineClasses.forEach(function(className) {
        try {
            var clazz = Java.use(className);
            console.log('[+] Found class: ' + className);
            
            // Try to hook invokeSuspend
            try {
                var invokeSuspend = clazz.invokeSuspend.overload('java.lang.Object');
                invokeSuspend.implementation = function(arg) {
                    console.log('\n' + '='.repeat(80));
                    console.log('>>> ' + className + '.invokeSuspend CALLED <<<');
                    console.log('='.repeat(80));
                    
                    // Inspect all fields
                    try {
                        var fields = this.getClass().getDeclaredFields();
                        for (var i = 0; i < fields.length; i++) {
                            try {
                                fields[i].setAccessible(true);
                                var fieldName = fields[i].getName();
                                var value = fields[i].get(this);
                                console.log('Field[' + i + ']: ' + fieldName + ' = ' + value);
                            } catch (e) {
                                console.log('Field[' + i + ']: ' + fields[i].getName() + ' (error)');
                            }
                        }
                    } catch (e) {
                        console.log('Error inspecting fields: ' + e);
                    }
                    
                    console.log('='.repeat(80) + '\n');
                    
                    return invokeSuspend.call(this, arg);
                };
                console.log('  [+] Hooked ' + className + '.invokeSuspend');
            } catch (e) {
                console.log('  [-] No invokeSuspend in ' + className);
            }
        } catch (e) {
            console.log('[-] Class not found: ' + className);
        }
    });
    
    // 5. Hook any method containing "unlock" or "lock"
    console.log('\n[*] Phase 5: Searching for unlock/lock methods...\n');
    
    interestingClasses.forEach(function(className) {
        try {
            var clazz = Java.use(className);
            var methods = clazz.class.getDeclaredMethods();
            
            for (var i = 0; i < methods.length; i++) {
                var method = methods[i];
                var methodName = method.getName().toLowerCase();
                
                if (methodName.indexOf('unlock') !== -1 || methodName.indexOf('lock') !== -1) {
                    console.log('[FOUND METHOD] ' + className + '.' + method.getName());
                    
                    try {
                        // Try to hook the method
                        var methodObj = clazz[method.getName()];
                        if (methodObj && methodObj.implementation) {
                            methodObj.implementation = function() {
                                console.log('\n>>> ' + className + '.' + method.getName() + ' CALLED <<<');
                                console.log('Arguments: ' + arguments.length);
                                for (var j = 0; j < arguments.length; j++) {
                                    console.log('  Arg[' + j + ']: ' + arguments[j]);
                                }
                                return methodObj.apply(this, arguments);
                            };
                            console.log('  [+] Hooked ' + method.getName());
                        }
                    } catch (e) {
                        console.log('  [-] Could not hook: ' + e);
                    }
                }
            }
        } catch (e) {
            // Class might not be loaded yet
        }
    });
    
    console.log('\n[*] ALL HOOKS INSTALLED!\n');
    console.log('[!] IMPORTANT: Use the Frida-spawned app instance only!\n');
    console.log('[!] Now unlock/lock a scooter and watch for output...\n');
    console.log('[!] Look for HTTP REQUEST DETECTED or method calls...\n');
});

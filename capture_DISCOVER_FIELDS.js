/**
 * MaynDrive Field Discovery Script
 * Discovers the correct field names for unlock/lock coroutines
 */
'use strict';

const LOG_LINE = '='.repeat(96);

function inspectObject(obj, label) {
    console.log('\n' + LOG_LINE);
    console.log('[INSPECT] ' + label);
    console.log(LOG_LINE);

    try {
        var fields = obj.getClass().getDeclaredFields();
        console.log('Total fields: ' + fields.length);

        for (var i = 0; i < fields.length; i++) {
            var field = fields[i];
            try {
                field.setAccessible(true);
                var fieldName = field.getName();
                var value = field.get(obj);
                var valueStr = '';

                if (value === null) {
                    valueStr = 'null';
                } else {
                    try {
                        valueStr = value.toString();
                        if (valueStr.length > 100) {
                            valueStr = valueStr.substring(0, 100) + '...';
                        }
                    } catch (e) {
                        valueStr = '[Object: ' + value.getClass().getName() + ']';
                    }
                }

                console.log('  Field[' + i + ']: ' + fieldName + ' = ' + valueStr);

                if (valueStr.indexOf('Bearer') !== -1 || valueStr.indexOf('eyJ') !== -1) {
                    console.log('    ^^^ LOOKS LIKE A TOKEN!');
                }
                if (valueStr.match(/^[A-Z]{3,6}\d{3,4}$/)) {
                    console.log('    ^^^ LOOKS LIKE A SCOOTER SERIAL!');
                }
            } catch (e) {
                console.log('  Field[' + i + ']: ' + field.getName() + ' (error reading: ' + e + ')');
            }
        }
    } catch (e) {
        console.log('Error inspecting: ' + e);
    }

    console.log(LOG_LINE + '\n');
}

Java.perform(function() {
    console.log('[*] MaynDrive Field Discovery - Installing hooks\n');

    function resolveAliases(className) {
        var names = [className];
        var aliasMatch = className.match(/\.C\d+([A-Za-z0-9_]+)$/);
        if (aliasMatch) {
            var simpleName = aliasMatch[1];
            var alias = className.replace(/\.C\d+([A-Za-z0-9_]+)$/, '.' + simpleName);
            if (names.indexOf(alias) === -1) {
                names.push(alias);
            }
        }
        return names;
    }

    function hookCoroutine(target) {
        var candidateNames = resolveAliases(target.className);
        var success = false;
        var lastError = null;

        for (var i = 0; i < candidateNames.length && !success; i++) {
            var name = candidateNames[i];
            try {
                var clazz = Java.use(name);
                var method = clazz.invokeSuspend.overload('java.lang.Object');

                method.implementation = (function(hookedName, hookedMethod) {
                    return function(arg) {
                        console.log('\n\n' + '='.repeat(100));
                        console.log('>>> ' + hookedName + '.invokeSuspend CALLED (' + target.description + ')');
                        console.log('='.repeat(100));

                        try {
                            inspectObject(this, hookedName + ' (Coroutine Instance)');
                        } catch (inspectErr) {
                            console.log('Unable to inspect coroutine instance: ' + inspectErr);
                        }

                        if (arg !== null) {
                            try {
                                inspectObject(arg, 'Argument passed to invokeSuspend');
                            } catch (argErr) {
                                console.log('Argument: ' + arg);
                            }
                        }

                        return hookedMethod.call(this, arg);
                    };
                })(name, method);

                var aliasNotice = name === target.className ? '' : ' [alias for ' + target.className + ']';
                console.log('[+] Hooked ' + name + '.invokeSuspend for field discovery (' + target.description + ')' + aliasNotice + '\n');
                success = true;
            } catch (e) {
                lastError = e;
            }
        }

        if (!success) {
            console.log('[-] Unable to hook ' + target.className + '.invokeSuspend: ' + lastError + '\n');
        }
    }

    var targets = [
        { className: 'B4.Y4', description: 'Unlock (standard)' },
        { className: 'B4.W4', description: 'Unlock (admin/force)' },
        { className: 'B4.M4', description: 'Lock (standard)' },
        { className: 'B4.U4', description: 'Lock (temporary/freefloat)' },
        { className: 'B4.K4', description: 'Lock (admin)' },
        { className: 'B4.A4', description: 'Serial refresh (admin)' },
        { className: 'B4.C4', description: 'Vehicle by serial lookup' },
        { className: 'B4.G4', description: 'Identify freefloat' },
        { className: 'B4.I4', description: 'Identify freefloat (admin)' },
        { className: 'B4.S4', description: 'Shutdown vehicle' },
        { className: 'B4.O4', description: 'Battery door open' },
        { className: 'B4.Q4', description: 'Register vehicle' },
        { className: 'B4.c5', description: 'Serial update (admin refresh)' },
        { className: 'B4.C0366w4', description: 'Nearest parkings' },
        { className: 'B4.C0378y4', description: 'Serial admin lookup' },
        { className: 'B4.E4', description: 'Vehicle models list' },
        { className: 'B4.a5', description: 'External lock code' }
    ];

    targets.forEach(hookCoroutine);

    console.log('[*] Discovery hooks installed!\n');
    console.log('Now UNLOCK or LOCK a scooter and watch the output...\n');
});

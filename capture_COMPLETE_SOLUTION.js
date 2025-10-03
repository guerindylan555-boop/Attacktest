/**
 * MaynDrive full capture script
 *
 * Hooks:
 *   - Coroutine layer (B4.Y4 / B4.M4) for HTTP unlock/lock data
 *   - Socket.io emit/packet flow (bg.p / bg.i)
 *   - Cipher AES/GCM operations for UDP plaintext
 *   - OkHttp RealCall as HTTP backup
 *   - Native sendto/recvfrom for raw UDP payloads
 */
'use strict';

const LOG_LINE = '='.repeat(96);
const LONG_LINE = '='.repeat(100);

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

function resolveAliases(className) {
    var names = [className];
    var match = className.match(/\.C\d+([A-Za-z0-9_]+)$/);
    if (match) {
        var alias = className.replace(/\.C\d+([A-Za-z0-9_]+)$/, '.' + match[1]);
        if (names.indexOf(alias) === -1) {
            names.push(alias);
        }
    }
    return names;
}

function inspectObject(obj, label) {
    if (!obj) {
        console.log('\n' + LOG_LINE);
        console.log('[INSPECT] ' + label + ' (null)');
        console.log(LOG_LINE + '\n');
        return;
    }
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
            } catch (inner) {
                console.log('  Field[' + i + ']: ' + field.getName() + ' (error reading: ' + inner + ')');
            }
        }
    } catch (e) {
        console.log('Error inspecting: ' + e);
    }
    console.log(LOG_LINE + '\n');
}

function readField(instance, fieldName) {
    if (!instance || !fieldName) return null;
    try {
        var value = unwrapField(instance, fieldName);
        if (value !== undefined) {
            return value;
        }
    } catch (ignored) {}
    try {
        var clazz = instance.getClass();
        if (!clazz) return null;
        var field = clazz.getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(instance);
    } catch (ignored2) {
        return null;
    }
}

function extractLocation(location) {
    var result = { lat: null, lng: null };
    if (!location) {
        return result;
    }
    try {
        result.lat = location.getLatitude();
    } catch (ignored) {}
    try {
        result.lng = location.getLongitude();
    } catch (ignored2) {}
    return result;
}

function toNumberSafe(value) {
    if (value === null || value === undefined) return null;
    if (typeof value === 'number') return value;
    try {
        var str = value.toString();
        var num = parseFloat(str);
        if (!isNaN(num)) {
            return num;
        }
    } catch (ignored) {}
    return null;
}

function toBooleanSafe(value) {
    if (value === null || value === undefined) return null;
    if (typeof value === 'boolean') return value;
    if (typeof value === 'number') return value !== 0;
    try {
        var str = value.toString().toLowerCase();
        if (str === 'true') return true;
        if (str === 'false') return false;
        var num = parseInt(str, 10);
        if (!isNaN(num)) return num !== 0;
    } catch (ignored) {}
    return null;
}

function handleUnlock(ctx) {
    var target = ctx.target;
    var instance = ctx.instance;
    var fieldMap = target.fieldMap || {};
    var token = toStringSafe(readField(instance, fieldMap.token));
    var serial = toStringSafe(readField(instance, fieldMap.serial));
    var coords = extractLocation(readField(instance, fieldMap.location));
    var lines = [];
    if (token) lines.push('  Authorization: ' + truncate(token, 60));
    if (serial) lines.push('  Scooter Serial: ' + serial);
    if (coords.lat !== null && coords.lng !== null) {
        lines.push('  Latitude:  ' + coords.lat);
        lines.push('  Longitude: ' + coords.lng);
    }
    var message = {
        type: target.messageType || 'api_coroutine_unlock',
        authorization: token || null,
        serial: serial || null,
        latitude: coords.lat,
        longitude: coords.lng,
        timestamp: nowIso(),
        className: ctx.hookedName
    };
    if (target.extraFields && target.extraFields.length) {
        target.extraFields.forEach(function(def) {
            var raw = readField(instance, def.field);
            var value;
            if (def.type === 'boolean') {
                value = toBooleanSafe(raw);
            } else if (def.type === 'number') {
                value = toNumberSafe(raw);
            } else {
                value = toStringSafe(raw);
            }
            if (value !== null && value !== undefined) {
                lines.push('  ' + def.label + ': ' + value);
            }
            if (def.key) {
                message[def.key] = value;
            }
        });
    }
    logBlock('[COROUTINE] ' + target.description + ' (' + ctx.hookedName + ')', lines);
    send(message);
    if (target.dumpFields) {
        inspectObject(instance, ctx.hookedName + ' (Coroutine Instance)');
    }
    if (target.inspectArg && ctx.arg !== null && ctx.arg !== undefined) {
        try {
            inspectObject(ctx.arg, 'Argument passed to ' + ctx.hookedName);
        } catch (argErr) {
            console.log('Argument: ' + ctx.arg);
        }
    }
}

function handleLock(ctx) {
    var target = ctx.target;
    var instance = ctx.instance;
    var fieldMap = target.fieldMap || {};
    var token = toStringSafe(readField(instance, fieldMap.token));
    var lines = [];
    if (token) lines.push('  Authorization: ' + truncate(token, 60));
    var message = {
        type: target.messageType || 'api_coroutine_lock',
        authorization: token || null,
        timestamp: nowIso(),
        className: ctx.hookedName
    };
    if (target.extraFields && target.extraFields.length) {
        target.extraFields.forEach(function(def) {
            var raw = readField(instance, def.field);
            var value;
            if (def.type === 'boolean') {
                value = toBooleanSafe(raw);
            } else if (def.type === 'number') {
                value = toNumberSafe(raw);
            } else {
                value = toStringSafe(raw);
            }
            if (value !== null && value !== undefined) {
                lines.push('  ' + def.label + ': ' + value);
            }
            if (def.key) {
                message[def.key] = value;
            }
        });
    }
    logBlock('[COROUTINE] ' + target.description + ' (' + ctx.hookedName + ')', lines);
    send(message);
    if (target.dumpFields) {
        inspectObject(instance, ctx.hookedName + ' (Coroutine Instance)');
    }
    if (target.inspectArg && ctx.arg !== null && ctx.arg !== undefined) {
        try {
            inspectObject(ctx.arg, 'Argument passed to ' + ctx.hookedName);
        } catch (argErr) {
            console.log('Argument: ' + ctx.arg);
        }
    }
}

function handleGeneric(ctx) {
    console.log('\n\n' + LONG_LINE);
    console.log('>>> ' + ctx.hookedName + '.invokeSuspend CALLED (' + ctx.target.description + ')');
    console.log(LONG_LINE);
    try {
        inspectObject(ctx.instance, ctx.hookedName + ' (Coroutine Instance)');
    } catch (e) {
        console.log('Unable to inspect coroutine instance: ' + e);
    }
    if (ctx.target.inspectArg && ctx.arg !== null && ctx.arg !== undefined) {
        try {
            inspectObject(ctx.arg, 'Argument passed to ' + ctx.hookedName);
        } catch (argErr) {
            console.log('Argument: ' + ctx.arg);
        }
    }
    console.log(LONG_LINE + '\n');
}

var handlerMap = {
    unlock: handleUnlock,
    lock: handleLock,
    generic: handleGeneric
};

function hookCoroutineTarget(target) {
    var handler = target.handler || handlerMap[target.type];
    if (!handler) {
        console.log('[-] No handler defined for ' + target.className);
        return;
    }
    var candidates = resolveAliases(target.className);
    var success = false;
    var lastError = null;
    for (var i = 0; i < candidates.length && !success; i++) {
        var name = candidates[i];
        try {
            var clazz = Java.use(name);
            var original = clazz.invokeSuspend.overload('java.lang.Object');
            original.implementation = (function(hookedName, originalMethod) {
                return function(arg) {
                    try {
                        handler({
                            instance: this,
                            arg: arg,
                            hookedName: hookedName,
                            target: target
                        });
                    } catch (handlerError) {
                        console.log('[-] Handler error for ' + hookedName + ': ' + handlerError);
                    }
                    return originalMethod.call(this, arg);
                };
            })(name, original);
            var note = name !== target.className ? ' [alias for ' + target.className + ']' : '';
            console.log('[+] Hooked ' + name + '.invokeSuspend (' + target.description + ')' + note);
            success = true;
        } catch (e) {
            lastError = e;
        }
    }
    if (!success) {
        console.log('[-] Unable to hook ' + target.className + '.invokeSuspend: ' + lastError);
    }
}

function truncate(str, maxLen) {
    if (!str) return '';
    if (str.length <= maxLen) return str;
    return str.substring(0, maxLen) + '...';
}

function nowIso() {
    return new Date().toISOString();
}

Java.perform(function() {
    console.log('[*] MaynDrive Full Capture - installing Java hooks');
    console.log('');

    // Coroutine and admin hooks
    var coroutineTargets = [
        {
            className: 'B4.Y4',
            description: 'Unlock (standard)',
            type: 'unlock',
            fieldMap: { token: 'f2925Z', serial: 'f2927g0', location: 'f2928h0' },
            messageType: 'api_coroutine_unlock'
        },
        {
            className: 'B4.W4',
            description: 'Unlock (admin/force)',
            type: 'unlock',
            fieldMap: { token: 'f2878Z', serial: 'f2880g0', location: 'f2881h0' },
            messageType: 'api_coroutine_unlock_admin',
            extraFields: [
                { label: 'Force', field: 'f2882i0', type: 'boolean', key: 'force' }
            ],
            dumpFields: true,
            inspectArg: true
        },
        {
            className: 'B4.M4',
            description: 'Lock (standard)',
            type: 'lock',
            fieldMap: { token: 'f2661Z' },
            messageType: 'api_coroutine_lock',
            extraFields: [
                { label: 'Pass / Vehicle ID', field: 'f2663g0', type: 'number', key: 'passId' },
                { label: 'Temporary', field: 'f2664h0', type: 'boolean', key: 'temporary' }
            ]
        },
        {
            className: 'B4.U4',
            description: 'Lock (temporary/freefloat)',
            type: 'lock',
            fieldMap: { token: 'f2836Z' },
            messageType: 'api_coroutine_lock_temporary',
            extraFields: [
                { label: 'Vehicle ID', field: 'f2838g0', type: 'number', key: 'vehicleId' },
                { label: 'Temporary', field: 'f2839h0', type: 'boolean', key: 'temporary' }
            ],
            dumpFields: true,
            inspectArg: true
        },
        {
            className: 'B4.K4',
            description: 'Lock (admin)',
            type: 'lock',
            fieldMap: { token: 'f2617Z' },
            messageType: 'api_coroutine_lock_admin',
            extraFields: [
                { label: 'Serial', field: 'f2619g0', type: 'string', key: 'serial' },
                { label: 'Force', field: 'f2620h0', type: 'boolean', key: 'force' }
            ],
            dumpFields: true,
            inspectArg: true
        },
        {
            className: 'B4.A4',
            description: 'Serial refresh (admin)',
            type: 'generic',
            dumpFields: true,
            inspectArg: true
        },
        {
            className: 'B4.C4',
            description: 'Vehicle by serial lookup',
            type: 'generic',
            dumpFields: true,
            inspectArg: true
        },
        {
            className: 'B4.G4',
            description: 'Identify freefloat',
            type: 'generic',
            dumpFields: true,
            inspectArg: true
        },
        {
            className: 'B4.I4',
            description: 'Identify freefloat (admin)',
            type: 'generic',
            dumpFields: true,
            inspectArg: true
        },
        {
            className: 'B4.S4',
            description: 'Shutdown vehicle',
            type: 'generic',
            dumpFields: true,
            inspectArg: true
        },
        {
            className: 'B4.O4',
            description: 'Battery door open',
            type: 'generic',
            dumpFields: true,
            inspectArg: true
        },
        {
            className: 'B4.Q4',
            description: 'Register vehicle',
            type: 'generic',
            dumpFields: true,
            inspectArg: true
        },
        {
            className: 'B4.c5',
            description: 'Serial update (admin refresh)',
            type: 'generic',
            dumpFields: true,
            inspectArg: true
        },
        {
            className: 'B4.C0366w4',
            description: 'Nearest parkings',
            type: 'generic',
            dumpFields: true,
            inspectArg: true
        },
        {
            className: 'B4.C0378y4',
            description: 'Serial admin lookup',
            type: 'generic',
            dumpFields: true,
            inspectArg: true
        },
        {
            className: 'B4.E4',
            description: 'Vehicle models list',
            type: 'generic',
            dumpFields: true,
            inspectArg: true
        },
        {
            className: 'B4.a5',
            description: 'External lock code',
            type: 'generic',
            dumpFields: true,
            inspectArg: true
        }
    ];

    coroutineTargets.forEach(hookCoroutineTarget);
    console.log('');

    // Cipher AES/GCM (UDP plaintext)
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        var doFinalBytes = Cipher.doFinal.overload('[B');
        doFinalBytes.implementation = function(input) {
            var result = doFinalBytes.call(this, input);
            try {
                var algorithm = this.getAlgorithm();
                if (algorithm && algorithm.indexOf('AES/GCM') !== -1 && input && input.length > 0) {
                    var length = input.length;
                    if (length >= 50 && length <= 512) {
                        var hex = hexFromArray(input, Math.min(length, 256));
                        console.log('\n' + LOG_LINE);
                        console.log('[CIPHER] AES/GCM doFinal captured');
                        console.log('  Algorithm : ' + algorithm);
                        console.log('  Input len : ' + length + ' bytes');
                        console.log(LOG_LINE);
                        console.log(hex);
                        console.log(LOG_LINE + '\n');

                        send({
                            type: 'udp_cipher_plaintext',
                            algorithm: algorithm,
                            length: length,
                            hex: hex,
                            timestamp: nowIso()
                        });
                    }
                }
            } catch (inner) {
                console.log('[-] Cipher hook error: ' + inner);
            }
            return result;
        };
        console.log('[+] Hooked javax.crypto.Cipher.doFinal(byte[])');
    } catch (e) {
        console.log('[-] Unable to hook Cipher.doFinal: ' + e);
    }
    console.log('');

    // Socket.io emit / packet flow
    try {
        var SocketIOSocket = Java.use('bg.p');
        var emit = SocketIOSocket.u;
        emit.implementation = function(eventName, args) {
            var argList = [];
            try {
                if (args) {
                    var len = args.length;
                    for (var i = 0; i < len; i++) {
                        var element = args[i];
                        argList.push(element ? element.toString() : 'null');
                    }
                }
            } catch (ignored) {}

            console.log('\n' + LOG_LINE);
            console.log('[SOCKET.IO] emit("' + eventName + '")');
            if (argList.length > 0) {
                for (var j = 0; j < argList.length; j++) {
                    console.log('  Arg[' + j + ']: ' + argList[j]);
                }
            } else {
                console.log('  (no arguments)');
            }
            console.log(LOG_LINE + '\n');

            send({
                type: 'socketio_emit',
                event: eventName,
                arguments: argList,
                timestamp: nowIso()
            });

            return emit.call(this, eventName, args);
        };
        console.log('[+] Hooked Socket.io emit (bg.p.u)');
    } catch (e) {
        console.log('[-] Unable to hook Socket.io emit: ' + e);
    }

    try {
        var SocketIOManager = Java.use('bg.i');
        var sendPacket = SocketIOManager.Q;
        sendPacket.implementation = function(packet) {
            var info = null;
            try {
                info = packet ? packet.toString() : null;
            } catch (ignored) {}

            if (info) {
                console.log('\n' + LOG_LINE);
                console.log('[SOCKET.IO] packet send: ' + info);
                console.log(LOG_LINE + '\n');
                send({
                    type: 'socketio_packet',
                    packet: info,
                    timestamp: nowIso()
                });
            }

            return sendPacket.call(this, packet);
        };
        console.log('[+] Hooked Socket.io packet sender (bg.i.Q)');
    } catch (e) {
        console.log('[-] Unable to hook Socket.io manager: ' + e);
    }
    console.log('');

    // OkHttp backup (qh.h)
    try {
        var RealCall = Java.use('qh.h');
        var execute = RealCall.h.overload();
        execute.implementation = function() {
            try {
                var request = unwrapField(this, 'f41886Y');
                if (request) {
                    var url = toStringSafe(unwrapField(request, 'f44085b'));
                    var method = toStringSafe(unwrapField(request, 'f44084a'));
                    if (url && url.indexOf('/api/application/passes/') !== -1 && (url.indexOf('/activate') !== -1 || url.indexOf('/deactivate') !== -1)) {
                        var passMatch = /\/passes\/(\d+)/.exec(url);
                        var passId = passMatch ? passMatch[1] : null;
                        var headers = unwrapField(request, 'f44086c');
                        var authorization = null;
                        if (headers && headers.b) {
                            try { authorization = headers.b('Authorization'); } catch (ignored) {}
                        }

                        console.log('\n' + LOG_LINE);
                        console.log('[HTTP] ' + method + ' ' + url);
                        if (passId) console.log('  Pass ID: ' + passId);
                        if (authorization) console.log('  Authorization: ' + truncate(authorization, 60));
                        console.log(LOG_LINE + '\n');

                        send({
                            type: url.indexOf('/activate') !== -1 ? 'api_http_unlock' : 'api_http_lock',
                            method: method,
                            url: url,
                            authorization: authorization || null,
                            passId: passId,
                            timestamp: nowIso()
                        });
                    }
                }
            } catch (inner) {
                console.log('[-] OkHttp hook error: ' + inner);
            }
            return execute.call(this);
        };
        console.log('[+] Hooked qh.h.h() (OkHttp RealCall.execute)');
    } catch (e) {
        console.log('[-] Unable to hook qh.h.h(): ' + e);
    }

    console.log('\n[*] Java layer hooks installed');
});

function hexFromMemory(ptr, length, limit) {
    if (!ptr) return '';
    var max = Math.min(length, limit || length);
    var lines = [];
    for (var offset = 0; offset < max; offset += 16) {
        var hexBytes = [];
        var ascii = [];
        for (var i = 0; i < 16 && offset + i < max; i++) {
            var value = ptr.add(offset + i).readU8();
            hexBytes.push(('0' + value.toString(16)).slice(-2));
            ascii.push(value >= 32 && value <= 126 ? String.fromCharCode(value) : '.');
        }
        while (hexBytes.length < 16) hexBytes.push('  ');
        lines.push(('0000' + offset.toString(16)).slice(-4) + '  ' + hexBytes.join(' ') + '  |' + ascii.join('') + '|');
    }
    return lines.join('\n');
}

function hexFromArray(bytes, limit) {
    var lines = [];
    var max = Math.min(bytes.length, limit || bytes.length);
    for (var offset = 0; offset < max; offset += 16) {
        var chunk = [];
        for (var i = 0; i < 16 && offset + i < max; i++) {
            var value = bytes[offset + i] & 0xff;
            chunk.push(('0' + value.toString(16)).slice(-2));
        }
        while (chunk.length < 16) chunk.push('  ');
        lines.push(('0000' + offset.toString(16)).slice(-4) + '  ' + chunk.join(' '));
    }
    return lines.join('\n');
}

function installNativeHooks() {
    try {
        var sendtoPtr = Module.findExportByName('libc.so', 'sendto');
        if (sendtoPtr) {
            Interceptor.attach(sendtoPtr, {
                onEnter: function(args) {
                    this.sockfd = args[0].toInt32();
                    this.buffer = args[1];
                    this.length = args[2].toInt32();
                    this.dest = args[4];
                },
                onLeave: function(retval) {
                    if (!this.buffer || this.length <= 0) return;
                    if (this.length >= 80 && this.length <= 300) {
                        var destination = null;
                        try {
                            var family = this.dest.readU16();
                            if (family === 2) {
                                var port = (this.dest.add(2).readU8() << 8) | this.dest.add(3).readU8();
                                var ip = [4,5,6,7].map(i => this.dest.add(i).readU8()).join('.');
                                destination = ip + ':' + port;
                            }
                        } catch (ignored) {}

                        var hex = hexFromMemory(this.buffer, this.length, 256);
                        console.log('\n' + LOG_LINE);
                        console.log('[UDP] sendto socket=' + this.sockfd + (destination ? ' -> ' + destination : ''));
                        console.log('  Length: ' + this.length + ' bytes');
                        console.log(LOG_LINE);
                        console.log(hex);
                        console.log(LOG_LINE + '\n');

                        send({
                            type: 'udp_sendto',
                            socket: this.sockfd,
                            length: this.length,
                            destination: destination,
                            hex: hex,
                            timestamp: nowIso()
                        });
                    }
                }
            });
            console.log('[+] Hooked native sendto');
        }
    } catch (e) {
        console.log('[-] Unable to hook sendto: ' + e);
    }

    try {
        var recvfromPtr = Module.findExportByName('libc.so', 'recvfrom');
        if (recvfromPtr) {
            Interceptor.attach(recvfromPtr, {
                onEnter: function(args) {
                    this.sockfd = args[0].toInt32();
                    this.buffer = args[1];
                },
                onLeave: function(retval) {
                    var bytesRead = retval.toInt32();
                    if (bytesRead > 400) {
                        var hex = hexFromMemory(this.buffer, bytesRead, 256);
                        console.log('\n' + LOG_LINE);
                        console.log('[UDP] recvfrom socket=' + this.sockfd + ' length=' + bytesRead);
                        console.log(LOG_LINE);
                        console.log(hex);
                        console.log(LOG_LINE + '\n');

                        send({
                            type: 'udp_recvfrom',
                            socket: this.sockfd,
                            length: bytesRead,
                            hex: hex,
                            timestamp: nowIso()
                        });
                    }
                }
            });
            console.log('[+] Hooked native recvfrom');
        }
    } catch (e) {
        console.log('[-] Unable to hook recvfrom: ' + e);
    }
}

setImmediate(installNativeHooks);





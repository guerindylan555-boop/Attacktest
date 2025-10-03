import frida
import sys
import datetime
import os
import json
import subprocess
import time

PACKAGE_NAME = "fr.mayndrive.app"
SCRIPT_FILE = "capture_COMPLETE_SOLUTION.js"  # Has BOTH coroutine hooks AND cipher decryption
OUTPUT_FILE = "CAPTURED_API_DECRYPT.txt"
OUTPUT_JSON = "CAPTURED_API_DECRYPT.json"

captured_data = []

def append_record(record):
    captured_data.append(record)
    with open(OUTPUT_JSON, 'w', encoding='utf-8') as jf:
        json.dump(captured_data, jf, indent=2, ensure_ascii=False)

def write_block(title, lines):
    with open(OUTPUT_FILE, 'a', encoding='utf-8') as f:
        separator = '=' * 100
        f.write(f"\n{separator}\n")
        f.write(f"{title}\n")
        f.write(f"{separator}\n")
        for line in lines:
            f.write(f"{line}\n")
        f.write(f"{separator}\n")

def restart_frida_server():
    print("[!] Restarting frida-server on device...")
    commands = [
        ["adb", "shell", "su", "-c", "pkill frida-server"],
        ["adb", "shell", "su", "-c", "/data/local/tmp/frida-server &"]
    ]
    for cmd in commands:
        try:
            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        except FileNotFoundError:
            print("[-] adb not found in PATH. Please restart frida-server manually.")
            return False
    time.sleep(2)
    print("[+] frida-server restart issued")
    return True

def on_message(message, data):
    if message['type'] != 'send':
        if message['type'] == 'error':
            print(f"[ERROR] {message.get('description', message)}")
        else:
            print(f"[*] {message}")
        return

    payload = message.get('payload', {})
    msg_type = payload.get('type', 'unknown')
    timestamp = datetime.datetime.now().isoformat()

    def log_header(header_lines):
        separator = '=' * 100
        print(f"\n{separator}")
        for line in header_lines:
            print(line)
        print(f"{separator}\n")
    def shorten_auth(auth_value):
        return auth_value[:60] + '...' if auth_value and len(auth_value) > 60 else auth_value
    if msg_type == 'api_coroutine_unlock':
        auth = payload.get('authorization')
        serial = payload.get('serial')
        lat = payload.get('latitude')
        lng = payload.get('longitude')
        class_name = payload.get('className')
        header_lines = [
            f"[{timestamp}] [COROUTINE] Unlock captured"
        ]
        if class_name:
            header_lines.append(f"Class: {class_name}")
        header_lines.extend([
            f"Authorization: {shorten_auth(auth)}",
            f"Serial: {serial}",
            f"Latitude: {lat}",
            f"Longitude: {lng}"
        ])
        log_header(header_lines)
        append_record({
            'timestamp': timestamp,
            'type': msg_type,
            'authorization': auth,
            'serial': serial,
            'latitude': lat,
            'longitude': lng,
            'className': class_name
        })
        block_lines = []
        if class_name:
            block_lines.append(f"Class: {class_name}")
        block_lines.extend([
            f"Authorization: {auth}",
            f"Serial: {serial}",
            f"Latitude: {lat}",
            f"Longitude: {lng}"
        ])
        write_block(f"[{timestamp}] [COROUTINE UNLOCK]", block_lines)
        return

    if msg_type == 'api_coroutine_unlock_admin':
        auth = payload.get('authorization')
        serial = payload.get('serial')
        lat = payload.get('latitude')
        lng = payload.get('longitude')
        force = payload.get('force')
        class_name = payload.get('className')
        header_lines = [
            f"[{timestamp}] [COROUTINE] Admin unlock captured"
        ]
        if class_name:
            header_lines.append(f"Class: {class_name}")
        header_lines.extend([
            f"Authorization: {shorten_auth(auth)}",
            f"Serial: {serial}",
            f"Latitude: {lat}",
            f"Longitude: {lng}",
            f"Force: {force}"
        ])
        log_header(header_lines)
        append_record({
            'timestamp': timestamp,
            'type': msg_type,
            'authorization': auth,
            'serial': serial,
            'latitude': lat,
            'longitude': lng,
            'force': force,
            'className': class_name
        })
        block_lines = []
        if class_name:
            block_lines.append(f"Class: {class_name}")
        block_lines.extend([
            f"Authorization: {auth}",
            f"Serial: {serial}",
            f"Latitude: {lat}",
            f"Longitude: {lng}",
            f"Force: {force}"
        ])
        write_block(f"[{timestamp}] [COROUTINE ADMIN UNLOCK]", block_lines)
        return

    if msg_type == 'api_coroutine_lock':
        auth = payload.get('authorization')
        pass_id = payload.get('passId')
        temporary = payload.get('temporary')
        class_name = payload.get('className')
        header_lines = [
            f"[{timestamp}] [COROUTINE] Lock captured"
        ]
        if class_name:
            header_lines.append(f"Class: {class_name}")
        header_lines.extend([
            f"Authorization: {shorten_auth(auth)}",
            f"Pass ID: {pass_id}",
            f"Temporary: {temporary}"
        ])
        log_header(header_lines)
        append_record({
            'timestamp': timestamp,
            'type': msg_type,
            'authorization': auth,
            'passId': pass_id,
            'temporary': temporary,
            'className': class_name
        })
        block_lines = []
        if class_name:
            block_lines.append(f"Class: {class_name}")
        block_lines.extend([
            f"Authorization: {auth}",
            f"Pass ID: {pass_id}",
            f"Temporary: {temporary}"
        ])
        write_block(f"[{timestamp}] [COROUTINE LOCK]", block_lines)
        return

    if msg_type == 'api_coroutine_lock_temporary':
        auth = payload.get('authorization')
        vehicle_id = payload.get('vehicleId')
        temporary = payload.get('temporary')
        class_name = payload.get('className')
        header_lines = [
            f"[{timestamp}] [COROUTINE] Temporary lock captured"
        ]
        if class_name:
            header_lines.append(f"Class: {class_name}")
        header_lines.extend([
            f"Authorization: {shorten_auth(auth)}",
            f"Vehicle ID: {vehicle_id}",
            f"Temporary: {temporary}"
        ])
        log_header(header_lines)
        append_record({
            'timestamp': timestamp,
            'type': msg_type,
            'authorization': auth,
            'vehicleId': vehicle_id,
            'temporary': temporary,
            'className': class_name
        })
        block_lines = []
        if class_name:
            block_lines.append(f"Class: {class_name}")
        block_lines.extend([
            f"Authorization: {auth}",
            f"Vehicle ID: {vehicle_id}",
            f"Temporary: {temporary}"
        ])
        write_block(f"[{timestamp}] [COROUTINE TEMP LOCK]", block_lines)
        return

    if msg_type == 'api_coroutine_lock_admin':
        auth = payload.get('authorization')
        serial = payload.get('serial')
        force = payload.get('force')
        class_name = payload.get('className')
        header_lines = [
            f"[{timestamp}] [COROUTINE] Admin lock captured"
        ]
        if class_name:
            header_lines.append(f"Class: {class_name}")
        header_lines.extend([
            f"Authorization: {shorten_auth(auth)}",
            f"Serial: {serial}",
            f"Force: {force}"
        ])
        log_header(header_lines)
        append_record({
            'timestamp': timestamp,
            'type': msg_type,
            'authorization': auth,
            'serial': serial,
            'force': force,
            'className': class_name
        })
        block_lines = []
        if class_name:
            block_lines.append(f"Class: {class_name}")
        block_lines.extend([
            f"Authorization: {auth}",
            f"Serial: {serial}",
            f"Force: {force}"
        ])
        write_block(f"[{timestamp}] [COROUTINE ADMIN LOCK]", block_lines)
        return

    if msg_type in ('api_http_unlock', 'api_http_lock'):
        auth = payload.get('authorization')
        url = payload.get('url')
        pass_id = payload.get('passId')
        method = payload.get('method')
        log_header([
            f"[{timestamp}] [HTTP BACKUP] {msg_type}",
            f"Method: {method}",
            f"URL: {url}",
            f"Pass ID: {pass_id}",
            f"Authorization: {auth[:60] + '...' if auth and len(auth) > 60 else auth}"
        ])
        append_record({
            'timestamp': timestamp,
            'type': msg_type,
            'method': method,
            'url': url,
            'authorization': auth,
            'passId': pass_id
        })
        write_block(f"[{timestamp}] [HTTP {msg_type.upper()}]", [
            f"Method: {method}",
            f"URL: {url}",
            f"Pass ID: {pass_id}",
            f"Authorization: {auth}"
        ])
        return

    if msg_type == 'cipher_plaintext':
        algorithm = payload.get('algorithm')
        operation = payload.get('operation')
        length = payload.get('length')
        hex_dump = payload.get('hex', '')
        text_content = payload.get('text', '')
        log_header([
            f"[{timestamp}] [PLAINTEXT BEFORE ENCRYPTION]",
            f"Algorithm: {algorithm}",
            f"Operation: {operation}",
            f"Length: {length} bytes",
            f"",
            f"HEX DUMP:",
            hex_dump,
            f"",
            f"TEXT CONTENT:",
            text_content
        ])
        append_record({
            'timestamp': timestamp,
            'type': msg_type,
            'algorithm': algorithm,
            'operation': operation,
            'length': length,
            'hex': hex_dump,
            'text': text_content
        })
        write_block(f"[{timestamp}] [PLAINTEXT BEFORE ENCRYPTION]", [
            f"Algorithm: {algorithm}",
            f"Operation: {operation}",
            f"Length: {length} bytes",
            "",
            "HEX DUMP:",
            hex_dump,
            "",
            "TEXT CONTENT:",
            text_content
        ])
        return

    if msg_type == 'udp_cipher_plaintext':
        algorithm = payload.get('algorithm')
        length = payload.get('length')
        hex_dump = payload.get('hex', '')
        log_header([
            f"[{timestamp}] [UDP CIPHER PLAINTEXT]",
            f"Algorithm: {algorithm}",
            f"Length: {length} bytes"
        ])
        append_record({
            'timestamp': timestamp,
            'type': msg_type,
            'algorithm': algorithm,
            'length': length,
            'hex': hex_dump
        })
        write_block(f"[{timestamp}] [UDP CIPHER PLAINTEXT]", [
            f"Algorithm: {algorithm}",
            f"Length: {length} bytes",
            hex_dump
        ])
        return

    if msg_type in ('udp_sendto', 'udp_recvfrom'):
        length = payload.get('length')
        socket = payload.get('socket')
        destination = payload.get('destination')
        hex_dump = payload.get('hex', '')
        log_header([
            f"[{timestamp}] [UDP {'SEND' if msg_type.endswith('sendto') else 'RECV'}]",
            f"Socket: {socket}",
            f"Length: {length} bytes",
            f"Destination: {destination}"
        ])
        append_record({
            'timestamp': timestamp,
            'type': msg_type,
            'socket': socket,
            'length': length,
            'destination': destination,
            'hex': hex_dump
        })
        write_block(f"[{timestamp}] [UDP {msg_type.upper()}]", [
            f"Socket: {socket}",
            f"Length: {length} bytes",
            f"Destination: {destination}",
            hex_dump
        ])
        return

    if msg_type in ('socketio_emit', 'socketio_packet'):
        event = payload.get('event')
        args = payload.get('arguments', [])
        packet = payload.get('packet')
        if msg_type == 'socketio_emit':
            lines = [
                f"[{timestamp}] [SOCKET.IO EMIT]",
                f"Event: {event}",
            ] + [f"Arg[{idx}]: {value}" for idx, value in enumerate(args)]
            log_header(lines)
            append_record({
                'timestamp': timestamp,
                'type': msg_type,
                'event': event,
                'arguments': args
            })
            write_block(f"[{timestamp}] [SOCKET.IO EMIT] {event}", [f"Arg[{idx}]: {value}" for idx, value in enumerate(args)])
        else:
            log_header([
                f"[{timestamp}] [SOCKET.IO PACKET]",
                packet or ''
            ])
            append_record({
                'timestamp': timestamp,
                'type': msg_type,
                'packet': packet
            })
            write_block(f"[{timestamp}] [SOCKET.IO PACKET]", [packet or ''])
        return

    data_blob = payload.get('hex') or payload.get('data') or json.dumps(payload, ensure_ascii=False)
    log_header([
        f"[{timestamp}] [{msg_type.upper()}]",
        data_blob[:2000]
    ])
    append_record({
        'timestamp': timestamp,
        'type': msg_type,
        'data': data_blob
    })
    write_block(f"[{timestamp}] [{msg_type.upper()}]", [data_blob])

def main():
    print('=' * 100)
    print('  MAYNDRIVE COMPLETE CAPTURE (HTTP + Cipher + UDP)')
    print('=' * 100)
    print('')

    for file_path in (OUTPUT_FILE, OUTPUT_JSON):
        if os.path.exists(file_path):
            os.remove(file_path)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('=== MAYNDRIVE COMPLETE CAPTURE ===\n')
        f.write(f'Started: {datetime.datetime.now().isoformat()}\n')
        f.write('=' * 100 + '\n')

    session = None
    script = None

    try:
        device = frida.get_usb_device(timeout=10)
        print(f"[+] Device: {device.name}")

        with open(SCRIPT_FILE, 'r', encoding='utf-8') as f:
            script_code = f.read()

        print('[*] Spawning app via Frida...')
        try:
            pid = device.spawn([PACKAGE_NAME])
        except frida.TransportError as err:
            print(f"[!] Spawn failed: {err}")
            if restart_frida_server():
                device = frida.get_usb_device(timeout=10)
                print('[*] Retrying spawn...')
                pid = device.spawn([PACKAGE_NAME])
            else:
                raise

        session = device.attach(pid)
        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        device.resume(pid)

        print('')
        print('=' * 100)
        print('  READY TO CAPTURE (ALL LAYERS)')
        print('=' * 100)
        print('')
        print('  Follow these steps in order:')
        print('    1. Wait for the app launched by Frida (do NOT open it manually)')
        print('    2. Log in to your account if required')
        print('    3. Select a scooter (e.g. TUF061)')
        print('    4. Press UNLOCK and LOCK')
        print('    5. Watch for "[COROUTINE]" messages with unlock/lock data')
        print('')
        print('  What you will see:')
        print('    - [COROUTINE] = Unlock/Lock HTTP requests with Bearer token')
        print('    - [UDP CIPHER PLAINTEXT] = Decrypted telemetry data')
        print('    - [UDP SEND/RECV] = Raw encrypted UDP packets')
        print('')
        print('  Notes:')
        print('    - Stay inside the spawned instance (do not switch apps)')
        print('    - Leave this window open until you finish testing')
        print('    - Press Ctrl+C here when you are done capturing')
        print('')
        print('=' * 100)
        print('')
        print('Waiting for traffic...')
        print('')

        try:
            sys.stdin.read()
        except KeyboardInterrupt:
            pass
    finally:
        try:
            if script is not None:
                script.off('message', on_message)
        except Exception:
            pass
        try:
            if session is not None:
                session.detach()
        except Exception:
            pass

        print('')
        print('[OK] Capture stopped')
        print(f'   Items captured: {len(captured_data)}')
        print(f'   Text log     : {OUTPUT_FILE}')
        print(f'   JSON export  : {OUTPUT_JSON}')
        print('')

if __name__ == '__main__':
    main()






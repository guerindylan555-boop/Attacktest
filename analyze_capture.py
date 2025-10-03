#!/usr/bin/env python3
"""
Analyze captured MaynDrive traffic
Finds patterns, timing, and potential plaintext
"""

import re
import sys
from datetime import datetime
from collections import defaultdict

def parse_captured_file(filename):
    """Parse CAPTURED_API.txt and extract all events"""
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    events = []
    
    # Pattern: [timestamp] [type]
    pattern = r'\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)\] \[(.*?)\]'
    
    # Split by log lines
    sections = re.split(r'={70,}', content)
    
    for section in sections:
        # Find timestamp and type
        match = re.search(pattern, section)
        if not match:
            continue
        
        timestamp_str, event_type = match.groups()
        timestamp = datetime.fromisoformat(timestamp_str)
        
        # Extract more details
        details = {}
        
        # Socket number
        socket_match = re.search(r'Socket:\s*(\d+)', section)
        if socket_match:
            details['socket'] = int(socket_match.group(1))
        
        # Length
        length_match = re.search(r'Length:\s*(\d+)', section)
        if length_match:
            details['length'] = int(length_match.group(1))
        
        # Direction (SEND/RECV)
        details['direction'] = 'SEND' if 'SEND' in event_type or 'sendto' in event_type else 'RECV'
        
        # Hex data
        hex_data = re.findall(r'([0-9a-f]{2})', section, re.IGNORECASE)
        if hex_data:
            details['hex'] = hex_data
            details['bytes'] = bytes(int(h, 16) for h in hex_data[:512])  # First 512 bytes
            
            # Try to find ASCII strings
            ascii_strings = []
            current_string = []
            for byte_val in details['bytes']:
                if 32 <= byte_val <= 126:
                    current_string.append(chr(byte_val))
                else:
                    if len(current_string) >= 4:
                        ascii_strings.append(''.join(current_string))
                    current_string = []
            if len(current_string) >= 4:
                ascii_strings.append(''.join(current_string))
            
            if ascii_strings:
                details['ascii_strings'] = ascii_strings
        
        events.append({
            'timestamp': timestamp,
            'type': event_type,
            'details': details
        })
    
    return events

def analyze_timing(events):
    """Analyze timing patterns"""
    print("\n" + "="*80)
    print("TIMING ANALYSIS")
    print("="*80)
    
    if not events:
        print("No events found")
        return
    
    # Calculate offsets from start
    start_time = events[0]['timestamp']
    for event in events:
        event['offset_ms'] = (event['timestamp'] - start_time).total_seconds() * 1000
    
    # Find clusters (events within 100ms)
    clusters = []
    current_cluster = [events[0]]
    
    for event in events[1:]:
        time_diff = event['offset_ms'] - current_cluster[-1]['offset_ms']
        if time_diff < 100:
            current_cluster.append(event)
        else:
            if len(current_cluster) > 1:
                clusters.append(current_cluster)
            current_cluster = [event]
    
    if len(current_cluster) > 1:
        clusters.append(current_cluster)
    
    print(f"\nTotal events: {len(events)}")
    print(f"Duration: {events[-1]['offset_ms']:.0f}ms ({events[-1]['offset_ms']/1000:.1f}s)")
    print(f"Traffic bursts: {len(clusters)}")
    
    print("\n=== BURSTS (>1 packet within 100ms) ===")
    for i, cluster in enumerate(clusters[:10]):  # Show first 10
        duration = cluster[-1]['offset_ms'] - cluster[0]['offset_ms']
        print(f"\nBurst #{i+1}:")
        print(f"  Time: {cluster[0]['offset_ms']:.0f}ms from start")
        print(f"  Packets: {len(cluster)}")
        print(f"  Duration: {duration:.0f}ms")
        print(f"  Types: {set(e['type'] for e in cluster)}")

def analyze_sockets(events):
    """Analyze socket patterns"""
    print("\n" + "="*80)
    print("SOCKET ANALYSIS")
    print("="*80)
    
    socket_stats = defaultdict(lambda: {'send': 0, 'recv': 0, 'bytes_send': 0, 'bytes_recv': 0})
    
    for event in events:
        socket = event['details'].get('socket')
        if socket:
            direction = event['details']['direction']
            length = event['details'].get('length', 0)
            
            if direction == 'SEND':
                socket_stats[socket]['send'] += 1
                socket_stats[socket]['bytes_send'] += length
            else:
                socket_stats[socket]['recv'] += 1
                socket_stats[socket]['bytes_recv'] += length
    
    print("\n=== SOCKET ACTIVITY ===")
    for socket, stats in sorted(socket_stats.items()):
        total = stats['send'] + stats['recv']
        total_bytes = stats['bytes_send'] + stats['bytes_recv']
        print(f"\nSocket {socket}:")
        print(f"  Packets: {total} ({stats['send']} sent, {stats['recv']} received)")
        print(f"  Bytes:   {total_bytes} ({stats['bytes_send']} sent, {stats['bytes_recv']} received)")
        if total > 0:
            print(f"  Avg size: {total_bytes/total:.0f} bytes/packet")

def analyze_encryption(events):
    """Analyze encryption patterns"""
    print("\n" + "="*80)
    print("ENCRYPTION ANALYSIS")
    print("="*80)
    
    tls_handshake = 0
    tls_app_data = 0
    other = 0
    
    for event in events:
        hex_data = event['details'].get('hex', [])
        if len(hex_data) >= 3:
            # TLS record type
            record_type = hex_data[0]
            major = hex_data[1]
            minor = hex_data[2]
            
            if major == '03' and minor == '03':  # TLS 1.2
                if record_type == '16':
                    tls_handshake += 1
                elif record_type == '17':
                    tls_app_data += 1
            else:
                other += 1
    
    print(f"\nTLS 1.2 Handshake (0x16): {tls_handshake}")
    print(f"TLS 1.2 Application Data (0x17): {tls_app_data} <- ENCRYPTED PAYLOADS")
    print(f"Other: {other}")
    
    print("\n[WARNING] ALL APPLICATION DATA IS DTLS ENCRYPTED")
    print("   Need to decrypt using:")
    print("   1. capture_DECRYPT.js (get plaintext before encryption)")
    print("   2. SSL session keys (for Wireshark)")

def search_for_patterns(events):
    """Search for interesting patterns in encrypted data"""
    print("\n" + "="*80)
    print("PATTERN SEARCH (in encrypted data)")
    print("="*80)
    
    interesting = []
    
    for i, event in enumerate(events):
        ascii_strings = event['details'].get('ascii_strings', [])
        
        # Look for interesting keywords even in encrypted data
        for s in ascii_strings:
            s_lower = s.lower()
            if any(keyword in s_lower for keyword in ['unlock', 'lock', 'vehicle', 'bearer', 'token', 'json', 'http', 'api']):
                interesting.append({
                    'event': i,
                    'time': event['offset_ms'],
                    'string': s,
                    'socket': event['details'].get('socket')
                })
    
    if interesting:
        print(f"\nFound {len(interesting)} potentially interesting strings:")
        for item in interesting[:20]:  # Show first 20
            print(f"\n  Event #{item['event']} (t={item['time']:.0f}ms, socket={item['socket']}):")
            print(f"    '{item['string']}'")
    else:
        print("\nNo plaintext patterns found - data is encrypted")
        print("Run: .\\RUN_DECRYPT_CAPTURE.bat to see plaintext")

def generate_recommendations(events):
    """Generate next steps based on analysis"""
    print("\n" + "="*80)
    print("RECOMMENDATIONS")
    print("="*80)
    
    # Check if we have the right timing
    if events:
        duration = (events[-1]['timestamp'] - events[0]['timestamp']).total_seconds()
        
        print("\n[OK] GOOD: Traffic captured during unlock/lock action")
        print(f"   Duration: {duration:.1f}s")
        
        # Count application data
        app_data_count = sum(1 for e in events if '17 03 03' in str(e['details'].get('hex', [])))
        print(f"\n[OK] GOOD: {app_data_count} encrypted application data packets")
        
        print("\n[NEXT STEPS]:")
        print("\n1. RUN ENHANCED CAPTURE (shows plaintext):")
        print("   .\\RUN_DECRYPT_CAPTURE.bat")
        print("   Then unlock/lock again")
        print("   Look for '[PLAINTEXT BEFORE ENCRYPTION]' messages")
        
        print("\n2. Alternative: Hook at coroutine level")
        print("   The HTTP request happens before DTLS")
        print("   Check if capture_COMPLETE_SOLUTION.js caught it")
        print("   Look for '[COROUTINE]' or '[HTTP Request]' in output")
        
        print("\n3. If still encrypted, try:")
        print("   - Check JADX for field name changes (B4.Y4)")
        print("   - Enable Android HTTP logging: adb logcat | findstr http")
        print("   - Use mitmproxy with SSL pinning bypass")

def main():
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = 'CAPTURED_API.txt'
    
    print(f"\n{'='*80}")
    print(f"ANALYZING: {filename}")
    print('='*80)
    
    try:
        events = parse_captured_file(filename)
        
        if not events:
            print("\n[ERROR] No events found in capture file")
            print("   Make sure you captured traffic during unlock/lock")
            return
        
        analyze_timing(events)
        analyze_sockets(events)
        analyze_encryption(events)
        search_for_patterns(events)
        generate_recommendations(events)
        
        print("\n" + "="*80)
        print("ANALYSIS COMPLETE")
        print("="*80 + "\n")
        
    except FileNotFoundError:
        print(f"\n[ERROR] File not found: {filename}")
        print("   Usage: python analyze_capture.py [filename]")
        print("   Default: python analyze_capture.py CAPTURED_API.txt")
    except Exception as e:
        print(f"\n[ERROR] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()


# 🎯 DECRYPT MAYNDRIVE TRAFFIC - EXECUTE NOW

**Date:** October 2, 2025  
**Status:** ✅ Traffic captured during unlock/lock  
**Problem:** DTLS encrypted (17 03 03 = TLS 1.2 Application Data)  
**Solution:** Hook BEFORE encryption to see plaintext

---

## 🚀 TWO OPTIONS

### Option 1: Analyze Current Capture (Fast)

```bash
py analyze_capture.py CAPTURED_API.txt
```

**What it does:**
- Shows timing of packets (when unlock happened)
- Identifies which socket is main communication
- Confirms DTLS encryption
- Gives recommendations

**Time:** 10 seconds  
**File:** `analyze_capture.py`

---

### Option 2: Capture with Decryption (BEST)

```batch
.\RUN_DECRYPT_CAPTURE.bat
```

**Then:**
1. Wait for "[*] All decryption hooks installed!"
2. App will auto-launch
3. Find a scooter
4. Press UNLOCK button
5. Watch terminal for:
   ```
   [PLAINTEXT BEFORE ENCRYPTION]
   {"serial":"MD-12345","action":"unlock",...}
   ```
6. Press Ctrl+C when done

**Time:** 2 minutes  
**Files:** `RUN_DECRYPT_CAPTURE.bat` + `capture_DECRYPT.js`

---

## 📊 What You'll Get

### From Option 1 (Analysis):
```
TIMING ANALYSIS
- Total events: 82
- Duration: 26.5s
- Traffic bursts: 12

SOCKET ANALYSIS
Socket 110: 45 packets (most active)
Socket 174: 3 packets
...

ENCRYPTION ANALYSIS
TLS 1.2 Application Data: 78 ← ENCRYPTED
⚠️ Need decryption tools

RECOMMENDATIONS
✅ Run: .\RUN_DECRYPT_CAPTURE.bat
```

### From Option 2 (Decryption):
```
====================================================================================================
[CIPHER] Operation: ENCRYPT
  Algorithm: AES/GCM/NoPadding
  Input:  156 bytes (plaintext)
  Output: 172 bytes (ciphertext)
====================================================================================================

[PLAINTEXT BEFORE ENCRYPTION] 156 bytes
====================================================================================================
0000  7b 22 73 65 72 69 61 6c 22 3a 22 4d 44 2d 50 41  |{"serial":"MD-PA|
0010  52 2d 31 32 33 34 35 22 2c 22 61 63 74 69 6f 6e  |R-12345","action|
0020  22 3a 22 75 6e 6c 6f 63 6b 22 2c 22 6c 61 74 22  |":"unlock","lat"|
0030  3a 34 38 2e 38 35 36 36 31 34 2c 22 6c 6f 6e 22  |:48.856614,"lon"|
0040  3a 32 2e 33 35 32 32 32 32 7d                    |:2.352222}|

[TEXT CONTENT]:
{"serial":"MD-PAR-12345","action":"unlock","lat":48.856614,"lon":2.352222}

⚠️  JSON DATA DETECTED!
⚠️  UNLOCK/LOCK COMMAND DETECTED!
====================================================================================================
```

---

## 🎯 RECOMMENDATION

**Run Option 2 first** for fastest results:

```batch
.\RUN_DECRYPT_CAPTURE.bat
```

If that doesn't work:
1. Run Option 1 to analyze timing
2. Check if coroutine hooks fired (in original capture)
3. Verify class names in JADX

---

## 📁 Files Reference

| File | Purpose |
|------|---------|
| `capture_DECRYPT.js` | Enhanced Frida script with encryption hooks |
| `RUN_DECRYPT_CAPTURE.bat` | One-click runner |
| `analyze_capture.py` | Post-capture analysis tool |
| `CAPTURED_API.txt` | Your captured traffic (encrypted) |
| `MAYNDRIVE_COMPLETE_ANALYSIS.md` | Full documentation (line 435) |
| `TRAFFIC_CAPTURE_ANALYSIS_AND_PLAN.md` | Complete plan (line 746) |

---

## ⚠️ Troubleshooting

**If no plaintext appears:**

1. **Check hooks installed:**
   ```
   [+] Hooked Cipher.doFinal(byte[])
   [+] Hooked SSLEngine.wrap/unwrap
   ```

2. **Verify you unlocked:**
   - Actually pressed unlock button
   - Not just opened app

3. **Alternative: Check HTTP layer:**
   - HTTP happens BEFORE DTLS
   - Original `capture_COMPLETE_SOLUTION.js` should catch it
   - Look for `[COROUTINE]` or `[HTTP Request]` in logs

4. **Check class names changed:**
   ```bash
   cd base_jadx/sources/B4
   cat Y4.java | head -100
   ```
   - Verify `f2925Z`, `f2927g0`, `f2928h0` fields exist

---

## ✅ Success Criteria

**You'll know it worked when you see:**
- ✅ `[PLAINTEXT BEFORE ENCRYPTION]` messages
- ✅ Readable JSON with `"serial"`, `"action"`, `"lat"`, `"lon"`
- ✅ `"unlock"` or `"lock"` in the text
- ✅ Scooter ID visible (e.g., `MD-PAR-12345`)

---

**Ready? Run this:**
```batch
.\RUN_DECRYPT_CAPTURE.bat
```


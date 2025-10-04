/**
 * Token-focused MaynDrive hooks
 * Based on working capture analysis - focuses on most likely token sources
 */
'use strict';

function safeString(v) {
  if (v === null || v === undefined) return null;
  try { return v.toString(); } catch (e) { return null; }
}

function logBlock(tag, lines) {
  console.log(`\n==== ${tag} ====`);
  lines.forEach(line => console.log(line));
  console.log('================\n');
}

function captureToken(value) {
  if (value && (value.includes('Bearer') || value.includes('Token') || value.includes('Authorization'))) {
    console.log(`[TOKEN] ${value}`);
    return true;
  }
  return false;
}

// Hook 1: HttpURLConnection (most common in Android apps)
function hookHttpURLConnection() {
  try {
    const HttpURLConnection = Java.use('java.net.HttpURLConnection');
    HttpURLConnection.setRequestProperty.overload('java.lang.String', 'java.lang.String').implementation = function(name, value) {
      if (name && name.toLowerCase() === 'authorization') {
        logBlock('HTTPURL AUTH', [
          `Thread: ${Java.use('java.lang.Thread').currentThread().getName()}`,
          `Value : ${value}`
        ]);
        captureToken(value);
      }
      return this.setRequestProperty(name, value);
    };
    console.log('[+] Hooked HttpURLConnection.setRequestProperty');
  } catch (e) {
    console.log('[-] Failed to hook HttpURLConnection:', e);
  }
}

// Hook 2: SharedPreferences (common for storing tokens)
function hookSharedPreferences() {
  try {
    const Editor = Java.use('android.content.SharedPreferences$Editor');
    
    Editor.putString.overload('java.lang.String', 'java.lang.String').implementation = function(key, value) {
      if (key && (key.toLowerCase().includes('token') || key.toLowerCase().includes('auth') || key.toLowerCase().includes('bearer') || key.toLowerCase().includes('jwt'))) {
        logBlock('SHARED PREF TOKEN', [
          `Key    : ${key}`,
          `Value  : ${value}`
        ]);
        captureToken(value);
      }
      return this.putString(key, value);
    };
    console.log('[+] Hooked SharedPreferences.putString');
  } catch (e) {
    console.log('[-] Failed to hook SharedPreferences:', e);
  }
}

// Hook 3: JSON operations (common for API responses)
function hookJSONObject() {
  try {
    const JSONObject = Java.use('org.json.JSONObject');
    JSONObject.put.overload('java.lang.String', 'java.lang.Object').implementation = function(name, value) {
      if (name && (name.toLowerCase().includes('token') || name.toLowerCase().includes('auth') || name.toLowerCase().includes('bearer') || name.toLowerCase().includes('jwt'))) {
        logBlock('JSON TOKEN', [
          `Key    : ${name}`,
          `Value  : ${value}`
        ]);
        captureToken(safeString(value));
      }
      return this.put(name, value);
    };
    console.log('[+] Hooked JSONObject.put');
  } catch (e) {
    console.log('[-] Failed to hook JSONObject:', e);
  }
}

// Hook 4: String operations (catch tokens in string manipulation)
function hookStringOperations() {
  try {
    const String = Java.use('java.lang.String');
    String.$init.overload('[B').implementation = function(bytes) {
      const result = this.$init(bytes);
      if (result && (result.includes('Bearer') || result.includes('Token') || result.includes('Authorization'))) {
        logBlock('STRING CONSTRUCTOR TOKEN', [
          `Value  : ${result}`
        ]);
        captureToken(result);
      }
      return result;
    };
    console.log('[+] Hooked String constructor');
  } catch (e) {
    console.log('[-] Failed to hook String constructor:', e);
  }
}

// Hook 5: Logging (catch tokens in debug logs)
function hookLogcat() {
  try {
    const Log = Java.use('android.util.Log');
    const originalD = Log.d.overload('java.lang.String', 'java.lang.String');
    Log.d.overload('java.lang.String', 'java.lang.String').implementation = function(tag, msg) {
      if (msg && (msg.includes('Bearer') || msg.includes('Token') || msg.includes('Authorization'))) {
        logBlock('LOGCAT TOKEN', [
          `Tag    : ${tag}`,
          `Value  : ${msg}`
        ]);
        captureToken(msg);
      }
      return originalD.call(this, tag, msg);
    };
    console.log('[+] Hooked Log.d');
  } catch (e) {
    console.log('[-] Failed to hook Log.d:', e);
  }
}

// Hook 6: OkHttp (in case it's used)
function hookOkHttp() {
  try {
    const RequestBuilder = Java.use('okhttp3.Request$Builder');
    RequestBuilder.addHeader.overload('java.lang.String', 'java.lang.String').implementation = function(name, value) {
      if (name && name.toLowerCase() === 'authorization') {
        logBlock('OKHTTP AUTH', [
          `Thread: ${Java.use('java.lang.Thread').currentThread().getName()}`,
          `Value : ${value}`
        ]);
        captureToken(value);
      }
      return this.addHeader(name, value);
    };
    console.log('[+] Hooked OkHttp Request.Builder.addHeader');
  } catch (e) {
    console.log('[-] Failed to hook OkHttp Request.Builder.addHeader:', e);
  }
}

// Hook 7: SSL bypass (from working capture)
function hookSSL() {
  try {
    const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function(chain, authType) {
      console.log('[+] Patched TrustManagerImpl.checkServerTrusted');
      return;
    };
    console.log('[+] Hooked TrustManagerImpl.checkServerTrusted');
  } catch (e) {
    console.log('[-] Failed to hook TrustManagerImpl:', e);
  }
}

// Main hook installation
console.log('[*] MaynDrive token-focused hooks installing...');

// Install all hooks
hookHttpURLConnection();
hookSharedPreferences();
hookJSONObject();
hookStringOperations();
hookLogcat();
hookOkHttp();
hookSSL();

console.log('[*] Token-focused hook installation finished');

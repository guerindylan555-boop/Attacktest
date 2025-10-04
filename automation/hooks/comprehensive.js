/**
 * Comprehensive MaynDrive instrumentation hooks
 * - Captures tokens from multiple HTTP libraries
 * - Logs network requests and responses
 * - Detects Authorization headers from various sources
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

  try {
    const Interceptor = Java.use('okhttp3.Interceptor');
    Interceptor.intercept.implementation = function(chain) {
      const request = chain.request();
      const headers = request.headers();
      for (let i = 0; i < headers.size(); i++) {
        const name = headers.name(i);
        const value = headers.value(i);
        if (name && name.toLowerCase() === 'authorization') {
          logBlock('OKHTTP INTERCEPTOR AUTH', [
            `URL    : ${request.url()}`,
            `Method : ${request.method()}`,
            `Value  : ${value}`
          ]);
          captureToken(value);
        }
      }
      const response = this.intercept(chain);
      return response;
    };
    console.log('[+] Hooked OkHttp Interceptor.intercept');
  } catch (e) {
    console.log('[-] Failed to hook OkHttp Interceptor.intercept:', e);
  }
}

function hookRetrofit() {
  try {
    const Retrofit = Java.use('retrofit2.Retrofit');
    console.log('[+] Retrofit detected');
  } catch (e) {
    console.log('[-] No Retrofit detected:', e);
  }
}

function hookVolley() {
  try {
    const StringRequest = Java.use('com.android.volley.toolbox.StringRequest');
    console.log('[+] Volley detected');
  } catch (e) {
    console.log('[-] No Volley detected:', e);
  }
}

function hookSharedPreferences() {
  try {
    const SharedPreferences = Java.use('android.content.SharedPreferences');
    const Editor = Java.use('android.content.SharedPreferences$Editor');
    
    Editor.putString.overload('java.lang.String', 'java.lang.String').implementation = function(key, value) {
      if (key && (key.toLowerCase().includes('token') || key.toLowerCase().includes('auth') || key.toLowerCase().includes('bearer'))) {
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

function hookJSONObject() {
  try {
    const JSONObject = Java.use('org.json.JSONObject');
    JSONObject.put.overload('java.lang.String', 'java.lang.Object').implementation = function(name, value) {
      if (name && (name.toLowerCase().includes('token') || name.toLowerCase().includes('auth') || name.toLowerCase().includes('bearer'))) {
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

function hookStringOperations() {
  try {
    const String = Java.use('java.lang.String');
    String.$init.overload('[B').implementation = function(bytes) {
      const result = this.$init(bytes);
      if (result && result.includes('Bearer')) {
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
console.log('[*] MaynDrive comprehensive hooks installing...');

// Try to hook various HTTP libraries
hookHttpURLConnection();
hookOkHttp();
hookRetrofit();
hookVolley();

// Try to hook data storage
hookSharedPreferences();
hookJSONObject();

// Try to hook string operations
hookStringOperations();

// Try to hook logging
hookLogcat();

// SSL bypass
hookSSL();

console.log('[*] Hook installation finished');

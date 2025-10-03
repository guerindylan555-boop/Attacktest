/**
 * General MaynDrive instrumentation hooks
 * - Logs Authorization headers and retrofit requests
 * - Provides placeholders for SSL pinning bypass helpers
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

function hookOkHttp() {
  try {
    const RequestBuilder = Java.use('okhttp3.Request$Builder');
    RequestBuilder.addHeader.overload('java.lang.String', 'java.lang.String').implementation = function(name, value) {
      if (name && name.toLowerCase() === 'authorization') {
        logBlock('AUTH HEADER', [
          `Thread: ${Java.use('java.lang.Thread').currentThread().getName()}`,
          `Value : ${value}`
        ]);
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
      logBlock('HTTP REQUEST', [
        `URL    : ${request.url()}`,
        `Method : ${request.method()}`,
        `HasBody: ${request.body() !== null}`
      ]);
      const response = this.intercept(chain);
      logBlock('HTTP RESPONSE', [
        `URL     : ${response.request().url()}`,
        `Code    : ${response.code()}`
      ]);
      return response;
    };
    console.log('[+] Hooked OkHttp Interceptor.intercept');
  } catch (e) {
    console.log('[-] Failed to hook OkHttp Interceptor.intercept:', e);
  }
}

function bypassSslPinning() {
  try {
    const CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
      logBlock('PINNING BYPASS', ['CertificatePinner.check bypassed']);
      return;
    };
    console.log('[+] Patched okhttp3.CertificatePinner');
  } catch (e) {
    console.log('[-] No okhttp3.CertificatePinner detected:', e);
  }

  try {
    const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String').implementation = function(chain, authType, host) {
      logBlock('CONScrypt BYPASS', [`Host: ${host}`]);
      return chain;
    };
    console.log('[+] Patched TrustManagerImpl.checkServerTrusted');
  } catch (e) {
    console.log('[-] Could not patch TrustManagerImpl:', e);
  }
}

Java.perform(function() {
  console.log('[*] MaynDrive general hooks installing...');
  hookOkHttp();
  bypassSslPinning();
  console.log('[*] Hook installation finished');
});

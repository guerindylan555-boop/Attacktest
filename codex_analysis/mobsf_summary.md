# MaynDrive MobSF Static Analysis (2025-10-03)

## Execution Notes
- Prepared virtual environment at `codex_analysis/mobsf_env` and installed MobSF 4.4.3 via Poetry dependencies.
- Ran MobSF static scan through the REST API (`upload` + `scan`) against `codex_analysis/input/base.apk` extracted from `Mayn Drive_1.1.34.xapk`.
- Retrieved machine-readable results `codex_analysis/mobsf_report.json`. HTML/PDF endpoints return 404 because wkhtmltopdf is not installed in this environment.
- The MobSF backing store for this run is kept in `~/.MobSF` (hash `995ff6d089b076c487be7dd572cad337`); `codex_analysis/MaynDrive_AndroidManifest.xml` is copied for reference.

## App Metadata
- Package: `fr.mayndrive.app`
- App name: Mayn Drive 1.1.34 (code 900034)
- Min SDK 24 (Android 7), target SDK 35
- SHA-256: `e5f5a2181b38b22d661ed0d992dea4f26512b73d920609709f69fdd5c9190ea2`

## High / Warning Findings
- **High**: App installs on API level 24 (Android 7.0) devices, exposing it to unpatched OS vulnerabilities.
- **Warning**: `android:allowBackup="true"` allows full ADB backups of app data.
- **Warning**: Exported payment/deep-link Activities without custom permissions (`com.braintreepayments.api.DropInActivity`, `com.stripe.android.link.LinkRedirectHandlerActivity`, `com.stripe.android.payments.StripeBrowserProxyReturnActivity`, `com.braintreepayments.api.BraintreeDeepLinkActivity`, `com.stripe.android.financialconnections.lite.FinancialConnectionsSheetLiteRedirectActivity`).
- **Warning**: Several exported Services/Broadcast Receivers rely on platform permissions (`android.permission.DUMP`, `android.permission.BIND_JOB_SERVICE`, `com.google.android.gms.auth.api.signin.permission.REVOCATION_NOTIFICATION`, `com.google.android.c2dm.permission.SEND`). Confirm these remain signature/privileged on production builds.

## Permissions & Capabilities
- Dangerous permissions requested: `ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATION`, `CAMERA`, `READ_EXTERNAL_STORAGE`, `POST_NOTIFICATIONS`.
- Normal permissions include advertising identifiers (`ACCESS_ADSERVICES_ATTRIBUTION`, `ACCESS_ADSERVICES_AD_ID`) and Firebase Cloud Messaging (`RECEIVE_BOOT_COMPLETED`, `com.google.android.c2dm.permission.RECEIVE`).

## Secrets & Static Strings
- Embedded keys detected: `google_api_key`, `google_crash_reporting_api_key`, Crashlytics mapping ID.
- URLs and domains observed: stripe.com (legal terms), link.com (promo), github.com (Braintree documentation).
- Support email hard-coded: `support@stripe.com`.
- MobSF flagged hard-coded certificate/key material: `assets/ds-amex.pem`, `assets/ds-cartesbancaires.pem`, `assets/ds-discover.cer`, `assets/ds-mastercard.crt`, `assets/ds-visa.crt` (validate packaging/rotation).

## 3rd-party Components
- Trackers detected: Dynatrace (analytics), Google Crashlytics (crash reporting), Google Firebase Analytics (analytics).
- SBOM highlights 100+ Jetpack Compose, CameraX, Hilt, Stripe, Braintree dependencies (see `mobsf_report.json` for full list).

## Suggested Follow-up
1. Revisit minimum supported OS level; align to API 29+ if feasible.
2. Disable `allowBackup` unless absolutely required; otherwise document mitigation.
3. Review exported activities and services—enforce authenticating intent filters or custom signature permissions.
4. Rotate and scope embedded Google keys; ensure server-side enforcement and restrict to required bundle IDs/SHA-1 fingerprints.
5. Validate privacy notices cover Dynatrace/Firebase/Crashlytics telemetry and ensure user consent flows align with regulatory requirements.

# 2nd Eye - Android web watcher (AlgoR3IthM)

The desktop watcher (`integrations/watcher/`) as an Android app: one WebView per service (WhatsApp Web, Messenger,
Instagram, Telegram Web, Gmail) with a desktop Chrome user agent. The **same reader scripts** run inside them; what they
read goes to the detector API on the laptop over Wi-Fi. Kotlin, one module, minSdk 26, targetSdk 34, no third-party
libraries (framework APIs only). Package `com.algor3ithm.scutulbunicii.web`.

## For the alert teammate

Every SCAM or SUSPICIOUS result goes through ONE class, `AlertDispatcher.kt`, in three ways. No message text is ever included.

1. Broadcast, action `com.algor3ithm.scamshield.ALERT` (sent without a target package, so a separate APK can receive it with a
   dynamically registered receiver; manifest receivers of other apps do not get implicit broadcasts on Android 8+):

   | extra | type | meaning |
   |---|---|---|
   | `service` | String | `whatsapp`, `messenger`, `instagram`, `telegram`, `gmail` |
   | `sender` | String | display name (or address) of the sender |
   | `verdict` | String | `SCAM` or `SUSPICIOUS` |
   | `label_ro` | String | official Romanian label from the API |
   | `warning_ro` | String | the API's `warning.ro` |
   | `risk_score` | Int | 0-100 |
   | `alert_id` | String | stable per conversation state (hash of service, sender, verdict and conversation; same state gives the same id) |

   ```kotlin
   registerReceiver(object : BroadcastReceiver() {
       override fun onReceive(c: Context, i: Intent) {
           val label = i.getStringExtra("label_ro"); val warning = i.getStringExtra("warning_ro")
           val id = i.getStringExtra("alert_id")   // show your full-screen alert here
       }
   }, IntentFilter("com.algor3ithm.scamshield.ALERT"), Context.RECEIVER_EXPORTED)
   ```
   Any app on the phone can receive this broadcast (it carries the sender name and the warning, not message text).
2. In the same APK after the merge: set `AlertDispatcher.listener = AlertListener { alert -> ... }` (`Alert` data class, same fields).
3. **Fallback to delete at merge time:** an ordinary heads-up notification with the label and warning, behind
   `AlertDispatcher.FALLBACK_NOTIFICATION = true`. Set it to `false` (or delete `fallback()`) when the real alert is merged.

## Build

Needs JDK 17 and the Android SDK (platform 34, build-tools 34.0.0). On the hackathon laptop they are in `..\.toolchain`
(git-ignored). From PowerShell:

```
cd android-webwatcher
$tc = (Resolve-Path ..\.toolchain).Path
$env:JAVA_HOME = "$tc\jdk\jdk-17.0.21+9"; $env:ANDROID_HOME = "$tc\sdk"
.\gradlew.bat assembleDebug
.\gradlew.bat --stop
```

With Android Studio: open the `android-webwatcher` folder and press Run (create `local.properties` with
`sdk.dir=...` if Studio does not). Versions: Gradle 8.14.7 (wrapper), Android Gradle Plugin 8.13.2, Kotlin 2.3.21.

APK: `android-webwatcher\app\build\outputs\apk\debug\app-debug.apk` (about 0.9 MB, debug-signed).

The Gradle task `copyReaders` copies `integrations/watcher/readers/*.js` into the APK at build time
(`assets/readers/`). There is one source of truth: edit the readers there, rebuild. The service list (name and start URL)
is read from each reader's first line `// @service name url`.

## Install

* USB: enable developer options and USB debugging on the phone, then `adb install -r app\build\outputs\apk\debug\app-debug.apk`
  (`adb` is in `..\.toolchain\sdk\platform-tools`).
* Or copy `app-debug.apk` to the phone (cable, cloud drive, messenger), open it in Files and allow "install unknown apps"
  for that app.

## First run

1. On the laptop start the detector so it listens on the network: `uvicorn backend.server:app --host 0.0.0.0 --port 8000`,
   and let port 8000 through Windows Firewall (private network). Find the laptop's address with `ipconfig` (for example 192.168.1.20).
2. Phone on the same Wi-Fi. Open **2nd Eye**, type `http://192.168.1.20:8000` in the address field, press
   **Testează legătura**: "Legătura funcționează." means the phone reaches `/api/health`.
3. Press **Conectare** next to a service, sign in inside the page (WhatsApp: see limits), then **Gata, sunt conectat**.
   The hint on the home screen changes to "Conectat". While a service is open in this screen, the reader draws the same
   warning banner as on the desktop.
4. Switch on **Păzește mesajele în fundal** (allow notifications when Android asks). A quiet notification "2nd Eye
   vă păzește mesajele" appears. For a SCAM or SUSPICIOUS preview a high-importance notification shows the official label and
   the API's warning, nothing else (the fallback, see "For the alert teammate").
5. **Required for the demo:** set Android Settings > Apps > 2nd Eye > Battery > Unrestricted, otherwise Android may throttle or stop the background WebViews. No throttling workarounds beyond a plain foreground service are built in.

## How it works

* `assets/shim.js` is injected before `common.js` and the matching reader. It defines `window.__sbAnalyze(payload)` and
  `window.__sbTrust(payload)` (the two bindings Playwright gives the desktop readers) as Promises over an
  `addJavascriptInterface` bridge (`__SBNative`); Kotlin answers with `evaluateJavascript("window.__sbResolve(id, json)")`.
  `window.__SB_CFG` is set the same way (`banner` true on screen, false in the background; `list` true; `openStrangers` false).
* Injection uses `evaluateJavascript` in `onPageFinished` and `doUpdateVisitedHistory` (single-page-app navigation), only on the
  service's own hosts (not on e.g. accounts.google.com), and skips itself if already present. It is not subject to the page's CSP.
* Trust Circle as on the desktop: a saved contact (or a sender in the trusted list) is sent with `?trust_gate=true` (tripwire
  only); strangers get the full check. "Il cunosc" in the banner adds the identifier (address, else name, lower case, no
  spaces) to SharedPreferences `trusted`.
* Background: `WatchService` keeps one off-screen WebView per connected service. The readers' `list()` path reads unread rows
  (sender, stranger or not, preview) on their own timer (`pollMs` 20 s) and on DOM changes; nothing is clicked or opened.
  A one-minute keep-alive reloads a page whose reader has gone. When a service is opened on screen, its background WebView is closed
  (two sessions of one site clash) and recreated afterwards.
* Alerts: `AlertDispatcher` is the only class that hands results to the alert layer (broadcast, callback, fallback notification).

### Foreground service and boot choices (targetSdk 34)

* Type `specialUse` (permission `FOREGROUND_SERVICE_SPECIAL_USE` and the required `PROPERTY_SPECIAL_USE_FGS_SUBTYPE`).
  `dataSync` was rejected: it is meant for transfers, and from Android 15 it may not be started from `BOOT_COMPLETED` and has a time limit. `specialUse` has none of that.
  It is fine for a sideloaded APK; Google Play would need a justification review.
* Boot (not a priority, untested): `BootReceiver` listens for `BOOT_COMPLETED` and `MY_PACKAGE_REPLACED` and starts the service only if the switch was on.
  Allowed at targetSdk 34 for `specialUse`.
* A partial wake lock (renewed every minute, 10 minute expiry) keeps the CPU awake so the page timers keep running with the screen off. Battery cost is real.

## Privacy

* Message text goes only to the configured detector address (`DetectorClient`). No `Log` calls anywhere, nothing about message
  content is stored (no cache on disk, no history), nothing is sent to any other host.
* Stored: the detector address, the background switch, per-service "connected" flags, and the trusted list (identifiers only).
  `allowBackup` is off.
* Cleartext HTTP: the network security config allows cleartext because Android cannot whitelist an IP range. The restriction is
  in code: `DetectorClient.normalize` accepts `http://` only for loopback, private (10/8, 172.16/12, 192.168/16), link-local,
  100.64/10, `.local` and single-label host names; anything else must be `https://`. The WebViews only follow `https://` links.
* Any script in a loaded page can call the bridge. Trust additions are accepted only while the page is on the service's own hosts.

## Honest limits

* Google usually refuses sign-in inside an embedded WebView ("this browser may not be secure"), so Gmail may not connect.
* WhatsApp Web on the same phone cannot be linked with the QR code (it needs a second device to scan); use "link with phone
  number" and enter the code in the WhatsApp app.
* Messenger and Instagram forbid automated access and may push the user to their apps (the app blocks non-https links
  such as `fb://`/`intent://`, so the page may just stay on a "get the app" screen) or lock the account. Use them for the demo with care.
* Background WebViews cost battery and RAM, and Android (especially Xiaomi, Samsung, Huawei battery managers) may throttle or
  stop them. Unrestricted battery use is recommended. Each service is roughly 100-300 MB.
* The detector itself still runs on the laptop: the phone must be on the same Wi-Fi, the laptop must be on and awake,
  and its firewall must allow port 8000.
* Layout is phone width (viewport not widened) so the banner stays readable; the desktop site is therefore rendered in its narrow
  responsive layout. Readers that depend on a wide layout may find fewer elements.
* Selectors are unverified on real accounts (same as the desktop readers). The "Conectat" hint is what she confirmed with
  "Gata, sunt conectat", not a check of the real session.
* **Nothing here has been run on a device or emulator.** The APK compiles and the readers are inside it; behaviour in WebView
  (injection, bridge, off-screen WebViews, foreground service, notifications, boot start) is unverified.

# Testing instructions for judges

**Live demo:** https://configshield.web.app. No login is needed, because the app signs you in anonymously.

## Requirements
- Chrome Desktop **139 or later** (Windows, macOS, Linux or ChromeOS).
- For the on-device path: open `chrome://flags/#prompt-api-for-gemini-nano-multimodal-input`, set it to **Enabled**, and restart Chrome. The first model download needs a few GB of free disk space and can take several minutes.
- Without Gemini Nano the app still works. Stage 1 shows **SKIPPED** and a strict rule-based scrub masks free-text descriptions instead. The rules and leak gate still protect secrets, and the audit runs in the cloud.
- If the cloud is also unreachable, you still get a report from the 32 local baseline checks.

## 2-minute test
1. Open the demo and click **Prepare on-device model**. Wait for the chip to read `Gemini Nano: available`.
2. Choose **Load sample… → Cisco IOS-XE branch switch**, then click **Redact & audit** (or press Ctrl+Enter).
3. Watch the stage badges (`LOCAL · rules` → `ON-DEVICE · Gemini Nano` → `LOCAL · rules` leak gate → `CLOUD · Gemini` → `LOCAL · rules` cross-check) and the privacy-boundary diagram above them. The **Cloud** box shows the privacy receipt.
4. In the report, look at the badges on each finding: *Cloud Gemini* / *Local rule*, **✓ rule-confirmed**, **✓ evidence verified**. Use the severity filters and **Copy fix script**.
5. Expand **What the cloud model actually saw** and confirm there are no passwords, IPs, names or circuit IDs.
6. Toggle **Reveal real values (local only)**. The report and the **Redaction map** now show the originals, restored in the browser.
7. Choose **Air-gapped**, load the **PAN-OS** sample, and run it. Every stage reports on-device, and the receipt reads "Nothing left this device".
8. Click **Save sanitized report**, open **Saved reports**, and click an entry to reopen it. Use **Delete** (click twice) to remove it.
9. Try the ASA, Junos and FortiOS samples. Each one triggers vendor-specific baseline checks.

## Run from source
See the [README](../README.md#run-it-locally). `npm test` runs 49 unit and integration tests and needs no Firebase project. Without a `.env.local`, `npm run dev` starts in **local-only mode**: rules, the strict scrub, the baseline audit and Gemini Nano work, and cloud features are labelled as disabled.

## Notes
- The live site protects AI Logic with **App Check (reCAPTCHA Enterprise)**, which works invisibly with no challenge to solve. Local development uses an App Check debug token instead.
- All sample data is fictitious: RFC 5737 documentation IPs and `.example` domains.
- The project stays free to use and unrestricted until the end of the Judging Period.

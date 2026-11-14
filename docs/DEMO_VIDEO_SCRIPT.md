# Demo video script — target 2:45 (hard limit 3:00)

Record at 1080p in Chrome with Gemini Nano already downloaded. Upload to YouTube as **Public** and add English captions. Keep the DevTools Network tab handy for the proof shot.

| Time | Screen | Voice-over |
|---|---|---|
| 0:00–0:15 | Title card: ConfigShield, plus a shot of a real-looking running config | "Every network engineer has a config full of secrets, and a security policy that says never paste it into a cloud AI. ConfigShield lets you use one anyway." |
| 0:15–0:30 | The app. Point at the **Gemini Nano: available** chip | "It runs in Chrome and uses Firebase AI Logic hybrid inference: Gemini Nano on my laptop, Gemini in the cloud." |
| 0:30–0:45 | Click **Sample: Cisco IOS-XE**. Highlight `enable password 7`, `snmp community public`, the ISAKMP key, and the description with a person's name | "This branch switch config has passwords, a default SNMP community, a VPN key, public IPs, and in the descriptions a customer name, an employee and a circuit ID." |
| 0:45–1:15 | Click **Redact & audit**. Stages tick: rules → **ON-DEVICE · Gemini Nano** → leak gate → **CLOUD · Gemini** | "Step one, rules strip the known secret formats. Step two, Gemini Nano, on-device only, finds what rules can't: names, sites, circuit IDs. It's set to ONLY_ON_DEVICE, so it can't fall back to the cloud. Step three, a leak gate re-checks everything and would block the upload if anything slipped through." |
| 1:15–1:35 | Open **What the cloud model actually saw**. Scroll over the purple tokens. Show DevTools Network: the request body contains only tokens | "This is the only thing the cloud model ever sees. Notice `<WEAKSECRET>`: a local check knows that community is a default, so the auditor can flag it without seeing it." |
| 1:35–2:05 | Report: score ring, critical findings (telnet, type-7, SNMP default, DES/MD5/DH1, no AAA). Point at the **✓ rule-confirmed** and **✓ evidence verified** badges, then a *Local rule* finding. Click **Copy fix script** | "Gemini returns a structured audit: severity, evidence, why it matters and the IOS-XE fix. Then 32 local rules cross-check it: they confirm what the AI got right, add anything it missed, and flag evidence that isn't really in the config." |
| 2:05–2:20 | Toggle **Reveal real values (local only)** | "Real values come back locally from an in-memory vault. They were never sent or stored." |
| 2:20–2:35 | Turn Wi-Fi off (the network chip turns amber). Choose **Air-gapped**, load the PAN-OS sample, run it. Badges show ON-DEVICE throughout and the receipt reads "Nothing left this device" | "Offline, or at a classified site? Air-gapped mode runs the whole audit on Gemini Nano, and nothing crosses the boundary." |
| 2:35–2:45 | Click **Save** to show history. End card listing App Check · Auth · Firestore · Remote Config, the repo URL, and Apache-2.0 | "Only sanitized reports reach Firestore, and the security rules enforce it. ConfigShield: hybrid AI for configs you can't afford to leak." |

**Tips:** keep it to a single take per section and cut the model-download wait. Spend no more than 10 seconds on the title. The judges score the first 3 minutes only.

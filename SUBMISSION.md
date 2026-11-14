# Devpost submission text — ConfigShield

> Copy each section into the matching Devpost field. Replace the `TODO` links before submitting.

**Tagline:** Audit your router and firewall configs with AI, without your secrets ever leaving the laptop.

**Platform category:** Web (Chrome)

**Links**
- Live demo: `TODO https://<project>.web.app`
- Code (public, Apache-2.0): https://github.com/natrajexplore/ConfigShield
- Video (YouTube, public, ≤ 3 min): `TODO`

---

## Inspiration
I've spent 10+ years as a network security engineer working on Cisco ISE, Palo Alto and enterprise wireless. Every configuration review runs into the same wall: AI would make it 10× faster, but a running config holds enable secrets, SNMP communities, VPN pre-shared keys, public IPs, customer names in interface descriptions and circuit IDs. Pasting that into a cloud chatbot breaks most security policies. So engineers either skip the review or spend an hour sanitising by hand and still miss things.

Hybrid inference solves this exact problem. A small model on the device can do the part that needs privacy, and a large model in the cloud can do the part that needs depth.

## What it does
ConfigShield runs a five-stage pipeline in the browser:

1. **Rule-based redaction (local):** 24 keyword-anchored rules for Cisco, PAN-OS, Junos and FortiOS secrets, plus hashes, key/cert blocks, emails, phones and IPs. Tokens stay consistent (`<HOST_1>`, `<IP_PUB_2>`). Weak or default secrets like `public` or `cisco123` become `<WEAKSECRET_n>`, so the auditor can flag them without seeing them.
2. **Contextual redaction with Gemini Nano (on-device only):** finds the identifiers that rules can't, such as *"Desk of Priya Raman – Treasury"*, *"Tata Comm circuit 045CHEN88812"* or a bank's name in a description. Results are JSON-schema constrained and checked to be verbatim substrings, so hallucinations aren't masked.
   If Nano can't run, a **strict free-text scrub** masks every non-generic description and comment instead, so names and circuit IDs still never reach the cloud.
3. **Leak gate (local):** re-scans everything. If any secret remains, the cloud call is **blocked**.
4. **Deep audit with Gemini (cloud-preferred, on-device fallback):** management plane, AAA, SNMP, crypto (DES, MD5, DH group 1/2), any/any rules, logging and NTP. Each finding includes evidence, the reason it matters, and a vendor-specific CLI fix.
5. **Local cross-check and re-hydration:** 32 deterministic baseline checks (Cisco IOS/ASA, PAN-OS, Junos, FortiOS, mapped to NIST SP 800-53 and PCI DSS v4.0) mark AI findings **rule-confirmed**, add anything the AI missed, and flag any AI finding whose cited evidence isn't in the config. The engineer can then reveal real values locally. The cloud and the database never see them.

The pipeline always produces a report. If the cloud and Gemini Nano are both unavailable, the baseline audit still runs and the stage list explains why. A **privacy receipt** shows exactly how many characters of sanitized text went to the cloud, or "Nothing left this device".

There is also an **Air-gapped mode** that runs the whole audit on Gemini Nano, for sites where nothing may leave the machine.

## How we built it (Firebase AI Logic)
- `firebase/ai` with `GoogleAIBackend`, and **three hybrid model configurations** in `src/ai/models.ts`:
  - Redactor: `InferenceMode.ONLY_ON_DEVICE`. Cloud fallback is **deliberately disabled** because raw configs must never leave the device. A runtime check aborts if `response.inferenceSource` is ever anything other than `on_device`.
  - Auditor: `InferenceMode.PREFER_IN_CLOUD` with `inCloudParams` (system instruction, `responseJsonSchema`) and `onDeviceParams` (`responseConstraint`, using the same schema). That gives one structured contract on both paths.
  - Local auditor: `InferenceMode.ONLY_ON_DEVICE` for air-gapped mode, with prompts chunked to fit Nano's 9,216-token window.
- `initializeDeviceModel()` runs on a user click with a download progress bar.
- `response.inferenceSource` drives the live **ON-DEVICE / CLOUD** badge on every stage.
- **App Check** (reCAPTCHA Enterprise, debug provider for judging), **Anonymous Auth**, **Firestore** (sanitized reports only, enforced by field allow-list rules), and **Remote Config** (cloud model name, chunk size, findings cap, and a kill switch that forces on-device auditing).
- Vite + TypeScript, no framework. **49 Vitest tests**, including pipeline integration tests that mock the models and assert that the prompt sent to cloud inference contains none of the sample's secrets, IPs, people or circuit IDs.
- Hardening: model output is coerced to the schema's enums before rendering, so it can't inject markup; prompts treat the config as untrusted data; and Firestore rules type- and size-check every field.

## Challenges we ran into
- **Choosing a fallback direction for each task.** A hybrid "prefer on-device" mode is wrong for redaction, because a silent cloud fallback would leak the very data we are protecting. Each stage needed its own `InferenceMode`.
- **Nano's context window.** Configs are often 50–200 KB. We chunk on line boundaries and keep tokens consistent across chunks through a shared vault.
- **Over-redaction.** Masking too much destroys the audit. We keep netmasks, wildcards, encryption-type digits and syntax words, and tag IPs as private or public so the cloud model can still reason about exposure.
- **Trusting the model.** LLM audits can invent evidence. Verifying every cited line against the sanitized config, and cross-checking with deterministic rules, turned "the AI says so" into something an engineer can act on.

## Accomplishments we're proud of
- The weak-secret signal: the auditor can say "SNMP community is a vendor default" without ever seeing `public`.
- A leak gate that fails closed, and a pipeline that degrades gracefully: cloud → on-device → rules-only, never a blank screen.
- Hallucination checks you can see: every AI finding carries *evidence verified* / *evidence not found* and *rule-confirmed* badges.
- Firestore rules that make it impossible to store a raw config, even from a modified client.

## What we learned
On-device AI isn't just a cost saving. It is what lets regulated industries use cloud AI at all.

## What's next
- A Chrome extension side panel to audit configs directly from web consoles (Meraki, Panorama, vManage).
- Larger policy packs (full CIS benchmarks), selectable through the existing `audit_policy_pack` Remote Config parameter.
- Android companion for field engineers, using Gemini Nano through ML Kit.
- Diffing two configs for change reviews.

## Built during the submission period
All code in this repository was written during the #BuildHybridAI Submission Period (from Nov 11, 2026). No pre-existing project code was reused. Standard tools only: Vite, TypeScript, Vitest, the Firebase JS SDK, and an AI coding assistant (Claude) used for scaffolding and review. The sample configs are fictitious and were written for this project.

## Built with
`firebase-ai-logic` `gemini-nano` `gemini` `chrome-prompt-api` `firebase-app-check` `firebase-auth` `cloud-firestore` `firebase-remote-config` `firebase-hosting` `typescript` `vite`

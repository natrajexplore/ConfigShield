# #BuildHybridAI 2026: eligibility, timeline and compliance checklist

## Eligibility (Official Rules §3), checked against your situation

| Rule | Status |
|---|---|
| Above the age of majority | ✅ |
| Not resident in Brazil, Italy, Quebec, Crimea, Russia, Belarus, Syria, Sudan, Cuba, Iran, North Korea or another OFAC country | ✅ India is not excluded |
| Not under US export controls or sanctions | ✅ (assumed) |
| Not an employee, intern or contractor of Google, Devpost or a contest-involved organisation, and no immediate family or household member is one | ⚠️ **Confirm this yourself.** Cognizant isn't named, but Cognizant does service work for Google. If you are personally assigned to a Google account or contract, you are a "contractor of Google" and **ineligible**. If you aren't, you're fine |
| Not a government-agency employee | ✅ |
| Entering as an individual, not on behalf of Cognizant | ✅ Recommended. Check that your Cognizant employment agreement doesn't claim IP in side projects built on your own time and equipment, because §6 requires the submission to be **solely owned** by you |

**Verdict:** eligible, provided you are not staffed on a Google engagement.

## Timeline (converted to IST)

| Milestone | PT | IST |
|---|---|---|
| Submissions open | Nov 11, 1:30 PM | Nov 12, 3:00 AM |
| Quota Sprint 2 request deadline | Wed Nov 18, 10:00 AM | **Wed Nov 18, 11:30 PM** |
| Quota Sprint 3 (final) request deadline | Wed Nov 25, 10:00 AM | **Wed Nov 25, 11:30 PM** |
| **Submission deadline** | Mon Nov 30, 2:00 PM | **Tue Dec 1, 3:30 AM** |
| Judging | Dec 10–16 | — |
| Winners announced | ~Dec 21, 12:00 PM | ~Dec 22, 1:30 AM |

Treat **Mon Nov 30, 11:59 PM IST** as your own deadline. Your Kiroween submission is due Dec 4, so finish this one first.

**Quota account:** not needed. ConfigShield runs on the free tier (Gemini Nano plus the Gemini Developer API free tier). Apply for Sprint 3 only if you add image generation or other billing-only models. The quota account lasts 4 days, and you pay for anything beyond it.

## Build plan (16 days)

| Days (IST) | Work |
|---|---|
| Nov 14–15 | Firebase project, AI Logic, App Check debug token, Anonymous Auth, Firestore. `npm run dev` working with Nano |
| Nov 16–19 | Tune the redactor prompt on 5–10 real-shaped (fictitious) configs; add an ASA sample; polish the UI |
| Nov 20–23 | Deploy to Firebase Hosting; optional Chrome side-panel extension (strengthens the Web/Chrome category) |
| Nov 24–26 | Record the video (`docs/DEMO_VIDEO_SCRIPT.md`) and upload to YouTube with captions |
| Nov 27–29 | Fill in the Devpost fields from `SUBMISSION.md` and do the final compliance pass below |
| Nov 30 | Submit. **Don't push commits after the deadline**, because they won't be evaluated |

## Mandatory submission checklist (§6)

- [ ] Uses **Firebase AI Logic**, imported **and called at runtime** (`src/ai/models.ts`, `src/pipeline.ts`)
- [ ] Platform: **Web (Chrome)** with **Gemini Nano** via AI Logic hybrid
- [ ] **App Check** enabled (debug token is fine)
- [ ] Supporting products: Auth ✅ Firestore ✅ Remote Config ✅
- [ ] **Public** GitHub repo with all source, assets and setup instructions
- [ ] **LICENSE** file (Apache-2.0) detected in the repo's *About* section. Check on GitHub after pushing
- [ ] README covers the value proposition and how AI Logic is used
- [ ] Text description: AI Logic usage, features, value proposition (`SUBMISSION.md`)
- [ ] Summary of what was built during the submission period (`SUBMISSION.md`)
- [ ] Disclosure of pre-existing code and tools (`SUBMISSION.md`). If you copy anything from ConfigGuard or another earlier project, **add it there**
- [ ] Demo video **≤ 3:00**, public on YouTube, English, showing the app working in Chrome
- [ ] Working test link (hosted URL) plus testing instructions (`docs/TESTING.md`)
- [ ] **No** production keys, service-account JSON, PII or real customer configs in the repo, form or video. `.env.local` stays git-ignored
- [ ] Platform category selected on Devpost: **Web/Chrome**
- [ ] Free and unrestricted access for judges until Dec 16

## How this maps to the judging criteria (equally weighted, 1–5 each)

| Criterion | What earns the points |
|---|---|
| Technological Implementation | Three distinct `InferenceMode`s, each chosen for a reason; the same JSON schema on both paths; the `inferenceSource` check; chunking for 9,216 tokens; a fail-closed leak gate; a cloud → on-device → rules fallback chain; an AI/rule cross-check with evidence verification; 49 tests, including privacy-boundary integration tests |
| Design | Complete flow: 5 samples, privacy-boundary diagram and receipt, live stage badges, score ring, provenance and verification badges, severity filters, copy fix / fix script, redaction map, re-hydrate, export, reopenable history. Not a bare prompt box |
| Potential Impact | A specific audience (network and security engineers in regulated industries) with a specific blocker (policy bans pasting configs into AI) that the product removes |
| Quality of the Idea | The hybrid split *is* the privacy boundary. Weak-secret detection without disclosure is a non-obvious touch |

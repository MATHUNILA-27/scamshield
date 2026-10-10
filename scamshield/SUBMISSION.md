# Devpost submission text (copy and paste)

**Title:** ScamShield: Check any message before you trust it
**Track:** AI + Cybersecurity
**Short description:** ScamShield helps ordinary people, especially elderly and non-English speakers, spot scams and impersonation by pasting a message and getting a clear verdict, reasons and next steps in English, Tamil or Hindi.

## Problem statement and target users
Phishing SMS, fake KYC alerts, parcel-fee texts and "new number" family impersonation cause huge financial losses, and AI now makes these messages more convincing. Existing tools are English-only, technical, or just say "spam". Our users are elderly relatives, students and first-time digital-payment users who need a fast, trustworthy second opinion before they click or pay.

## Technical approach and components
- FastAPI backend, plain HTML/JS frontend (no build step).
- Rule engine: six scam-tactic detectors plus link analysis (shorteners, brand look-alikes via string similarity, odd TLDs, IP hosts, punycode).
- LLM fraud analyst via any OpenAI-compatible API (we used Featherless open models), prompted to return structured JSON in the user's language and hardened against prompt injection.
- Hybrid scoring: 60% LLM + 40% rules, with a floor so strong rule evidence is never diluted, and graceful fallback to rules-only if the model fails.

## Real-world impact
It gives a non-technical person an instant, understandable decision ("Likely a scam, here's why, here's what to do, report at 1930"), removing the confusion scammers rely on. It works offline-capable in rules mode, supports local languages, stores nothing, and can be extended to WhatsApp bots or bank apps.

## 2-4 minute demo video script
1. (0:00) Hook: show a real-looking "SBI KYC blocked" SMS. "Millions get this. Many click."
2. (0:25) Paste it into ScamShield, choose English, press Check. Show red verdict, risk bar, tactics chips, the flagged `sbi-kyc-update.xyz` link, and next steps.
3. (1:15) Switch to Tamil and run the "Mom, new number" example. Show impersonation detection.
4. (1:50) Run the real OTP message: green "Looks safe", showing it doesn't cry wolf.
5. (2:20) Show architecture (rules + LLM + fusion) and the GitHub repo.
6. (2:50) Impact and next steps: screenshots, voice transcripts, WhatsApp bot.

## Submission checklist
- [ ] Push to a public GitHub repo
- [ ] Deploy (Render/Railway) and add the link
- [ ] Record the video, upload to YouTube (public), add link
- [ ] Add 2-3 screenshots and the architecture diagram from the README
- [ ] Submit on Devpost before Oct 10, 12:00 PM

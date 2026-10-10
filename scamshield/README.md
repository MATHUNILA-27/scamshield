# ScamShield

**Check a message. Know what to do next.**

ScamShield is a web-based scam-awareness prototype for people who want a second opinion before they click a link, share a code, or send money. It analyzes pasted messages, explains common warning signs, and offers practical next steps. The interface includes English, Tamil, and Hindi options.

> **Important:** ScamShield is an educational aid, not proof that a message is safe or fraudulent. Do not use it as the only basis for financial or security decisions.

## Features

- **Message analysis:** A rules-based detector checks for common scam tactics and suspicious links. An optional LLM analyst can contribute to the verdict when configured.
- **Clear explanation:** Shows the risk score, detected tactics, link warnings, and suggested actions.
- **Recovery checklist:** Provides fixed guidance based on what happened, such as paying money, sharing credentials, or opening a link or app.
- **Call Shield:** An offline questionnaire that helps users think through risky call situations. It does not listen to calls, use a microphone, or send call data.
- **Optional emergency contacts:** User-entered contacts are stored in the browser on that device and can be used for tap-to-call links.
- **Rules-only fallback:** Analysis still works without an LLM key or when the LLM is unavailable.

## How analysis works

1. The rules engine checks the message for scam tactics and suspicious URL patterns.
2. If configured, an LLM reviews the message. Long digit sequences are masked before being sent to the model provider.
3. When an LLM result is available, its score is combined with the rules score. Strong rule evidence is not allowed to be softened by the AI score.
4. ScamShield returns a verdict, explanations, link flags, and suggested actions.

The rules engine is pattern-based. It can miss new or unfamiliar scam tactics, and a suspicious-looking message can still be genuine. A “No common scam signals found” result does not mean a message is safe.

## Requirements

- Python 3.10 or newer
- Packages listed in `requirements.txt`
- Optional: an API key for an OpenAI-compatible LLM provider

## Run locally

From the project directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python -m uvicorn app:app --reload
```

Open [http://localhost:8000](http://localhost:8000).

On macOS or Linux, create and activate the virtual environment with:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
python -m uvicorn app:app --reload
```

### Optional LLM configuration

Edit `.env` and set `LLM_API_KEY` to a valid key for your chosen provider. The sample base URL and model in `.env.example` are configured for the example provider; change `LLM_BASE_URL` and `LLM_MODEL` if using another compatible service.

Without a valid key, ScamShield runs in rules-only mode. When LLM mode is enabled, pasted message text is sent to the configured provider for analysis. Do not submit sensitive personal information.

## Run tests

Run the focused rule-engine regression tests with:

```bash
python -m unittest discover -s eval -p "test_*.py" -v
```

The labeled evaluation cases are in `eval/robustness.json`. To run the optional robustness evaluator:

```bash
python eval/run_robustness.py
```

The robustness evaluator runs each case three times and writes `eval/robustness_results.json`. With an LLM key configured, it sends the evaluation messages to that provider. Without a working key, it evaluates the rules-only fallback.

### Current evaluation snapshot

In the rules-only evaluation performed during development:

- Tune split: **27 of 30** labeled scam cases were classified as suspicious or likely scam.
- Holdout split: **2 of 12** labeled scam cases were classified as suspicious or likely scam; **2 of 3** non-prompt-injection scam cases were detected.
- No labeled genuine cases crossed the suspicious threshold in that run.

These are results from the project's own small evaluation set, not an independent benchmark or a guarantee of real-world accuracy. Several Tamil and Hindi samples in the set contain `?` in place of the original script, which limits what they can measure. Prompt-injection examples are also included as test inputs; message instructions are untrusted content, not evidence that a message is itself a scam.

## Privacy and safety notes

- ScamShield does not intentionally store or log pasted message text.
- In LLM mode, the message (with long digit runs masked) is sent to the configured AI provider. Provider data practices may differ.
- Emergency contacts are saved in the browser's local storage on the current device. ScamShield does not receive those contacts.
- Call Shield uses fixed questions and guidance; it does not record audio or assess a caller's voice.
- The app includes a simple in-memory limit of 20 requests per minute per client IP. Hosting-provider logs and deployment settings are outside the app's control.

## Known limitations

- Rules and URL checks are heuristic and can produce both missed detections and false alarms.
- Tamil and Hindi detection is limited to implemented keywords and may not understand varied wording, transliteration, or dialects. Have native speakers review localized wording before wider use.
- URL warnings use patterns, not live reputation checks or website inspection.
- ScamShield cannot verify a sender's identity, confirm whether a payment is legitimate, or determine whether a call uses a cloned voice.
- Recovery guidance is general information. Confirm urgent steps with your bank, payment provider, or official authorities.

## Deployment

For a compatible hosting provider, use:

```bash
python -m uvicorn app:app --host 0.0.0.0 --port $PORT
```

Configure any required environment variables in the hosting provider's settings. Do not commit `.env` files or API keys.

## Project context

Built for the AI + Cybersecurity track at ForgeHacks 2026.

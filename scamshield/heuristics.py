"""Rule-based scam signals. Works with no API key, so the demo never breaks."""
import re, difflib
from urllib.parse import urlparse

BRANDS = ["paypal", "amazon", "google", "microsoft", "apple", "netflix", "sbi", "hdfc",
          "icici", "paytm", "phonepe", "gpay", "irctc", "flipkart", "whatsapp",
          "instagram", "facebook", "dhl", "fedex", "indiapost", "aadhaar", "epfo"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy", "is.gd", "shorturl.at"}
BAD_TLDS = {"xyz", "top", "click", "icu", "buzz", "live", "support", "info", "vip", "work"}
TACTICS = {
    "Urgency / threat": r"urgent|immediately|within \d+ ?(hours?|hrs?|mins?)|last warning|final warning|suspended|blocked|expire|legal action|arrest|final notice|act now|right now|payment due|account will close|under investigation|tax due|not later|jaroori|zaroori|turant|abhi",
    "Fake authority": r"\b(bank|rbi|police|cbi|customs|income tax|support team|customer care|kyc|government|officer)\b",
    "Asks for money or card details": r"\b(gift ?card|bitcoin|crypto|wire transfer|processing fee|advance fee)\b|\b(link par click|details bhar(?:o|na)?|details fill)\b|\b(share|send|provide|give|enter|reply with|tell|pay|transfer|deposit|scan|need|require|help)\b.{0,40}\b(your\s+)?(otp|cvv|pin|upi(?:\s+id|\s+link)?|password|passcode|verification code|card details|money|cash|amount|rs\.?|inr|fee|fine|tax|deposit|payment)\b",
    "Too-good-to-be-true reward": r"\b(lottery|you (have )?won|prize|cashback|free gift|claim your|refund|work from home|earn \$?\d+)\b",
    "Impersonating family or friend": r"(?:new number|lost my phone|it'?s me|mom|dad|beta|family member|friend).{0,60}(?:send|transfer|pay|help|need).{0,30}(?:money|amount|rs\.?|upi|cash|\d{2,})",
    "Secrecy request": r"don'?t tell|do not tell|keep (this )?secret|do not share with|do not discuss|do not mention|reply privately|confidential",
}
URL_RE = re.compile(
    r"(?:https?|hxxps?)://[^\s<>\"']+|www\.[^\s<>\"']+|"
    r"(?<![@\w.-])[a-z0-9-]+(?:(?:\.|\[\.\])[a-z0-9-]+)+(?:/[^\s<>\"']*)?",
    re.I,
)


def _host(url):
    candidate = (url or "").strip().rstrip(".,;)")
    candidate = re.sub(r"(?i)^hxxp(?=://)", "http", candidate)
    candidate = candidate.replace("[.]", ".").replace("[at]", "@")
    candidate = re.sub(r"[\[\]()]", "", candidate)
    if not candidate:
        return ""
    if "://" not in candidate and "/" not in candidate:
        candidate = "http://" + candidate
    elif "://" not in candidate:
        candidate = "http://" + candidate
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
        if host:
            return host
    except ValueError:
        pass
    cleaned = re.sub(r"^[a-z]+://", "", candidate)
    cleaned = cleaned.split("/")[0].split(":")[0].strip()
    return cleaned.lower()


def analyze_url(url):
    host, flags = _host(url), []
    if not host:
        return {"url": url, "host": "", "flags": ["Malformed link"]}
    parts = host.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else host
    if host in SHORTENERS:
        flags.append("Shortened link hides the real destination")
    if parts and parts[-1] in BAD_TLDS:
        flags.append(f"Unusual domain ending '.{parts[-1]}'")
    if re.fullmatch(r"[\d.]+", host):
        flags.append("Link uses a raw IP address")
    if "xn--" in host:
        flags.append("Look-alike (punycode) characters in domain")
    if host.count("-") >= 2:
        flags.append("Many hyphens in domain, common in fake sites")
    label = re.sub(r"[^a-z0-9]", "", parts[-2]) if len(parts) >= 2 else ""
    for b in BRANDS:
        # brand name inside a domain that isn't the brand's own (e.g. sbi-kyc-update.com)
        if b in host and label != b:
            flags.append(f"Mentions '{b}' but is not the real {b} site")
            break
        if label and label != b and difflib.SequenceMatcher(None, label, b).ratio() >= 0.8:
            flags.append(f"Domain '{root}' looks like a typo of '{b}'")
            break
    return {"url": url, "host": host, "flags": flags}


def analyze(text):
    t, tactics, score = text.lower(), [], 0
    tactic_spans = []
    for name, pat in TACTICS.items():
        matches = list(re.finditer(pat, t))
        if matches:
            tactics.append(name)
            score += 14
            tactic_spans.extend({"start": m.start(), "end": m.end(), "tactic": name} for m in matches)
    if "Impersonating family or friend" in tactics and "Asks for money or card details" in tactics:
        score += 20  # classic 'new number' impersonation scam
    if len(tactics) >= 2:
        score += 4
    if "Asks for money or card details" in tactics:
        if re.search(r"\b(job|hiring|recruit|interview|loan)\b", t):
            score += 16
        if re.search(r"\b(small favour|return it|pay me back|pay you back)\b", t):
            score += 16
    url_spans, urls = [], []
    for match in URL_RE.finditer(text):
        url = match.group().rstrip(".,)")
        if not url:
            continue
        urls.append(analyze_url(url))
        url_spans.append({"start": match.start(), "end": match.start() + len(url), "url": url})
    for u in urls:
        score += min(len(u["flags"]) * 22, 44)
    if urls and not any(u["flags"] for u in urls):
        score += 4
    return {"score": min(score, 100), "tactics": tactics, "urls": urls,
            "spans": {"tactics": tactic_spans, "urls": url_spans}}

# Tamil and Hindi keywords so rules-only mode is not English-only
TACTICS["Urgency / threat"] += r"|உடனே|முடக்க|தடை|तुरंत|ब्लॉक|बंद हो"
TACTICS["Fake authority"] += r"|வங்கி|கணக்கு|காவல்|बैंक|खाता|केवाईसी|पुलिस"
TACTICS["Asks for money or card details"] += r"|பணம் அனுப்ப|கடவுச்சொல்|पैसे भेज|ओटीपी|पासवर्ड"
TACTICS["Too-good-to-be-true reward"] += r"|பரிசு|லாட்டரி|इनाम|लॉटरी|रिफंड"
TACTICS["Secrecy request"] += r"|ரகசியம்|किसी को न बताओ|गुप्त"

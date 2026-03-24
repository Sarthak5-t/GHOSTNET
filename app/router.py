import asyncio
import re
from collections import defaultdict
from app.ollama import call_model

# --- Conversation History ---
history: list[str] = []

# --- Keywords ---
CODING_KW = [
    "code","script","exploit","payload","function","class","def","import",
    "bug","fix","refactor","snippet","program","algorithm","debug","bash",
    "python","javascript","golang","rust","c++","java","powershell","write a"
]

ANALYSIS_KW = [
    "analyze","analyse","scan","nmap","vulnerability","assess","report",
    "review","compare","summarize","summarise","audit","explain","describe",
    "what is","how does","research","recon","enumerate","fingerprint"
]

PENTEST_KW = [
    "pentest","penetration","red team","redteam","ctf","privilege escalation",
    "privesc","lateral movement","persistence","exfiltrate","c2",
    "post exploit","metasploit","burpsuite","sqlmap","hydra","hashcat",
    "pass the hash","kerberoast","bloodhound","reverse shell","bind shell",
    "webshell","phishing","social engineering"
]

CVE_KW = [
    "cve","nvd","exploit-db","0day","zero day","rce","lfi","rfi","sqli",
    "xss","ssrf","xxe","deserialization","buffer overflow","use after free",
    "heap spray","rop chain","shellcode","bypass","evasion"
]

GPT_KW = [
    "ask chatgpt","chatgpt","leo ai","leo chat","@leo"
]

# --- System Prompts ---
SYSTEM_PROMPTS = {
    "pentest": """You are an expert penetration tester and red team operator.
Provide detailed, technical, actionable information for authorized security testing.
Include actual commands, tools, and methodologies. Format code in proper code blocks.
Always note this is for authorized testing only.""",

    "cve": """You are a CVE analysis expert and security researcher.
Provide detailed technical analysis of vulnerabilities including root cause,
affected versions, exploitation techniques, detection and mitigation strategies.
Format all code with proper syntax highlighting.""",

    "code": """You are an elite security-focused developer.
Write clean, well-commented, production-ready security tools and scripts.
Always include usage instructions and dependencies.""",

    "analysis": """You are a senior security analyst.
Provide thorough structured analysis with clear sections, severity ratings,
and actionable recommendations. Use markdown formatting.""",

    "leo": """You are an advanced AI assistant (Leo) capable of answering questions conversationally
and providing guidance interactively.""",

    "ai_pentest": """You are an expert in adversarial AI and LLM security. 
Targeted for AI/LLM red-teaming, you generate advanced prompt injection, jailbreaking, and extraction payloads.
Provide technical details, payload structure, and the logic behind the attack.
Focus on bypass techniques and defensive gaps.""",

    "general": """You are GHOSTNET, an advanced AI assistant for cybersecurity professionals.
Provide expert-level guidance on security topics, tools, and methodologies."""
}

    # --- Mode → Model Mapping ---
MODE_MODEL = {
    "code":     "hf.co/dphn/dolphin-2.9.3-mistral-nemo-12b-gguf:Q5_K_M",
    "cve":      "dolphin-mistral:7b",
    "pentest":  "pentest-assistant",
    "analysis": "dolphin-mistral:7b",
    "leo":      "dolphin-mistral:7b",  # Now uses local model with Leo persona
    "ai_pentest": "dolphin-mistral:7b",
    "general":  "dolphin-mistral:7b",
}

# --- Mode → Keywords Mapping ---
MODE_KEYWORDS = {
    "leo": GPT_KW,
    "cve": CVE_KW,
    "pentest": PENTEST_KW,
    "code": CODING_KW,
    "analysis": ANALYSIS_KW
}

# --- Routing Functions ---
def choose_mode(prompt: str) -> str:
    """
    Determine the most relevant mode based on keyword scoring.
    Handles multi-keyword prompts and avoids substring false positives.
    """
    p = prompt.lower()
    scores = defaultdict(int)

    for mode, keywords in MODE_KEYWORDS.items():
        for kw in keywords:
            kw_clean = kw.strip()
            if re.search(rf"\b{re.escape(kw_clean)}\b", p):
                scores[mode] += 1

    if not scores:
        return "general"

    # Return the mode with the highest score
    return max(scores, key=scores.get)


def choose_model(mode: str) -> str:
    return MODE_MODEL.get(mode, MODE_MODEL["general"])


def smart_route(prompt: str, use_memory: bool = False, force_model: str = "") -> dict:
    global history
    mode = choose_mode(prompt)
    model = force_model if force_model else choose_model(mode)
    system = SYSTEM_PROMPTS.get(mode, SYSTEM_PROMPTS["general"])

    # Use conversation memory if enabled
    if use_memory and history:
        context = "\n".join(history[-10:]) + f"\nUser: {prompt}"
    else:
        context = prompt

    # Call the selected model
    response = call_model(model, context, system=system)

    # Append to memory
    if use_memory:
        history.append(f"User: {prompt}")
        history.append(f"Assistant: {response}")
        if len(history) > 20:
            history = history[-20:]

    return {
        "model": model,
        "mode": mode,
        "response": response,
        "history_depth": len(history) // 2
    }


def clear_history():
    global history
    history = []

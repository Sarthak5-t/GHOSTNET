from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import asyncio

from app.router import smart_route, clear_history, history, choose_mode, choose_model
from app.ollama import list_models
from app.cve_crawler import extract_cve_ids, fetch_cve, search_recent_cves

app = FastAPI(title="GHOSTNET", version="3.0.0")

class LeoRequest(BaseModel):
    text: str

@app.post("/leo/ask")
async def leo_ask(req: LeoRequest):
    if not req.text.strip():
        raise HTTPException(400, "Prompt cannot be empty.")
    try:
        # Standardize Leo mode to use the smart_route engine
        result = smart_route(req.text, use_memory=True) # Always use memory for chat
        return {
            "response": result["response"],
            "model": result["model"],
            "mode": result["mode"]
        }
    except Exception as e:
        raise HTTPException(503, str(e))

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")


# ── Schemas ───────────────────────────────────────────────────────

class PromptRequest(BaseModel):
    text: str
    use_memory: bool = False
    force_model: str = ""


class CVERequest(BaseModel):
    cve_id: str
    generate_exploit: bool = False
    language: str = "python"
    exploit_type: str = "poc"


class CVESearchRequest(BaseModel):
    keyword: str = ""
    limit: int = 10


class ExploitRequest(BaseModel):
    cve_id: str
    description: str
    language: str = "python"
    exploit_type: str = "poc"


class ReconRequest(BaseModel):
    target: str
    recon_type: str = "passive"


class AIPentestRequest(BaseModel):
    target_model: str
    attack_type: str
    context: str = ""





# ── Routes ────────────────────────────────────────────────────────

@app.get("/")
def root():
    return FileResponse("static/index.html")


@app.get("/health")
def health():
    return {
        "status":           "ok",
        "models_available": list_models(),
        "history_depth":    len(history) // 2
    }


@app.post("/ask")
async def ask(req: PromptRequest):
    if not req.text.strip():
        raise HTTPException(400, "Prompt cannot be empty.")
    try:
        # Offload intensive ML routing/generation to a thread
        result = await asyncio.to_thread(
            smart_route,
            req.text,
            use_memory=req.use_memory,
            force_model=req.force_model
        )
        result["detected_cves"] = extract_cve_ids(result["response"])[:3]
        return result
    except RuntimeError as e:
        raise HTTPException(503, str(e))


@app.post("/cve/lookup")
async def cve_lookup(req: CVERequest):
    try:
        cve_data = await fetch_cve(req.cve_id)
    except Exception as e:
        cve_data = {
            "id":          req.cve_id,
            "description": f"Could not fetch: {e}",
            "severity":    "UNKNOWN",
            "pocs":        {"github":[],"exploit_db":[],"packet_storm":[],"vulhub":[]},
            "poc_count":   0
        }

    result = {"cve": cve_data}

    if req.generate_exploit:
        desc  = cve_data.get("description", "") or f"Vulnerability: {req.cve_id}"
        etype = {"poc":"proof-of-concept","full":"full working","detection":"detection/scanner"}.get(req.exploit_type,"proof-of-concept")

        prompt = f"""You are a security researcher. Generate a {etype} for:

CVE ID:      {req.cve_id}
Description: {desc}
CVSS Score:  {cve_data.get('score','N/A')}
Severity:    {cve_data.get('severity','N/A')}
Weaknesses:  {', '.join(cve_data.get('weaknesses', [])) or 'N/A'}
Language:    {req.language}

Provide:
1. Complete {req.language} code with inline comments
2. Step-by-step usage instructions
3. Required dependencies
4. How to detect if target is vulnerable
5. Mitigation and patch guidance

Format all code in markdown code blocks with language tags."""

        try:
            from app.ollama import call_model
            from app.router import SYSTEM_PROMPTS, choose_model
            model = await asyncio.to_thread(choose_model, "code")
            # Offload heavy ML generation
            result["exploit"] = await asyncio.to_thread(call_model, model, prompt, system=SYSTEM_PROMPTS["cve"])
        except RuntimeError as e:
            raise HTTPException(503, str(e))

    return result


@app.post("/cve/search")
async def cve_search(req: CVESearchRequest):
    results = await search_recent_cves(req.keyword, req.limit)
    return {"results": results, "count": len(results), "keyword": req.keyword}


@app.post("/exploit/generate")
async def generate_exploit(req: ExploitRequest):
    from app.ollama import call_model
    from app.router import SYSTEM_PROMPTS

    prompt = f"""Generate a detailed {req.exploit_type} for {req.cve_id}.

Vulnerability: {req.description}
Language:      {req.language}
Type:          {req.exploit_type}

Provide:
1. Complete working exploit code with comments
2. Step-by-step exploitation methodology
3. Prerequisites and setup
4. Evasion techniques if applicable
5. Detection signatures for defenders"""

    try:
        model = await asyncio.to_thread(choose_model, "code")
        code = await asyncio.to_thread(call_model, model, prompt, system=SYSTEM_PROMPTS["cve"])
        return {"exploit": code, "cve_id": req.cve_id, "language": req.language}
    except RuntimeError as e:
        raise HTTPException(503, str(e))


@app.post("/pentest/recon")
async def recon(req: ReconRequest):
    from app.ollama import call_model
    from app.router import SYSTEM_PROMPTS

    prompt = f"""Generate a comprehensive {req.recon_type} reconnaissance plan for: {req.target}

Include:
1. OSINT gathering techniques and tools
2. DNS enumeration commands
3. Port scanning strategies (nmap commands)
4. Service enumeration
5. Web application fingerprinting
6. Subdomain enumeration
7. Technology stack detection
8. Vulnerability surface mapping

Format all commands in code blocks."""

    try:
        model = await asyncio.to_thread(choose_model, "analysis")
        result = await asyncio.to_thread(call_model, model, prompt, system=SYSTEM_PROMPTS["pentest"])
        return {"recon_plan": result, "target": req.target, "type": req.recon_type}
    except RuntimeError as e:
        raise HTTPException(503, str(e))


@app.post("/ai-pentest")
async def ai_pentest(req: AIPentestRequest):
    from app.ollama import call_model
    from app.router import SYSTEM_PROMPTS, choose_model
    
    prompt = f"Target: {req.target_model}\nAttack: {req.attack_type}\nContext: {req.context}"
    
    try:
        model = await asyncio.to_thread(choose_model, "ai_pentest")
        payloads = await asyncio.to_thread(call_model, model, prompt, system=SYSTEM_PROMPTS["ai_pentest"])
        return {
            "payloads": payloads,
            "model": model,
            "mode": "ai_pentest"
        }
    except RuntimeError as e:
        raise HTTPException(503, str(e))


@app.get("/memory")
def get_memory():
    return {"history": history, "depth": len(history) // 2}


@app.delete("/memory")
def reset_memory():
    clear_history()
    return {"status": "ok"}


@app.get("/models")
def get_models():
    return {"models": list_models()}





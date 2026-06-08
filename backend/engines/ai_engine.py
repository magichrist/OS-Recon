import os
import json
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

class AIEngine:
    def __init__(self):
        self.api_key = os.environ.get("GROQ_API_KEY")
        if not self.api_key:
            raise RuntimeError("GROQ_API_KEY is missing from environment variables.")
        
        self.client = OpenAI(
            base_url="https://api.groq.com/openai/v1",
            api_key=self.api_key
        )
        self.default_model = "llama-3.1-8b-instant"
        self.system_prompt = (
            "You are the central cognitive module of OS-Recon, an advanced target profiling and threat intelligence system.\n"
            "Your task is to analyze the provided raw telemetry JSON and generate a aggressive, highly synthesized OpSec Evaluation Report.\n\n"
            "CRITICAL DIRECTIVES:\n"
            "1. DO NOT regurgitate data structures. Do not say 'Interesting repositories: 1' or list out counts. Synthesize what those counts mean.\n"
            "2. FILTER OUT SCRAPER NOISE. Ignore generic platform footer/system links (e.g., YouTube Kids, Meta About, Instagram Help, GitHub assets). Only analyze unique user-inserted external links (like Carrd, personal domains, or secondary socials).\n"
            "3. FOCUS ON CORRELATION. Analyze how username variations (e.g., ic0e vs ascended_ice) link across platforms. Point out identity clusters.\n"
            "4. NO CONVERSATIONAL FILLER. Start immediately with the first header. Use clinical, defensive engineering language.\n"
            "5. USE TERMINAL INDICATORS EXACTLY:\n"
            "   [+] for high-value intelligence insights, verified links, or target infrastructure details.\n"
            "   [!] for legitimate, actionable OpSec vulnerabilities (e.g., specific exposed email patterns, clear text associations, asset links).\n"
            "   [-] for operational intelligence notes regarding behavior, platform usage, or tracking recommendations.\n\n"
            "REPORT STRUCTURE REQUIREMENT:\n"
            "Phase 1: [!] CRITICAL OPSEC EXPOSURES - Highlight actual high-risk findings (like the exposed emails or high-value pivot domains).\n"
            "Phase 2: [+] IDENTITY GRAPH & INFRASTRUCTURE CLUSTERS - Correlate usernames and unique tracking links (e.g., analyzing how a Carrd page connects profiles).\n"
            "Phase 3: [-] TARGET PROFILE & BEHAVIORAL MATRIX - Summarize what the technical stack (languages used) and profile telemetry tell you about the target's skillset and online persona."
        )

    def _prune_payload(self, raw_data: dict) -> dict:
        pruned = {
            "social": {
                "username": raw_data.get("social", {}).get("username"),
                "total_found": raw_data.get("social", {}).get("total_found"),
                "total_checked": raw_data.get("social", {}).get("total_checked")
            },
            "github": None,
            "deepPry": []
        }
        
        git = raw_data.get("github")
        if git:
            pruned["github"] = {
                "username": git.get("username"),
                "exposed_emails": git.get("exposed_emails", []),
                "metrics": git.get("metrics", {}),
                "interesting_repos": [
                    {
                        "name": r.get("name"), 
                        "description": r.get("description"), 
                        "language": r.get("language")
                    } for r in git.get("interesting", []) if isinstance(r, dict)
                ],
                "standard_repos": [
                    {
                        "name": r.get("name"), 
                        "language": r.get("language")
                    } for r in git.get("standard", []) if isinstance(r, dict)
                ]
            }
            
        pry = raw_data.get("deepPry")
        if pry:
            for item in pry:
                if not isinstance(item, dict):
                    continue
                metrics = item.get("metrics", {})
                pruned["deepPry"].append({
                    "site": item.get("site"),
                    "username": item.get("username"),
                    "status": item.get("status"),
                    "bio": metrics.get("bio") if isinstance(metrics, dict) else None,
                    "external_links": metrics.get("external_links", []) if isinstance(metrics, dict) else []
                })
                
        return pruned

    def generate_report(self, raw_payload: dict) -> str:
        try:
            clean_data = self._prune_payload(raw_payload)
            json_str = json.dumps(clean_data, default=str)
            
            response = self.client.chat.completions.create(
                model=self.default_model,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": json_str}
                ],
                temperature=0.1
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"[AI Engine Error]: Failed to execute pipeline. Details: {str(e)}"

ai_engine = AIEngine()
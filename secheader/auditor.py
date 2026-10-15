import asyncio
from typing import Dict, Any, List
import httpx
from secheader.rules import SECURITY_HEADERS, INFO_DISCLOSURE_HEADERS, calculate_grade


class HeaderAuditor:
    def __init__(self, timeout: float = 8.0, concurrency: int = 10, verify_ssl: bool = True):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)
        self.verify_ssl = verify_ssl

    async def audit_url(self, client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        async with self.semaphore:
            try:
                response = await client.get(
                    url,
                    follow_redirects=True,
                    headers={"User-Agent": "SecHeader-Auditor/1.1 (Security Compliance Scanner)"},
                )
                return self._evaluate_response(url, str(response.url), response.status_code, response.headers)
            except Exception as exc:
                return {
                    "target": url,
                    "error": str(exc),
                    "score": 0,
                    "grade": "F",
                }

    def _evaluate_response(
        self, original_url: str, final_url: str, status_code: int, headers: httpx.Headers
    ) -> Dict[str, Any]:
        score = 0
        present_headers: List[Dict[str, Any]] = []
        missing_headers: List[Dict[str, Any]] = []
        warnings: List[str] = []
        disclosed_info: Dict[str, str] = {}

        lower_headers = {k.lower(): v for k, v in headers.items()}

        # 1. Check Security Headers
        for key, rule in SECURITY_HEADERS.items():
            if key in lower_headers:
                val = lower_headers[key]
                score += rule["weight"]
                warning_msg = self._check_weak_value(key, val)
                if warning_msg:
                    warnings.append(warning_msg)
                present_headers.append({
                    "header": rule["name"],
                    "value": val,
                    "weight": rule["weight"],
                })
            else:
                missing_headers.append({
                    "header": rule["name"],
                    "severity": rule["severity"],
                    "weight": rule["weight"],
                    "remediation": rule["remediation"],
                })

        # 2. Check Information Disclosure Headers
        for info_key in INFO_DISCLOSURE_HEADERS:
            if info_key in lower_headers:
                disclosed_info[info_key] = lower_headers[info_key]

        # 3. Check CORS Misconfigurations
        acao = lower_headers.get("access-control-allow-origin")
        acac = lower_headers.get("access-control-allow-credentials")
        if acao == "*":
            warnings.append("Permissive CORS policy detected: Access-Control-Allow-Origin is set to '*'.")
        if acao == "*" and acac and acac.lower() == "true":
            warnings.append("Critical CORS misconfiguration: Wildcard origin combined with Allow-Credentials.")

        # 4. Check Set-Cookie Security Flags
        raw_cookies = headers.get_list("set-cookie")
        cookies_report, cookie_penalty = self._evaluate_cookies(raw_cookies, final_url.startswith("https://"))
        score = max(0, score - cookie_penalty)

        return {
            "target": original_url,
            "final_url": final_url,
            "status_code": status_code,
            "score": score,
            "grade": calculate_grade(score),
            "present": present_headers,
            "missing": missing_headers,
            "cookies": cookies_report,
            "disclosed": disclosed_info,
            "warnings": warnings,
        }

    @staticmethod
    def _evaluate_cookies(raw_cookies: List[str], is_https: bool) -> tuple[List[Dict[str, Any]], int]:
        cookies_analysis: List[Dict[str, Any]] = []
        total_penalty = 0

        for raw in raw_cookies:
            parts = [p.strip() for p in raw.split(";") if p.strip()]
            if not parts:
                continue

            name_val = parts[0]
            cookie_name = name_val.split("=", 1)[0].strip()
            attributes = parts[1:]

            attr_map: Dict[str, str] = {}
            for attr in attributes:
                if "=" in attr:
                    k, v = attr.split("=", 1)
                    attr_map[k.strip().lower()] = v.strip()
                else:
                    attr_map[attr.strip().lower()] = "true"

            has_secure = "secure" in attr_map
            has_httponly = "httponly" in attr_map
            samesite_val = attr_map.get("samesite", None)

            issues: List[str] = []
            remediations: List[str] = []
            penalty = 0

            if not has_secure:
                issues.append("Missing 'Secure' flag")
                remediations.append("Add '; Secure' to ensure transmission only over HTTPS.")
                penalty += 5

            if not has_httponly:
                issues.append("Missing 'HttpOnly' flag")
                remediations.append("Add '; HttpOnly' to prevent client-side script access (XSS mitigation).")
                penalty += 5

            if not samesite_val:
                issues.append("Missing 'SameSite' attribute")
                remediations.append("Add '; SameSite=Lax' or '; SameSite=Strict' for CSRF protection.")
                penalty += 3
            elif samesite_val.lower() == "none":
                if not has_secure:
                    issues.append("SameSite=None used without 'Secure' flag (rejected by modern browsers)")
                    remediations.append("Ensure '; Secure' is set whenever 'SameSite=None' is used.")
                    penalty += 5

            # Check Cookie Prefixes (__Host- and __Secure-)
            if cookie_name.startswith("__Host-"):
                path_val = attr_map.get("path", "")
                if not has_secure or "domain" in attr_map or path_val != "/":
                    issues.append("Invalid '__Host-' prefix requirements (requires Secure, Path=/, and no Domain)")
                    penalty += 5
            elif cookie_name.startswith("__Secure-") and not has_secure:
                issues.append("Invalid '__Secure-' prefix requirement (requires Secure flag)")
                penalty += 5

            total_penalty += penalty
            cookies_analysis.append({
                "name": cookie_name,
                "secure": has_secure,
                "httponly": has_httponly,
                "samesite": samesite_val if samesite_val else "Missing",
                "status": "SECURE" if not issues else "VULNERABLE",
                "issues": issues,
                "remediation": " ".join(remediations) if remediations else "All primary security attributes are properly configured.",
            })

        # Cap total cookie penalty at 20 points so it stays balanced with headers
        return cookies_analysis, min(total_penalty, 20)

    @staticmethod
    def _check_weak_value(header_key: str, value: str) -> str:
        val_lower = value.lower()
        if header_key == "content-security-policy":
            if "unsafe-inline" in val_lower or "unsafe-eval" in val_lower:
                return "CSP contains 'unsafe-inline' or 'unsafe-eval', which weakens XSS protection."
        if header_key == "strict-transport-security":
            if "max-age=0" in val_lower:
                return "HSTS max-age is set to 0, effectively disabling HSTS protection."
        return ""

    async def run_batch(self, urls: List[str]) -> List[Dict[str, Any]]:
        async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl) as client:
            tasks = [self.audit_url(client, u.strip()) for u in urls if u.strip()]
            return await asyncio.gather(*tasks)

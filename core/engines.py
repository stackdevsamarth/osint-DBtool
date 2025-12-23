import os
import requests
import hashlib
import math
import re

class BreachEngine:
    def __init__(self, data_path="tool/data/breaches"):
        self.data_path = data_path

    def check(self, target, target_type):
        breaches = []
        
        # 1. Password HIBP Check (Special case)
        if target_type == "password":
            return self._check_hibp_password(target)

        # 2. Email/Phone Checks
        # Free Sources
        breaches.extend(self._check_emailrep(target))
        breaches.extend(self._check_leakcheck(target))
        breaches.extend(self._check_proxynova(target))
        breaches.extend(self._check_local(target))
        
        # Premium Sources (if keys exist)
        breaches.extend(self._check_hibp_account(target))
        breaches.extend(self._check_intelx(target))
        
        # Dedup by name
        seen = set()
        unique = []
        for b in breaches:
            if b['name'] not in seen:
                seen.add(b['name'])
                unique.append(b)
        
        # Sort by year (for timeline)
        unique.sort(key=lambda x: int(x['year']) if str(x['year']).isdigit() else 9999)
        return unique

    def _check_hibp_password(self, password):
        try:
            sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix, suffix = sha1[:5], sha1[5:]
            resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    h, count = line.split(':')
                    if h == suffix:
                        return [{
                            "name": "HIBP Pwned Passwords",
                            "year": "Unknown",
                            "source_type": "HIBP k-Anonymity",
                            "leak_count": int(count)
                        }]
        except: pass
        return []

    def _check_emailrep(self, email):
        try:
            resp = requests.get(f"https://emailrep.io/{email}", timeout=5)
            if resp.status_code == 200 and resp.json().get("details", {}).get("data_breach"):
                return [{"name": "EmailRep.io Detection", "year": "Unknown", "source_type": "Reputation API", "data_leaked": ["unknown"]}]
        except: pass
        return []
        
    def _check_leakcheck(self, target):
        try:
            resp = requests.get(f"https://leakcheck.io/api/public?check={target}", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success"):
                    return [{
                        "name": src.get("name"),
                        "year": src.get("date", "Unknown")[:4] if src.get("date") else "Unknown",
                        "source_type": "LeakCheck.io",
                        "data_leaked": ["unknown"]
                    } for src in data.get("sources", [])]
        except: pass
        return []

    def _check_proxynova(self, target):
        try:
            resp = requests.get(f"https://api.proxynova.com/comb?query={target}", timeout=5)
            if resp.status_code == 200 and resp.json().get("count", 0) > 0:
                return [{"name": "Proxynova COMB", "year": "Unknown", "source_type": "COMB", "data_leaked": ["password"]}]
        except: pass
        return []

    def _check_local(self, target):
        results = []
        if os.path.exists(self.data_path):
            for f in os.listdir(self.data_path):
                try:
                    with open(os.path.join(self.data_path, f), errors='ignore') as file:
                        if target in file.read():
                            results.append({"name": f"Local: {f}", "year": "Unknown", "source_type": "Local DB", "data_leaked": ["unknown"]})
                except: pass
        return results

    def _check_hibp_account(self, email):
        key = os.environ.get("HIBP_API_KEY")
        if not key: return []
        try:
            resp = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", headers={"hibp-api-key": key}, timeout=10)
            if resp.status_code == 200:
                return [{
                    "name": b["Name"], 
                    "year": b["BreachDate"][:4], 
                    "source_type": "HIBP", 
                    "data_leaked": b["DataClasses"]
                } for b in resp.json()]
        except: pass
        return []

    def _check_intelx(self, target):
        # Placeholder for IntelX
        return []

class PasswordAnalyzer:
    def analyze(self, password, leak_count):
        entropy = self._entropy(password)
        score = self._score(password, entropy, leak_count)
        return {
            "entropy": round(entropy, 2),
            "crack_time": self._crack_time(entropy),
            "score": score,
            "leak_count": leak_count
        }

    def _entropy(self, pwd):
        pool = 0
        if re.search(r'[a-z]', pwd): pool += 26
        if re.search(r'[A-Z]', pwd): pool += 26
        if re.search(r'[0-9]', pwd): pool += 10
        if re.search(r'[^a-zA-Z0-9]', pwd): pool += 32
        return len(pwd) * math.log2(pool) if pool else 0

    def _crack_time(self, entropy):
        seconds = (2**entropy) / 100_000_000_000
        intervals = [('centuries', 3.154e9), ('years', 31536000), ('days', 86400), ('hours', 3600), ('minutes', 60), ('seconds', 1)]
        for name, count in intervals:
            val = seconds / count
            if val >= 1: return f"{int(val)} {name}"
        return "Instantly"

    def _score(self, pwd, entropy, leaks):
        if leaks > 0: return 0
        score = min(entropy, 60) + (20 if len(pwd)>12 else 0) + (20 if re.search(r'[^a-zA-Z0-9]', pwd) else 0)
        return min(int(score), 100)

class RiskScorer:
    def calculate(self, breaches):
        score = len(breaches) * 15
        for b in breaches:
            if "password" in b.get("data_leaked", []): score += 20
        return min(score, 100)

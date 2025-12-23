import requests
import hashlib

class TimelineEngine:
    def estimate_first_seen(self, email, domain):
        dates = []
        
        # 1. Domain Registration
        if domain:
            try:
                resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=5)
                if resp.status_code == 200:
                    for e in resp.json().get("events", []):
                        if e["eventAction"] == "registration":
                            dates.append(e["eventDate"][:7]) # YYYY-MM
            except: pass

        # 2. Gravatar Profile
        if email:
            try:
                h = hashlib.md5(email.strip().lower().encode()).hexdigest()
                # There is no direct public timestamp in Gravatar JSON usually, 
                # but we can verify existence.
                # If we really wanted date, we'd need other OSINT sources.
                # Just checking existence here.
                requests.get(f"https://en.gravatar.com/{h}.json", timeout=5)
            except: pass
            
        if dates:
            dates.sort()
            return dates[0]
            
        return "Unknown"

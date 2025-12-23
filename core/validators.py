import re

class Validator:
    def __init__(self):
        self.email_regex = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
        self.phone_regex = re.compile(r"^\+?[1-9]\d{7,14}$")

    def identify_type(self, input_str):
        if not input_str: return "unknown"
        clean = input_str.strip()
        
        if "@" in clean and self.email_regex.match(clean):
            return "email"
            
        # Phone heuristic: mostly digits, maybe +, length 7-15
        phone_clean = re.sub(r"[\s\-\(\)]", "", clean)
        if (phone_clean.isdigit() or (phone_clean.startswith('+') and phone_clean[1:].isdigit())) and 7 <= len(phone_clean) <= 15:
            return "phone"
            
        return "password"

    def normalize(self, input_str, type_):
        if not input_str: return ""
        if type_ == "email":
            return input_str.strip().lower()
        if type_ == "phone":
            return re.sub(r"[^\d+]", "", input_str.strip())
        return input_str 

    def get_domain(self, email):
        if "@" in email:
            return email.split("@")[1]
        return None

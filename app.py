import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, flash
from tool.core.validators import Validator
from tool.core.engines import BreachEngine, PasswordAnalyzer, RiskScorer
from tool.core.timeline import TimelineEngine

app = Flask(__name__, template_folder='templates')
app.secret_key = 'v2_rebuild_secret'

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return render_template('home.html')
        
    user_input = request.form.get('target')
    forced_type = request.form.get('type', 'auto')
    
    validator = Validator()
    target_type = forced_type if forced_type in ['email', 'password'] else validator.identify_type(user_input)
    normalized = validator.normalize(user_input, target_type)
    
    # Analysis
    breach_engine = BreachEngine()
    breaches = breach_engine.check(normalized, target_type)
    
    result = {
        "target": normalized,
        "type": target_type,
        "breaches": breaches,
        "stats": {}
    }
    
    if target_type == "password":
        analyzer = PasswordAnalyzer()
        leak_count = sum(b.get("leak_count", 0) for b in breaches)
        result["stats"] = analyzer.analyze(normalized, leak_count)
    else:
        # Email/Phone
        risk_engine = RiskScorer()
        result["stats"]["risk_score"] = risk_engine.calculate(breaches)
        if target_type == "email":
            timeline = TimelineEngine()
            domain = validator.get_domain(normalized)
            result["stats"]["first_seen"] = timeline.estimate_first_seen(normalized, domain)

    return render_template('report.html', result=result)

if __name__ == '__main__':
    app.run(debug=True, port=5002)

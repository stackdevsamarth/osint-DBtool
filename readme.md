# 🛡️ OSINT Breach Detection Tool (V2)

A powerful, dark-themed OSINT tool to check if your **Email**, **Phone Number**, or **Password** has been compromised in data breaches. Built with Python and Flask.

## ✨ Features

- **Multi-Input Support**: Automatically detects and analyzes:
  - **Emails**: Checks reputation, breaches, and domain timeline.
  - **Phone Numbers**: Scans public leaked databases.
  - **Passwords**: securely checks against [Have I Been Pwned](https://haveibeenpwned.com/) (using k-Anonymity for privacy).
- **Advanced Metrics**:
  - **Risk Score**: 0-100 score based on breach severity.
  - **Password Analysis**: Calculates Entropy, Safety Score, and Estimated Crack Time.
- **Timeline View**: Visual chronological timeline of when your data was leaked.
- **Clean UI**: Modern, dark-themed interface with specific tabs for Email and Password checks.
- **Privacy First**: No data is stored. Password checks use hash prefixes only.

## 🚀 Installation

1.  **Clone/Open the project**
2.  **Set up Virtual Environment**:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## 🏃 Usage

Start the web application:

```bash
python3 app.py
```

Open your browser at **[http://127.0.0.1:5002](http://127.0.0.1:5002)**.

## 🔑 Configuration (Optional)

The tool works great with free sources, but you can add API keys for deeper analysis:

```bash
export HIBP_API_KEY="your_key_here"
export INTELX_API_KEY="your_key_here"
python3 app.py
```

## 📂 Project Structure

- `app.py`: Main Flask application.
- `core/`:
  - `validators.py`: Input detection and normalization.
  - `engines.py`: Logic for breach checking, risk scoring, and crypto analysis.
  - `timeline.py`: Domain estimation logic.
- `templates/`: HTML templates (Home, Report, Base).
- `data/breaches/`: Place any local text/CSV breach files here to include them in the scan.

---
*For educational and defensive purposes only.*

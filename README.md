# AI-ScamShield 

AI-ScamShield is a Python-based web application that helps users identify potentially fraudulent SMS messages and suspicious URLs.

## Features

- **AI-powered SMS analysis:** Uses a locally running Qwen 2.5 model through Ollama to analyze suspicious messages.
- **Rule-based detection:** Checks for common scam indicators using predefined patterns.
- **URL risk checker:** Evaluates URLs using heuristic checks.
- **Scan history:** Stores previous scan records using SQLite.
- **PDF reports:** Generates downloadable reports of scan results.

## Tech Stack

- Python
- Flask
- SQLite
- Ollama
- Qwen 2.5
- HTML
- ReportLab

## Getting Started

### Prerequisites

- Python
- [Ollama](https://ollama.com/)
- Git

### Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/sameenarubab-25/AI-ScamShield.git
   cd AI-ScamShield
   ```

2. Create and activate a virtual environment:

   ```bash
   python -m venv venv
   ```

   On Windows PowerShell:

   ```powershell
   .\venv\Scripts\Activate.ps1
   ```

3. Install the required Python packages:

   ```bash
   python -m pip install Flask requests reportlab
   ```

4. Download the model:

   ```bash
   ollama pull qwen2.5:1.5b
   ```

5. Start Ollama if it isn't already running, then start the Flask application:

   ```bash
   python app.py
   ```

6. Open `http://127.0.0.1:5000` in your browser.

## Limitations

- Scam detection results are estimates and may be incorrect.
- URL risk checks use heuristics and do not establish whether a website is definitively malicious.
- The application does not replace independent verification or professional cybersecurity tools.

## Future Improvements

- Improve detection accuracy and testing.
- Add more robust URL reputation checks.
- Enhance the user interface and reporting features.

## Author

Developed as a personal project to explore AI integration, backend development, and practical scam-awareness tools.

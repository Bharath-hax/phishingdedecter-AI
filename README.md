# Phishing URL Detector AI

A professional phishing URL detection project built with Python, Flask, and machine learning. It analyzes suspicious links, extracts threat-style URL features, and classifies them as either `safe` or `phishing` using a hybrid rule-based + ML decision pipeline.

## Project Overview

This project is designed to help detect phishing URLs in a real-world, production-like workflow. It includes:

- URL feature extraction and scoring
- A lightweight fallback rule model
- A trained Random Forest classifier
- A Flask web dashboard for live prediction
- A REST API endpoint for programmatic analysis
- Logging for prediction activity and result tracking

## Key Features

The detector focuses on modern phishing indicators such as:

- suspicious keyword hits
- hidden brand impersonation inside the path
- path-domain detection
- shortener domain detection
- IP-address-based URL detection
- suspicious TLD detection
- subdomain abuse
- query and fragment abuse
- port usage and insecure scheme detection
- presence of encoded/obfuscated URL patterns

## Project Structure

- `feature_extractor.py` — feature engineering, rule-based scoring, and hybrid prediction logic
- `modle_trainer.py` — dataset loading, model training, and model artifact saving
- `flask_app.py` — Flask web app and prediction API
- `main.py` — command-line testing entrypoint
- `templates/index.html` — modern web dashboard UI
- `phishing_urls.csv` — training dataset
- `phishing_model.pkl` — trained model artifact

## Tech Stack

- Python 3.x
- Flask
- scikit-learn
- pandas

## Installation

1. Clone or open the project folder.
2. Create and activate a Python environment if desired.
3. Install the required dependencies:

```bash
pip install Flask pandas scikit-learn
```

You can also install from the project requirements file:

```bash
pip install -r requirements.txt
```

## Training the Model

To train and save the model artifact again:

```bash
python modle_trainer.py
```

This will:

- load the dataset from `phishing_urls.csv`
- build feature vectors
- train a Random Forest model
- save the model into `phishing_model.pkl`

## Running the App

Start the Flask web server:

```bash
python flask_app.py
```

Or on Windows with the Python launcher:

```bash
py flask_app.py
```

Then open the app in your browser at:

```text
http://127.0.0.1:5000/
```

## Using the Web UI

1. Open the dashboard in the browser.
2. Paste a URL into the input box.
3. Click `Analyze URL`.
4. The app will return:
   - the predicted label (`phishing` or `safe`)
   - a risk score percentage
   - key extracted URL features

## Using the API

Send a POST request to the prediction endpoint:

```bash
curl -X POST http://127.0.0.1:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url":"https://mail.printakid.com/www.online.americanexpress.com/index.html"}'
```

Example response:

```json
{
  "url": "https://mail.printakid.com/www.online.americanexpress.com/index.html",
  "label": "phishing",
  "score": 96.0,
  "model_version": "1.1.0"
}
```

## Command-Line Check

You can also test the detector directly from the terminal:

```bash
python main.py "https://mail.printakid.com/www.online.americanexpress.com/index.html"
```

## Notes

- The fallback rule model gives strong protection for suspicious URL patterns even when the ML artifact is unavailable.
- The project is designed as a real-world phishing classification prototype with a professional UI and evidence-driven response flow.
- The model artifact should be retrained if you expand the dataset further for production-level generalization.

## Future Enhancements

Potential improvements for a production-grade version:

- larger real-world phishing datasets
- hostname reputation lookup
- WHOIS and DNS-based signals
- antivirus or URL sandbox integration
- user feedback and model retraining pipeline
- deployment with Gunicorn and Docker


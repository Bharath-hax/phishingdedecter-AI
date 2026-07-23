<div align="center">

# 🛡️ Phishing URL Detector AI

### 🚀 AI-Powered Phishing URL Detection using Machine Learning, Flask & Python

<p align="center">

<img src="https://readme-typing-svg.demolab.com?font=Poppins&weight=700&size=28&duration=3000&pause=1200&color=00E5FF&center=true&vCenter=true&width=900&lines=Detect+Phishing+URLs+with+Artificial+Intelligence;Machine+Learning+Based+Threat+Detection;Professional+Cybersecurity+Project;Hybrid+Rule-Based+%2B+Random+Forest+Engine;Built+Using+Python+%7C+Flask+%7C+Scikit-Learn" />

</p>

<p align="center">

<img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/Flask-Web%20Application-black?style=for-the-badge&logo=flask"/>
<img src="https://img.shields.io/badge/Machine%20Learning-Random%20Forest-orange?style=for-the-badge"/>
<img src="https://img.shields.io/badge/Cybersecurity-Phishing%20Detection-red?style=for-the-badge"/>
<img src="https://img.shields.io/badge/REST-API-success?style=for-the-badge"/>
<img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge"/>

</p>

<p align="center">

<img src="https://img.shields.io/github/stars/Bharath-hax/Phishing-URL-Detector-AI?style=social"/>
<img src="https://img.shields.io/github/forks/Bharath-hax/Phishing-URL-Detector-AI?style=social"/>
<img src="https://img.shields.io/github/watchers/Bharath-hax/Phishing-URL-Detector-AI?style=social"/>

</p>

</div>

---

# 📖 Overview

**Phishing URL Detector AI** is a professional cybersecurity project designed to identify malicious and phishing URLs using a **hybrid detection approach** that combines intelligent **rule-based analysis** with a **Machine Learning Random Forest classifier**.

The application extracts multiple security-related URL characteristics, evaluates suspicious indicators, and predicts whether a URL is **Safe** or **Phishing** with a confidence score.

Unlike simple blacklist-based detectors, this project focuses on analyzing URL behavior and structure, making it capable of identifying previously unseen phishing attempts through feature engineering and machine learning.

The project also includes a clean **Flask Web Dashboard**, a **REST API**, and a **command-line interface**, making it suitable for educational purposes, cybersecurity demonstrations, and portfolio projects.

---

# ✨ Key Features

## 🛡 Intelligent Threat Detection

✔ Machine Learning Based Classification

✔ Hybrid Rule-Based Detection Engine

✔ Random Forest Prediction Model

✔ Real-Time URL Analysis

✔ Risk Score Calculation

✔ Confidence-Based Prediction

---

## 🔍 URL Security Analysis

The detector analyzes several phishing indicators including:

- 🔸 Suspicious Keywords
- 🔸 Brand Impersonation
- 🔸 Hidden Domain Names
- 🔸 URL Shorteners
- 🔸 Raw IP Address URLs
- 🔸 Suspicious Top-Level Domains
- 🔸 Excessive Subdomains
- 🔸 Long Query Parameters
- 🔸 Fragment Abuse
- 🔸 Non-Standard Port Usage
- 🔸 HTTP vs HTTPS Detection
- 🔸 URL Encoding & Obfuscation
- 🔸 Path-Domain Manipulation
- 🔸 URL Length Analysis
- 🔸 Symbol-Based Feature Extraction

---

# 🌟 Why This Project?

Phishing attacks remain one of the most common cyber threats affecting individuals and organizations worldwide.

This project demonstrates how machine learning and feature engineering can be combined to detect suspicious URLs before users interact with malicious websites.

The project was built to simulate a production-style phishing detection workflow while maintaining a lightweight architecture suitable for learning, research, and demonstration purposes.

---

# 🎯 Objectives

- Detect phishing websites using machine learning.
- Analyze suspicious URL characteristics.
- Provide confidence-based predictions.
- Offer a modern web interface for live analysis.
- Expose prediction functionality through REST APIs.
- Demonstrate practical cybersecurity concepts using Python.

---

# ⚙ Tech Stack

| Category | Technology |
|------------|------------|
| 💻 Programming Language | Python 3 |
| 🌐 Backend | Flask |
| 🤖 Machine Learning | Scikit-Learn |
| 📊 Data Processing | Pandas |
| 🧠 Model | Random Forest Classifier |
| 🎨 Frontend | HTML5, CSS3, JavaScript |
| 📦 Serialization | Pickle (.pkl) |
| 📡 API | Flask REST API |

---

# 🏗 System Architecture

```text
                           User
                             │
                             ▼
                 ┌────────────────────┐
                 │ Flask Web Interface│
                 └────────────────────┘
                             │
                             ▼
                  URL Feature Extraction
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
          ▼                  ▼                  ▼
  Rule-Based Checks   Feature Engineering   URL Parsing
          │                  │                  │
          └──────────────────┼──────────────────┘
                             │
                             ▼
                  Random Forest Classifier
                             │
                             ▼
                 Hybrid Decision Engine
                             │
                             ▼
          ┌────────────────────────────────┐
          │  Safe / Phishing + Risk Score  │
          └────────────────────────────────┘
```

---

# 🧠 Machine Learning Workflow

```text
                     URL Input
                         │
                         ▼
              URL Feature Extraction
                         │
                         ▼
           Security Feature Engineering
                         │
                         ▼
            Random Forest Classifier
                         │
                         ▼
            Probability Prediction
                         │
                         ▼
          Rule-Based Validation Engine
                         │
                         ▼
              Hybrid Final Prediction
                         │
                         ▼
         Safe ✅        or       Phishing 🚨
```

---

# 🔍 Detection Features

| Feature | Purpose |
|---------|----------|
| 🛑 Suspicious Keywords | Detects phishing-related words |
| 🏦 Brand Impersonation | Detects fake banking domains |
| 🌍 Hidden Domain in Path | Finds embedded domains inside URLs |
| 🔗 URL Shortener Detection | Identifies shortened malicious URLs |
| 🌐 IP Address Detection | Flags raw IP-based URLs |
| 📂 Long URL Detection | Detects abnormally long URLs |
| 📑 Query Parameter Analysis | Checks suspicious query strings |
| 🔖 Fragment Detection | Detects hidden fragments |
| 📛 Suspicious TLD | Identifies risky domain extensions |
| 🌳 Subdomain Abuse | Detects excessive subdomains |
| 🔒 HTTPS Validation | Verifies secure protocol usage |
| ⚠ Port Detection | Flags uncommon network ports |
| 🔐 URL Encoding | Detects encoded and obfuscated URLs |

---

# 🚀 Highlights

- ⚡ Fast Prediction Engine
- 🔥 Hybrid AI + Rule-Based Detection
- 🌐 REST API Support
- 🖥 Modern Flask Dashboard
- 📊 Machine Learning Model
- 📁 Modular Code Structure
- 🧩 Easy Integration
- 🎓 Beginner Friendly
- 🔒 Cybersecurity Focused
- 📈 Easily Extendable

---

<div align="center">

## ⭐ Building Intelligent Defenses Against Phishing Attacks

*"Security begins with awareness, detection, and continuous innovation."*

</div>
---

# 📂 Project Structure

```text
📦 Phishing-URL-Detector-AI
│
├── 📄 feature_extractor.py      # URL feature extraction & hybrid detection logic
├── 📄 modle_trainer.py          # Machine Learning model training
├── 📄 flask_app.py              # Flask web application & REST API
├── 📄 main.py                   # Command-line prediction interface
├── 📄 phishing_urls.csv         # Training dataset
├── 📄 phishing_model.pkl        # Trained Random Forest model
├── 📄 requirements.txt          # Project dependencies
├── 📄 README.md                 # Project documentation
│
├── 📂 templates
│   └── 📄 index.html            # Flask dashboard interface
│
├── 📂 static
│   ├── 📂 css
│   ├── 📂 js
│   └── 📂 images
│
├── 📂 screenshots
│   ├── dashboard.png
│   ├── prediction.png
│   └── api_response.png
│
└── 📂 logs
    └── prediction.log
```

---

# ⚙ Installation

## 1️⃣ Clone the Repository

```bash
git clone https://github.com/Bharath-hax/Phishing-URL-Detector-AI.git
```

Move into the project directory.

```bash
cd Phishing-URL-Detector-AI
```

---

## 2️⃣ Create Virtual Environment (Recommended)

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv

source venv/bin/activate
```

---

## 3️⃣ Install Dependencies

Using pip

```bash
pip install Flask pandas scikit-learn
```

or

```bash
pip install -r requirements.txt
```

---

# 🧠 Training the Machine Learning Model

The project uses a **Random Forest Classifier** trained on phishing and legitimate URL datasets.

Run

```bash
python modle_trainer.py
```

The trainer will automatically

✔ Load the dataset

✔ Extract URL features

✔ Train the Random Forest model

✔ Evaluate the model

✔ Save the trained model

```
phishing_model.pkl
```

---

# 🚀 Running the Flask Dashboard

Start the web application

```bash
python flask_app.py
```

or

```bash
py flask_app.py
```

After the server starts, open

```
http://127.0.0.1:5000/
```

---

# 🖥 Dashboard Preview

The web interface provides an easy way to test URLs.

### Features

✅ URL Input Box

✅ One-Click URL Analysis

✅ Live Prediction

✅ Risk Score

✅ Feature Summary

✅ Detection Result

---

> 📸 **Screenshot Placeholder**

```
screenshots/dashboard.png
```

(Add your dashboard screenshot here after uploading it.)

---

# 💻 Command Line Usage

You can also analyze URLs directly from the terminal.

Example

```bash
python main.py "https://mail.printakid.com/www.online.americanexpress.com/index.html"
```

Output

```text
Prediction : PHISHING

Confidence : 96%

Risk Level : HIGH
```

---

# 🌐 REST API

The detector exposes a REST API for integration into other systems.

## Endpoint

```
POST /predict
```

---

## Request Example

```bash
curl -X POST http://127.0.0.1:5000/predict \
-H "Content-Type: application/json" \
-d '{"url":"https://mail.printakid.com/www.online.americanexpress.com/index.html"}'
```

---

## JSON Request

```json
{
    "url":"https://mail.printakid.com/www.online.americanexpress.com/index.html"
}
```

---

## JSON Response

```json
{
    "url":"https://mail.printakid.com/www.online.americanexpress.com/index.html",
    "label":"phishing",
    "score":96.0,
    "model_version":"1.1.0"
}
```

---

# 📊 Prediction Workflow

```text
          User enters URL
                  │
                  ▼
       Flask Receives Request
                  │
                  ▼
      Feature Extraction Module
                  │
                  ▼
      Security Feature Analysis
                  │
                  ▼
       Random Forest Prediction
                  │
                  ▼
      Rule-Based Verification
                  │
                  ▼
      Hybrid Decision Engine
                  │
                  ▼
      Confidence Score Generated
                  │
                  ▼
       Safe ✅   or   Phishing 🚨
```

---

# 🔬 Detection Pipeline

```text
                 URL
                  │
                  ▼
         Parse URL Components
                  │
                  ▼
      Extract Security Features
                  │
                  ▼
        Feature Vector Creation
                  │
                  ▼
      Machine Learning Prediction
                  │
                  ▼
       Rule-Based Risk Analysis
                  │
                  ▼
        Hybrid Final Decision
```

---

# 📈 Risk Levels

| Risk Score | Status |
|------------|--------|
| 🟢 0–30% | Safe |
| 🟡 31–60% | Suspicious |
| 🔴 61–100% | Phishing |

---

# 📋 Prediction Report

Every prediction includes

- 🌐 Submitted URL
- 🤖 Prediction Label
- 📊 Confidence Score
- 🔍 Extracted Features
- 🕒 Prediction Timestamp
- 🧠 Model Version

Reports can be exported for future analysis.

---

# 📸 Screenshots

## 🖥 Dashboard

```
screenshots/dashboard.png
```

---

## 🚨 Prediction Result

```
screenshots/prediction.png
```

---

## 📡 REST API Response

```
screenshots/api_response.png
```

---

# 📦 Requirements

- Python 3.10+
- Flask
- pandas
- scikit-learn

Install all dependencies using

```bash
pip install -r requirements.txt
```

---

<div align="center">

## 🚀 Fast • Intelligent • Secure

**Designed for modern phishing detection using AI-powered analysis.**

</div>
---

# 🚀 Future Enhancements

The current version provides a strong foundation for phishing URL detection. Future releases aim to expand the system into a more comprehensive cybersecurity platform.

## 🎯 Planned Features

- [x] Hybrid Rule-Based Detection
- [x] Random Forest Machine Learning Model
- [x] Flask Web Dashboard
- [x] REST API Support
- [x] Feature Engineering Pipeline
- [x] JSON Prediction Reports
- [ ] WHOIS Domain Analysis
- [ ] DNS Reputation Lookup
- [ ] SSL Certificate Validation
- [ ] Google Safe Browsing Integration
- [ ] VirusTotal API Integration
- [ ] URL Redirect Chain Analysis
- [ ] Email Phishing Detection
- [ ] QR Code URL Scanner
- [ ] Docker Container Support
- [ ] Kubernetes Deployment
- [ ] CI/CD Pipeline
- [ ] Dark Mode Dashboard
- [ ] Multi-Language Support
- [ ] Explainable AI (XAI)
- [ ] Deep Learning Detection Model
- [ ] Real-Time Browser Extension

---

# 📊 Performance

The phishing detector is designed to provide:

| Metric | Description |
|---------|-------------|
| ⚡ Fast Prediction | Analyze URLs within milliseconds |
| 🎯 High Accuracy | Machine Learning based classification |
| 🛡 Hybrid Detection | Rule-Based + Random Forest |
| 🌐 API Ready | Easy integration with other applications |
| 💻 Cross Platform | Windows, Linux and macOS |
| 📈 Scalable | Modular architecture for future enhancements |

---

# 🔒 Security Features

The detector examines multiple security indicators before making a prediction.

### URL Analysis

- ✅ Suspicious Keywords
- ✅ URL Length
- ✅ Special Characters
- ✅ Multiple Subdomains
- ✅ Brand Impersonation
- ✅ Hidden Domains
- ✅ URL Encoding
- ✅ HTTP/HTTPS Scheme
- ✅ Port Number Detection
- ✅ Query String Analysis
- ✅ Fragment Analysis
- ✅ Suspicious Top-Level Domains

---

# 📚 Learning Objectives

This project demonstrates practical implementation of:

- Machine Learning
- Cybersecurity Fundamentals
- URL Feature Engineering
- Random Forest Classification
- Flask Web Development
- REST API Development
- Python Programming
- Data Preprocessing
- Feature Extraction
- Software Architecture

---

# 🎯 Applications

This project can be used for:

🏦 Banking Security

🏢 Enterprise Security

🎓 Cybersecurity Education

🔬 Academic Research

🧪 Security Testing

🌐 Secure Web Browsing

📧 Email Security Systems

🛡 Security Awareness Training

---

# 🤝 Contributing

Contributions are welcome!

If you have ideas to improve this project, feel free to contribute.

## Contribution Steps

1. Fork the repository.

2. Create a new feature branch.

```bash
git checkout -b feature/your-feature-name
```

3. Commit your changes.

```bash
git commit -m "Add new feature"
```

4. Push your branch.

```bash
git push origin feature/your-feature-name
```

5. Open a Pull Request.

Every contribution, whether it's fixing bugs, improving documentation, or adding new features, is greatly appreciated.

---

# 🐞 Reporting Issues

Found a bug?

Please create an Issue with:

- Project version
- Operating System
- Python version
- Error logs
- Steps to reproduce

This helps improve the project for everyone.

---

# ⭐ Support the Project

If this project helped you or inspired your work,

please consider giving it a ⭐ on GitHub.

It motivates further development and helps others discover the project.

---

# 👨‍💻 Developer

<div align="center">

# Bharathi Kannan

### 🚀 Full Stack Web Developer

### 🔐 Cybersecurity Enthusiast

### 🤖 AI & Machine Learning Explorer

Passionate about building secure, scalable, and intelligent software solutions that solve real-world problems.

</div>

---

# 🌐 Connect With Me

<p align="center">

<a href="https://github.com/Bharath-hax">
<img src="https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white"/>
</a>

<a href="https://www.linkedin.com/in/bharathi-kannan-32a84a326/">
<img src="https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white"/>
</a>

<a href="mailto:bk3165843@gmail.com">
<img src="https://img.shields.io/badge/Gmail-EA4335?style=for-the-badge&logo=gmail&logoColor=white"/>
</a>

</p>

---

# 📄 License

This project is licensed under the **MIT License**.

You are free to:

- Use
- Modify
- Distribute
- Fork
- Contribute

Please include the original license when redistributing the project.

---

# 🙏 Acknowledgements

Special thanks to the amazing open-source community and the developers behind:

- Python
- Flask
- Scikit-Learn
- Pandas
- NumPy
- GitHub
- Open Source Contributors

Their tools and libraries make projects like this possible.

---

# 💡 Quote

<div align="center">

> **"Cybersecurity is not only about preventing attacks—it's about building trust through secure systems."**

</div>

---

# 📈 Project Status

```text
██████████████████████████████ 100%

Project Status : ✅ Active Development

Version        : v1.1.0

Last Updated   : 2026

Maintainer     : Bharathi Kannan
```

---

<div align="center">

## ⭐ Thank You for Visiting!

### If you like this project, don't forget to ⭐ Star the repository.

### Happy Coding! 🚀

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:00C9FF,100:92FE9D&height=140&section=footer&text=Secure%20The%20Web&fontSize=35&fontColor=ffffff&animation=fadeIn"/>

</div>

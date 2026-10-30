# Network Intrusion Detection System

## Project Overview
The Network Intrusion Detection System is a machine learning-based application designed to identify suspicious network activities and classify network traffic as Normal or Attack.

The system uses a Random Forest classifier trained on the NSL-KDD dataset and provides a Flask-based web interface for network traffic analysis and monitoring.

## Features
- Machine Learning-based intrusion detection
- Random Forest classification
- Network packet capture and analysis
- Live traffic monitoring
- Normal and Attack prediction
- Prediction confidence display
- Dashboard for monitoring
- Confusion matrix and ROC curve visualization
- Prediction history and reporting

## Technologies Used
- Python
- Flask
- Scikit-learn
- Pandas
- NumPy
- Matplotlib
- Scapy
- HTML, CSS and Bootstrap
- Git and GitHub

## Dataset
NSL-KDD dataset.

## Machine Learning Model
Random Forest Classifier.

## Project Structure
```text
NetworkIntrusionDetection/
├── dataset/
├── models/
├── static/
├── templates/
├── app.py
├── train.py
├── predict.py
├── live_capture.py
├── preprocessing.py
├── feature_extractor.py
├── requirements.txt
└── README.md
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/Network-Intrusion-Detection.git
```

2. Open the project folder:
```bash
cd Network-Intrusion-Detection
```

3. Create a virtual environment:
```bash
python -m venv .venv
```

4. Activate it on Windows:
```bash
.venv\Scripts\activate
```

5. Install dependencies:
```bash
python -m pip install -r requirements.txt
```

6. Start the Flask application:
```bash
python app.py
```

7. Open your browser:
```text
http://127.0.0.1:5000
```

## Model Performance
The Random Forest model achieved approximately 99.92% accuracy on the project's NSL-KDD test split.

Note: This benchmark result does not guarantee the same performance on real-world network traffic.

## Author
Ganesh

## License
This project is intended for academic and educational purposes.
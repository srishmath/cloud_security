# app/routes.py

from flask import render_template, request, jsonify
import pandas as pd
import joblib
from app import app

# Load the model and transformers
model = joblib.load('../models/model.pkl')
le_cwe = joblib.load('../models/le_cwe.pkl')
le_vector = joblib.load('../models/le_vector.pkl')
tfidf = joblib.load('../models/tfidf.pkl')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/predictor')
def predictor():
    return render_template('predictor.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json(force=True)
    
    # Extract the input features from the request
    short_description = data['short_description']
    cwe = data['cwe']
    vector = data['vector']
    
    # Prepare the data for prediction
    cwe_num = int(cwe.split('-')[1])  # Extract the numerical part from CWE-xx
    cwe_encoded = le_cwe.transform([cwe_num])[0]
    vector_encoded = le_vector.transform([vector])[0]
    
    X_desc = tfidf.transform([short_description])
    X_new = pd.concat([pd.DataFrame(X_desc.toarray()), pd.DataFrame([[cwe_encoded, vector_encoded]])], axis=1)
    X_new.columns = X_new.columns.astype(str)
    
    # Make prediction
    prediction = model.predict(X_new)[0]
    
    return jsonify({'prediction': prediction})

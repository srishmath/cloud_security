from flask import Flask, jsonify, render_template, send_file
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
import joblib
import os
import matplotlib.pyplot as plt
import numpy as np



# Hardcoded file path
FILE_PATH = r"C:\Users\srish\Documents\pes\cloud_security_internship\project\data\Final_dataset.csv"

# Load and preprocess the dataset
def load_and_preprocess_data(filepath):
    data = pd.read_csv(filepath)
    data = data[['cwe', 'vector', 'short_description', 'severity']]
    data = data.assign(short_description=data['short_description'].fillna(''))

    le_cwe = LabelEncoder()
    le_vector = LabelEncoder()
    data['cwe'] = le_cwe.fit_transform(data['cwe'])
    data['vector'] = le_vector.fit_transform(data['vector'])

    tfidf = TfidfVectorizer(max_features=500)
    X_desc = tfidf.fit_transform(data['short_description'])
    X = pd.concat([pd.DataFrame(X_desc.toarray()), data[['cwe', 'vector']].reset_index(drop=True)], axis=1)
    X.columns = X.columns.astype(str)
    y = data['severity']

    return X, y, le_cwe, le_vector, tfidf

# Train and save models
def train_and_save_models(X_train, y_train, models_dir):
    models = {
        'MultinomialNB': MultinomialNB(),
        'SVC': SVC(kernel='linear', random_state=42),
        'RandomForest': RandomForestClassifier(random_state=42),
        'GradientBoosting': GradientBoostingClassifier(random_state=42),
    }

    if not os.path.exists(models_dir):
        os.makedirs(models_dir)

    for model_name, model in models.items():
        model.fit(X_train, y_train)
        joblib.dump(model, os.path.join(models_dir, f'{model_name}.pkl'))

    return models

# Evaluate models
def evaluate_models(models, X_test, y_test):
    results = {}
    for model_name, model in models.items():
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted')
        results[model_name] = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1
        }
    return results

# Plot the results
def plot_results(results, metric, save_path):
    model_names = list(results.keys())
    scores = [results[model][metric] for model in model_names]

    x = np.arange(len(model_names))

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(x, scores, color='b', alpha=0.7,width=0.3)

    ax.set_xlabel('Models')
    ax.set_ylabel(metric.capitalize())
    ax.set_title(f'Comparative Analysis of Models: {metric.capitalize()}')
    ax.set_xticks(x)
    ax.set_xticklabels(model_names)

    plt.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)

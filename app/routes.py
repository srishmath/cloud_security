# routes.py

from flask import render_template, request, jsonify
from flask.helpers import get_root_path
from dash import Dash
from dash import html
from app.dashboard import app as dash_app
from app import app
import io
from app.dashboard import create_cloud_plots
from app.dashboard import create_vulnerability_plots
import matplotlib.pyplot as plt
from app.dashboard import static_dir
from app.ml import *

# Other imports for your Flask application
import pandas as pd
import joblib
import os

from app.dependency import *

# Load the model and transformers
models_dir = os.path.join(os.path.dirname(get_root_path(__name__)), 'models')

# Load the model and transformers
model_path = os.path.join(models_dir, 'model.pkl')
le_cwe_path = os.path.join(models_dir, 'le_cwe.pkl')
le_vector_path = os.path.join(models_dir, 'le_vector.pkl')
tfidf_path = os.path.join(models_dir, 'tfidf.pkl')

model = joblib.load(model_path)
le_cwe = joblib.load(le_cwe_path)
le_vector = joblib.load(le_vector_path)
tfidf = joblib.load(tfidf_path)

print("Loaded model:", model)
print("Loaded le_cwe:", le_cwe)
print("Loaded le_vector:", le_vector)
print("Loaded tfidf:", tfidf)



# Flask routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        vendor = request.form['vendor']
        plot_type = request.form['plot_type']
        
        if plot_type == 'Vulnerability':
            plots = create_vulnerability_plots(vendor)
        elif plot_type == 'Cloud':
            plots = create_cloud_plots(vendor)
        else:
            plots = None
        
        if plots is None:
            return render_template('dashboard.html', error='No data available for the selected vendor or plot type.')
        
        plot_urls = []
        for i, fig in enumerate(plots):
            img = io.BytesIO()
            fig.savefig(img, format='png')
            img.seek(0)
            plot_url = f'plot{i}.png'
            plot_urls.append(plot_url)
            with open(os.path.join(static_dir, plot_url), 'wb') as f:
                f.write(img.getbuffer())
            plt.close(fig)
        
        return render_template('dashboard.html', vendor=vendor, plot_type=plot_type, plot_urls=plot_urls)

    return render_template('dashboard.html')




@app.route('/predictor')
def predictor():
    return render_template('predictor.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json(force=True)
        print("Received data:", data)
        
        # Extract the input features from the request
        short_description = data['short_description']
        cwe = data['cwe']
        vector = data['vector']
    
        cwe_num = cwe.split('-')[1]
        cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
        
        # Handle unseen labels with LabelEncoder
        try:
            cwe_encoded = le_cwe.transform([cwe])
            vector_encoded = le_vector.transform([vector])
        except ValueError as ve:
            return jsonify({'error': str(ve)})
        
        X_desc = tfidf.transform([short_description])
        
        # Combine features
        X_new = pd.concat([pd.DataFrame(X_desc.toarray()), pd.DataFrame({'cwe': cwe_encoded, 'vector': vector_encoded})], axis=1)
        X_new.columns = X_new.columns.astype(str)
        
        # Make prediction
        try:
            prediction = model.predict(X_new)
            print("Prediction:", prediction)
            print("url:", cwe_url)
            return jsonify({'prediction': prediction[0], 'cwe_url': cwe_url})
        except Exception as e:
            print("Prediction error:", str(e))
            return jsonify({'error': 'Prediction error: ' + str(e)})
    
    except KeyError as ke:
        print("KeyError:", str(ke))
        return jsonify({'error': f'Missing key in JSON payload: {str(ke)}'})
    
    except Exception as e:
        print("General error:", str(e))
        return jsonify({'error': str(e)})
    
@app.route('/predictor/model_index')
def model_index():
        return render_template('ml.html')
@app.route('/train',methods=['POST'])
def train():
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    plots_dir = os.path.join(os.path.dirname(__file__), 'static', 'plots')

    if not os.path.exists(plots_dir):
        os.makedirs(plots_dir)

    X, y, le_cwe, le_vector, tfidf = load_and_preprocess_data(FILE_PATH)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    models = train_and_save_models(X_train, y_train, models_dir)

    joblib.dump(le_cwe, os.path.join(models_dir, 'le_cwe.pkl'))
    joblib.dump(le_vector, os.path.join(models_dir, 'le_vector.pkl'))
    joblib.dump(tfidf, os.path.join(models_dir, 'tfidf.pkl'))

    results = evaluate_models(models, X_test, y_test)

    metrics = ['accuracy', 'precision', 'recall', 'f1_score']
    plot_paths = {}

    for metric in metrics:
        save_path = os.path.join(plots_dir, f'{metric}.png')
        plot_results(results, metric, save_path)
        plot_paths[metric] = save_path

    return jsonify({
        'message': 'Models trained and saved successfully!',
        'results': results,
        'plot_paths': plot_paths
    })

@app.route('/static/plots/<filename>')
def plot(filename):
    return send_file(os.path.join('static', 'plots', filename), mimetype='image/png')


@app.route('/dependency', methods=['GET', 'POST'])
def dependency():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
            uploaded_file.save(file_path)
            audit_data = run_npm_audit(file_path)
            if audit_data:
                severity_img_base64 = generate_vulnerability_report(audit_data, 'severity_report.png')
                package_img_base64 = generate_vulnerability_package_report(audit_data)
                cwe_img_base64 = generate_vulnerability_cwe_report(audit_data)
                return render_template('dependency.html', severity_img_base64=severity_img_base64, package_img_base64=package_img_base64, cwe_img_base64=cwe_img_base64)
            else:
                return "Failed to generate vulnerability report."
    return render_template('dependency.html')




import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.svm import SVC
import joblib
import os

# Load the dataset
data = pd.read_csv('../data/Final_dataset.csv')

# Select relevant columns
data = data[['cwe', 'vector', 'short_description', 'severity']]

# Handle missing values
data = data.assign(short_description=data['short_description'].fillna(''))

# Encode categorical features
le_cwe = LabelEncoder()
le_vector = LabelEncoder()

data['cwe'] = le_cwe.fit_transform(data['cwe'])
data['vector'] = le_vector.fit_transform(data['vector'])

# Vectorize the short_description
tfidf = TfidfVectorizer(max_features=500)
X_desc = tfidf.fit_transform(data['short_description'])

# Combine features
X = pd.concat([pd.DataFrame(X_desc.toarray()), data[['cwe', 'vector']].reset_index(drop=True)], axis=1)
X.columns = X.columns.astype(str)  # Convert all column names to strings
y = data['severity']

# Split the data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Build and train the SVM model
model = SVC(kernel='linear', random_state=42)  # You can experiment with different kernels
model.fit(X_train, y_train)


# Create the models directory if it doesn't exist
models_dir = os.path.join(os.path.dirname(__file__), '../models')
# print(f"Models will be saved in {os.path.abspath(models_dir)}")
os.makedirs(models_dir, exist_ok=True)

# Save the model and encoders
joblib.dump(model, os.path.join(models_dir, 'model.pkl'))
joblib.dump(le_cwe, os.path.join(models_dir, 'le_cwe.pkl'))
joblib.dump(le_vector, os.path.join(models_dir, 'le_vector.pkl'))
joblib.dump(tfidf, os.path.join(models_dir, 'tfidf.pkl'))

# print("Models saved successfully!")
from flask import Flask, request, render_template, jsonify
import pandas as pd
import matplotlib.pyplot as plt
import io
import os
from app import app
# app = Flask(__name__)

# Get the directory of the Flask application script
app_dir = os.path.dirname(os.path.abspath(__file__))

# Load the dataset
file_path = os.path.join(app_dir, "../data/Final_dataset.csv")
df = pd.read_csv(file_path)

# Define the static directory
static_dir = os.path.join(app_dir, 'static')

# Ensure the static directory exists
os.makedirs(static_dir, exist_ok=True)

vendor_names = df['vendor_project'].unique().tolist()

# Define functions to create plots based on user selections
def create_vulnerability_plots(vendor):
    vendor_data = df[df['vendor_project'] == vendor]
    if vendor_data.empty:
        return None

    # Bar plot
    severity_counts = vendor_data['severity'].value_counts()
    fig1, ax1 = plt.subplots(figsize=(8, 8))
    severity_counts.plot(kind='bar', color='skyblue', ax=ax1)
    ax1.set_title('Vulnerability Severity Counts for ' + vendor)
    ax1.set_xlabel('Severity Level')
    ax1.set_ylabel('Count')
    ax1.tick_params(axis='x', rotation=0)

    # Time graph
    vendor_data['year'] = pd.to_datetime(vendor_data['pub_date'], errors='coerce').dt.year
    yearly_counts = vendor_data['year'].value_counts().sort_index()
    fig2, ax2 = plt.subplots(figsize=(10, 6))
    yearly_counts.plot(marker='o', ax=ax2)
    ax2.set_title('Vulnerability Discovery Over Time for ' + vendor)
    ax2.set_xlabel('Year')
    ax2.set_ylabel('Number of Vulnerabilities Discovered')
    ax2.grid(True)
    ax2.set_xticks(yearly_counts.index)
    ax2.set_xticklabels(yearly_counts.index, rotation=45)
    
    # Pie chart
    attack_vector_counts = vendor_data['vector'].value_counts()
    fig3, ax3 = plt.subplots(figsize=(4, 4))
    ax3.pie(attack_vector_counts, labels=attack_vector_counts.index, autopct='%1.1f%%', startangle=140)
    ax3.set_title('Distribution of Attack Vectors for ' + vendor)
    
    # Stacked bar chart
    cwe_severity_counts = vendor_data.groupby(['cwe', 'severity']).size().unstack(fill_value=0)
    fig4, ax4 = plt.subplots(figsize=(10, 6))
    cwe_severity_counts.plot(kind='bar', stacked=True, ax=ax4)
    ax4.set_title('Vulnerability Counts by CWE Category and Severity for ' + vendor)
    ax4.set_xlabel('CWE Category')
    ax4.set_ylabel('Count')
    ax4.legend(title='Severity')
    
    return [fig1, fig2, fig3, fig4]

def create_cloud_plots(vendor):
    vendor_data = df[df['vendor_project'] == vendor]
    if (vendor_data.empty) or ('cloud_component' not in df.columns):
        return None
    
    # Plot 1: Severity of Vulnerabilities Across Cloud Components
    severity_counts = vendor_data.groupby(['cloud_component', 'severity']).size().unstack(fill_value=0)    
    fig1, ax1 = plt.subplots(figsize=(10, 8))
    severity_counts.plot(kind='bar', stacked=True, color=['red', 'orange', 'yellow', 'green'], width=0.8, ax=ax1)
    ax1.set_title('Severity of Vulnerabilities Across Cloud Components')
    ax1.set_xlabel('Cloud Component')
    ax1.set_ylabel('Number of Vulnerabilities')
    ax1.set_xticklabels(ax1.get_xticklabels(), rotation=45, ha='right')
    ax1.legend(title='Severity')
    plt.tight_layout()

    # Plot 2: Pie charts for each cloud_component based on vulnerability_category
    grouped_data = vendor_data.groupby(['cloud_component', 'vulnerability_category']).size().unstack(fill_value=0)
    figs = [fig1]

    for component in grouped_data.index:
        fig, ax = plt.subplots(figsize=(8, 6))
        ax.pie(grouped_data.loc[component], labels=grouped_data.columns, autopct='%1.1f%%', startangle=140)
        ax.set_title(f'{vendor.capitalize()} - {component} Vulnerabilities by Category')
        ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
        figs.append(fig)

    return figs




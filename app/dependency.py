from flask import Flask, render_template, request, send_file
import os
import subprocess
import json
import matplotlib
matplotlib.use("agg")


import matplotlib.pyplot as plt
import base64
from io import BytesIO

from app import app

# Ensure the 'uploads' folder exists
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def run_npm_audit(package_json_path):
    try:
        # Ensure the correct working directory
        cwd = os.path.dirname(package_json_path)
        
        # Full path to npm executable (example for Windows)
        npm_path = r'C:\nodejs\npm.cmd'  # Adjust the path as per your installation

        # Run npm install to install the dependencies
        subprocess.run([npm_path, 'install'], check=True, cwd=cwd)
        
        # Run npm audit --json and capture the output
        result = subprocess.run([npm_path, 'audit', '--json'], capture_output=True, text=True, cwd=cwd)
        audit_data = json.loads(result.stdout)
        return audit_data
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while running npm: {e}")
        return None

def generate_vulnerability_report(audit_data, output_path):
    vulnerabilities = audit_data.get('vulnerabilities', {})
    
    severity_counts = {'low': 0, 'moderate': 0, 'high': 0, 'critical': 0}

    # Count vulnerabilities by severity
    for advisory in vulnerabilities.values():
        severity = advisory.get('severity', 'unknown')  # Handle cases where severity is missing
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts['other'] = severity_counts.get('other', 0) + 1

    # Print audit data and severity counts for debugging
    print(f"SEVERITY COUNT {severity_counts}")

    # Create bar chart of vulnerabilities by severity
    plt.figure(figsize=(10, 6))
    plt.bar(severity_counts.keys(), severity_counts.values(), color=['green', 'yellow', 'orange', 'red', 'gray'], width=0.6)
    plt.xlabel('Severity', fontsize=12)
    plt.ylabel('Number of Vulnerabilities', fontsize=12)
    plt.title('NPM Audit Vulnerabilities by Severity', fontsize=14)
    plt.xticks(fontsize=10)
    plt.yticks(fontsize=10)
    plt.tight_layout()

    # Save the plot to a BytesIO object
    img_bytes = BytesIO()
    plt.savefig(img_bytes, format='png')
    img_bytes.seek(0)
    plt.close()

    # Convert plot to base64 encoded string
    severity_img_base64 = base64.b64encode(img_bytes.getvalue()).decode('utf-8')

    return severity_img_base64

def generate_vulnerability_package_report(audit_data, top_n=10):
    vulnerabilities = audit_data.get('vulnerabilities', {})
    
    package_counts = {}

    # Count vulnerabilities by package
    for package, advisory in vulnerabilities.items():
        package_name = advisory.get('name', 'Unknown Package')
        for item in advisory.get('via', []):
            if isinstance(item, dict):
                if package_name not in package_counts:
                    package_counts[package_name] = 0
                package_counts[package_name] += 1

    # Sort packages by number of vulnerabilities and select top_n
    sorted_packages = sorted(package_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    packages, counts = zip(*sorted_packages) if sorted_packages else ([], [])

    # Create bar chart of vulnerabilities by package
    plt.figure(figsize=(10, 6))
    plt.barh(packages, counts, color='skyblue')
    plt.xlabel('Number of Vulnerabilities', fontsize=12)
    plt.ylabel('Package', fontsize=12)
    plt.title('Top Packages by Vulnerabilities', fontsize=14)
    plt.xticks(fontsize=10)
    plt.yticks(fontsize=10)
    plt.tight_layout()

    # Save the plot to a BytesIO object
    img_bytes = BytesIO()
    plt.savefig(img_bytes, format='png')
    img_bytes.seek(0)
    plt.close()

    # Convert plot to base64 encoded string
    package_img_base64 = base64.b64encode(img_bytes.getvalue()).decode('utf-8')

    return package_img_base64

def generate_vulnerability_cwe_report(audit_data):
    try:
        vulnerabilities = audit_data.get('vulnerabilities', {})
        
        cwe_counts = {}
    
        # Iterate over each vulnerability
        for package, advisory in vulnerabilities.items():
            via = advisory.get('via', [])
            
            # Ensure 'via' is a list
            if not isinstance(via, list):
                print(f"Warning: 'via' for package '{package}' is not a list, skipping.")
                continue
            
            # Iterate over each item in 'via'
            for item in via[:-1]:
                print(type(item))
                # Access 'cwe' attribute from each item
                cwes = item.get('cwe', ['Unknown CWE'])  # Default to 'Unknown CWE' if 'cwe' is missing
                print(f"CWE:::::::{cwes}")
                # Handle both list and string formats of 'cwe'
                if isinstance(cwes, list):
                    for cwe in cwes:
                        if cwe in cwe_counts:
                            cwe_counts[cwe] += 1
                        else:
                            cwe_counts[cwe] = 1
                elif isinstance(cwes, str):
                    if cwes in cwe_counts:
                        cwe_counts[cwes] += 1
                    else:
                        cwe_counts[cwes] = 1
    
        # Sort CWEs by number of vulnerabilities
        sorted_cwes = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)
    
        # Limit to top 10 CWEs for the plot
        top_cwes = dict(sorted_cwes[:10])
    
        # Create bar chart of vulnerabilities by CWE
        plt.figure(figsize=(12, 6))
        plt.bar(top_cwes.keys(), top_cwes.values(), color='purple')
        plt.xlabel('Common Weakness Enumeration (CWE)', fontsize=12)
        plt.ylabel('Number of Vulnerabilities', fontsize=12)
        plt.title('Vulnerabilities by CWE', fontsize=14)
        plt.xticks(rotation=45, fontsize=10, ha='right')
        plt.tight_layout()
    
        # Save the plot to a BytesIO object
        img_bytes = BytesIO()
        plt.savefig(img_bytes, format='png')
        img_bytes.seek(0)
        plt.close()
    
        # Convert plot to base64 encoded string
        cwe_img_base64 = base64.b64encode(img_bytes.getvalue()).decode('utf-8')
    
        return cwe_img_base64
    
    except Exception as e:
        print(f"Exception occurred: {str(e)}")
        return None






from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
import yaml
import os
import datetime
import re

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For flash messages
DATA_DIR = 'data'

def load_ttps():
    ttps = []
    for filename in os.listdir(DATA_DIR):
        if filename.endswith('.yaml'):
            try:
                with open(os.path.join(DATA_DIR, filename), 'r') as f:
                    ttp = yaml.safe_load(f)
                    ttps.append(ttp)
            except Exception as e:
                print(f"Error loading {filename}: {e}")
    return ttps

def get_yaml_filename(ttp_name):
    """Find the filename for a given TTP name"""
    for filename in os.listdir(DATA_DIR):
        if filename.endswith('.yaml'):
            try:
                with open(os.path.join(DATA_DIR, filename), 'r') as f:
                    ttp = yaml.safe_load(f)
                    if ttp.get('name', '').lower() == ttp_name.lower():
                        return filename
            except Exception:
                pass
    return None

def get_raw_yaml_content(filename):
    """Get the raw YAML content of a file"""
    file_path = os.path.join(DATA_DIR, filename)
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return f.read()
    return None

def validate_yaml(content):
    """Validate YAML content"""
    try:
        data = yaml.safe_load(content)
        required_fields = ['name', 'description', 'impact']
        for field in required_fields:
            if field not in data:
                return False, f"Missing required field: {field}"
        return True, data
    except Exception as e:
        return False, f"Invalid YAML format: {str(e)}"

@app.route('/')
def index():
    ttps = load_ttps()
    return render_template('index.html', tools=ttps)

@app.route('/tool/<name>')
def tool(name):
    ttps = load_ttps()
    for ttp in ttps:
        if ttp['name'].lower() == name.lower():
            filename = get_yaml_filename(name)
            yaml_content = get_raw_yaml_content(filename)
            return render_template('tool.html', tool=ttp, filename=filename, yaml_content=yaml_content)
    return "TTP not found", 404

@app.route('/search')
def search():
    query = request.args.get('query')
    if not query:
        return "Missing search parameters", 400
    ttps = load_ttps()
    results = [ttp for ttp in ttps if any(query.lower() in str(ttp.get(field, '')).lower() for field in ['name', 'impact', 'tags'])]
    return render_template('search.html', results=results, query=query)

@app.route('/suggest')
def suggest():
    query = request.args.get('q', '').lower()
    if not query:
        return jsonify([])
    ttps = load_ttps()
    matches = []
    for ttp in ttps:
        matched_fields = []
        for field in ['impact', 'tags']:
            values = ttp.get(field, [])
            if isinstance(values, str):
                values = [values]
            for value in values:
                if query in str(value).lower():
                    matched_fields.append(value)
        if matched_fields:
            matches.append({
                'name': ttp['name'],
                'url': f"/tool/{ttp['name']}",
                'matched': matched_fields
            })
    return jsonify(matches[:10])

@app.route('/update/<filename>', methods=['POST'])
def update_yaml(filename):
    yaml_content = request.form.get('yamlContent')
    if not yaml_content:
        flash('No content provided', 'danger')
        return redirect(url_for('index'))
    
    # Validate YAML
    is_valid, result = validate_yaml(yaml_content)
    if not is_valid:
        flash(f'Error: {result}', 'danger')
        ttps = load_ttps()
        for ttp in ttps:
            if get_yaml_filename(ttp['name']) == filename:
                return render_template('tool.html', tool=ttp, filename=filename, yaml_content=yaml_content)
        return redirect(url_for('index'))
    
    # Save the file
    try:
        with open(os.path.join(DATA_DIR, filename), 'w') as f:
            f.write(yaml_content)
        flash('TTP updated successfully', 'success')
        # Reload TTPs and redirect to the updated TTP page
        ttps = load_ttps()
        for ttp in ttps:
            if ttp['name'] == result['name']:
                return redirect(url_for('tool', name=ttp['name']))
    except Exception as e:
        flash(f'Error saving file: {str(e)}', 'danger')
    
    return redirect(url_for('index'))

@app.route('/create', methods=['POST'])
def create_yaml():
    filename = request.form.get('filename')
    yaml_content = request.form.get('yamlContent')
    
    if not filename or not yaml_content:
        flash('Filename and content are required', 'danger')
        return redirect(url_for('index'))
    
    # Sanitize filename
    filename = re.sub(r'[^a-zA-Z0-9-]', '-', filename)
    if not filename.endswith('.yaml'):
        filename += '.yaml'
    
    # Check if file already exists
    if os.path.exists(os.path.join(DATA_DIR, filename)):
        flash(f'A file with name {filename} already exists', 'danger')
        return redirect(url_for('index'))
    
    # Validate YAML
    is_valid, result = validate_yaml(yaml_content)
    if not is_valid:
        flash(f'Error: {result}', 'danger')
        return redirect(url_for('index'))
    
    # Save the file
    try:
        with open(os.path.join(DATA_DIR, filename), 'w') as f:
            f.write(yaml_content)
        flash('TTP created successfully', 'success')
        return redirect(url_for('tool', name=result['name']))
    except Exception as e:
        flash(f'Error saving file: {str(e)}', 'danger')
    
    return redirect(url_for('index'))

@app.route('/delete/<name>')
def delete_yaml(name):
    filename = get_yaml_filename(name)
    if not filename:
        flash('TTP not found', 'danger')
        return redirect(url_for('index'))
    
    try:
        os.remove(os.path.join(DATA_DIR, filename))
        flash('TTP deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting file: {str(e)}', 'danger')
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

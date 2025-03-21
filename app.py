from flask import Flask, render_template, request, jsonify
import yaml
import os

app = Flask(__name__)
DATA_DIR = 'data'

def load_tools():
    tools = []
    for filename in os.listdir(DATA_DIR):
        if filename.endswith('.yaml'):
            try:
                with open(os.path.join(DATA_DIR, filename), 'r') as f:
                    tool = yaml.safe_load(f)
                    tools.append(tool)
            except Exception as e:
                print(f"Error loading {filename}: {e}")
    return tools

tools = load_tools()

@app.route('/')
def index():
    return render_template('index.html', tools=tools)

@app.route('/tool/<name>')
def tool(name):
    for t in tools:
        if t['name'].lower() == name.lower():
            return render_template('tool.html', tool=t)
    return "Tool not found", 404

@app.route('/search')
def search():
    query = request.args.get('query')
    if not query:
        return "Missing search parameters", 400
    results = [t for t in tools if any(query.lower() in str(t.get(field, '')).lower() for field in ['name', 'impact', 'tags'])]
    return render_template('search.html', results=results, query=query)

@app.route('/suggest')
def suggest():
    query = request.args.get('q', '').lower()
    if not query:
        return jsonify([])
    matches = []
    for tool in tools:
        matched_fields = []
        for field in ['impact', 'tags']:
            values = tool.get(field, [])
            if isinstance(values, str):
                values = [values]
            for value in values:
                if query in str(value).lower():
                    matched_fields.append(value)
        if matched_fields:
            matches.append({
                'name': tool['name'],
                'url': f"/tool/{tool['name']}",
                'matched': matched_fields
            })
    return jsonify(matches[:10])

if __name__ == '__main__':
    app.run(debug=True)

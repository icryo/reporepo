from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
import yaml
import os
import datetime
import re
import json
from typing import List, Dict, Any, Optional, Union
import hashlib

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For flash messages
DATA_DIR = 'data'

# API version
API_VERSION = 'v1'

# Model context protocol version
MCP_VERSION = 'v1'

# Simple cache for vector representations
# In a production environment, consider using a proper vector database
vector_cache = {}

# Function to create a simple hash-based vector representation of text
# This is a placeholder for a proper embedding model
def create_vector(text: str, dims: int = 128) -> List[float]:
    """Create a simple hash-based vector representation of text.
    
    This is a placeholder for a proper embedding model. In a production environment,
    you would use a proper embedding model like sentence-transformers or OpenAI embeddings.
    """
    if not text:
        return [0.0] * dims
        
    # Create a hash of the text
    hash_obj = hashlib.sha256(text.encode())
    hash_bytes = hash_obj.digest()
    
    # Convert the hash to a vector of the specified dimension
    # This is not a proper embedding, just a placeholder
    vector = []
    for i in range(dims):
        # Use modulo to get a value between 0 and 1
        byte_val = hash_bytes[i % len(hash_bytes)] / 255.0
        vector.append(byte_val)
    
    return vector

# Function to compute cosine similarity between two vectors
def cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
    """Compute cosine similarity between two vectors."""
    if len(vec1) != len(vec2):
        raise ValueError("Vectors must have the same dimension")
    
    dot_product = sum(a * b for a, b in zip(vec1, vec2))
    magnitude1 = sum(a * a for a in vec1) ** 0.5
    magnitude2 = sum(b * b for b in vec2) ** 0.5
    
    if magnitude1 == 0 or magnitude2 == 0:
        return 0.0
    
    return dot_product / (magnitude1 * magnitude2)

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

# API Endpoints
@app.route('/api/v1/ttps', methods=['GET'])
def api_get_ttps():
    """API endpoint to get all TTPs"""
    ttps = load_ttps()
    return jsonify({
        'status': 'success',
        'data': ttps,
        'count': len(ttps)
    })

@app.route('/api/v1/ttps/<name>', methods=['GET'])
def api_get_ttp(name):
    """API endpoint to get a specific TTP by name"""
    filename = get_yaml_filename(name)
    if not filename:
        return jsonify({
            'status': 'error',
            'message': f'TTP with name {name} not found'
        }), 404
    
    yaml_content = get_raw_yaml_content(filename)
    ttp = yaml.safe_load(yaml_content)
    
    return jsonify({
        'status': 'success',
        'data': ttp
    })

@app.route('/api/v1/ttps', methods=['POST'])
def api_create_ttp():
    """API endpoint to create a new TTP"""
    if not request.is_json:
        return jsonify({
            'status': 'error',
            'message': 'Request must be JSON'
        }), 400
    
    data = request.get_json()
    
    # Convert to YAML
    yaml_content = yaml.dump(data)
    
    # Validate YAML
    is_valid, result = validate_yaml(yaml_content)
    if not is_valid:
        return jsonify({
            'status': 'error',
            'message': result
        }), 400
    
    # Generate filename from name
    name = data.get('name')
    if not name:
        return jsonify({
            'status': 'error',
            'message': 'Name is required'
        }), 400
    
    filename = re.sub(r'[^a-zA-Z0-9-]', '-', name) + '.yaml'
    
    # Check if file already exists
    if os.path.exists(os.path.join(DATA_DIR, filename)):
        return jsonify({
            'status': 'error',
            'message': f'A TTP with name {name} already exists'
        }), 409
    
    # Save the file
    try:
        with open(os.path.join(DATA_DIR, filename), 'w') as f:
            f.write(yaml_content)
        
        return jsonify({
            'status': 'success',
            'message': 'TTP created successfully',
            'data': data
        }), 201
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error saving file: {str(e)}'
        }), 500

@app.route('/api/v1/ttps/<name>', methods=['PUT'])
def api_update_ttp(name):
    """API endpoint to update an existing TTP"""
    if not request.is_json:
        return jsonify({
            'status': 'error',
            'message': 'Request must be JSON'
        }), 400
    
    filename = get_yaml_filename(name)
    if not filename:
        return jsonify({
            'status': 'error',
            'message': f'TTP with name {name} not found'
        }), 404
    
    data = request.get_json()
    
    # Convert to YAML
    yaml_content = yaml.dump(data)
    
    # Validate YAML
    is_valid, result = validate_yaml(yaml_content)
    if not is_valid:
        return jsonify({
            'status': 'error',
            'message': result
        }), 400
    
    # Save the file
    try:
        with open(os.path.join(DATA_DIR, filename), 'w') as f:
            f.write(yaml_content)
        
        return jsonify({
            'status': 'success',
            'message': 'TTP updated successfully',
            'data': data
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error saving file: {str(e)}'
        }), 500

@app.route('/api/v1/ttps/<name>', methods=['DELETE'])
def api_delete_ttp(name):
    """API endpoint to delete a TTP"""
    filename = get_yaml_filename(name)
    if not filename:
        return jsonify({
            'status': 'error',
            'message': f'TTP with name {name} not found'
        }), 404
    
    try:
        os.remove(os.path.join(DATA_DIR, filename))
        return jsonify({
            'status': 'success',
            'message': 'TTP deleted successfully'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error deleting file: {str(e)}'
        }), 500

# Model Context Protocol Endpoints
@app.route('/mcp/v1/query', methods=['POST'])
def mcp_query():
    """Model Context Protocol query endpoint
    
    This endpoint allows AI models to query the TTPs database with natural language
    and retrieve relevant TTPs for their context window.
    """
    if not request.is_json:
        return jsonify({
            'status': 'error',
            'message': 'Request must be JSON'
        }), 400
    
    data = request.get_json()
    query = data.get('query')
    max_results = data.get('max_results', 5)
    
    if not query:
        return jsonify({
            'status': 'error',
            'message': 'Query is required'
        }), 400
    
    # Load all TTPs
    ttps = load_ttps()
    
    # Simple search implementation - can be enhanced with better ranking
    results = []
    for ttp in ttps:
        score = 0
        # Check various fields for matches
        for field in ['name', 'description', 'impact', 'tags', 'Category', 'Command', 'MITRE_ATT&CK']:
            if field in ttp and query.lower() in str(ttp.get(field, '')).lower():
                score += 1
                
        if score > 0:
            results.append({
                'ttp': ttp,
                'score': score
            })
    
    # Sort by score and limit results
    results = sorted(results, key=lambda x: x['score'], reverse=True)[:max_results]
    
    # Format for model consumption
    formatted_results = []
    for result in results:
        ttp = result['ttp']
        formatted_result = {
            'name': ttp.get('name', ''),
            'description': ttp.get('description', ''),
            'impact': ttp.get('impact', []),
            'mitigation': ttp.get('mitigation', ''),
            'tags': ttp.get('tags', []),
            'category': ttp.get('Category', ''),
            'command': ttp.get('Command', ''),
            'detection': ttp.get('Detection', []),
            'mitre_attack': ttp.get('MITRE_ATT&CK', ''),
            'references': ttp.get('references', [])
        }
        formatted_results.append(formatted_result)
    
    return jsonify({
        'status': 'success',
        'query': query,
        'results': formatted_results,
        'count': len(formatted_results)
    })

@app.route('/mcp/v1/retrieve/<name>', methods=['GET'])
def mcp_retrieve(name):
    """Model Context Protocol retrieve endpoint
    
    This endpoint allows AI models to retrieve a specific TTP by name
    and get it formatted for their context window.
    """
    filename = get_yaml_filename(name)
    if not filename:
        return jsonify({
            'status': 'error',
            'message': f'TTP with name {name} not found'
        }), 404
    
    yaml_content = get_raw_yaml_content(filename)
    ttp = yaml.safe_load(yaml_content)
    
    # Format for model consumption
    formatted_result = {
        'name': ttp.get('name', ''),
        'description': ttp.get('description', ''),
        'impact': ttp.get('impact', []),
        'mitigation': ttp.get('mitigation', ''),
        'tags': ttp.get('tags', []),
        'category': ttp.get('Category', ''),
        'command': ttp.get('Command', ''),
        'detection': ttp.get('Detection', []),
        'mitre_attack': ttp.get('MITRE_ATT&CK', ''),
        'references': ttp.get('references', [])
    }
    
    return jsonify({
        'status': 'success',
        'data': formatted_result
    })

@app.route('/mcp/v1/batch_retrieve', methods=['POST'])
def mcp_batch_retrieve():
    """Model Context Protocol batch retrieve endpoint
    
    This endpoint allows AI models to retrieve multiple TTPs by name in a single request.
    """
    if not request.is_json:
        return jsonify({
            'status': 'error',
            'message': 'Request must be JSON'
        }), 400
    
    data = request.get_json()
    names = data.get('names', [])
    
    if not names or not isinstance(names, list):
        return jsonify({
            'status': 'error',
            'message': 'Names must be a non-empty list'
        }), 400
    
    results = []
    not_found = []
    
    for name in names:
        filename = get_yaml_filename(name)
        if not filename:
            not_found.append(name)
            continue
        
        yaml_content = get_raw_yaml_content(filename)
        ttp = yaml.safe_load(yaml_content)
        
        # Format for model consumption
        formatted_result = {
            'name': ttp.get('name', ''),
            'description': ttp.get('description', ''),
            'impact': ttp.get('impact', []),
            'mitigation': ttp.get('mitigation', ''),
            'tags': ttp.get('tags', []),
            'category': ttp.get('Category', ''),
            'command': ttp.get('Command', ''),
            'detection': ttp.get('Detection', []),
            'mitre_attack': ttp.get('MITRE_ATT&CK', ''),
            'references': ttp.get('references', [])
        }
        results.append(formatted_result)
    
    return jsonify({
        'status': 'success',
        'results': results,
        'count': len(results),
        'not_found': not_found
    })

@app.route('/mcp/v1/list_tags', methods=['GET'])
def mcp_list_tags():
    """Model Context Protocol list tags endpoint
    
    This endpoint allows AI models to retrieve all available tags in the TTP database.
    """
    ttps = load_ttps()
    all_tags = set()
    
    for ttp in ttps:
        tags = ttp.get('tags', [])
        if isinstance(tags, list):
            for tag in tags:
                all_tags.add(tag)
        elif isinstance(tags, str):
            all_tags.add(tags)
    
    return jsonify({
        'status': 'success',
        'tags': sorted(list(all_tags)),
        'count': len(all_tags)
    })

@app.route('/mcp/v1/search_by_tag/<tag>', methods=['GET'])
def mcp_search_by_tag(tag):
    """Model Context Protocol search by tag endpoint
    
    This endpoint allows AI models to retrieve all TTPs with a specific tag.
    """
    ttps = load_ttps()
    results = []
    
    for ttp in ttps:
        tags = ttp.get('tags', [])
        if isinstance(tags, list) and tag in tags:
            results.append(ttp)
        elif isinstance(tags, str) and tag == tags:
            results.append(ttp)
    
    # Format for model consumption
    formatted_results = []
    for ttp in results:
        formatted_result = {
            'name': ttp.get('name', ''),
            'description': ttp.get('description', ''),
            'impact': ttp.get('impact', []),
            'mitigation': ttp.get('mitigation', ''),
            'tags': ttp.get('tags', []),
            'category': ttp.get('Category', ''),
            'command': ttp.get('Command', ''),
            'detection': ttp.get('Detection', []),
            'mitre_attack': ttp.get('MITRE_ATT&CK', ''),
            'references': ttp.get('references', [])
        }
        formatted_results.append(formatted_result)
    
    return jsonify({
        'status': 'success',
        'tag': tag,
        'results': formatted_results,
        'count': len(formatted_results)
    })

@app.route('/mcp/v1/search_by_tags', methods=['POST'])
def mcp_search_by_multiple_tags():
    """Model Context Protocol search by multiple tags endpoint
    
    This endpoint allows AI models to retrieve TTPs matching multiple tags.
    Supports both AND and OR logic for tag matching.
    
    Request format:
    {
        "tags": ["tag1", "tag2", ...],
        "match_type": "all" or "any" (default: "any")
    }
    
    - "all": TTP must have ALL specified tags (AND logic)
    - "any": TTP must have AT LEAST ONE of the specified tags (OR logic)
    """
    if not request.is_json:
        return jsonify({
            'status': 'error',
            'message': 'Request must be JSON'
        }), 400
    
    data = request.get_json()
    tags = data.get('tags', [])
    match_type = data.get('match_type', 'any').lower()  # Default to 'any' (OR logic)
    
    if not tags or not isinstance(tags, list):
        return jsonify({
            'status': 'error',
            'message': 'Tags must be a non-empty list'
        }), 400
    
    if match_type not in ['all', 'any']:
        return jsonify({
            'status': 'error',
            'message': 'Match type must be either "all" or "any"'
        }), 400
    
    ttps = load_ttps()
    results = []
    
    for ttp in ttps:
        ttp_tags = ttp.get('tags', [])
        
        # Convert to list if it's a string
        if isinstance(ttp_tags, str):
            ttp_tags = [ttp_tags]
        elif not isinstance(ttp_tags, list):
            ttp_tags = []
        
        # Check if TTP matches the tag criteria
        if match_type == 'all':
            # AND logic: TTP must have ALL specified tags
            if all(tag in ttp_tags for tag in tags):
                results.append(ttp)
        else:  # 'any'
            # OR logic: TTP must have AT LEAST ONE of the specified tags
            if any(tag in ttp_tags for tag in tags):
                results.append(ttp)
    
    # Format for model consumption
    formatted_results = []
    for ttp in results:
        formatted_result = {
            'name': ttp.get('name', ''),
            'description': ttp.get('description', ''),
            'impact': ttp.get('impact', []),
            'mitigation': ttp.get('mitigation', ''),
            'tags': ttp.get('tags', []),
            'category': ttp.get('Category', ''),
            'command': ttp.get('Command', ''),
            'detection': ttp.get('Detection', []),
            'mitre_attack': ttp.get('MITRE_ATT&CK', ''),
            'references': ttp.get('references', [])
        }
        formatted_results.append(formatted_result)
    
    return jsonify({
        'status': 'success',
        'tags': tags,
        'match_type': match_type,
        'results': formatted_results,
        'count': len(formatted_results)
    })

@app.route('/mcp/v1/docs', methods=['GET'])
def mcp_docs():
    """Model Context Protocol documentation endpoint
    
    This endpoint provides documentation on how to use the Model Context Protocol.
    """
    docs = {
        'version': MCP_VERSION,
        'description': 'Model Context Protocol for accessing TTPs (Tactics, Techniques, and Procedures)',
        'endpoints': [
            {
                'path': '/mcp/v1/query',
                'method': 'POST',
                'description': 'Query the TTPs database with natural language',
                'parameters': {
                    'query': 'Natural language query string',
                    'max_results': 'Maximum number of results to return (default: 5)'
                },
                'returns': 'List of TTPs matching the query'
            },
            {
                'path': '/mcp/v1/vector_search',
                'method': 'POST',
                'description': 'Semantic search using vector similarity',
                'parameters': {
                    'query': 'Natural language query string',
                    'max_results': 'Maximum number of results to return (default: 5)',
                    'threshold': 'Similarity threshold (default: 0.7)'
                },
                'returns': 'List of TTPs with similarity scores'
            },
            {
                'path': '/mcp/v1/retrieve/<name>',
                'method': 'GET',
                'description': 'Retrieve a specific TTP by name',
                'parameters': {
                    'name': 'Name of the TTP to retrieve'
                },
                'returns': 'TTP data formatted for model consumption'
            },
            {
                'path': '/mcp/v1/batch_retrieve',
                'method': 'POST',
                'description': 'Retrieve multiple TTPs by name',
                'parameters': {
                    'names': 'List of TTP names to retrieve'
                },
                'returns': 'List of TTPs formatted for model consumption'
            },
            {
                'path': '/mcp/v1/list_tags',
                'method': 'GET',
                'description': 'List all available tags in the TTP database',
                'parameters': {},
                'returns': 'List of all tags'
            },
            {
                'path': '/mcp/v1/search_by_tag/<tag>',
                'method': 'GET',
                'description': 'Search for TTPs with a specific tag',
                'parameters': {
                    'tag': 'Tag to search for'
                },
                'returns': 'List of TTPs with the specified tag'
            },
            {
                'path': '/mcp/v1/search_by_tags',
                'method': 'POST',
                'description': 'Search for TTPs matching multiple tags with AND/OR logic',
                'parameters': {
                    'tags': 'List of tags to search for',
                    'match_type': '"all" (AND logic) or "any" (OR logic, default)'
                },
                'returns': 'List of TTPs matching the tag criteria'
            },
            {
                'path': '/mcp/v1/metadata',
                'method': 'GET',
                'description': 'Get metadata about the TTP database',
                'parameters': {},
                'returns': 'Metadata about the TTP database'
            }
        ]
    }
    
    return jsonify(docs)

@app.route('/mcp/v1/vector_search', methods=['POST'])
def mcp_vector_search():
    """Model Context Protocol vector search endpoint
    
    This endpoint allows AI models to perform semantic search using vector similarity.
    """
    if not request.is_json:
        return jsonify({
            'status': 'error',
            'message': 'Request must be JSON'
        }), 400
    
    data = request.get_json()
    query = data.get('query')
    max_results = data.get('max_results', 5)
    threshold = data.get('threshold', 0.7)
    
    if not query:
        return jsonify({
            'status': 'error',
            'message': 'Query is required'
        }), 400
    
    # Create a vector for the query
    query_vector = create_vector(query)
    
    # Load all TTPs
    ttps = load_ttps()
    results = []
    
    for ttp in ttps:
        # Create a combined text representation of the TTP
        ttp_text = f"{ttp.get('name', '')} {ttp.get('description', '')} {' '.join(str(i) for i in ttp.get('impact', []))} {ttp.get('Category', '')} {ttp.get('Command', '')}"
        
        # Get or create the vector for this TTP
        ttp_id = ttp.get('name', '')
        if ttp_id in vector_cache:
            ttp_vector = vector_cache[ttp_id]
        else:
            ttp_vector = create_vector(ttp_text)
            vector_cache[ttp_id] = ttp_vector
        
        # Compute similarity
        similarity = cosine_similarity(query_vector, ttp_vector)
        
        if similarity >= threshold:
            results.append({
                'ttp': ttp,
                'similarity': similarity
            })
    
    # Sort by similarity and limit results
    results = sorted(results, key=lambda x: x['similarity'], reverse=True)[:max_results]
    
    # Format for model consumption
    formatted_results = []
    for result in results:
        ttp = result['ttp']
        formatted_result = {
            'name': ttp.get('name', ''),
            'description': ttp.get('description', ''),
            'impact': ttp.get('impact', []),
            'mitigation': ttp.get('mitigation', ''),
            'tags': ttp.get('tags', []),
            'category': ttp.get('Category', ''),
            'command': ttp.get('Command', ''),
            'detection': ttp.get('Detection', []),
            'mitre_attack': ttp.get('MITRE_ATT&CK', ''),
            'references': ttp.get('references', []),
            'similarity': result['similarity']
        }
        formatted_results.append(formatted_result)
    
    return jsonify({
        'status': 'success',
        'query': query,
        'results': formatted_results,
        'count': len(formatted_results)
    })

@app.route('/mcp/v1/metadata', methods=['GET'])
def mcp_metadata():
    """Model Context Protocol metadata endpoint
    
    This endpoint provides metadata about the TTP database structure and contents.
    """
    ttps = load_ttps()
    
    # Count TTPs by category
    categories = {}
    for ttp in ttps:
        category = ttp.get('Category', 'Uncategorized')
        categories[category] = categories.get(category, 0) + 1
    
    # Count TTPs by MITRE ATT&CK tactic
    tactics = {}
    for ttp in ttps:
        tactic = ttp.get('MITRE_ATT&CK', 'Unknown')
        tactics[tactic] = tactics.get(tactic, 0) + 1
    
    # Get all unique fields across all TTPs
    all_fields = set()
    for ttp in ttps:
        for field in ttp.keys():
            all_fields.add(field)
    
    # Get all unique tags
    all_tags = set()
    for ttp in ttps:
        tags = ttp.get('tags', [])
        if isinstance(tags, list):
            for tag in tags:
                all_tags.add(tag)
        elif isinstance(tags, str):
            all_tags.add(tags)
    
    return jsonify({
        'status': 'success',
        'total_ttps': len(ttps),
        'categories': categories,
        'mitre_tactics': tactics,
        'fields': sorted(list(all_fields)),
        'tags': sorted(list(all_tags)),
        'schema': {
            'name': 'string',
            'description': 'string',
            'impact': 'array or string',
            'mitigation': 'string',
            'tags': 'array or string',
            'Category': 'string',a
            'Command': 'string',
            'Detection': 'array',
            'MITRE_ATT&CK': 'string',
            'references': 'array'
        }
    })

if __name__ == '__main__':
    app.run(debug=True)
a

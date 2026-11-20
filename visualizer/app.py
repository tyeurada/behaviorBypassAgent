import os
import json
import re
import sys
import subprocess
import yaml
from pathlib import Path
from flask import Flask, render_template, jsonify, send_from_directory, request

app = Flask(__name__)

# Base directory for outputs (relative to this file)
BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / 'output'
FRONTEND_DIST = Path(__file__).resolve().parent / 'frontend' / 'dist'

@app.route('/')
def index():
    """Serve the built Vite frontend, falling back to the legacy template."""
    dist_index = FRONTEND_DIST / 'index.html'
    if dist_index.exists():
        return send_from_directory(FRONTEND_DIST, 'index.html')
    return render_template('index.html')

@app.route('/assets/<path:filename>')
def frontend_assets(filename):
    return send_from_directory(FRONTEND_DIST / 'assets', filename)

@app.route('/api/sessions')
def get_sessions():
    """List all session directories in output/"""
    sessions = []
    if not OUTPUT_DIR.exists():
        return jsonify(sessions)

    for item in OUTPUT_DIR.iterdir():
        if item.is_dir():
            # Check if it looks like a session dir (YYYYMMDD_HHMMSS)
            # Simplest check: just list all dirs
            sessions.append({
                'id': item.name,
                'path': str(item)
            })
    
    # Prefer timestamp-like session IDs first (YYYYMMDD_HHMMSS), then newest by name.
    sessions.sort(
        key=lambda x: (bool(re.fullmatch(r"\d{8}_\d{6}", x['id'])), x['id']),
        reverse=True
    )
    return jsonify(sessions)

import ast

@app.route('/api/sessions/<session_id>')
def get_session_details(session_id):
    """Get iterations for a specific session"""
    print(f"DEBUG: API Request for session {session_id}")
    session_dir = OUTPUT_DIR / session_id
    if not session_dir.exists():
        return jsonify({'error': 'Session not found'}), 404

    iterations = []
    
    # Scan for iter_N directories
    for item in session_dir.iterdir():
        if item.is_dir() and item.name.startswith('iter_'):
            try:
                iter_num = int(item.name.replace('iter_', ''))
            except ValueError:
                continue

            iter_data = {
                'iteration': iter_num,
                'prompt': '',
                'response': '',
                'code': '',
                'has_prompt': False,
                'has_response': False,
                'has_code': False,
                'has_code': False,
                'response_parsed': False,
                'response_data': {},
                'review_prompt': None,
                'review_response': None
            }

            # Read prompt.txt
            prompt_file = item / 'prompt.txt'
            if prompt_file.exists():
                try:
                    iter_data['prompt'] = prompt_file.read_text(encoding='utf-8', errors='replace')
                    iter_data['has_prompt'] = True
                except Exception as e:
                    iter_data['prompt'] = f"Error reading file: {e}"

            # Read response.txt
            response_file = item / 'response.txt'
            if response_file.exists():
                try:
                    raw_response = response_file.read_text(encoding='utf-8', errors='replace')
                    iter_data['response'] = raw_response
                    iter_data['has_response'] = True
                    
                    # Try to parse as python dict (it's often repr(dict))
                    try:
                        parsed = ast.literal_eval(raw_response)
                        if isinstance(parsed, dict):
                            iter_data['response_parsed'] = True
                            iter_data['response_data'] = parsed
                            if 'text' in parsed:
                                iter_data['response_text'] = parsed['text']
                            if 'extras' in parsed:
                                iter_data['response_extras'] = parsed['extras']
                        else:
                            # Not a dict, might be just a string from safe eval?
                            # Treat as raw markdown
                            iter_data['response_text'] = raw_response
                            iter_data['response_parsed'] = True

                    except Exception:
                        # Not a valid python literal structure (e.g. just plain text that looks like code or normal text)
                        # Treat as raw markdown
                        iter_data['response_text'] = raw_response
                        iter_data['response_parsed'] = True

                except Exception as e:
                    iter_data['response'] = f"Error reading file: {e}"

            # Try to find generated code (loader_N.c, loader_N.cs, loader_N.py or similar)
            # Scan for various supported language extensions
            code_files = []
            for ext in ('*.c', '*.cpp', '*.cs', '*.py'):
                code_files.extend(list(item.glob(ext)))
                
            if code_files:
                # Pick the first matching code file
                code_file = code_files[0]
                try:
                    iter_data['code'] = code_file.read_text(encoding='utf-8', errors='replace')
                    iter_data['has_code'] = True
                except Exception as e:
                    iter_data['code'] = f"Error reading code: {e}"
                    
            # Check for AI Analysis files (New Flow)
            analysis_prompt_file = item / "analysis_prompt.txt"
            if analysis_prompt_file.exists():
                 iter_data['analysis_prompt'] = analysis_prompt_file.read_text(encoding='utf-8', errors='replace')
                 
            analysis_response_file = item / "analysis_response.txt"
            if analysis_response_file.exists():
                 raw_analysis = analysis_response_file.read_text(encoding='utf-8', errors='replace')
                 iter_data['analysis_response'] = raw_analysis
                 
                 # PARSE: Check if it's a legacy dict string (from before the fix in nodes.py)
                 try:
                     parsed = ast.literal_eval(raw_analysis)
                     if isinstance(parsed, dict) and 'text' in parsed:
                         iter_data['analysis_response'] = parsed['text']
                 except Exception:
                     # Already plain text
                     # Already plain text
                     pass
            
            # Check for Review Agent files (New Flow)
            review_prompt_file = item / "review_prompt.txt"
            if review_prompt_file.exists():
                 try:
                     print(f"DEBUG: Found review_prompt at {review_prompt_file}")
                     content = review_prompt_file.read_text(encoding='utf-8', errors='replace')
                     print(f"DEBUG: Read {len(content)} chars")
                     iter_data['review_prompt'] = content
                 except Exception as e:
                     print(f"DEBUG: Error reading review_prompt: {e}")
                     pass
            else:
                 print(f"DEBUG: No review_prompt found at {review_prompt_file}")

            review_response_file = item / "review_response.txt"
            if review_response_file.exists():
                 try:
                     raw_review = review_response_file.read_text(encoding='utf-8', errors='replace')
                     iter_data['review_response'] = raw_review
                     # Handle legacy dict-like payloads: {'type': 'text', 'text': '...'}
                     try:
                         parsed = ast.literal_eval(raw_review)
                         if isinstance(parsed, dict) and 'text' in parsed:
                             iter_data['review_response'] = parsed['text']
                     except Exception:
                         pass
                 except Exception:
                     pass

            iterations.append(iter_data)

    iterations.sort(key=lambda x: x['iteration'])

    # Read final summary if available
    final_summary = ""
    summary_file = session_dir / 'final_summary.txt'
    if summary_file.exists():
        try:
            final_summary = summary_file.read_text(encoding='utf-8', errors='replace')
        except Exception:
            final_summary = "Error reading summary file."
    CONFIG_FILE = BASE_DIR / 'config' / 'config.yaml'
    run_config = {}
    run_config_file = session_dir / 'run_config.yaml'
    if run_config_file.exists():
        try:
            with open(run_config_file, 'r', encoding='utf-8') as f:
                run_config = yaml.safe_load(f)
        except Exception:
            pass
    else:
        # Fallback to current config for old sessions
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                run_config = yaml.safe_load(f)
        except Exception:
            pass

    return jsonify({
        'session_id': session_id,
        'iterations': iterations,
        'final_summary': final_summary,
        'config': run_config
    })

CONFIG_FILE = BASE_DIR / 'config' / 'config.yaml'

active_process = None
active_session_id = None

@app.route('/api/config', methods=['GET', 'POST'])
def handle_config():
    if request.method == 'GET':
        if not CONFIG_FILE.exists():
            return jsonify({'error': 'Config file not found'}), 404
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            return jsonify(config)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
            
    elif request.method == 'POST':
        data = request.json
        if not data:
            return jsonify({'error': 'Invalid request body'}), 400
        try:
            # Backup config just in case
            if CONFIG_FILE.exists():
                backup_path = CONFIG_FILE.with_suffix('.yaml.bak')
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f_in:
                    backup_content = f_in.read()
                with open(backup_path, 'w', encoding='utf-8') as f_out:
                    f_out.write(backup_content)

            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
                
            # Clear nodes cached globals
            try:
                if 'core.nodes' in sys.modules:
                    import core.nodes
                    core.nodes._config = None
                    core.nodes._compiler = None
                    core.nodes._executor = None
                    core.nodes._detectors = None
                    core.nodes._rule_analyzer = None
                    core.nodes._llm = None
                    print("DEBUG: Cleared core.nodes globals.")
            except Exception as ex:
                print(f"DEBUG: Error clearing core.nodes: {ex}")

            return jsonify({'status': 'saved'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

@app.route('/api/run', methods=['POST'])
def run_agent():
    global active_process, active_session_id
    
    # Check if currently running
    if active_process and active_process.poll() is None:
        return jsonify({'error': 'Agent is already running. Stop it before starting a new run.'}), 400
        
    data = request.json or {}
    shellcode_path = data.get('shellcode_path', '')
    iterations = data.get('iterations', 10)
    
    if not shellcode_path:
        return jsonify({'error': 'shellcode_path is required'}), 400
        
    import datetime
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    session_id = timestamp
    session_dir = OUTPUT_DIR / session_id
    session_dir.mkdir(parents=True, exist_ok=True)
    
    log_file_path = session_dir / 'agent_run.log'
    
    # We open the log file to redirect output
    log_file = open(log_file_path, 'w', encoding='utf-8')
    
    cmd = [
        sys.executable,
        str(BASE_DIR / 'main.py'),
        '--shellcode', shellcode_path,
        '--iterations', str(iterations),
        '--session-dir', str(session_dir)
    ]
    
    print(f"DEBUG: Launching command: {' '.join(cmd)}")
    
    # Start subprocess in background
    try:
        process = subprocess.Popen(
            cmd,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            cwd=str(BASE_DIR)
        )
        active_process = process
        active_session_id = session_id
        
        return jsonify({
            'status': 'started',
            'session_id': session_id
        })
    except Exception as e:
        return jsonify({'error': f"Failed to start process: {e}"}), 500

@app.route('/api/run/status')
def run_status():
    global active_process, active_session_id
    status = 'idle'
    if active_process:
        poll = active_process.poll()
        if poll is None:
            status = 'running'
        elif poll == 0:
            status = 'completed'
        else:
            status = 'failed'
            
    return jsonify({
        'status': status,
        'session_id': active_session_id
    })

@app.route('/api/run/stop', methods=['POST'])
def stop_agent():
    global active_process
    if active_process and active_process.poll() is None:
        try:
            active_process.terminate()
            active_process.wait(timeout=5)
        except Exception:
            try:
                active_process.kill()
            except Exception:
                pass
        return jsonify({'status': 'stopped'})
    return jsonify({'status': 'idle', 'message': 'No agent is currently running'})

@app.route('/api/sessions/<session_id>/logs')
def get_session_logs(session_id):
    session_dir = OUTPUT_DIR / session_id
    log_file_path = session_dir / 'agent_run.log'
    if not log_file_path.exists():
        return jsonify({'logs': '(Waiting for agent logs to initialize...)'})
        
    try:
        logs = log_file_path.read_text(encoding='utf-8', errors='replace')
        return jsonify({'logs': logs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print(f"Starting Visualizer...")
    print(f"Scanning directory: {OUTPUT_DIR}")
    app.run(debug=True, port=5001)

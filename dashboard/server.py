"""
Evil Twin Detection System - Backend API
Python Flask implementation with real-time SSE support
"""

import os
import json
import time
import queue
import threading
from datetime import datetime
from flask import Flask, jsonify, request, Response, render_template
from flask_cors import CORS

app = Flask(__name__, template_folder=".")
CORS(app)

# --- Global State ---
system_data = {
    'metrics': {
        'threatsDetected': 0,
        'networksScanned': 0,
        'newThreats': 0,
        'uptime': 0
    },
    'threats': [],
    'networks': [], # APs discovered
    'timeline': []
}

start_time = time.time()
event_queues = []

def broadcast_event(event_type, data):
    event = {
        'type': event_type,
        'data': data,
        'timestamp': datetime.now().isoformat()
    }
    
    global event_queues
    # Clean up stale queues
    event_queues = [q for q in event_queues] # In a real app we'd track active ones better
    
    for q in event_queues:
        try:
            q.put(event)
        except:
            pass

def update_uptime():
    while True:
        system_data['metrics']['uptime'] = int(time.time() - start_time)
        time.sleep(10)

# Start uptime thread
threading.Thread(target=update_uptime, daemon=True).start()

def load_initial_data():
    """Load previous alerts from file if they exist"""
    alerts_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'alerts.json')
    if os.path.exists(alerts_path):
        try:
            with open(alerts_path, 'r') as f:
                alerts = json.load(f)
                for alert in alerts:
                    # Convert alert.json format to dashboard format
                    threat = {
                        'id': int(datetime.fromisoformat(alert['timestamp']).timestamp() * 1000),
                        'ssid': alert.get('ssid', 'Unknown'),
                        'mac': alert.get('bssid', 'Unknown'),
                        'severity': alert.get('level', 'Medium').capitalize(),
                        'detectedAt': alert.get('timestamp'),
                        'reasons': alert.get('reasons', []),
                        'score': alert.get('score', 0)
                    }
                    system_data['threats'].append(threat)
                
                system_data['metrics']['threatsDetected'] = len(system_data['threats'])
                print(f"[*] Loaded {len(system_data['threats'])} historical threats from alerts.json")
        except Exception as e:
            print(f"[!] Warning: Could not load historical alerts: {e}")

load_initial_data()

# --- Routes ---

@app.route("/")
def index():
    return render_template("index.html")

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'engine_connected': True # We assume if threats are coming in
    })

@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    return jsonify(system_data['metrics'])

@app.route('/api/threats', methods=['GET'])
def get_threats():
    return jsonify(system_data['threats'])

@app.route('/api/networks', methods=['GET'])
def get_networks():
    # In a fully connected system, the engine would also POST all seen networks here.
    # For now, we return threats as a subset of networks if no others reported.
    if not system_data['networks']:
        return jsonify(system_data['threats'])
    return jsonify(system_data['networks'])

@app.route('/api/timeline', methods=['GET'])
def get_timeline():
    return jsonify(system_data['timeline'][:50])

@app.route('/api/scan', methods=['POST'])
def initiate_scan():
    """Triggered by UI to start a new scan"""
    entry = {
        'id': int(time.time() * 1000),
        'timestamp': datetime.now().isoformat(),
        'action': 'Scan Initiated',
        'description': 'System scanning for new access points and potential threats'
    }
    system_data['timeline'].insert(0, entry)
    broadcast_event('timeline_update', entry)
    return jsonify({'success': True, 'message': 'Scan signal sent to engine'})

@app.route('/api/report', methods=['GET'])
def get_report():
    return jsonify({
        'generatedAt': datetime.now().isoformat(),
        'metrics': system_data['metrics'],
        'threats': system_data['threats'],
        'timeline': system_data['timeline'][:50]
    })

@app.route('/api/networks', methods=['POST'])
def add_network():
    """Endpoint for Detection Engine to report discovered APs"""
    net_data = request.get_json()
    bssid = net_data.get('mac')
    
    # Check if exists
    exists = False
    for i, net in enumerate(system_data['networks']):
        if net.get('mac') == bssid:
            system_data['networks'][i].update(net_data)
            exists = True
            break
            
    if not exists:
        system_data['networks'].append(net_data)
        system_data['metrics']['networksScanned'] = len(system_data['networks'])
        broadcast_event('network_discovered', net_data)
    else:
        broadcast_event('network_updated', net_data)
        
    broadcast_event('metrics_update', system_data['metrics'])
    
    return jsonify({'success': True}), 201

@app.route('/api/threats', methods=['POST'])
def add_threat():
    """Endpoint for Detection Engine to report threats"""
    threat_data = request.get_json()
    bssid = threat_data.get('mac')
    
    # Check if exists
    existing_index = next((i for i, t in enumerate(system_data['threats']) if t['mac'] == bssid), None)
    
    threat = {
        'id': int(time.time() * 1000) if existing_index is None else system_data['threats'][existing_index]['id'],
        **threat_data,
        'detectedAt': datetime.now().isoformat()
    }
    
    if existing_index is not None:
        # Update existing
        system_data['threats'][existing_index].update(threat)
        # Broadcast update instead of new threat
        broadcast_event('threat_updated', threat)
    else:
        # New threat
        system_data['threats'].insert(0, threat)
        system_data['metrics']['threatsDetected'] = len(system_data['threats'])
        system_data['metrics']['newThreats'] += 1
        
        # Add to timeline ONLY for new threats
        timeline_entry = {
            'id': int(time.time() * 1000),
            'timestamp': datetime.now().isoformat(),
            'action': 'Evil Twin Detected',
            'description': f'Threat AP "{threat["ssid"]}" ({threat["mac"]}) was reported by engine'
        }
        system_data['timeline'].insert(0, timeline_entry)
        
        # Broadcast new threat
        broadcast_event('threat_detected', threat)
        broadcast_event('timeline_update', timeline_entry)
        broadcast_event('metrics_update', system_data['metrics'])
    
    return jsonify(threat), 201

@app.route('/api/threats/<int:threat_id>', methods=['DELETE'])
def delete_threat(threat_id):
    threat_index = next((i for i, t in enumerate(system_data['threats']) if t['id'] == threat_id), None)
    
    if threat_index is not None:
        threat = system_data['threats'].pop(threat_index)
        
        timeline_entry = {
            'id': int(time.time() * 1000),
            'timestamp': datetime.now().isoformat(),
            'action': 'Threat Ignored',
            'description': f'User marked threat "{threat["ssid"]}" as resolved/ignored'
        }
        system_data['timeline'].insert(0, timeline_entry)
        
        broadcast_event('threat_resolved', {'id': threat_id})
        broadcast_event('timeline_update', timeline_entry)
        broadcast_event('metrics_update', system_data['metrics'])
        
        return jsonify({'success': True})
    return jsonify({'success': False}), 404

@app.route('/api/config', methods=['GET'])
def get_config():
    config_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'config.json')
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return jsonify(json.load(f))
        else:
            return jsonify({
                "IS_NOTIF_ON": "False",
                "TG_CHAT_ID": ""
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config', methods=['POST'])
def update_config():
    config_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'config.json')
    new_config = request.get_json()
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(new_config, f, indent=4)
        
        # Log to timeline
        timeline_entry = {
            'id': int(time.time() * 1000),
            'timestamp': datetime.now().isoformat(),
            'action': 'Config Updated',
            'description': 'Alert notification settings were updated by user'
        }
        system_data['timeline'].insert(0, timeline_entry)
        broadcast_event('timeline_update', timeline_entry)
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/events', methods=['GET'])
def stream_events():
    def event_stream():
        q = queue.Queue()
        event_queues.append(q)
        try:
            yield f"data: {json.dumps({'type': 'connected', 'timestamp': datetime.now().isoformat()})}\n\n"
            while True:
                event = q.get(timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
        except queue.Empty:
            yield f": keepalive\n\n"
        except Exception:
            pass
        finally:
            if q in event_queues:
                event_queues.remove(q)
    
    return Response(event_stream(), mimetype='text/event-stream')

if __name__ == '__main__':
    print('=' * 60)
    print('AirSentinel Dashboard Service')
    print('Listening on: http://localhost:5000')
    print('=' * 60)
    
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)

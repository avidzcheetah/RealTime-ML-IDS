from flask_socketio import SocketIO, emit
from flask import Flask, render_template, url_for, request
from threading import Thread, Event
import warnings
warnings.filterwarnings("ignore")

# Network capture
from scapy.sendrecv import sniff

# Custom modules
from flow.Flow import Flow
from flow.PacketInfo import PacketInfo

# Data processing
import numpy as np
import pandas as pd
import pickle
import csv 
import traceback
import json

# ML and Analysis
from scipy.stats import norm
from tensorflow import keras
from lime import lime_tabular
import dill
import joblib

# Utilities
import ipaddress
from urllib.request import urlopen
import plotly
import plotly.graph_objs as go

__author__ = 'hoang'

# =============================================================================
# Flask and SocketIO Configuration
# =============================================================================

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['DEBUG'] = True

# Initialize SocketIO with updated parameters
socketio = SocketIO(
    app, 
    async_mode='threading',
    cors_allowed_origins="*",
    logger=True, 
    engineio_logger=True,
    ping_timeout=60,
    ping_interval=25
)

# =============================================================================
# Global Variables
# =============================================================================

# Threading
thread = Thread()
thread_stop_event = Event()

# File handlers
try:
    f = open("output_logs.csv", 'w', newline='', encoding='utf-8')
    w = csv.writer(f)
    f2 = open("input_logs.csv", 'w', newline='', encoding='utf-8')
    w2 = csv.writer(f2)
except Exception as e:
    print(f"Error opening log files: {e}")
    raise

# Column definitions
cols = ['FlowID', 'FlowDuration', 'BwdPacketLenMax', 'BwdPacketLenMin',
        'BwdPacketLenMean', 'BwdPacketLenStd', 'FlowIATMean', 'FlowIATStd',
        'FlowIATMax', 'FlowIATMin', 'FwdIATTotal', 'FwdIATMean', 'FwdIATStd',
        'FwdIATMax', 'FwdIATMin', 'BwdIATTotal', 'BwdIATMean', 'BwdIATStd',
        'BwdIATMax', 'BwdIATMin', 'FwdPSHFlags', 'FwdPackets_s', 'MaxPacketLen',
        'PacketLenMean', 'PacketLenStd', 'PacketLenVar', 'FINFlagCount',
        'SYNFlagCount', 'PSHFlagCount', 'ACKFlagCount', 'URGFlagCount',
        'AvgPacketSize', 'AvgBwdSegmentSize', 'InitWinBytesFwd', 'InitWinBytesBwd',
        'ActiveMin', 'IdleMean', 'IdleStd', 'IdleMax', 'IdleMin', 'Src', 'SrcPort',
        'Dest', 'DestPort', 'Protocol', 'FlowStartTime', 'FlowLastSeen', 'PName',
        'PID', 'Classification', 'Probability', 'Risk']

ae_features = np.array([
    'FlowDuration', 'BwdPacketLengthMax', 'BwdPacketLengthMin', 'BwdPacketLengthMean',
    'BwdPacketLengthStd', 'FlowIATMean', 'FlowIATStd', 'FlowIATMax', 'FlowIATMin',
    'FwdIATTotal', 'FwdIATMean', 'FwdIATStd', 'FwdIATMax', 'FwdIATMin',
    'BwdIATTotal', 'BwdIATMean', 'BwdIATStd', 'BwdIATMax', 'BwdIATMin',
    'FwdPSHFlags', 'FwdPackets/s', 'PacketLengthMax', 'PacketLengthMean',
    'PacketLengthStd', 'PacketLengthVariance', 'FINFlagCount', 'SYNFlagCount',
    'PSHFlagCount', 'ACKFlagCount', 'URGFlagCount', 'AveragePacketSize',
    'BwdSegmentSizeAvg', 'FWDInitWinBytes', 'BwdInitWinBytes', 'ActiveMin',
    'IdleMean', 'IdleStd', 'IdleMax', 'IdleMin'
])

# Flow tracking
flow_count = 0
flow_df = pd.DataFrame(columns=cols)
src_ip_dict = {}
current_flows = {}
FlowTimeout = 600

# =============================================================================
# Model Loading
# =============================================================================

print("="*60)
print("Loading ML Models...")
print("="*60)
try:
    print("  [1/4] Loading autoencoder scaler...")
    ae_scaler = joblib.load("models/preprocess_pipeline_AE_39ft.save")
    
    print("  [2/4] Loading autoencoder model...")
    ae_model = keras.models.load_model('models/autoencoder_39ft.hdf5', compile=False)
    
    print("  [3/4] Loading Random Forest classifier...")
    rf_classifier = joblib.load('models/model.pkl')
    
    if not hasattr(rf_classifier, 'predict'):
        raise TypeError(f"Loaded object is not a classifier: {type(rf_classifier)}")
    
    print(f"  ✓ Classifier type: {type(rf_classifier).__name__}")
    print(f"  ✓ Number of classes: {len(rf_classifier.classes_)}")
    print(f"  ✓ Classes: {list(rf_classifier.classes_)}")
    
    classifier = rf_classifier
    
    print("  [4/4] Loading LIME explainer...")
    with open('models/explainer', 'rb') as f:
        explainer = dill.load(f)
    
    predict_fn_rf = lambda x: classifier.predict_proba(x).astype(float)
    
    print("="*60)
    print("✓ All models loaded successfully!")
    print("="*60)
    
except FileNotFoundError as e:
    print(f"✗ Model file not found: {e}")
    print("\nPlease run: python retrain_classifier.py")
    raise
    
except TypeError as e:
    print(f"✗ Model loading error: {e}")
    print("\nThe model.pkl file is corrupted or incompatible.")
    print("Please retrain by running: python retrain_classifier.py")
    raise
    
except Exception as e:
    print(f"✗ Error loading models: {e}")
    print("\nTroubleshooting:")
    print("1. Run 'python retrain_classifier.py' to retrain models")
    print("2. Make sure all model files exist in the 'models' directory")
    print("3. Check that models were trained with compatible sklearn version")
    traceback.print_exc()
    raise

# =============================================================================
# Utility Functions
# =============================================================================

def ipInfo(addr=''):
    """Get country information for IP address"""
    try:
        if addr == '':
            url = 'https://ipinfo.io/json'
        else:
            url = f'https://ipinfo.io/{addr}/json'
        
        with urlopen(url, timeout=5) as res:
            data = json.load(res)
            return data.get('country')
    except Exception as e:
        print(f"IP info lookup failed for {addr}: {e}")
        return None

def get_risk_html(proba_risk):
    """Generate risk level HTML based on probability"""
    if proba_risk > 0.8:
        return '<p style="color:#ff4444; font-weight: bold;">🔴 Very High</p>'
    elif proba_risk > 0.6:
        return '<p style="color:#ff6b35; font-weight: bold;">🟠 High</p>'
    elif proba_risk > 0.4:
        return '<p style="color:#ffa500; font-weight: bold;">🟡 Medium</p>'
    elif proba_risk > 0.2:
        return '<p style="color:#00ff88; font-weight: bold;">🟢 Low</p>'
    else:
        return '<p style="color:#00ff88; font-weight: bold;">✅ Minimal</p>'

def get_country_flag_html(ip):
    """Generate country flag HTML for IP address"""
    try:
        if not ipaddress.ip_address(ip).is_private:
            country = ipInfo(ip)
            if country and country not in ['ano', 'unknown']:
                return f' <img src="static/images/blank.gif" class="flag flag-{country.lower()}" title="{country}">'
            else:
                return ' <img src="static/images/blank.gif" class="flag flag-unknown" title="UNKNOWN">'
        else:
            return ' <img src="static/images/lan.gif" height="11px" style="margin-bottom: 0px" title="LAN">'
    except Exception as e:
        print(f"Error getting flag for IP {ip}: {e}")
        return ' <img src="static/images/blank.gif" class="flag flag-unknown" title="UNKNOWN">'

# =============================================================================
# Classification Function
# =============================================================================

def classify(features):
    """Classify network flow and emit results via SocketIO"""
    global flow_count, classifier
    
    try:
        if not hasattr(classifier, 'predict'):
            print(f"ERROR: classifier is {type(classifier)}, not a model!")
            return None
        
        feature_string = [str(i) for i in features[39:]]
        record = features.copy()
        features_numeric = [np.nan if x in [np.inf, -np.inf] else float(x) for x in features[:39]]
        
        # Track source IP
        src_ip = feature_string[0]
        src_ip_dict[src_ip] = src_ip_dict.get(src_ip, 0) + 1
        
        # Add country flags
        for i in [0, 2]:
            feature_string[i] += get_country_flag_html(feature_string[i])
        
        # Skip if invalid features
        if np.nan in features_numeric:
            print("⚠️  Warning: NaN values in features, skipping classification")
            return
        
        # Predict
        result = classifier.predict([features_numeric])
        proba = predict_fn_rf([features_numeric])
        proba_score = float(proba[0].max())
        proba_risk = float(sum(proba[0, 1:]))
        
        risk_html = get_risk_html(proba_risk)
        classification = str(result[0])
        
        if result[0] != 'Benign':
            print(f"🚨 ALERT: {classification} detected from {feature_string[0]}")
        
        # Log to files
        flow_count += 1
        w.writerow([f'Flow #{flow_count}'])
        w.writerow(['Flow info:'] + feature_string)
        w.writerow(['Flow features:'] + features_numeric)
        w.writerow(['Prediction:'] + [classification, proba_score])
        w.writerow(['-' * 100])
        
        w2.writerow([f'Flow #{flow_count}'])
        w2.writerow(['Flow info:'] + features_numeric)
        w2.writerow(['-' * 100])
        
        # Update DataFrame
        flow_df.loc[len(flow_df)] = [flow_count] + record + [classification, proba_score, risk_html]
        
        # Prepare IP data for frontend
        ip_data = pd.DataFrame({
            'SourceIP': list(src_ip_dict.keys()),
            'count': list(src_ip_dict.values())
        }).to_json(orient='records')
        
        # Emit to frontend
        socketio.emit('newresult', {
            'result': [flow_count] + feature_string + [classification, proba_score, risk_html],
            'ips': json.loads(ip_data)
        }, namespace='/test')
        
        return [flow_count] + record + [classification, proba_score, risk_html]
        
    except Exception as e:
        print(f"❌ Classification error: {e}")
        traceback.print_exc()
        return None

# =============================================================================
# Packet Processing
# =============================================================================

def newPacket(p):
    """Process new packet and update flows"""
    try:
        packet = PacketInfo()
        packet.setDest(p)
        packet.setSrc(p)
        packet.setSrcPort(p)
        packet.setDestPort(p)
        packet.setProtocol(p)
        packet.setTimestamp(p)
        packet.setPSHFlag(p)
        packet.setFINFlag(p)
        packet.setSYNFlag(p)
        packet.setACKFlag(p)
        packet.setURGFlag(p)
        packet.setRSTFlag(p)
        packet.setPayloadBytes(p)
        packet.setHeaderBytes(p)
        packet.setPacketSize(p)
        packet.setWinBytes(p)
        packet.setFwdID()
        packet.setBwdID()
        
        # Forward flow
        if packet.getFwdID() in current_flows:
            flow = current_flows[packet.getFwdID()]
            
            if (packet.getTimestamp() - flow.getFlowLastSeen()) > FlowTimeout:
                classify(flow.terminated())
                del current_flows[packet.getFwdID()]
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow
            
            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'fwd')
                classify(flow.terminated())
                del current_flows[packet.getFwdID()]
            
            else:
                flow.new(packet, 'fwd')
                current_flows[packet.getFwdID()] = flow
        
        # Backward flow
        elif packet.getBwdID() in current_flows:
            flow = current_flows[packet.getBwdID()]
            
            if (packet.getTimestamp() - flow.getFlowLastSeen()) > FlowTimeout:
                classify(flow.terminated())
                del current_flows[packet.getBwdID()]
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow
            
            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'bwd')
                classify(flow.terminated())
                del current_flows[packet.getBwdID()]
            
            else:
                flow.new(packet, 'bwd')
                current_flows[packet.getBwdID()] = flow
        
        # New flow
        else:
            flow = Flow(packet)
            current_flows[packet.getFwdID()] = flow
    
    except AttributeError:
        pass
    except Exception as e:
        print(f"❌ Packet processing error: {e}")
        traceback.print_exc()

def snif_and_detect():
    """Main packet sniffing loop"""
    while not thread_stop_event.isSet():
        try:
            print("="*60)
            print("🔍 Starting Network Capture...")
            print("="*60)
            sniff(prn=newPacket, store=False, stop_filter=lambda x: thread_stop_event.isSet())
            
            # Classify remaining flows
            for flow in list(current_flows.values()):
                classify(flow.terminated())
            
            current_flows.clear()
            
        except Exception as e:
            print(f"❌ Sniffing error: {e}")
            traceback.print_exc()
            if not thread_stop_event.isSet():
                import time
                time.sleep(5)

# =============================================================================
# Flask Routes
# =============================================================================

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/flow-detail')
def flow_detail():
    """Flow detail page with LIME explanation and AE reconstruction"""
    try:
        flow_id = request.args.get('flow_id', default=-1, type=int)
        
        if flow_id == -1:
            return "Invalid flow ID", 400
        
        flow = flow_df.loc[flow_df['FlowID'] == flow_id]
        
        if flow.empty:
            return "Flow not found", 404
        
        # Extract features
        X = [flow.values[0, 1:40]]
        choosen_instance = X[0]
        
        # Calculate risk
        proba_score = list(predict_fn_rf(X))
        risk_proba = sum(proba_score[0][1:])
        risk = get_risk_html(risk_proba)
        risk = f"Risk Assessment: {risk}"
        
        # LIME explanation
        exp = explainer.explain_instance(
            choosen_instance,
            predict_fn_rf,
            num_features=6,
            top_labels=1
        )
        
        # Autoencoder reconstruction error
        X_transformed = ae_scaler.transform(X)
        reconstruct = ae_model.predict(X_transformed, verbose=0)
        err = reconstruct - X_transformed
        abs_err = np.absolute(err)
        
        # Top 5 largest errors
        ind_n_abs_largest = np.argpartition(abs_err[0], -5)[-5:]
        col_n_largest = ae_features[ind_n_abs_largest]
        err_n_largest = err[0][ind_n_abs_largest]
        
        # Create plot with modern styling
        plot_div = plotly.offline.plot({
            "data": [
                go.Bar(
                    x=col_n_largest.tolist(),
                    y=err_n_largest.tolist(),
                    marker=dict(
                        color=err_n_largest.tolist(),
                        colorscale='Viridis',
                        line=dict(color='rgba(0, 255, 255, 0.3)', width=1)
                    )
                )
            ],
            "layout": go.Layout(
                title="Top 5 Autoencoder Reconstruction Errors",
                xaxis=dict(title="Feature", gridcolor='rgba(255, 255, 255, 0.1)'),
                yaxis=dict(title="Error", gridcolor='rgba(255, 255, 255, 0.1)'),
                paper_bgcolor='rgba(15, 20, 40, 0.8)',
                plot_bgcolor='rgba(15, 20, 40, 0.8)',
                font=dict(color='#e0e0e0')
            )
        }, include_plotlyjs=False, output_type='div')
        
        return render_template(
            'detail.html',
            tables=[flow.reset_index(drop=True).transpose().to_html(classes='data', border=0)],
            exp=exp.as_html(),
            ae_plot=plot_div,
            risk=risk
        )
    
    except Exception as e:
        print(f"❌ Flow detail error: {e}")
        traceback.print_exc()
        return f"Error: {str(e)}", 500

# =============================================================================
# SocketIO Events
# =============================================================================

@socketio.on('connect', namespace='/test')
def test_connect():
    """Handle client connection"""
    global thread
    print('✓ Client connected')
    
    if not thread.is_alive():
        print("▶️  Starting packet capture thread...")
        thread = socketio.start_background_task(snif_and_detect)

@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    """Handle client disconnection"""
    print('✗ Client disconnected')

# =============================================================================
# Cleanup
# =============================================================================

def cleanup():
    """Cleanup resources on shutdown"""
    try:
        thread_stop_event.set()
        f.close()
        f2.close()
        print("✓ Cleanup completed")
    except Exception as e:
        print(f"❌ Cleanup error: {e}")

import atexit
atexit.register(cleanup)

# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == '__main__':
    print("="*60)
    print("🛡️  APT Detection System Starting...")
    print("="*60)
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
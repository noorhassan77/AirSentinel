#!/usr/bin/env python3
"""
Diagnostic mode - shows WHY each AP is flagged
Helps tune the detection threshold
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import sniff
import joblib
import numpy as np
from datetime import datetime
from collections import defaultdict
import pickle

class DiagnosticDetector:
    """Shows detailed scoring for debugging false positives"""
    
    def __init__(self, model_path, scaler_path):
        print("Loading model...")
        
        try:
            self.model = joblib.load(model_path)
        except:
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
        
        try:
            self.scaler = joblib.load(scaler_path)
        except:
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
        
        self.feature_names = [
            'rssi_mean', 'rssi_std', 'rssi_range', 'signal_stability',
            'time_since_first_seen', 'beacon_timing_irregularity',
            'ssid_bssid_count', 'channel_changes',
            'same_ssid_different_channels', 'encryption_numeric',
            'encryption_changed', 'locally_administered_mac',
            'vendor_is_common', 'vendor_mismatch', 'disappearance_count',
            'rssi_sudden_change_max', 'rssi_sudden_change_mean'
        ]
        
        self.ap_observations = defaultdict(list)
        self.ap_info = defaultdict(dict)
        self.ssid_bssid_map = defaultdict(set)
        self.checked = set()
        
        print(f"✓ Model loaded: {type(self.model).__name__}")
        print(f"✓ Features: {len(self.feature_names)}")
        print()
    
    def observe_packet(self, packet):
        from data_collection.capture import extract_ap_features
        
        try:
            pkt_features = extract_ap_features(packet)
        except:
            return
        
        if not pkt_features or 'bssid' not in pkt_features:
            return
        
        bssid = pkt_features['bssid']
        ssid = pkt_features.get('ssid', '')
        
        obs = {
            'rssi': pkt_features.get('rssi'),
            'vendor': pkt_features.get('vendor', 'Unknown'),
            'encryption': pkt_features.get('encryption_type', 'Unknown'),
            'locally_admin': pkt_features.get('locally_administered_mac', 0),
        }
        
        self.ap_observations[bssid].append(obs)
        self.ssid_bssid_map[ssid].add(bssid)
        
        if bssid not in self.ap_info:
            self.ap_info[bssid] = {
                'ssid': ssid,
                'first_seen': datetime.now(),
                'vendor': obs['vendor'],
            }
        
        # Analyze after 30 packets
        if len(self.ap_observations[bssid]) == 30 and bssid not in self.checked:
            self.analyze(bssid)
            self.checked.add(bssid)
    
    def analyze(self, bssid):
        """Detailed analysis"""
        
        obs = self.ap_observations[bssid]
        info = self.ap_info[bssid]
        ssid = info['ssid']
        
        # Extract RSSI
        rssi_vals = [o['rssi'] for o in obs if o.get('rssi')]
        
        if not rssi_vals:
            return
        
        rssi_mean = np.mean(rssi_vals)
        rssi_std = np.std(rssi_vals)
        
        # RSSI changes
        changes = [abs(rssi_vals[i] - rssi_vals[i-1]) for i in range(1, len(rssi_vals))]
        
        # Build feature vector
        features = {
            'rssi_mean': rssi_mean,
            'rssi_std': rssi_std,
            'rssi_range': max(rssi_vals) - min(rssi_vals),
            'signal_stability': 1 - (rssi_std / max(abs(rssi_mean), 1)),
            'time_since_first_seen': (datetime.now() - info['first_seen']).total_seconds(),
            'beacon_timing_irregularity': rssi_std * 50,
            'ssid_bssid_count': len(self.ssid_bssid_map[ssid]),
            'channel_changes': 0,
            'same_ssid_different_channels': 0,
            'encryption_numeric': 3,
            'encryption_changed': 0,
            'locally_administered_mac': obs[0]['locally_admin'],
            'vendor_is_common': int(obs[0]['vendor'] in ['Cisco', 'Aruba', 'Ubiquiti']),
            'vendor_mismatch': 0,
            'disappearance_count': 0,
            'rssi_sudden_change_max': max(changes) if changes else 0,
            'rssi_sudden_change_mean': np.mean(changes) if changes else 0,
        }
        
        # Predict
        X = np.array([features[f] for f in self.feature_names]).reshape(1, -1)
        X_scaled = self.scaler.transform(X)
        
        prediction = self.model.predict(X_scaled)[0]
        score = self.model.decision_function(X_scaled)[0]
        
        # Display
        print()
        print("="*70)
        print(f"AP: {ssid}")
        print(f"BSSID: {bssid}")
        print(f"Vendor: {obs[0]['vendor']}")
        print("="*70)
        print()
        
        print("Model Prediction:")
        print(f"  Prediction: {prediction} ({'ANOMALY' if prediction == -1 else 'NORMAL'})")
        print(f"  Score: {score:.4f}")
        print()
        
        print("Key Features:")
        print(f"  RSSI Mean:          {rssi_mean:.1f} dBm")
        print(f"  RSSI Std Dev:       {rssi_std:.2f}")
        print(f"  Signal Stability:   {features['signal_stability']:.3f}")
        print(f"  Software MAC:       {'YES ⚠️' if features['locally_administered_mac'] else 'No'}")
        print(f"  SSID-BSSID Count:   {features['ssid_bssid_count']}")
        print(f"  Vendor Common:      {'Yes' if features['vendor_is_common'] else 'No'}")
        print()
        
        print("Interpretation:")
        
        # Determine if this looks like a false positive
        is_likely_legit = (
            features['locally_administered_mac'] == 0 and  # Hardware MAC
            features['signal_stability'] > 0.85 and  # Very stable
            rssi_std < 5  # Low variance
        )
        
        is_likely_hotspot = (
            features['locally_administered_mac'] == 1 or  # Software MAC
            features['signal_stability'] < 0.7 or  # Unstable
            rssi_std > 10  # High variance
        )
        
        if prediction == -1:
            if is_likely_legit:
                print("  🟡 FALSE POSITIVE (likely legitimate infrastructure)")
                print(f"     Suggested threshold: < {score:.3f}")
            elif is_likely_hotspot:
                print("  ✅ TRUE POSITIVE (likely hotspot/threat)")
            else:
                print("  🟠 UNCERTAIN - Review manually")
        else:
            if is_likely_hotspot:
                print("  🔴 FALSE NEGATIVE (missed threat!)")
            else:
                print("  ✅ TRUE NEGATIVE (correctly classified as normal)")
        
        print()
        print(f"Recommendation for threshold:")
        if is_likely_legit and prediction == -1:
            print(f"  Use: --threshold {score - 0.1:.3f} (to avoid flagging this)")
        
        print("="*70)
    
    def start(self, interface, duration=60):
        print(f"Interface: {interface}")
        print(f"Duration: {duration}s")
        print()
        print("Collecting packets... Will analyze after 30 packets per AP")
        print()
        
        import time
        time.sleep(2)
        
        try:
            sniff(iface=interface, prn=self.observe_packet, timeout=duration, store=False)
        except KeyboardInterrupt:
            pass
        
        print()
        print("="*70)
        print(f"Analyzed {len(self.checked)} APs")
        print("="*70)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Diagnostic mode to tune threshold')
    parser.add_argument('--model', required=True)
    parser.add_argument('--scaler', required=True)
    parser.add_argument('--interface', default='wlan0mon')
    parser.add_argument('--duration', type=int, default=60)
    
    args = parser.parse_args()
    
    detector = DiagnosticDetector(args.model, args.scaler)
    detector.start(args.interface, args.duration)


if __name__ == "__main__":
    main()

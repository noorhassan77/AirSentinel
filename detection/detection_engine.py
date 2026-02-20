#!/usr/bin/env python3
"""
AirSentinel Detection Engine
Real-time evil twin detection with trained model
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import sniff
import joblib
import numpy as np
import json
import requests
from datetime import datetime
from collections import defaultdict
import argparse
from data_collection.channel_hopper import ChannelHopper
from utils.notifications import TelegramNotifier


class AirSentinelEngine:
    """
    Production evil twin detection engine
    Uses pre-trained model for real-time detection
    """
    
    def __init__(self, model_path, scaler_path=None, min_packets=10, alert_threshold=-0.3, telegram_token=None, telegram_chat_id=None):
        """
        Initialize detection engine
        
        Args:
            model_path: Path to trained model (.joblib)
            min_packets: Minimum packets before checking (default: 10)
            alert_threshold: Anomaly score threshold (default: -0.3)
        """
        print("="*70)
        print("🛡️  AirSentinel Detection Engine v1.0")
        print("="*70)
        print()
        
        # Load model
        print("[*] Loading trained model...")
        
        # Try loading - works with both .pkl and .joblib
        try:
            model_data = joblib.load(model_path)
        except:
            import pickle
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
        
        # Check if it's a dict (model + scaler together)
        if isinstance(model_data, dict):
            print("  → Dict format detected")
            self.model = model_data.get('model')
            self.scaler = model_data.get('scaler')
            
            # Get feature names
            if 'features' in model_data:
                self.feature_names = model_data['features']
            elif 'feature_names' in model_data:
                self.feature_names = model_data['feature_names']
            else:
                self.feature_names = None
        
        else:
            # Separate files
            print("  → Single model format detected")
            self.model = model_data
            
            self.scaler = None
            
            # Use provided scaler path or try to find it
            if scaler_path and os.path.exists(scaler_path):
                print(f"  → Loading provided scaler: {scaler_path}")
                try:
                    self.scaler = joblib.load(scaler_path)
                except:
                    import pickle
                    with open(scaler_path, 'rb') as f:
                        self.scaler = pickle.load(f)
            
            # If no scaler yet, try to auto-find
            if self.scaler is None:
                scaler_paths = [
                    model_path.replace('_model.joblib', '_scaler.joblib'),
                    model_path.replace('_model.pkl', '_scaler.pkl'),
                    model_path.replace('.joblib', '_scaler.joblib'),
                    model_path.replace('.pkl', '_scaler.pkl'),
                ]
                
                for spath in scaler_paths:
                    if os.path.exists(spath):
                        print(f"  → Found scaler: {spath}")
                        try:
                            self.scaler = joblib.load(spath)
                        except:
                            import pickle
                            with open(spath, 'rb') as f:
                                self.scaler = pickle.load(f)
                        break
            
            if self.scaler is None:
                print("  ⚠️  WARNING: No scaler found!")
                print("  ⚠️  Creating default scaler (may not work correctly)")
                from sklearn.preprocessing import StandardScaler
                self.scaler = StandardScaler()
                # This will fail on first use - need to fit it
            
            # Try to find features
            feature_paths = [
                model_path.replace('_model.joblib', '_features.json'),
                model_path.replace('_model.pkl', '_features.json'),
                model_path.replace('.joblib', '_features.json'),
                model_path.replace('.pkl', '_features.json'),
            ]
            
            self.feature_names = None
            for fpath in feature_paths:
                if os.path.exists(fpath):
                    try:
                        with open(fpath, 'r') as f:
                            self.feature_names = json.load(f)
                        break
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        # Not a JSON file, try pickle
                        try:
                            import pickle
                            with open(fpath, 'rb') as f:
                                self.feature_names = pickle.load(f)
                            break
                        except:
                            continue
        
        # Default features if not found
        if self.feature_names is None:
            print("  → Using default feature names (17 features)")
            self.feature_names = [
                'rssi_mean', 'rssi_std', 'rssi_range', 'signal_stability',
                'time_since_first_seen', 'beacon_timing_irregularity',
                'ssid_bssid_count', 'channel_changes',
                'same_ssid_different_channels', 'encryption_numeric',
                'encryption_changed', 'locally_administered_mac',
                'vendor_is_common', 'vendor_mismatch', 'disappearance_count',
                'rssi_sudden_change_max', 'rssi_sudden_change_mean'  # Added 2 more
            ]
        
        print(f"  ✓ Model loaded: {type(self.model).__name__}")
        print(f"  ✓ Features: {len(self.feature_names)}")
        print()
        
        # Configuration
        self.min_packets = min_packets
        self.alert_threshold = alert_threshold
        
        # Tracking
        self.ap_observations = defaultdict(list)
        self.ap_info = defaultdict(dict)
        self.ssid_bssid_map = defaultdict(set)
        self.checked_aps = set()
        self.alerts = []
        self.last_alert_time = {}
        
        # Stats
        self.total_packets = 0
        self.start_time = datetime.now()
        
        # Notifications
        self.notifier = TelegramNotifier(telegram_token, telegram_chat_id)
        self.IS_NOTIF_ON = False
        # Load Configuration
        config_path = 'data/config.json'
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as file:
                    config = json.load(file)
                    val = config.get("IS_NOTIF_ON", "False")
                    self.IS_NOTIF_ON = val.lower() == "true" if isinstance(val, str) else bool(val)
            except Exception as e:
                print(f"  [!] Error loading config.json: {e}")
        else:
            print(f"  [!] Config file not found at {config_path}, using defaults.")
        
        print("[*] Configuration:")
        print(f"  Min packets for detection: {min_packets}")
        print(f"  Alert threshold: {alert_threshold}")
        print(f"  Notfications: {self.IS_NOTIF_ON}")
        
        # Dashboard API
        self.dashboard_base_url = "http://localhost:5000/api"
        print(f"  Dashboard API: {self.dashboard_base_url}")
        print()
    
    def observe_packet(self, packet):
        """Process captured packet"""
        
        # Import here to avoid circular dependency
        from data_collection.capture import extract_ap_features
        
        self.total_packets += 1
        
        # Extract features
        try:
            packet_features = extract_ap_features(packet)
        except Exception as e:
            return
        
        if not packet_features or 'bssid' not in packet_features:
            return
        
        bssid = packet_features['bssid']
        ssid = packet_features.get('ssid', '')
        
        # Store observation
        observation = {
            'timestamp': datetime.now(),
            'rssi': packet_features.get('rssi'),
            'channel': packet_features.get('channel'),
            'vendor': packet_features.get('vendor', 'Unknown'),
            'encryption': packet_features.get('encryption_type', 'Unknown'),
            'locally_admin': packet_features.get('locally_administered_mac', 0),
        }
        
        self.ap_observations[bssid].append(observation)
        self.ssid_bssid_map[ssid].add(bssid)
        
        # Track AP info (first time)
        if bssid not in self.ap_info:
            self.ap_info[bssid] = {
                'ssid': ssid,
                'first_seen': datetime.now(),
                'vendor': packet_features.get('vendor', 'Unknown'),
                'encryption': packet_features.get('encryption_type', 'Unknown'),
            }
            # Report new network to dashboard
            self._report_network_to_dashboard(bssid, packet_features)
        
        # Check for threats
        if len(self.ap_observations[bssid]) >= self.min_packets:
            if bssid not in self.checked_aps:
                self.check_threat(bssid)
                self.checked_aps.add(bssid)
            elif len(self.ap_observations[bssid]) % 50 == 0:
                # Re-check every 50 packets
                self.check_threat(bssid)
    
    def check_threat(self, bssid):
        """
        Check if AP is a threat. 
        Modified to ONLY detect Evil Twins (SSID collisions) as per user request.
        """
        
        # Extract features
        features = self._extract_features(bssid)
        if not features:
            return
        
        ssid = features.get('ssid', 'Unknown')
        
        # 1. Gather Suspicion Factors (but don't set is_threat yet)
        feature_vector = [features.get(fname, 0) for fname in self.feature_names]
        X = np.array(feature_vector).reshape(1, -1)
        X_scaled = self.scaler.transform(X)
        
        prediction = self.model.predict(X_scaled)[0]
        score = self.model.decision_function(X_scaled)[0]
        
        is_suspicious = False
        reasons = []
        
        # Anomaly Score check
        if score < self.alert_threshold:
            is_suspicious = True
            reasons.append(f"Low anomaly score ({score:.3f} < {self.alert_threshold})")
            
        if prediction == -1 and score < self.alert_threshold:
            reasons.append(f"Anomalous behavior detected by model (score: {score:.3f})")
            
        # Software MAC check
        current_has_software_mac = features.get('locally_administered_mac', 0) == 1
        if current_has_software_mac:
            is_suspicious = True
            reasons.append("Software MAC detected (typical of hotspots/software APs)")
            
        # Signal Stability check (supplementary reason)
        stability = features.get('signal_stability', 1.0)
        if stability < 0.5:
            reasons.append(f"Highly unstable signal (stability: {stability:.2f})")
            
        # 2. Check for SSID collision (The "Evil Twin" condition)
        same_ssid_bssids = list(self.ssid_bssid_map[ssid])
        ssid_bssid_count = len(same_ssid_bssids)
        
        # GATEKEEPER: Only flag if there are multiple BSSIDs for this SSID
        if ssid_bssid_count <= 1:
            # We ignore standalone hotspots or anomalous APs as per instructions
            return
            
        # 3. Analyze the group of APs sharing this SSID
        is_threat = False
        threat_level = 'NONE'
        
        bssid_analysis = []
        for other_bssid in same_ssid_bssids:
            other_obs = self.ap_observations.get(other_bssid, [])
            if len(other_obs) < 3:
                continue
            
            other_info = {
                'bssid': other_bssid,
                'vendor': self.ap_info[other_bssid].get('vendor', 'Unknown'),
                'locally_admin': other_obs[0].get('locally_admin', 0),
                'first_seen': self.ap_info[other_bssid]['first_seen'],
                'is_current': other_bssid == bssid
            }
            bssid_analysis.append(other_info)
            
        if len(bssid_analysis) < 2:
            # Not enough data on peers yet
            return
            
        # Check for presence of an authentic (hardware) peer
        other_bssids = [b for b in bssid_analysis if not b['is_current']]
        has_authentic_peer = any(b['locally_admin'] == 0 for b in other_bssids)
        
        # MAIN RULE: Current AP is suspicious AND an authentic peer exists
        if is_suspicious and has_authentic_peer:
            is_threat = True
            threat_level = 'HIGH'
            reasons.insert(0, f"Evil Twin detected: Suspicious AP shadowing an authentic hardware AP ('{ssid}')")
                
        # CASE 3: Vendor Mismatch among hardware MACs (Secondary check)
        elif not current_has_software_mac:
            unique_vendors = set(b['vendor'] for b in bssid_analysis)
            if len(unique_vendors) > 1 and 'Unknown' in unique_vendors:
                current_vendor = features.get('vendor', 'Unknown')
                if current_vendor == 'Unknown':
                    is_threat = True
                    threat_level = 'HIGH'
                    reasons.append(f"Unknown AP vendor among known providers for SSID '{ssid}'")
                
        # CASE 4: Age difference check (only if already somewhat suspicious)
        if not is_threat and is_suspicious and len(bssid_analysis) > 1:
            sorted_by_age = sorted(bssid_analysis, key=lambda x: x['first_seen'])
            if sorted_by_age[-1]['bssid'] == bssid:
                age_diff = (sorted_by_age[-1]['first_seen'] - sorted_by_age[0]['first_seen']).total_seconds()
                if age_diff > 30:
                    # Only flag if there's at least one other AP that appeared much earlier
                    is_threat = True
                    threat_level = 'MEDIUM'
                    reasons.append(f"AP appeared significantly later ({age_diff:.0f}s) than others with same SSID")

        # FALSE POSITIVE MITIGATION (Enterprise WiFi)
        if is_threat and not current_has_software_mac:
            unique_vendors = set(b['vendor'] for b in bssid_analysis)
            if len(unique_vendors) == 1 and list(unique_vendors)[0] in ['Cisco', 'Aruba', 'Ubiquiti', 'Ruckus']:
                is_threat = False
                
        # Final Alert
        if is_threat:
            self.alert(bssid, ssid, threat_level, reasons, score, features)
        
    
    def alert(self, bssid, ssid, level, reasons, score, features):
        """Send alert"""
        
        # Rate limiting (max 1 alert per AP per minute)
        now = datetime.now()
        if bssid in self.last_alert_time:
            if (now - self.last_alert_time[bssid]).seconds < 60:
                return
        
        self.last_alert_time[bssid] = now
        
        # Create alert
        alert = {
            'timestamp': now,
            'bssid': bssid,
            'ssid': ssid,
            'level': level,
            'score': score,
            'reasons': reasons,
            'features': features
        }
        
        self.alerts.append(alert)
        
        # Display alert
        emoji = {'HIGH': '🚨', 'MEDIUM': '⚠️', 'LOW': '🟡'}
        
        print()
        print("="*70)
        print(f"{emoji.get(level, '⚠️')} THREAT DETECTED - {level} PRIORITY")
        print("="*70)
        print(f"Time:   {now.strftime('%H:%M:%S')}")
        print(f"SSID:   {ssid}")
        print(f"BSSID:  {bssid}")
        print(f"Vendor: {features.get('vendor', 'Unknown')}")
        print(f"Score:  {score:.3f}")
        print()
        print("Reasons:")
        for i, reason in enumerate(reasons, 1):
            print(f"  {i}. {reason}")
        print()
        print("Details:")
        print(f"  Signal Stability: {features.get('signal_stability', 0):.2f}")
        print(f"  RSSI Std Dev:     {features.get('rssi_std', 0):.1f} dBm")
        print(f"  Software MAC:     {'Yes ⚠️' if features.get('locally_administered_mac') else 'No'}")
        
        if level == 'HIGH':
            print()
            print("⚠️  RECOMMENDED ACTION:")
            print("  → DO NOT CONNECT to this network")
            print("  → Investigate immediately")
            print("  → Possible evil twin attack")
        
        print("="*70)
        print()
        
        # Log to file
        self._log_alert(alert)
        if self.IS_NOTIF_ON:
            self.notifier.send_alert(alert)
            
        # Send to Dashboard
        self._report_to_dashboard(alert)
    
    def _report_network_to_dashboard(self, bssid, packet_features):
        """Send discovered network info to dashboard"""
        try:
            payload = {
                'ssid': packet_features.get('ssid', 'Unknown') or 'Unknown',
                'mac': bssid,
                'status': 'Monitored',
                'signal': int(packet_features.get('rssi', -100)) if packet_features.get('rssi') else -100,
                'channel': int(packet_features.get('channel', 1)),
                'vendor': packet_features.get('vendor', 'Unknown')
            }
            requests.post(f"{self.dashboard_base_url}/networks", json=payload, timeout=1)
        except:
            pass

    def _report_to_dashboard(self, alert):
        """Send threat to dashboard API"""
        try:
            payload = {
                'ssid': alert['ssid'],
                'mac': alert['bssid'],
                'legitimateMac': 'Unknown',  # Default if not available
                'signal': int(alert['features'].get('rssi_mean', 0)),
                'channel': int(alert['features'].get('channel', 1)),
                'encryption': alert['features'].get('encryption', 'Open'),
                'severity': alert['level'].capitalize(),
                'clientCount': 0  # Default or extract from features if available
            }
            
            requests.post(f"{self.dashboard_base_url}/threats", json=payload, timeout=2)
        except Exception as e:
            pass
    
    def _extract_features(self, bssid):
        """Extract features for a BSSID"""
        
        observations = self.ap_observations.get(bssid, [])
        
        if len(observations) < 3:
            return None
        
        # Extract RSSI values
        rssi_values = [obs['rssi'] for obs in observations if obs.get('rssi')]
        
        if not rssi_values:
            return None
        
        rssi_mean = np.mean(rssi_values)
        rssi_std = np.std(rssi_values)
        rssi_min = np.min(rssi_values)
        rssi_max = np.max(rssi_values)
        
        # Calculate RSSI sudden changes (for the 2 missing features)
        rssi_changes = []
        for i in range(1, len(rssi_values)):
            change = abs(rssi_values[i] - rssi_values[i-1])
            rssi_changes.append(change)
        
        rssi_sudden_change_max = max(rssi_changes) if rssi_changes else 0
        rssi_sudden_change_mean = np.mean(rssi_changes) if rssi_changes else 0
        
        # Calculate features
        ssid = self.ap_info[bssid]['ssid']
        
        features = {
            'rssi_mean': rssi_mean,
            'rssi_std': rssi_std,
            'rssi_range': rssi_max - rssi_min,
            'signal_stability': 1 - (rssi_std / max(abs(rssi_mean), 1)),
            'time_since_first_seen': (datetime.now() - self.ap_info[bssid]['first_seen']).total_seconds(),
            'beacon_timing_irregularity': rssi_std * 50,
            'ssid_bssid_count': len(self.ssid_bssid_map[ssid]),
            'channel_changes': 0,
            'same_ssid_different_channels': 0,
            'encryption_numeric': self._encode_encryption(observations[0]['encryption']),
            'encryption_changed': 0,
            'locally_administered_mac': observations[0]['locally_admin'],
            'vendor_is_common': int(observations[0]['vendor'] in ['Cisco', 'Aruba', 'Ubiquiti', 'Ruckus']),
            'vendor_mismatch': 0,
            'disappearance_count': 0,
            'rssi_sudden_change_max': rssi_sudden_change_max,  # Feature 16
            'rssi_sudden_change_mean': rssi_sudden_change_mean,  # Feature 17
            # Extra (not in model)
            'ssid': ssid,
            'vendor': observations[0]['vendor'],
        }
        
        return features
    
    def _encode_encryption(self, enc_type):
        """Encode encryption as number"""
        mapping = {
            'Open': 0,
            'WEP': 1,
            'WPA': 2,
            'WPA2': 3,
            'WPA3': 3,
        }
        return mapping.get(enc_type, 0)
    
    def _log_alert(self, alert):
        """Log alert to file"""
        alert_copy = alert.copy()
        alert_copy['timestamp'] = alert['timestamp'].isoformat()
        
        # Exclude features from the JSON output as requested
        if 'features' in alert_copy:
            del alert_copy['features']
            
        # Ensure data directory exists
        os.makedirs('data', exist_ok=True)
        log_file = "data/alerts.json"
        
        try:
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    logs = json.load(f)
            else:
                logs = []
            
            logs.append(alert_copy)
            
            with open(log_file, 'w') as f:
                json.dump(logs, f, indent=2)
        except Exception as e:
            print(f"Error logging alert: {e}")
    
    def print_status(self):
        """Print current status"""
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        print(f"\r[Status] Packets: {self.total_packets} | "
              f"APs: {len(self.ap_observations)} | "
              f"Alerts: {len(self.alerts)} | "
              f"Time: {elapsed:.0f}s", end='', flush=True)
    
    def print_summary(self):
        """Print session summary"""
        
        print("\n")
        print("="*70)
        print("SESSION SUMMARY")
        print("="*70)
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        print(f"Duration:       {elapsed:.0f}s ({elapsed/60:.1f} min)")
        print(f"Packets:        {self.total_packets}")
        print(f"APs observed:   {len(self.ap_observations)}")
        print(f"Threats found:  {len(self.alerts)}")
        print()
        
        if self.alerts:
            print("Threat Summary:")
            high = sum(1 for a in self.alerts if a['level'] == 'HIGH')
            medium = sum(1 for a in self.alerts if a['level'] == 'MEDIUM')
            low = sum(1 for a in self.alerts if a['level'] == 'LOW')
            
            print(f"  HIGH:   {high}")
            print(f"  MEDIUM: {medium}")
            print(f"  LOW:    {low}")
            print()
            
            print("Recent Threats:")
            for alert in self.alerts[-5:]:
                time_str = alert['timestamp'].strftime('%H:%M:%S')
                print(f"  [{time_str}] {alert['level']:6s} - {alert['ssid']}")
        
        print("="*70)
    
    def start(self, interface='wlan0mon', duration=None,
          channels=None, dwell_time=1.0):

        print(f"Interface: {interface}")

        if channels:
            print(f"Channel hopping enabled: {channels}")
            hopper = ChannelHopper(interface, channels, dwell_time)
            hopper.start()
        else:
            hopper = None

        print()
        print("Starting detection...")
        print()

        try:
            packet_count = [0]

            def packet_handler(pkt):
                # Optional: tag packet with current channel
                if hopper:
                    pkt.current_channel = hopper.get_current_channel()

                self.observe_packet(pkt)

                packet_count[0] += 1
                if packet_count[0] % 100 == 0:
                    self.print_status()

            if duration:
                sniff(iface=interface,
                    prn=packet_handler,
                    timeout=duration,
                    store=False)
            else:
                sniff(iface=interface,
                    prn=packet_handler,
                    store=False)

        except KeyboardInterrupt:
            print("\nStopping detection...")

        finally:
            if hopper:
                hopper.stop()

        self.print_summary()

def main():
    parser = argparse.ArgumentParser(
        description='AirSentinel Detection Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage
  sudo python3 detection_engine.py --model models/trained_model.joblib
  
  # Custom interface
  sudo python3 detection_engine.py --model models/trained_model.joblib --interface mon1
  
  # Run for 30 minutes
  sudo python3 detection_engine.py --model models/trained_model.joblib --duration 1800
  
  # Adjust sensitivity
  sudo python3 detection_engine.py --model models/trained_model.joblib --threshold -0.5
        """
    )
    
    parser.add_argument('--model', required=True,
                        help='Path to trained model (.pkl or .joblib)')
    parser.add_argument('--scaler',
                        help='Path to scaler (.pkl or .joblib) - auto-detected if not provided')
    parser.add_argument('--interface', default='wlan0mon',
                        help='Monitor mode interface (default: wlan0mon)')
    parser.add_argument('--duration', type=int,
                        help='Detection duration in seconds (default: continuous)')
    parser.add_argument('--min-packets', type=int, default=10,
                        help='Minimum packets before checking (default: 10)')
    parser.add_argument('--threshold', type=float, default=-0.3,
                        help='Alert threshold (default: -0.3, lower=more sensitive)')
    parser.add_argument('--channels',
                        help='Comma separated channel list (e.g. 1,6,11)')
    parser.add_argument('--dwell-time', type=float, default=1.0,
                        help='Seconds to stay on each channel (default: 1.0)')
    
    args = parser.parse_args()
    
    # Check root
    if os.geteuid() != 0:
        print("[!] Must run as root: sudo python3 detection_engine.py ...")
        sys.exit(1)
    
    # Start engine
    engine = AirSentinelEngine(
        model_path=args.model,
        scaler_path=args.scaler,
        min_packets=args.min_packets,
        alert_threshold=args.threshold
    )
    
    engine.start(
        interface=args.interface, 
        duration=args.duration,
        channels=args.channels,
        dwell_time=args.dwell_time
    )


if __name__ == "__main__":
    main()

"""
Feature Extractor
Converts raw events into numerical feature vectors for ML
"""

class FeatureExtractor:
    def __init__(self):
        pass
    
    def extract(self, event):
        """
        Extract numerical features from event
        
        Returns:
            List of 10 numerical features
        """
        features = [
            self._normalize_port(event.get('source_port', 0)),      # 0: Source port (normalized)
            self._normalize_port(event.get('dest_port', 0)),        # 1: Dest port (normalized)
            self._normalize_bytes(event.get('bytes', 0)),           # 2: Bytes transferred
            self._normalize_packets(event.get('packets', 0)),       # 3: Packet count
            self._protocol_to_numeric(event.get('protocol', '')),   # 4: Protocol
            self._action_to_numeric(event.get('action', '')),       # 5: Action type
            self._ip_diversity(event.get('source_ip', '')),         # 6: Source IP diversity
            self._ip_diversity(event.get('dest_ip', '')),           # 7: Dest IP diversity
            self._time_based_feature(event.get('timestamp', '')),   # 8: Time-based
            self._payload_size_ratio(event)                         # 9: Payload characteristics
        ]
        
        return features
    
    def _normalize_port(self, port):
        """Normalize port number to 0-1 range"""
        return min(1.0, port / 65535.0)
    
    def _normalize_bytes(self, bytes_val):
        """Normalize byte count (log scale)"""
        if bytes_val <= 0:
            return 0
        # Use log scale for large values
        import math
        return min(1.0, math.log10(bytes_val + 1) / 10.0)
    
    def _normalize_packets(self, packets):
        """Normalize packet count"""
        if packets <= 0:
            return 0
        import math
        return min(1.0, math.log10(packets + 1) / 5.0)
    
    def _protocol_to_numeric(self, protocol):
        """Convert protocol to numeric value"""
        protocol_map = {
            'tcp': 0.3,
            'udp': 0.6,
            'icmp': 0.9,
            'http': 0.2,
            'https': 0.25,
            'ssh': 0.4,
            'ftp': 0.5
        }
        return protocol_map.get(protocol.lower(), 0.0)
    
    def _action_to_numeric(self, action):
        """Convert action to numeric value"""
        action_map = {
            'allow': 0.1,
            'deny': 0.9,
            'drop': 0.95,
            'reject': 0.85,
            'accept': 0.2,
            'fail': 0.8,
            'success': 0.15
        }
        
        action_lower = action.lower()
        for key, value in action_map.items():
            if key in action_lower:
                return value
        
        return 0.5  # neutral
    
    def _ip_diversity(self, ip):
        """
        Measure IP diversity/unusualness
        Simple hash-based approach
        """
        if not ip or ip == 'unknown':
            return 0.5
        
        # Use last octet for diversity measure
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                last_octet = int(parts[-1])
                return last_octet / 255.0
        except:
            pass
        
        return 0.5
    
    def _time_based_feature(self, timestamp):
        """
        Extract time-based feature (hour of day)
        Normalized 0-1
        """
        try:
            from datetime import datetime
            if timestamp:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                hour = dt.hour
                return hour / 24.0
        except:
            pass
        
        return 0.5
    
    def _payload_size_ratio(self, event):
        """
        Calculate payload size characteristics
        """
        bytes_val = event.get('bytes', 0)
        packets = event.get('packets', 1)
        
        if packets <= 0:
            return 0.5
        
        # Average bytes per packet
        avg_size = bytes_val / packets
        
        # Normalize (typical packet size ~1500 bytes)
        return min(1.0, avg_size / 1500.0)

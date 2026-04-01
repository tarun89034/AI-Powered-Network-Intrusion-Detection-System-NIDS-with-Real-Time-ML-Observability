"""
Storage Module
Handles lightweight database (SQLite) operations to store network flows and alerts.
"""

import os
import json
import sqlite3
import threading
from typing import Any, Dict, List, Optional

class FlowDatabase:
    def __init__(self, db_path: Optional[str] = "nids_engine/storage/nids.db"):
        self.db_path = db_path or "nids_engine/storage/nids.db"
        self._lock = threading.Lock()
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initializes the SQLite database schemas."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Flows table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    start_time REAL,
                    end_time REAL,
                    is_anomaly INTEGER,
                    attack_type TEXT,
                    features JSON
                )
            ''')
            
            # Alerts table for quick dashboard querying
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    attack_type TEXT,
                    severity TEXT
                )
            ''')
            
            conn.commit()
            conn.close()

    def insert_flow(self, flow_data: Dict[str, Any], is_anomaly: bool, attack_type: str):
        """Inserts a completed flow and optionally triggers an alert."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO flows (flow_id, src_ip, dst_ip, src_port, dst_port, protocol, start_time, end_time, is_anomaly, attack_type, features)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                flow_data['flow_id'], flow_data['src_ip'], flow_data['dst_ip'],
                flow_data['src_port'], flow_data['dst_port'], flow_data['protocol'],
                flow_data['start_time'], flow_data['end_time'],
                1 if is_anomaly else 0, attack_type,
                json.dumps(flow_data['features'])
            ))
            
            if is_anomaly:
                cursor.execute('''
                    INSERT INTO alerts (timestamp, src_ip, dst_ip, attack_type, severity)
                    VALUES (?, ?, ?, ?, ?)
                ''', (flow_data['end_time'], flow_data['src_ip'], flow_data['dst_ip'], attack_type, "HIGH"))
                
            conn.commit()
            conn.close()

    def get_recent_flows(self, limit: int = 100) -> List[Dict]:
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM flows ORDER BY end_time DESC LIMIT ?', (limit,))
            rows = [dict(row) for row in cursor.fetchall()]
            for row in rows:
                if row.get("features"):
                    try:
                        row["features"] = json.loads(row["features"])
                    except json.JSONDecodeError:
                        row["features"] = {}
            conn.close()
            return rows

    def get_alerts(self, limit: int = 50) -> List[Dict]:
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?', (limit,))
            rows = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return rows
            
    def get_stats(self) -> Dict:
        """Returns aggregate stats for the dashboard."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM flows")
            total_flows = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = cursor.fetchone()[0]
            
            cursor.execute("SELECT protocol, COUNT(*) FROM flows GROUP BY protocol")
            protocols = {row[0]: row[1] for row in cursor.fetchall()}

            cursor.execute("SELECT src_ip, COUNT(*) AS c FROM flows GROUP BY src_ip ORDER BY c DESC LIMIT 5")
            top_source_ips = [{"ip": row[0], "count": row[1]} for row in cursor.fetchall()]

            cursor.execute("SELECT dst_ip, COUNT(*) AS c FROM flows GROUP BY dst_ip ORDER BY c DESC LIMIT 5")
            top_destination_ips = [{"ip": row[0], "count": row[1]} for row in cursor.fetchall()]
            
            conn.close()
            
            return {
                "total_flows": total_flows,
                "total_alerts": total_alerts,
                "protocol_distribution": protocols,
                "top_source_ips": top_source_ips,
                "top_destination_ips": top_destination_ips,
            }

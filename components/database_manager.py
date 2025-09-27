"""
Database Manager for PhishPrint
Handles PostgreSQL database operations for emails, analysis, and threat intelligence
"""

import os
import psycopg2
import psycopg2.extras
import json
import hashlib
import pickle
from datetime import datetime, date
from typing import Dict, List, Any, Optional, Tuple
from contextlib import contextmanager

class DatabaseManager:
    """Manages PostgreSQL database operations for PhishPrint"""
    
    def __init__(self):
        """Initialize database manager with connection parameters"""
        self.database_url = os.getenv('DATABASE_URL')
        if not self.database_url:
            raise ValueError("DATABASE_URL environment variable not found")
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = None
        try:
            conn = psycopg2.connect(self.database_url)
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            raise e
        finally:
            if conn:
                conn.close()
    
    def store_email(self, email_data: Dict[str, Any]) -> str:
        """Store email in database and return email_hash"""
        # Create unique hash for email
        email_content = f"{email_data['from']}{email_data['subject']}{email_data['body']}"
        email_hash = hashlib.sha256(email_content.encode()).hexdigest()
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Insert or update email
            cursor.execute("""
                INSERT INTO emails (email_hash, sender, subject, body, timestamp, user_id)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (email_hash) DO NOTHING
            """, (
                email_hash,
                email_data['from'],
                email_data['subject'],
                email_data['body'],
                email_data.get('timestamp', datetime.now()),
                email_data.get('user_id', 'default_user')
            ))
            
            conn.commit()
        
        return email_hash
    
    def store_analysis_result(self, email_hash: str, analysis: Dict[str, Any]):
        """Store security analysis results"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO analysis_results (
                    email_hash, total_score, risk_level, risk_color,
                    heuristic_score, code_injection_score, ml_anomaly_score, api_analysis_score,
                    flags, breach_info
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (email_hash) DO UPDATE SET
                    total_score = EXCLUDED.total_score,
                    risk_level = EXCLUDED.risk_level,
                    risk_color = EXCLUDED.risk_color,
                    heuristic_score = EXCLUDED.heuristic_score,
                    code_injection_score = EXCLUDED.code_injection_score,
                    ml_anomaly_score = EXCLUDED.ml_anomaly_score,
                    api_analysis_score = EXCLUDED.api_analysis_score,
                    flags = EXCLUDED.flags,
                    breach_info = EXCLUDED.breach_info,
                    analyzed_at = CURRENT_TIMESTAMP
            """, (
                email_hash,
                analysis['total_score'],
                analysis['risk_level'],
                analysis['color'],
                analysis['components'].get('heuristic', 0),
                analysis['components'].get('code_injection', 0),
                analysis['components'].get('ml_anomaly', 0),
                analysis['components'].get('api_analysis', 0),
                json.dumps(analysis['flags']),
                json.dumps(analysis['breach_info'])
            ))
            
            conn.commit()
    
    def get_user_emails(self, user_id: str = 'default_user', limit: int = 50) -> List[Dict[str, Any]]:
        """Get user's emails with analysis results"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            cursor.execute("""
                SELECT 
                    e.email_hash, e.sender, e.subject, e.body, e.timestamp,
                    ar.total_score, ar.risk_level, ar.risk_color, ar.flags, ar.breach_info,
                    ar.heuristic_score, ar.code_injection_score, ar.ml_anomaly_score, ar.api_analysis_score
                FROM emails e
                LEFT JOIN analysis_results ar ON e.email_hash = ar.email_hash
                WHERE e.user_id = %s
                ORDER BY e.timestamp DESC
                LIMIT %s
            """, (user_id, limit))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def store_user_baseline(self, user_id: str, baseline_data: Dict[str, Any], ml_model_data: Optional[bytes] = None):
        """Store or update user's ML baseline data"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO user_baselines (
                    user_id, total_emails, avg_length, std_length, common_hour,
                    common_senders, avg_response_time, typical_subject_length, ml_model_data
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (user_id) DO UPDATE SET
                    total_emails = EXCLUDED.total_emails,
                    avg_length = EXCLUDED.avg_length,
                    std_length = EXCLUDED.std_length,
                    common_hour = EXCLUDED.common_hour,
                    common_senders = EXCLUDED.common_senders,
                    avg_response_time = EXCLUDED.avg_response_time,
                    typical_subject_length = EXCLUDED.typical_subject_length,
                    ml_model_data = EXCLUDED.ml_model_data,
                    updated_at = CURRENT_TIMESTAMP
            """, (
                user_id,
                baseline_data['total_emails'],
                baseline_data['avg_length'],
                baseline_data['std_length'],
                baseline_data['common_hour'],
                json.dumps(baseline_data['common_senders']),
                baseline_data['avg_response_time'],
                baseline_data['typical_subject_length'],
                ml_model_data if ml_model_data is not None else b''
            ))
            
            conn.commit()
    
    def get_user_baseline(self, user_id: str = 'default_user') -> Optional[Dict[str, Any]]:
        """Get user's baseline data"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            cursor.execute("""
                SELECT * FROM user_baselines WHERE user_id = %s
            """, (user_id,))
            
            result = cursor.fetchone()
            if result:
                result_dict = dict(result)
                # Parse JSON fields
                result_dict['common_senders'] = json.loads(result_dict['common_senders'])
                return result_dict
            return None
    
    def add_threat_intelligence(self, threat_data: Dict[str, Any], shared_by: str = 'system'):
        """Add threat intelligence data"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO threat_intelligence (
                    threat_type, indicator_value, indicator_type, severity,
                    description, shared_by
                ) VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                threat_data['threat_type'],
                threat_data['indicator_value'],
                threat_data['indicator_type'],
                threat_data['severity'],
                threat_data.get('description', ''),
                shared_by
            ))
            
            conn.commit()
    
    def get_threat_intelligence(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get active threat intelligence"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            cursor.execute("""
                SELECT * FROM threat_intelligence 
                WHERE is_active = TRUE
                ORDER BY created_at DESC
                LIMIT %s
            """, (limit,))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def generate_security_report(self, user_id: str, start_date: date, end_date: date, 
                                report_type: str = 'custom') -> Dict[str, Any]:
        """Generate security report for date range"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            # Get email statistics
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_emails,
                    SUM(CASE WHEN ar.risk_level = 'HIGH RISK' THEN 1 ELSE 0 END) as high_risk,
                    SUM(CASE WHEN ar.risk_level = 'MEDIUM RISK' THEN 1 ELSE 0 END) as medium_risk,
                    SUM(CASE WHEN ar.risk_level = 'LOW RISK' THEN 1 ELSE 0 END) as low_risk,
                    AVG(ar.total_score) as avg_risk_score
                FROM emails e
                LEFT JOIN analysis_results ar ON e.email_hash = ar.email_hash
                WHERE e.user_id = %s 
                AND e.timestamp::date BETWEEN %s AND %s
            """, (user_id, start_date, end_date))
            
            result = cursor.fetchone()
            stats = dict(result) if result else {'total_emails': 0, 'high_risk': 0, 'medium_risk': 0, 'low_risk': 0, 'avg_risk_score': 0}
            
            # Get top threats
            cursor.execute("""
                SELECT ar.flags, COUNT(*) as count
                FROM emails e
                JOIN analysis_results ar ON e.email_hash = ar.email_hash
                WHERE e.user_id = %s 
                AND e.timestamp::date BETWEEN %s AND %s
                AND ar.total_score > 40
                GROUP BY ar.flags
                ORDER BY count DESC
                LIMIT 10
            """, (user_id, start_date, end_date))
            
            top_threats = [dict(row) for row in cursor.fetchall()]
            
            report_data = {
                'total_emails': stats['total_emails'] or 0,
                'high_risk_emails': stats['high_risk'] or 0,
                'medium_risk_emails': stats['medium_risk'] or 0,
                'low_risk_emails': stats['low_risk'] or 0,
                'avg_risk_score': float(stats['avg_risk_score'] or 0),
                'top_threats': top_threats,
                'date_range': f"{start_date} to {end_date}"
            }
            
            # Store report
            cursor.execute("""
                INSERT INTO security_reports (
                    user_id, report_type, start_date, end_date,
                    total_emails, high_risk_emails, medium_risk_emails, low_risk_emails,
                    top_threats, report_data
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                user_id, report_type, start_date, end_date,
                report_data['total_emails'], report_data['high_risk_emails'],
                report_data['medium_risk_emails'], report_data['low_risk_emails'],
                json.dumps(top_threats), json.dumps(report_data)
            ))
            
            result = cursor.fetchone()
            report_id = result[0] if result else None
            conn.commit()
            
            report_data['report_id'] = report_id
            return report_data
    
    def get_threat_trends(self, user_id: str, days: int = 30) -> Dict[str, Any]:
        """Get threat trends for visualization"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            cursor.execute("""
                SELECT 
                    DATE(e.timestamp) as date,
                    COUNT(*) as total_emails,
                    AVG(ar.total_score) as avg_score,
                    SUM(CASE WHEN ar.total_score >= 70 THEN 1 ELSE 0 END) as high_risk_count
                FROM emails e
                LEFT JOIN analysis_results ar ON e.email_hash = ar.email_hash
                WHERE e.user_id = %s 
                AND e.timestamp >= CURRENT_DATE - make_interval(days => %s)
                GROUP BY DATE(e.timestamp)
                ORDER BY date
            """, (user_id, days))
            
            trends = [dict(row) for row in cursor.fetchall()]
            
            return {
                'daily_trends': trends,
                'total_days': days,
                'avg_daily_emails': sum(t['total_emails'] for t in trends) / max(len(trends), 1)
            }
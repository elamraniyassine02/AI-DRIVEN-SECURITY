#!/usr/bin/env python3
"""
Notification system for the AI-Driven Security Solution.
"""
import argparse
import json
import logging
import os
import sys
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/notifications.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def send_email(config, subject, body, recipients=None):
    """Send an email notification."""
    if not config.get('enabled', False):
        logger.info("Email notifications are disabled")
        return False
        
    smtp_config = config.get('smtp', {})
    sender = smtp_config.get('sender')
    
    if not sender:
        logger.error("No sender email configured")
        return False
        
    # Use specified recipients or default recipients
    if recipients is None:
        recipients = config.get('recipients', [])
        
    if not recipients:
        logger.error("No recipients specified")
        return False
        
    try:
        # Create a multipart message
        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = ', '.join(recipients)
        msg['Subject'] = subject
        
        # Add body to email
        msg.attach(MIMEText(body, 'plain'))
        
        # Connect to SMTP server
        server = smtplib.SMTP(smtp_config.get('server'), smtp_config.get('port', 587))
        server.ehlo()
        
        # Use TLS if specified
        if smtp_config.get('use_tls', True):
            server.starttls()
            server.ehlo()
            
        # Login if credentials provided
        if smtp_config.get('username') and smtp_config.get('password'):
            server.login(smtp_config.get('username'), smtp_config.get('password'))
            
        # Send email
        server.sendmail(sender, recipients, msg.as_string())
        server.quit()
        
        logger.info(f"Email sent to {len(recipients)} recipients: {subject}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending email: {e}")
        return False

def send_slack_notification(config, message):
    """Send a Slack notification."""
    if not config.get('enabled', False):
        logger.info("Slack notifications are disabled")
        return False
        
    webhook_url = config.get('webhook_url')
    if not webhook_url:
        logger.error("No Slack webhook URL configured")
        return False
        
    try:
        import requests
        
        payload = {
            "text": message,
            "username": config.get('username', 'Security Solution'),
            "icon_emoji": config.get('icon_emoji', ':lock:')
        }
        
        response = requests.post(webhook_url, json=payload)
        
        if response.status_code == 200:
            logger.info("Slack notification sent successfully")
            return True
        else:
            logger.error(f"Error sending Slack notification: {response.status_code} {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Error sending Slack notification: {e}")
        return False

def generate_alert_for_anomalies(config, anomalies, threshold=3):
    """Generate an alert for anomalies."""
    if not anomalies or len(anomalies) < threshold:
        logger.info(f"Not enough anomalies to trigger an alert (found {len(anomalies) if anomalies else 0}, threshold {threshold})")
        return False
        
    subject = f"ALERT: {len(anomalies)} security anomalies detected"
    
    body = f"""
Security Alert: Anomalies Detected

The AI-Driven Security Solution has detected {len(anomalies)} anomalies in the last monitoring period.

Top 5 Anomalies:
"""
    
    # Add details for the top 5 anomalies
    for i, anomaly in enumerate(anomalies[:5]):
        body += f"\n{i+1}. Host: {anomaly.get('host', 'unknown')}"
        body += f"\n   Score: {anomaly.get('score', 0):.2f}"
        body += f"\n   Timestamp: {anomaly.get('timestamp', '')}"
        body += f"\n   Details: {anomaly.get('details', {})}"
        body += "\n"
        
    body += f"""
Full details are available in the security dashboard: http://{config.get('server_host', 'localhost')}:{config.get('server_port', '5601')}

This is an automated message from the AI-Driven Security Solution.
"""
    
    # Send email notification
    email_result = send_email(config.get('email', {}), subject, body)
    
    # Send Slack notification
    slack_result = send_slack_notification(config.get('slack', {}), f"{subject}\n\n{len(anomalies)} anomalies detected. Check the security dashboard for details.")
    
    return email_result or slack_result

def generate_alert_for_vulnerabilities(config, vulnerabilities, severity_threshold='medium'):
    """Generate an alert for vulnerabilities."""
    # Filter vulnerabilities by severity
    severe_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() >= severity_threshold.lower()]
    
    if not severe_vulns:
        logger.info(f"No vulnerabilities with severity >= {severity_threshold}")
        return False
        
    subject = f"ALERT: {len(severe_vulns)} {severity_threshold}+ severity vulnerabilities detected"
    
    body = f"""
Security Alert: Vulnerabilities Detected

The AI-Driven Security Solution has detected {len(severe_vulns)} vulnerabilities with severity >= {severity_threshold}.

Top 5 Vulnerabilities:
"""
    
    # Add details for the top 5 vulnerabilities
    for i, vuln in enumerate(severe_vulns[:5]):
        body += f"\n{i+1}. Host: {vuln.get('host', 'unknown')}"
        body += f"\n   Service: {vuln.get('service', 'unknown')} on port {vuln.get('port', 'unknown')}"
        body += f"\n   Severity: {vuln.get('severity', 'unknown')}"
        body += f"\n   Description: {vuln.get('description', '')}"
        body += "\n"
        
    body += f"""
Full details are available in the security dashboard: http://{config.get('server_host', 'localhost')}:{config.get('server_port', '5601')}

This is an automated message from the AI-Driven Security Solution.
"""
    
    # Send email notification
    email_result = send_email(config.get('email', {}), subject, body)
    
    # Send Slack notification
    slack_result = send_slack_notification(config.get('slack', {}), f"{subject}\n\nCheck the security dashboard for details.")
    
    return email_result or slack_result

def test_notification_system(config_path):
    """Test the notification system."""
    try:
        # Load configuration
        with open(config_path) as f:
            config = json.load(f)
            
        # Test email notification
        email_subject = "Test: Security Solution Notification System"
        email_body = f"""
This is a test email from the AI-Driven Security Solution notification system.

Timestamp: {datetime.now().isoformat()}

If you received this email, the notification system is working correctly.
"""
        
        email_result = send_email(config.get('email', {}), email_subject, email_body)
        
        # Test Slack notification
        slack_message = f"Test: Security Solution Notification System\n\nTimestamp: {datetime.now().isoformat()}"
        slack_result = send_slack_notification(config.get('slack', {}), slack_message)
        
        if email_result or slack_result:
            logger.info("Notification system test completed successfully")
        else:
            logger.error("Notification system test failed: no notifications were sent")
            
    except Exception as e:
        logger.error(f"Error testing notification system: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Notification System")
    parser.add_argument("--config", type=str, default="config/notification_config.json",
                      help="Path to the configuration file")
    parser.add_argument("--test", action="store_true",
                      help="Test the notification system")
                      
    args = parser.parse_args()
    
    if args.test:
        test_notification_system(args.config)
    else:
        logger.info("Use the --test flag to test the notification system")
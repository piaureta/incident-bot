import os
import json
import logging
import hashlib
import hmac
from datetime import datetime
from flask import Flask, request, jsonify
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import requests
from functools import wraps

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Environment variables
SLACK_BOT_TOKEN = os.environ.get('SLACK_BOT_TOKEN')
SLACK_SIGNING_SECRET = os.environ.get('SLACK_SIGNING_SECRET')
PAGERDUTY_ROUTING_KEY = os.environ.get('PAGERDUTY_ROUTING_KEY')
AUTHORIZED_USERS = set(os.environ.get('AUTHORIZED_USERS', '').split(','))

slack_client = WebClient(token=SLACK_BOT_TOKEN)

def verify_slack_signature(func):
    """Verify Slack request signature for security"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        timestamp = request.headers.get('X-Slack-Request-Timestamp')
        signature = request.headers.get('X-Slack-Signature')
        
        if not timestamp or not signature:
            logger.warning("Missing Slack signature headers")
            return jsonify({'error': 'Unauthorized'}), 401
        
        # Prevent replay attacks (5 minutes tolerance)
        if abs(datetime.now().timestamp() - int(timestamp)) > 300:
            logger.warning("Request timestamp too old")
            return jsonify({'error': 'Request too old'}), 401
        
        # Verify signature
        sig_basestring = f"v0:{timestamp}:{request.get_data().decode()}"
        expected_signature = 'v0=' + hmac.new(
            SLACK_SIGNING_SECRET.encode(),
            sig_basestring.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            logger.warning("Invalid Slack signature")
            return jsonify({'error': 'Invalid signature'}), 401
        
        return func(*args, **kwargs)
    return wrapper

def authorize_user(user_id, user_email=None):
    """Validate user authorization"""
    if user_id in AUTHORIZED_USERS:
        return True
    if user_email and user_email in AUTHORIZED_USERS:
        return True
    
    logger.warning(f"Unauthorized access attempt by user {user_id}")
    return False

class PagerDutyClient:
    def __init__(self, routing_key):
        self.routing_key = routing_key
        self.events_url = "https://events.pagerduty.com/v2/enqueue"
    
    def trigger_incident(self, summary, severity="error", source="slack-bot", 
                        custom_details=None, dedup_key=None):
        """Trigger incident via PagerDuty Events API v2"""
        
        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": summary,
                "severity": severity,
                "source": source,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        }
        
        if custom_details:
            payload["payload"]["custom_details"] = custom_details
        
        if dedup_key:
            payload["dedup_key"] = dedup_key
        
        try:
            response = requests.post(
                self.events_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"PagerDuty incident triggered: {result.get('dedup_key')}")
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error(f"PagerDuty API error: {str(e)}")
            raise Exception(f"Failed to trigger PagerDuty incident: {str(e)}")

pd_client = PagerDutyClient(PAGERDUTY_ROUTING_KEY)

@app.route('/slack/commands/incident', methods=['POST'])
@verify_slack_signature
def handle_incident_command():
    """Handle /incident slash command"""
    
    try:
        # Parse Slack command
        user_id = request.form.get('user_id')
        user_name = request.form.get('user_name')
        channel_id = request.form.get('channel_id')
        text = request.form.get('text', '').strip()
        
        # Get user email for additional authorization
        try:
            user_info = slack_client.users_info(user=user_id)
            user_email = user_info['user']['profile'].get('email')
        except SlackApiError:
            user_email = None
        
        # Authorization check
        if not authorize_user(user_id, user_email):
            return jsonify({
                "response_type": "ephemeral",
                "text": "❌ You are not authorized to trigger incidents."
            })
        
        # Parse command arguments
        if not text:
            return jsonify({
                "response_type": "ephemeral",
                "text": "Usage: `/incident <summary> [severity=error] [details=...]`\n"
                       "Example: `/incident Database connection timeout severity=critical`"
            })
        
        # Parse incident details
        incident_data = parse_incident_command(text)
        
        # Log incident trigger attempt
        logger.info(f"Incident trigger attempt by {user_name} ({user_id}): {incident_data}")
        
        # Trigger PagerDuty incident
        pd_result = pd_client.trigger_incident(
            summary=incident_data['summary'],
            severity=incident_data['severity'],
            source=f"slack-bot-{user_name}",
            custom_details={
                "triggered_by": user_name,
                "slack_channel": channel_id,
                "command_text": text
            }
        )
        
        # Success response
        incident_key = pd_result.get('dedup_key', 'Unknown')
        
        response_text = (
            f"✅ **Incident Triggered Successfully**\n"
            f"**Incident Key:** `{incident_key}`\n"
            f"**Summary:** {incident_data['summary']}\n"
            f"**Severity:** {incident_data['severity']}\n"
            f"**Triggered by:** {user_name}"
        )
        
        return jsonify({
            "response_type": "in_channel",
            "text": response_text
        })
        
    except Exception as e:
        logger.error(f"Error handling incident command: {str(e)}")
        return jsonify({
            "response_type": "ephemeral",
            "text": f"❌ Failed to trigger incident: {str(e)}"
        })

def parse_incident_command(text):
    """Parse incident command arguments"""
    parts = text.split()
    
    # Extract summary (everything before severity/details)
    summary_parts = []
    severity = "error"  # default
    details = {}
    
    i = 0
    while i < len(parts):
        part = parts[i]
        
        if part.startswith('severity='):
            severity = part.split('=', 1)[1]
        elif part.startswith('details='):
            details_str = part.split('=', 1)[1]
            try:
                details = json.loads(details_str)
            except json.JSONDecodeError:
                details = {"raw_details": details_str}
        else:
            summary_parts.append(part)
        
        i += 1
    
    if not summary_parts:
        raise ValueError("Incident summary is required")
    
    return {
        "summary": " ".join(summary_parts),
        "severity": severity,
        "details": details
    }

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Test Slack connection
        slack_client.auth_test()
        
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            "status": "unhealthy",
            "error": str(e)
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

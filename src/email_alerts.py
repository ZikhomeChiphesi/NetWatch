import smtplib
from email.mime.text import MIMEText

SENDER_EMAIL = "YOUR_EMAIL@gmail.com"
APP_PASSWORD = "YOUR_APP_PASSWORD"
RECEIVER_EMAIL = "YOUR_EMAIL@gmail.com"


def send_email_alert(device, score, reason):
    subject = "🚨 NetWatch Security Alert - High Risk Device"

    body = f"""
NetWatch Security Alert

A high-risk device was detected:

IP: {device['ip']}
MAC: {device['mac']}
Score: {score}
Reason: {reason}

Action recommended: Investigate immediately.
"""

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.send_message(msg)
        server.quit()

        print("📧 Email alert sent")

    except Exception as e:
        print("Email failed:", e)
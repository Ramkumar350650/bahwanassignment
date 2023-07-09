import os
import json
import sqlite3
import datetime
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

# Gmail API configuration
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
API_VERSION = 'v1'
SERVICE_NAME = 'gmail'

# Database configuration
DB_FILE = 'emails.db'
EMAILS_TABLE = 'emails'

# Authenticate with Gmail API
def authenticate():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return creds

# Fetch emails from Gmail API
def fetch_emails():
    creds = authenticate()
    service = build(SERVICE_NAME, API_VERSION, credentials=creds)
    results = service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
    messages = results.get('messages', [])
    emails = []
    if messages:
        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            email = {
                'id': message['id'],
                'from': get_header(msg['payload'], 'From'),
                'to': get_header(msg['payload'], 'To'),
                'subject': get_header(msg['payload'], 'Subject'),
                'date': get_header(msg['payload'], 'Date'),
                'snippet': msg['snippet']
            }
            emails.append(email)
    return emails

# Get header value from email payload
def get_header(payload, name):
    headers = payload.get('headers', [])
    for header in headers:
        if header['name'] == name:
            return header['value']
    return ''

# Store emails in SQLite database
def store_emails(emails):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(f"CREATE TABLE IF NOT EXISTS {EMAILS_TABLE} (id TEXT PRIMARY KEY, from_email TEXT, to_email TEXT, subject TEXT, date TEXT, snippet TEXT)")
    for email in emails:
        c.execute(f"INSERT OR IGNORE INTO {EMAILS_TABLE} VALUES (?, ?, ?, ?, ?, ?)", (
            email['id'],
            email['from'],
            email['to'],
            email['subject'],
            email['date'],
            email['snippet']
        ))
    conn.commit()
    conn.close()

# Process emails based on rules
def process_emails(rules_file):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(f"SELECT * FROM {EMAILS_TABLE}")
    emails = c.fetchall()
    with open(rules_file, 'r') as f:
        rules = json.load(f)
    for rule in rules:
        field = rule['field']
        predicate = rule['predicate']
        value = rule['value']
        for email in emails:
            if check_condition(email, field, predicate, value):
                perform_actions(email, rule['actions'])
    conn.close()

# Check if an email satisfies the condition
def check_condition(email, field, predicate, value):
    if field == 'From':
        field_value = email[1]
    elif field == 'To':
        field_value = email[2]
    elif field == 'Subject':
        field_value = email[3]
    elif field == 'Date':
        field_value = email[4]
        value = (datetime.datetime.now() - datetime.datetime.strptime(value, '%Y-%m-%d')).days
    else:
        return False

    if predicate == 'contains':
        return value.lower() in field_value.lower()
    elif predicate == 'does_not_contain':
        return value.lower() not in field_value.lower()
    elif predicate == 'equals':
        return value.lower() == field_value.lower()
    elif predicate == 'does_not_equal':
        return value.lower() != field_value.lower()
    elif predicate == 'less_than':
        return int(field_value) < int(value)
    elif predicate == 'greater_than':
        return int(field_value) > int(value)
    else:
        return False

# Perform actions on an email
def perform_actions(email, actions):
    creds = authenticate()
    service = build(SERVICE_NAME, API_VERSION, credentials=creds)
    msg = service.users().messages().get(userId='me', id=email[0]).execute()
    for action in actions:
        if action == 'mark_as_read':
            msg['labelIds'].remove('UNREAD')
        elif action == 'mark_as_unread':
            msg['labelIds'].append('UNREAD')
        elif action == 'move_message':
            msg['labelIds'].append('TRASH')
    service.users().messages().modify(userId='me', id=email[0], body=msg).execute()

# Run the script
if __name__ == '__main__':
    emails = fetch_emails()
    store_emails(emails)
    process_emails('rules.json')

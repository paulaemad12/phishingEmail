import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

# Path to your service account key JSON file
cred = credentials.Certificate('serviceAccountKey.json')

# Initialize the Firebase app
firebase_admin.initialize_app(cred)

# Get reference to Firestore client
db = firestore.client()

# List of phishing keywords to upload
phishing_keywords = [
    'urgent', 'password', 'click here', 'verify', 'account', 'login', 'update',
    'security', 'alert', 'bank', 'confirm', 'suspicious', 'unusual activity',
    'locked', 'suspended', 'verify your identity', 'immediate action required',
    'access', 'limited', 'risk', 'unauthorized', 'dear customer', 'account holder',
    'won', 'prize', 'lottery', 'offer', 'free', 'money', 'payment', 'invoice',
    'bill', 'refund', 'tax', 'government', 'apple', 'google', 'microsoft',
    'facebook', 'paypal', 'amazon', 'ebay', 'delivery', 'package', 'failure notice',
    'help desk', 'it support', 'new message', 'important', 'open this', 'respond now',
    'reset', 'compromised', 'validation', 'secure', 'compliance', 'confidential',
    'wire transfer', 'transaction', 'legal', 'lawsuit', 'court', 'subpoena',
    'password expires', 'payment failed', 'problem with your order',
    'your account is on hold', 'breach', 'security notice'
]

def upload_keywords():
    collection_ref = db.collection('phishingKeywords')

    for keyword in phishing_keywords:
        # Use keyword as document ID to prevent duplicates
        doc_ref = collection_ref.document(keyword.lower())
        doc_ref.set({
            'keyword': keyword.lower()
        })
        print(f'Keyword "{keyword}" uploaded.')

if __name__ == '__main__':
    upload_keywords()
    print('All keywords have been uploaded.')

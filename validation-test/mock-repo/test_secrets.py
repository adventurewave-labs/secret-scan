# Python file with comprehensive secret examples
import os

# AWS Secrets
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Google Cloud
GOOGLE_API_KEY = "AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI"
FIREBASE_SERVER_KEY = "AAAA1234567890:APA91bHun4MxP5egoKMwt2KkAH-IuLux"

# GitHub
GITHUB_PERSONAL_ACCESS_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
GITHUB_OAUTH_TOKEN = "gho_1234567890abcdefghijklmnopqrstuvwxyz"

# Database URLs
POSTGRES_URL = "postgresql://user:password@localhost:5432/database"
MONGODB_URL = "mongodb://user:password@localhost:27017/database"
REDIS_URL = "redis://user:password@localhost:6379/0"

# API Keys
STRIPE_SECRET_KEY = "sk_live_1234567890abcdefghijklmnopqrstuvwxyz"
SENDGRID_API_KEY = "SG.1234567890abcdefghijklmnopqrstuvwxyz"
SLACK_BOT_TOKEN = "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwxyz"

# JWT Token (example)
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Obfuscated secrets
ENCODED_SECRET = "c2VjcmV0LWFwaS1rZXktZW5jb2RlZA=="  # Base64 encoded
HEX_SECRET = "736563726574746f6b656e696e686578"  # Hex encoded

# Character array (should be detected)
SECRET_ARRAY = [115, 107, 45, 116, 101, 115, 116, 95, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48]

# Private key example
PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
wEiOfQIp8ta6UhYyEXLTXh5KmxCXfgK6ySjWHIjP+eF8Ew5L7EB3jfm4+n6tV6n6
-----END PRIVATE KEY-----"""

# Environment variables that might contain secrets
os.environ['SECRET_KEY'] = 'super-secret-environment-variable'
os.environ['API_TOKEN'] = 'token-from-environment-variables'

print("Test secrets loaded for scanning validation")
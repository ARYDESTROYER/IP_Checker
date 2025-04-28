import re

def is_valid_username(username):
    # Only alphabetic usernames, 3-30 chars
    return bool(re.fullmatch(r'[A-Za-z]{3,30}', username))

def is_valid_email(email):
    # Simple but robust email regex
    return bool(re.fullmatch(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', email))

def is_valid_password(password):
    # Minimum 8 chars, at least one letter and one number
    return bool(re.fullmatch(r'(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d!@#$%^&*()_+\-=]{8,}', password))

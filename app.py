from flask import Flask, request, jsonify, render_template
from nltk.corpus import words
import hashlib
import os
import requests
import re

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
app = Flask(__name__)
engWords = set(words.words())

#function to check whether the password has been compromised using Have I Been Pwned's database
def check_pwned_password(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_password[:5]
    response = requests.get(HIBP_API_URL + prefix)
    suffix = sha1_password[5:]
    
    for line in response.text.splitlines():
        h, count = line.split(':')
        if h == suffix:
            return True, count
    return False, 0

#function to check whether any english words have been used in the password
def hasEngWord(password):
    n = len(password)
    for i in range(n):
        for j in range(i + 1, n + 1):
            substring = password[i:j].lower()
            if len(substring) < 2:
                continue
            if substring in engWords:
                print(f"Found English word: {substring}")
                return True
    return False

#function to ask for the user's security level preference
def securityLevel():
    secLevel = request.json.get('Security Level')
    return secLevel

#function to check password's strength depending on the sec. level preference indicated by the user
def passCheck(secLevel, password):
    length = len(password)
    hasCapital = bool(re.search(r'[A-Z]', password))
    hasLower = bool(re.search(r'[a-z]', password))
    hasNumber = bool(re.search(r'\d', password))
    hasSpecial = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    if secLevel == 1:
        if length >= 10 and hasCapital and hasLower and hasNumber:
            return "Good job! This password is strong enough for level 1!"
        if length<10 or hasCapital == False or hasLower == False or hasNumber == False:
            return "This password isn't strong enough for level 1 security."
        if length < 10:
            return "The password isn't long enough, you need to have minimum 10 characters."
        if hasCapital == False:
            return "There are no capital letters. You need at least one capital letter in level 1."
        if hasLower == False:
            return "There aren't any lower-case letters. It is best to mix it up a bit. Please add some lowercase characters."
        if hasNumber == False:
            return "There aren't numbers. You need at least one number to achieve level 1 security."

    elif secLevel == 2:
        if length >=10 and hasCapital and hasLower and hasNumber and hasSpecial:
            return "Good job! This password is strong enough for level 2 security!"
        if length<10 or hasCapital == False or hasLower == False or hasNumber == False or hasSpecial == False:
            return "This password isn't strong enough for level 2 security."
        if length < 10:
            return "The password isn't long enough, you need to have minimum 10 characters."
        if hasCapital == False:
            return "There are no capital letters. You need at least one capital letter in level 2."
        if hasLower == False:
            return "There aren't any lower-case letters. It is best to mix it up a bit. Please add some lowercase characters."
        if hasNumber == False:
            return "There are no numbers. You need at least one number to achieve level 2 security."
        if hasSpecial == False:
            return "There are no special characters (!@#$%^&*()?<>). You need at least one for level 2 security."
    
    elif secLevel == 3:
        if length >=12 and hasCapital and hasLower and hasNumber and hasSpecial:
            return "Good job! This password is strong enough for level 3 security!"
        if length < 12 or hasCapital == False or hasLower == False or hasNumber == False or hasSpecial == False:
            return "This password isn't strong enough for level 3 security."
        if length < 12:
            return "The password isn't long enough, you need to have minimum 12 characters."
        if hasCapital == False:
            return "There are no capital letters. You need at least one capital letter in level 3."
        if hasLower == False:
            return "There aren't any lower-case letters. It is best to mix it up a bit. Please add some lowercase characters (minimum 3)"
        if hasNumber == False:
            return "There are no numbers. You need at least two numbers to achieve level 3 security."
        if hasSpecial == False:
            return "There are no special characters (!@#$%^&*()?<>). You need at least one for level 2 security."
    
    elif secLevel == 4:
        if length >=12 and hasCapital and hasLower and hasNumber and hasSpecial and hasEngWord == False:
            return "Good job! This password is strong enough for level 4 security!"
        if length < 12 or hasCapital == False or hasLower == False or hasNumber == False or hasSpecial == False:
            return "This password isn't strong enough for level 4 security."
        if length < 12:
            return "The password isn't long enough, you need to have minimum 12 characters."
        if hasCapital == False:
            return "There are no capital letters. You need at least one capital letter in level 4."
        if hasLower == False:
            return "There aren't any lower-case letters. It is best to mix it up a bit. Please add some lowercase characters (minimum 3)"
        if hasNumber == False:
            return "There are no numbers. You need at least two numbers to achieve level 4 security."
        if hasSpecial == False:
            return "There are no special characters (!@#$%^&*()?<>). You need at least one for level 4 security."
        
#routing to check password strength and also check for any breaches
@app.route('/analyze', methods=['POST'])
def analyze():
    password = request.json.get('password')
    
    # Check if password has been compromised
    breached, breach_count = check_pwned_password(password)

    # Evaluate password strength
    strength, strength_color = passCheck(password)

    return jsonify({
        'breached': breached,
        'breach_count': breach_count,
    })

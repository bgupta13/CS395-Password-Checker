from flask import Flask, request, jsonify, render_template
from nltk.corpus import words
import nltk
import hashlib
import os
import requests
import re
import html

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
app = Flask(__name__)
nltk.download('words')
engWords = set(words.words())

@app.route('/')
def home():
    return render_template('index.html')

#function to check whether the password has been compromised using Have I Been Pwned's database
def checkPwned(password):
    sha1Password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1Password[:5]
    response = requests.get(HIBP_API_URL + prefix)
    suffix = sha1Password[5:]
    
    for line in response.text.splitlines():
        h, count = line.split(':')
        if h == suffix:
            return True, count
    return False, 0

#function to validate the password and confirm that the password isn't malicious code
def passValidate(password):
    #make sure the password is a string
    if not isinstance(password, str):
        return False, "Password must be a string."

    #length check
    if len(password) > 30:
        return False, "Password must be less than 30 characters."

    #reject HTML tags or encoded characters that can lead to XSS
    if re.search(r'<[^>]*>', password) or re.search(r'&[a-z]+;', password):
        return False, "Password contains potentially malicious characters. Please avoid putting anything between '<>' or anything between '&' and ';'"

    #reject any control characters
    if any(ord(c) < 32 for c in password):
        return False, "Password contains invalid control characters."

    return True, "Password is valid."

#function to check whether any english words have been used in the password
def hasEngWord(password):
    n = len(password)
    for i in range(n):
        for j in range(i + 3, n + 1):
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
    messages = []
    length = len(password)
    hasCapital = bool(re.search(r'[A-Z]', password))
    hasLower = bool(re.search(r'[a-z]', password))
    hasNumber = bool(re.search(r'\d', password))
    hasSpecial = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    containsEngWord = bool(hasEngWord(password))
    if secLevel == 1:
        if length >= 10 and hasCapital and hasLower and hasNumber:
            messages.append("Good job! This password is strong enough for level 1!")
        else:
            messages.append("This password isn't strong enough for level 1 security.")
            if length < 10:
                messages.append("The password isn't long enough, you need minimum 10 characters.")
            if not hasCapital:
                messages.append("There are no capital letters. You need at least one for level 1.")
            if not hasLower:
                messages.append("There aren't any lower-case letters. Please add some.")
            if not hasNumber:
                messages.append("There are no numbers. You need at least one.")

    elif secLevel == 2:
        if length >= 10 and hasCapital and hasLower and hasNumber and hasSpecial:
            messages.append("Good job! This password is strong enough for level 2 security!")
        else:
            messages.append("This password isn't strong enough for level 2 security.")
            if length < 10:
                messages.append("The password isn't long enough, you need minimum 10 characters.")
            if not hasCapital:
                messages.append("There are no capital letters. You need at least one for level 2.")
            if not hasLower:
                messages.append("There aren't any lower-case letters. Please add some.")
            if not hasNumber:
                messages.append("There are no numbers. You need at least one.")
            if not hasSpecial:
                messages.append("There are no special characters (!@#$%^&*()?<>). You need at least one for level 2.")
    
    elif secLevel == 3:
        if length >= 12 and hasCapital and hasLower and hasNumber and hasSpecial:
            messages.append("Good job! This password is strong enough for level 3 security!")
        else:
            messages.append("This password isn't strong enough for level 3 security.")
            if length < 12:
                messages.append("The password isn't long enough, you need minimum 12 characters.")
            if not hasCapital:
                messages.append("There are no capital letters. You need at least one for level 3.")
            if not hasLower:
                messages.append("There aren't any lower-case letters. Add some (minimum 3).")
            if not hasNumber:
                messages.append("There are no numbers. You need at least one for level 3.")
            if not hasSpecial:
                messages.append("There are no special characters. You need at least one.")
    
    elif secLevel == 4:
        if length >= 12 and hasCapital and hasLower and hasNumber and hasSpecial and not containsEngWord:
            messages.append("Good job! This password is strong enough for level 4 security!")
        else:
            messages.append("This password isn't strong enough for level 4 security.")
            if length < 12:
                messages.append("The password isn't long enough, you need minimum 12 characters.")
            if not hasCapital:
                messages.append("There are no capital letters. You need at least one for level 4.")
            if not hasLower:
                messages.append("There aren't any lower-case letters. Add some (minimum 3).")
            if not hasNumber:
                messages.append("There are no numbers. You need at least two for level 4.")
            if not hasSpecial:
                messages.append("There are no special characters. You need at least one.")
            if containsEngWord:
                messages.append("There is an English word in your password. No real words allowed for level 4.")
    return messages
        
#routing to check password strength and also check for any breaches
@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    password = data.get('password')
    secLevel = int(data.get('security_level', 1))
    
    valid, message = passValidate(password)
    if not valid:
        return jsonify({
            'error': message
        }), 400

    pwned, pwnedCount = checkPwned(password)
    
    if pwned:
        # If breached, return immediately with breach info
        return jsonify({
            'strength_feedback': ["This password has been found in a data breach! Please choose a new password."],
            'strength_color': "red",
            'breached': True,
            'breach_count': pwnedCount
        })

    strengthMsg = passCheck(secLevel, password)

    #calculate what color to return depending on strength
    if all("Good job!" in msg for msg in strengthMsg):
        strengthColor = "green"
    else:
        strengthColor = "red"
    
    return jsonify({
        'strength_feedback': strengthMsg,
        'strength_color': strengthColor,
        'breached': pwned,
        'breach_count': pwnedCount
    })

if __name__ == '__main__':
    app.run(debug=True)

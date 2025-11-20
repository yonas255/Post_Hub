PostHub – Secure & Insecure Web Application (College Assignment)

This repository contains the PostHub Web Application, developed for the Secure Application Programming module.
The project demonstrates:

✔ Secure coding
✔ Insecure coding
✔ Vulnerability analysis
✔ OWASP Top 10 practices
✔ SDLC and ethical decision-making

The application is intentionally built in two versions:

🔴 Insecure Version (insecure branch)

This version intentionally includes vulnerabilities:

🔥 Implemented OWASP Top 10 Vulnerabilities

SQL Injection (login + registration)

Stored XSS (create post page)

Reflected XSS (/search?q=...)

DOM-Based XSS (/dom#payload)

Sensitive Data Exposure

Plaintext passwords

Hardcoded secret key

Debug mode enabled

This version is used for:

Vulnerability demonstration

ZAP scanning

Documentation screenshots

Comparison with secure version

🟢 Secure Version (secure branch)

The secure implementation includes:

✔ Mitigations & Security Enhancements

Prepared statements (SQL injection prevention)

Input validation + output encoding (XSS prevention)

DOM sanitization (DOM XSS prevention)

Password hashing (bcrypt/werkzeug)

CSRF protection (Flask-WTF)

Secure session cookies (HttpOnly, Secure, expiry time)

Security Headers:

Content-Security-Policy (CSP)

X-Frame-Options

X-Content-Type-Options

Logging & Monitoring (audit log table)

Secret keys stored securely (environment variables)

🗂 Branches Overview
Branch	Purpose
main	Clean main branch (empty starter)
insecure	Full insecure version (vulnerable on purpose)
secure	Full secure version with protections

Switch branches using:

git checkout insecure
git checkout secure

▶️ How to Run the Application
1. Install dependencies
pip install flask

2. Run the application
python app.py


or

py app.py


The app runs on:

http://127.0.0.1:5000/

🔍 Testing the Insecure Version
SQL Injection Test

On login page → Email field:

' OR '1'='1' --


You should be logged in without a password.

Stored XSS Test

In "Create Post":

<script>alert('XSS')</script>


Alert box will appear on the posts page.

Reflected XSS Test
/search?q=<script>alert("XSS")</script>

DOM XSS Test
/dom#"><iframe srcdoc="<script>alert('DOM')</script>"></iframe>

🧪 Security Tools Used
Tool	Purpose
ZAP Proxy	DAST scanning on insecure + secure versions
Selenium/Playwright	Automated browser tests
Chrome Lighthouse	Performance, SEO, accessibility, best-practices tests
SQLite3	Database used for basic testing
📖 Documentation

All documentation is included in the main Word report, including:

SDLC justification

SRS

ERD

Use-case models

Testing plan

Screenshots

Secure vs Insecure comparison

Ethical analysis

🎥 Video Demonstration

A short demonstration video will be recorded showing:

Insecure version vulnerabilities

Secure version protections

Code structure

ZAP scan results

Link will be added here when video is completed.

✉️ Author

Name: Yonas Haf

Module: Secure Application Programming

College: City of Dublin ETB

Project: PostHub – Secure & Insecure Web Application
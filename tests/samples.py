"""Sample emails used by the tests (kept here, not in the UI)."""

PHISHING_PAYPAL = """From: PayPal Security <security@paypa1-support.com>
Subject: URGENT: Your account has been limited

Dear customer,

We noticed unusual activity on your account. Verify your identity within 24 hours
or your account will be permanently suspended:

http://paypa1-support.com/verify-login

Thank you,
PayPal Security Team
"""

PHISHING_MICROSOFT = """From: Microsoft Support <support@microsoft-365-security.xyz>
Subject: Password expires today

Your password will expire today. Click here to keep your account active:
https://microsoft.com.secure-login.verify-account.xyz/auth

Microsoft Account Team
"""

PHISHING_IP_LINK = """From: Bank Alerts <alerts@secure-bank-notice.top>
Reply-To: collect@gmail.com
Subject: Action required

Dear customer, please enter your password and confirm your card number now.
Login: http://192.168.10.5/bank/login
"""

PHISHING_HTML_MISMATCH = """From: HBL Support <support@hbl-secure.xyz>
Subject: Verify your account
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>
<p>Dear customer, your account will be suspended. Verify your account now:</p>
<p><a href="http://hbl-secure.xyz/login">https://www.hbl.com</a></p>
</body></html>
"""

PHISHING_EXE_ATTACHMENT = """From: Accounts <billing@random-company.com>
Subject: Invoice
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="XX"

--XX
Content-Type: text/plain; charset=utf-8

Please open the attached invoice.
--XX
Content-Type: application/octet-stream; name="invoice.pdf.exe"
Content-Disposition: attachment; filename="invoice.pdf.exe"
Content-Transfer-Encoding: base64

AAAA
--XX--
"""

PHISHING_AUTH_FAIL = """From: IT Helpdesk <helpdesk@company-portal.example>
Subject: Mailbox update
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=company-portal.example; dkim=fail; dmarc=fail

Please verify your account to avoid account suspension.
"""

PHISHING_BODY_ONLY = """Your account will be suspended. Verify your account now:
http://bit.ly/3xYz12
"""

LEGIT_PERSONAL = """From: Ayesha Khan <ayesha.khan@ucp.edu.pk>
Subject: Meeting notes from Tuesday

Hi Shahroz,

Attaching the notes from our project meeting. Let me know if I missed anything.
We can review them together on Thursday.

Best regards,
Ayesha
"""

LEGIT_AMAZON = """From: Amazon <shipment-tracking@amazon.com>
Subject: Your package has shipped

Hello Muhammad,

Your order has shipped. Track it here:
https://www.amazon.com/gp/css/order-details?orderId=123-4567890
"""

LEGIT_GITHUB = """From: GitHub <noreply@github.com>
Subject: Please verify your email address

Hi Muhammad,

Click here to verify your email address:
https://github.com/users/muhammad/emails/confirm
"""

LEGIT_NEWSLETTER = """From: Tech Weekly <news@techweekly.org>
Subject: This week in tech

Hi there,

This is an important notice that our weekly edition is out. Click here to read it:
http://techweekly.org/issues/42
"""

LEGIT_GOOGLE_ACCOUNT = """From: Google <no-reply@accounts.google.com>
Subject: Security alert

Hi Muhammad,
A new sign-in was detected on your account. If this was you, no action is needed.
https://accounts.google.com/AccountChooser
"""

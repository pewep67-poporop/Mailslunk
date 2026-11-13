"""Test stub for libpst readpst: writes 3 EML messages into the -o folder."""
import os, sys, base64

args = sys.argv[1:]
out = src = None
i = 0
while i < len(args):
    if args[i] == "-o":
        out = args[i + 1]; i += 2; continue
    src = args[i]; i += 1
if not out or not src:
    sys.exit("bad args")
os.makedirs(out, exist_ok=True)

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

msgs = []

msgs.append(b"""From: Alice Example <alice@example.com>
To: Bob <bob@example.org>
Subject: Quarterly report
Date: Tue, 10 Nov 2026 09:00:00 +0000
Message-ID: <msg1@example.com>
Return-Path: <alice@example.com>
Received: from mail.example.com (mail.example.com [93.184.216.34]) by mx.local with ESMTP id a1; Tue, 10 Nov 2026 09:00:01 +0000
Content-Type: text/plain; charset=utf-8

Hello Bob, the quarterly report is attached in the shared folder.
""")

html = """<html><body><p>Dear customer,</p>
<p>Your invoice is overdue. <a href="http://203.0.113.7/login">https://paypal.com/login</a></p>
</body></html>"""
att = base64.b64encode(EICAR).decode()
msgs.append(("""From: "PayPal Billing" <billing@paypa1-secure.example>
To: victim@example.org
Subject: URGENT: verify your invoice now
Date: Tue, 10 Nov 2026 10:00:00 +0000
Message-ID: <msg2@paypa1-secure.example>
Return-Path: <bounce@evil-mailer.example>
Reply-To: <reply@another-bad.example>
Received: from unknown (unknown [8.8.8.8]) by mx.local with ESMTP id b2; Tue, 10 Nov 2026 10:00:01 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUND"

--BOUND
Content-Type: text/html; charset=utf-8

""" + html + """
--BOUND
Content-Type: application/octet-stream; name="invoice.pdf.exe"
Content-Disposition: attachment; filename="invoice.pdf.exe"
Content-Transfer-Encoding: base64

""" + att + """
--BOUND--
""").encode())

msgs.append(b"""From: Carol <carol@example.net>
To: Dave <dave@example.org>
Subject: Lunch tomorrow?
Date: Tue, 10 Nov 2026 11:00:00 +0000
Message-ID: <msg3@example.net>
Return-Path: <carol@example.net>
Received: from mail.example.net (mail.example.net [93.184.216.35]) by mx.local with ESMTP id c3; Tue, 10 Nov 2026 11:00:01 +0000
Content-Type: text/plain; charset=utf-8

Sure, see you at noon.
""")

for n, data in enumerate(msgs, 1):
    with open(os.path.join(out, "msg%d.eml" % n), "wb") as fh:
        fh.write(data)

# nested folder to exercise recursive walk
sub = os.path.join(out, "Inbox", "Archive")
os.makedirs(sub, exist_ok=True)
with open(os.path.join(sub, "msg4.eml"), "wb") as fh:
    fh.write(msgs[0].replace(b"Quarterly report", b"Archived copy"))

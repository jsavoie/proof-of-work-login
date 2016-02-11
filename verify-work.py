#!/usr/bin/python
import hashlib

validnonces = ["0000", "abcd", "00000", "000000"]
username = raw_input("Username: ")
password = raw_input("Password: ")
cnonce = raw_input("cnonce: ")
nonce = raw_input("nonce: ")

if nonce in validnonces:
	hash = hashlib.sha256(username + password + cnonce).hexdigest()
	if hash.startswith(nonce):
		print "Congrats, you did it. Process login now."
	else:
		print "No"
else:
	print "No"

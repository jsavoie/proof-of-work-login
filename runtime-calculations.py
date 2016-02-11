#!/usr/bin/python
import hashlib

username = raw_input("Username: ")
password = raw_input("Password: ")
nonce = "000000";
cnonce = 0;

print "Looking for nonce " + nonce

hash = hashlib.sha256(username + password + str(cnonce)).hexdigest()
while not hash.startswith(nonce):
	cnonce += 1
	hash = hashlib.sha256(username + password + str(cnonce)).hexdigest()

print "Found hash : " + str(hash)
print "Correct cnonce is " + str(cnonce)

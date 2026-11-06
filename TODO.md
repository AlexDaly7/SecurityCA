# TODO

## Dirs
Store data in <user-home>/SecurityCA

Files:
- /logins.txt
- 

## Auth

On connect, prompt the user to enter a user identifier, or start as a new user
- If starting as new user, generate a crypto secure random name, e.g. 
- If using exising identifier, enter it, the server then checks against a logins.txt file in the serverdir

## Files

Save encrypted files

we take file file and decrypt it
then encrypt it with a new nonce
then take the first x characters of the generated hash

- Decrypt file
- Save file with different AES label
- 
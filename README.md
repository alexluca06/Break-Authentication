# Break Authentication
**Capture-the-flag**: You want to capture the flag of a server that is protected
under an administrative account. You will need to obtain a valid admin tag.
The server also offers us a guest account, but it does not have access to this
flag.

Fortunately, you were able to extract the source code from the server,
but it seems that it does not contain the secret flag.
This exercise will test your ability to understand cryptographic constructions
by analyzing source code and using cryptanalysis to prove that a cipher is
insecure. 

Finally, you will need to build a proof-of-concept that demonstrates
an effective attack by running the attack against a server.

Copyright: https://ocw.cs.pub.ro/courses/ic/teme/tema2022

## Server Code understanding and Cryptanalysis: 
   
   - The server exposes two functionalities for us:
        1. Get a guest token;
        2. Logging to the server with the token got it at step 1;
  #    
   - When we request a token:
   
        1. The server uses a random key(rnd, len(rnd) == 16) generated by
    AES Encryption Scheme in ECB mode to encrypt an USERNAME using XOR:
            - OTP: -> cipher_username = XOR(plaintext_username, rnd)
                -> token = cipher_username
        
        2. The server attaches to the token a const variable: SERVER_PUBLIC_BANNER -> token = cipher_username | SERVER_PUBLIC_BANNER
            
        3. The server gets based on plaintext and key size using AES functionalities
    (self.INTEGRITY.encrypt()) an integrity variable to make the encryption more secure:
            -> token = cipher_username | SERVER_PUBLIC_BANNER | integrity
  #
   - When we try to login with a token:
    	
    	1. The server decodes the token using b64decode();
    	
    	2. The server checks the length of token (must be <= 16);
    	
    	3. The server decrypts the token using decrypt function:
    		
    		* Gets the rnd key;
    		* Separates the token in: cipher_username | BANNER | integrity;
    		* Gets plaintext from cipher_username: XOR(cipher_username, rnd);
    		* Checks if BANNER is correct;
    		* Checks if integrity is valid;
    		* return plaintext
    		
    	4. Checks if plaintext have a valid value and send to user a response; 
    	
## SERVER VULNERABILITIES:
    	
   1. Because the SERVER_PUBLIC_BANNER is not encrypted, when an user gets
    multiple tokens, it can extract the banner(it doesn't change at multiple
    runnings);
    	
   2. Because we know a pair (plaintext == GUEST_NAME, ciphertext == TOKEN),
    we can find the encryption key used by XOR:
    	
      - A big issue of OTP when you know a pair (plaintext, ciphertext): 
    	 	 cipher = XOR(rnd, username) -> rnd = XOR(cipher, username)
    	 	! WE KNOW BOTH: username = "Anonymous"; cipher = token
      - Using this issue, we can get an encryption for any username:
    	 	cipher_new_username = XOR(rnd, new_username)
    	 			    = XOR(XOR(cipher, username), new_username)
        
   3. We cannot get the integrity value, but using (1) and (2) we can get the
    integrity length:
    	  -> INTEGRITY_LEN = TOKEN_LEN - (CIPHER_LEN + BANNER_LEN) = 1
-----------------------------------------------------------------------------------
## Run the attack against server(OS Linux):
  1. Install **python3** and **Crypto** library using pip:
      * sudo apt install python3
      * pip install crypto
  2. Run in command line:
      * python3 skel.py
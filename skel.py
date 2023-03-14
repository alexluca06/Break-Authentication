import base64 as b64
from time import sleep

from pwn import *


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


LOCAL = True  # Local means that you run binary directly

if LOCAL:
    # Complete this if you want to test locally
    r = process("./server.py")
else:
    r = remote("141.85.224.117", 1337)  # Complete this if changed


def read_options():
    """Reads server options menu."""
    r.readuntil(b"Input:")


def get_token():
    """Gets anonymous token as bytearray."""
    read_options()
    r.sendline(b"1")
    token = r.readline()[:-1]
    return b64.b64decode(token)

def login(tag):
    """Expects bytearray. Sends base64 tag."""
    r.readline()
    read_options()
    r.sendline(b"2")
    sleep(0.01) # Uncoment this if server rate-limits you too hard
    r.sendline(b64.b64encode(tag))
    r.readuntil(b"Token:")
    response = r.readline().strip()
    return response


# TODO: Solve challenge
"""
*** Steps for running the attack ***

STEP 1:

    *** How to get a valid ciphertext for the ADMIN_NAME == b'Ephvuln' ***

    token_guest_name = ciphertext for GUEST_NAME
    GUEST_NAME = plaintext
    rnd = the secret key used by server to encrypt and decrypt messages
    .......................................................................
    (1) token_guest_name = GUEST_NAME XOR rnd -> rnd = XOR(token, GUEST_NAME)
    -----------------------------------------------------------------------

    ADMIN_NAME -> ciphertext_admin = XOR(ADMIN_NAME, rnd)
    .......................................................................
    Using (1) -> ciphertext_admin = XOR(ADMIN_NAME, XOR(token, GUEST_NAME))
    -----------------------------------------------------------------------
    *** When you open a connection to the server (nc 141.85.224.117 1337),
    rnd remains the same until you close the connection and open it again!
    -----------------------------------------------------------------------

STEP 2: 

    *** Get SERVER_PUBLIC_BANNER and INTEGRITY_LEN ***
    
    Tokens for GUEST_NAME(get_token()):

         guest_name       SPB       IL
        ..............................
        0ExyeC2ZtJQl . AXN1p+X5 . tg==
        kEP1FaxZiYKb . AXN1p+X5 . wQ==
        0v/y2ss2RJjm . AXN1p+X5 . Rg==
        ANn7PqclnCfS . AXN1p+X5 . Dg==
        Vt20HDq+omsB . AXN1p+X5 . vg==
    ......................................................................
    -> guest_name_len = 9 bytes
       banner_len = 6 bytes
       integrity_len = token_guest_len - (guest_name_len + banner_len) = 1
    
STEP 3:
    *** GET the FLAG ***

    Merging STEP 1 and STEP 2:

      -> token_admin = ciphertext_admin | SERVER_PUBLIC_BANNER | ???
       ! INTEGRITY still unknown, but we know INTEGRITY_LEN = 1 byte
    .......................................................................

    Brute Force on integrity: O(2^8) -> 256 possible values:
        
      for every possible value:
        token_admin = ciphertext_admin | SERVER_PUBLIC_BANNER | integrity_byte
        send_to_server(login(token_admin))
        get_response_from_server()
        catch_the_flag()
        
-------------------------------------------------------------------------------
"""

GUEST_NAME = b"Anonymous"
ADMIN_NAME = b"Ephvuln"  # login(Enc(k, ADMIN_NAME)) -> return SECRET FLAG
SERVER_PUBLIC_BANNER = b64.b64decode('AXN1p+X5')


# STEP 1: get an encryption for ADMIN_NAME

token_guest_name = get_token()  # get a token for guest user
rnd = byte_xor(token_guest_name[:9], GUEST_NAME)  # get the key rnd
ciphertext_admin = byte_xor(rnd, ADMIN_NAME)  # get valid ciphertext for ADMIN

# STEP 2: Find the banner and INTEGRITY_LEN

# STEP 3: Brute force on integrity
for byte in range(256):
   
    integrity_byte = bytes(chr(byte), 'raw_unicode_escape')
    payload = ciphertext_admin + SERVER_PUBLIC_BANNER + integrity_byte    
    response = login(payload).decode('utf-8')
    if "CTF" in response:
        print("[*] Found flag:",response)
        break


r.close()

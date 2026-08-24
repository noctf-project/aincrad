from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib
import hmac
import re
import base64
from operator import itemgetter
import ipaddress

FLAG_REGEX = re.compile(r'[a-zA-Z0-9_]+\{(?P<public>[a-zA-Z0-9-=!@#$%^&*()_+{}\[\]:";\',./<>?~`\\]+)\|(?P<payload>[a-zA-Z0-9_-]+)\}')
VERSION = b"DUCTF1"
MAGIC = b"TOM0NK3$"
IP_PADDING = b'\0\0\0\0'
V6V4 = b'\0\0\0\0\0\0\xff\xff'

def decode(uid: str, secret: str, flag: str):
  parsed = FLAG_REGEX.match(flag)
  if not parsed:
    raise ValueError('Not a valid flag')
  public, payload = itemgetter('public', 'payload')(parsed.groupdict())
  payload = base64.urlsafe_b64decode(payload + '==')

  if len(payload) != 32:
    raise ValueError('Not a valid flag')

  plain = []
  key = hmac.new(VERSION, secret, digestmod=hashlib.sha256).digest()
  key = hmac.new(key, public.encode('utf-8', 'ignore'), digestmod=hashlib.sha256).digest()
  cipher = Cipher(algorithms.AES256(key), modes.ECB())
  decryptor = cipher.decryptor()
  plain = decryptor.update(payload[0:16]) + decryptor.finalize()

  key = hmac.new(key, uid.encode('utf-8', 'ignore'), digestmod=hashlib.sha256).digest()
  key = hmac.new(key, plain[0:16], digestmod=hashlib.sha256).digest()
  cipher = Cipher(algorithms.AES256(key), modes.ECB())
  decryptor = cipher.decryptor()
  plain += decryptor.update(payload[16:32]) + decryptor.finalize()

  lm = len(MAGIC)
  if not hmac.compare_digest(MAGIC, plain[12:12+lm]):
    raise ValueError('Flag decode error')
  timestamp = int.from_bytes(plain[0:8], byteorder='big')
  ip_bytes = plain[20:32]
  if ip_bytes[:8] == V6V4:
    ip_bytes = ip_bytes[8:12]
  else:
    ip_bytes = ip_bytes + IP_PADDING

  return {
    'timestamp': timestamp,
    'ip': ipaddress.ip_address(ip_bytes)
  }



if __name__ == '__main__':
  uid = input('Team ID: ')
  secret = input('Secret: ')
  flag = input('Flag: ')
  print(decode(uid, secret.encode('utf-8'), flag))

"""Regenerate public NoxV CCM vectors with independent cryptography AES/AESCCM."""
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
lookup={};vectors=[]
def aes(key,block):
 result=Cipher(algorithms.AES(key),modes.ECB()).encryptor().update(block)
 lookup[(key,block)]=result
 return result
def xor(a,b):return bytes(x^y for x,y in zip(a,b))
for seed in (0,1):
 key=bytes((i+seed*71)&255 for i in range(16));nonce=bytes((i*7+seed*19)&255 for i in range(13));aad=bytes([2+seed])
 for length in (0,1,8,15,16,17,27,28):
  plain=bytes((i*37+seed*11)&255 for i in range(length))
  expected=AESCCM(key,tag_length=4).encrypt(nonce,plain,aad)
  mac=aes(key,b'\x49'+nonce+length.to_bytes(2,'big'))
  mac=aes(key,xor(mac,b'\x00\x01'+aad+bytes(13)))
  for off in range(0,length,16):mac=aes(key,xor(mac,plain[off:off+16].ljust(16,b'\x00')))
  s0=aes(key,b'\x01'+nonce+b'\x00\x00');tag=xor(mac,s0)[:4];cipher=b''
  for off in range(0,length,16):cipher+=xor(plain[off:off+16],aes(key,b'\x01'+nonce+(1+off//16).to_bytes(2,'big')))
  assert cipher+tag==expected
  vectors.append((key,nonce,aad[0],plain,cipher,tag,length))
key=bytes(range(16));block=bytes.fromhex('00112233445566778899aabbccddeeff');assert aes(key,block).hex()=='69c4e0d86a7b0430d8cdb78070b4c55a'
def arr(b):return '{'+','.join('0x%02x'%x for x in b)+'}'
lines=['/* Generated public test data; regenerate with generate_noxv_ccm_vectors.py. */','typedef struct { unsigned char key[16],input[16],output[16]; } aes_vector_t;','static const aes_vector_t aes_vectors[] = {']
for (key,block),result in lookup.items():lines.append(' {'+','.join(map(arr,(key,block,result)))+'},')
lines+=['};','typedef struct { unsigned char key[16],nonce[13],aad,plain[32],cipher[32],tag[4]; unsigned length; } ccm_vector_t;','static const ccm_vector_t ccm_vectors[] = {']
for key,nonce,aad,plain,cipher,tag,length in vectors:lines.append(' {'+arr(key)+','+arr(nonce)+',0x%02x,'%aad+arr(plain.ljust(32,b'\x00'))+','+arr(cipher.ljust(32,b'\x00'))+','+arr(tag)+',%du},'%length)
lines+=['};','']
Path(__file__).with_name('noxv_ccm_vectors.h').write_bytes(('\n'.join(lines)).encode())
print('Generated',len(vectors),'independent CCM vectors and',len(lookup),'AES primitive mappings')

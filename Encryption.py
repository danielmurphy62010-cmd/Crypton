from cryptography.hazmat.primitives.serialization import load_der_private_key, load_der_public_key, load_pem_private_key, load_pem_public_key, Encoding, PrivateFormat, PublicFormat, NoEncryption, BestAvailableEncryption
from cryptography.x509 import NameAttribute, Name, load_der_x509_certificate, CertificateBuilder, random_serial_number, BasicConstraints, load_pem_x509_certificate,DNSName,SubjectAlternativeName,IPAddress
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519, ec, ed448, x448
from cryptography.hazmat.primitives.ciphers.algorithms import AES, ChaCha20
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from datetime import datetime, timedelta, timezone
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
import os, hmac, ipaddress, util, string, secrets
def gen_id(length=64):return ''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(length))
try:
    import blake3
    def HASH(d,l=32,hex=False):
        if hex:return blake3.blake3(d).hexdigest(l)
        return blake3.blake3(d).digest(l)
    def basic_kdf(master_pw:bytes, salt:bytes, length:int = 32) -> bytes:
        return blake3.blake3(master_pw + salt).digest(length)
except ImportError:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    import hashlib
    def HASH(d,l=32,hex=False):
        h=(hashlib.sha3_256(d).digest() if l<=32 else hashlib.sha3_512(d).digest() if l<=64 else hashlib.shake_256(d).digest(l))[:l]
        return util.to_hex(h) if hex else h
    def basic_kdf(master_pw:bytes, salt:bytes, length:int = 32) -> bytes:return HKDF(algorithm=hashes.SHA512(),length=length,salt=salt,info=b"kdf").derive(master_pw)
def kdf_level(LEVEL):
    if not isinstance(LEVEL,int) or isinstance(LEVEL,bool) or LEVEL < 0:raise ValueError("LEVEL must be a non-negative integer")
    return int(round(3+0.7*LEVEL-0.12*LEVEL**2/10,0)), int(round(131072+39321.6*LEVEL))
def kdf_fast(master_pw:bytes, salt:bytes) -> bytes:return kdf(master_pw,salt,0)
def kdf_slow(master_pw:bytes, salt:bytes) -> bytes:return kdf(master_pw,salt,10)
def kdf(master_pw,salt,level=5):lvl=kdf_level(level);return hash_secret_raw(secret=master_pw, salt=salt, time_cost=lvl[0], memory_cost=lvl[1], parallelism=1, hash_len=512, type=Type.ID)
def encrypt(data:bytes, key:bytes) -> bytes:
    salt, iv = os.urandom(32), os.urandom(16)
    cipher = Cipher(AES(basic_kdf(key, salt)), modes.CTR(iv)).encryptor()
    ct, mv = bytearray(iv + salt), memoryview(data)
    for i in range(0, len(mv), 32768):ct.extend(cipher.update(mv[i:i+32768]))
    return bytes(ct + cipher.finalize())
def decrypt(encrypted:bytes, key:bytes) -> bytes:
    if len(encrypted) < 48:raise ValueError("Ciphertext too short")
    cipher = Cipher(AES(basic_kdf(key, encrypted[16:48])), modes.CTR(encrypted[:16])).decryptor()
    mv, out = memoryview(encrypted[48:]), bytearray()
    for i in range(0, len(mv), 32768):out.extend(cipher.update(mv[i:i+32768]))
    return bytes(out + cipher.finalize())
def encryptGCM(data:bytes, key:bytes, aad:bytes = None) -> bytes:
    salt, iv = os.urandom(32), os.urandom(12)
    return iv + salt + AESGCM(basic_kdf(key, salt)).encrypt(iv, data, aad)
def decryptGCM(encrypted:bytes, key:bytes, aad:bytes = None) -> bytes:
    if len(encrypted) < 60:raise ValueError("Ciphertext too short")
    salt = encrypted[12:44]
    return AESGCM(basic_kdf(key, salt)).decrypt(encrypted[:12], encrypted[44:], aad)
def gen_chacha20() -> bytes:return os.urandom(32)
def encrypt_chacha(data:bytes, key:bytes, auth=True) -> bytes:s, n = os.urandom(32), os.urandom(12 if auth else 16);return s + n + (ChaCha20Poly1305(basic_kdf(key, s)).encrypt(n, data, None) if auth else Cipher(ChaCha20(basic_kdf(key, s), n), mode=None).encryptor().update(data))
def decrypt_chacha(data:bytes, key:bytes, auth=True) -> bytes:nl = 12 if auth else 16;(len(data) < 32 + nl) and (_ for _ in ()).throw(ValueError("Ciphertext too short"));return (ChaCha20Poly1305(basic_kdf(key, data[:32])).decrypt(data[32:32 + nl], data[32 + nl:], None) if auth else Cipher(ChaCha20(basic_kdf(key, data[:32]), data[32:32 + nl]), mode=None).decryptor().update(data[32 + nl:]))
def gen_x25519(overkill=False) -> tuple[bytes, bytes]:private_key=(x448.X448PrivateKey if overkill else x25519.X25519PrivateKey).generate();return (private_key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption()), private_key.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw))
def shared_secret(prv:bytes, pub:bytes) -> bytes:
    if len(prv)!=len(pub):raise ValueError(f"Key length mismatch: {len(prv)} {len(pub)}")
    if len(prv)==56:return x448.X448PrivateKey.from_private_bytes(prv).exchange(x448.X448PublicKey.from_public_bytes(pub))
    if len(pub)==32:return x25519.X25519PrivateKey.from_private_bytes(prv).exchange(x25519.X25519PublicKey.from_public_bytes(pub))
    raise ValueError("Invalid key length")
def gen_ed25519(overkill=False) -> tuple[bytes, bytes]:private_key = (ed448.Ed448PrivateKey if overkill else ed25519.Ed25519PrivateKey).generate();return private_key.private_bytes(encoding=Encoding.Raw,format=PrivateFormat.Raw,encryption_algorithm=NoEncryption(),), private_key.public_key().public_bytes(encoding=Encoding.Raw,format=PublicFormat.Raw,)
def ed25519_sign(prv:bytes, data:bytes) -> bytes:return load_keys(prv, type=1).sign(data) + data
def ed25519_verify(pub:bytes, data:bytes) -> bytes:sig_len = 114 if len(pub) == 57 else 64;load_keys(pub, type=2).verify(data[:sig_len], data[sig_len:]);return data[sig_len:]
# generate_tls is black magic, and I don't really trust it THAT much, but it gets the job done
def generate_tls(cert_path,key_path,common_name="TLS Certificate",country=None,state=None,locality=None,organization=None,organizational_unit=None,email=None,valid_days=3650,san_ips=None,san_dns=None):
    if os.path.exists(cert_path) and os.path.exists(key_path):return
    san_ips,san_dns=san_ips or [],san_dns or []
    key=ec.generate_private_key(ec.SECP256R1())
    subject=Name([NameAttribute(oid,value) for oid,value in [(NameOID.COMMON_NAME,common_name),(NameOID.COUNTRY_NAME,country),(NameOID.STATE_OR_PROVINCE_NAME,state),(NameOID.LOCALITY_NAME,locality),(NameOID.ORGANIZATION_NAME,organization),(NameOID.ORGANIZATIONAL_UNIT_NAME,organizational_unit),(NameOID.EMAIL_ADDRESS,email)] if value])
    san_entries=[IPAddress(ipaddress.ip_address(ip)) for ip in san_ips]+[DNSName(dns) for dns in san_dns]
    cert=CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1)).not_valid_after(datetime.now(timezone.utc)+timedelta(days=valid_days)).add_extension(BasicConstraints(ca=False,path_length=None),critical=True)
    if san_entries:cert=cert.add_extension(SubjectAlternativeName(san_entries),critical=False)
    cert=cert.sign(key,hashes.SHA256())
    with open(key_path,"wb") as f:f.write(key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
    with open(cert_path,"wb") as f:f.write(cert.public_bytes(Encoding.PEM))
def gen_CA(prv_path,pub_path,cert_path,password=None,common_name=None,country=None,state=None,locality=None,organization=None,organizational_unit=None,email=None,valid_days=3650,overkill=False):
    prv = ed448.Ed448PrivateKey.generate() if overkill else ed25519.Ed25519PrivateKey.generate()
    pub=prv.public_key()
    name_attributes=[]
    if common_name:name_attributes.append(NameAttribute(NameOID.COMMON_NAME,common_name))
    if country:name_attributes.append(NameAttribute(NameOID.COUNTRY_NAME,country))
    if state:name_attributes.append(NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,state))
    if locality:name_attributes.append(NameAttribute(NameOID.LOCALITY_NAME,locality))
    if organization:name_attributes.append(NameAttribute(NameOID.ORGANIZATION_NAME,organization))
    if organizational_unit:name_attributes.append(NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,organizational_unit))
    if email:name_attributes.append(NameAttribute(NameOID.EMAIL_ADDRESS,email))
    subject=Name(name_attributes)
    with open(prv_path,'wb') as f:f.write(prv.private_bytes(Encoding.PEM if prv_path.lower().endswith('.pem') else Encoding.DER,PrivateFormat.PKCS8,BestAvailableEncryption(password) if password else NoEncryption()))
    with open(pub_path,'wb') as f:f.write(pub.public_bytes(Encoding.PEM if pub_path.lower().endswith('.pem') else Encoding.DER,PublicFormat.SubjectPublicKeyInfo))
    with open(cert_path,'wb') as f:f.write(CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(pub).serial_number(random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1)).not_valid_after(datetime.now(timezone.utc)+timedelta(days=valid_days)).add_extension(BasicConstraints(ca=True,path_length=None),critical=True).sign(prv,None).public_bytes(Encoding.PEM if cert_path.lower().endswith('.pem') else Encoding.DER))
def gen_keys(prv_path,pub_path,cert_path,ca_prv_path,ca_cert_path,password=None,ca_password=None,common_name=None,country=None,state=None,locality=None,organization=None,organizational_unit=None,email=None,valid_days=3650,overkill=False):
    with open(ca_prv_path,'rb') as f:ca_priv=load_der_private_key(f.read(),password=ca_password)
    with open(ca_cert_path,'rb') as f:ca_cert=load_der_x509_certificate(f.read())
    prv=(ed448.Ed448PrivateKey.generate() if overkill else ed25519.Ed25519PrivateKey.generate())
    pub=prv.public_key()
    name_attributes=[]
    if common_name:name_attributes.append(NameAttribute(NameOID.COMMON_NAME,common_name))
    if country:name_attributes.append(NameAttribute(NameOID.COUNTRY_NAME,country))
    if state:name_attributes.append(NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,state))
    if locality:name_attributes.append(NameAttribute(NameOID.LOCALITY_NAME,locality))
    if organization:name_attributes.append(NameAttribute(NameOID.ORGANIZATION_NAME,organization))
    if organizational_unit:name_attributes.append(NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,organizational_unit))
    if email:name_attributes.append(NameAttribute(NameOID.EMAIL_ADDRESS,email))
    with open(prv_path,'wb') as f:f.write(prv.private_bytes(Encoding.DER,PrivateFormat.PKCS8,BestAvailableEncryption(password) if password else NoEncryption()))
    with open(pub_path,'wb') as f:f.write(pub.public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo))
    with open(cert_path,'wb') as f:f.write(CertificateBuilder().subject_name(Name(name_attributes)).issuer_name(ca_cert.subject).public_key(pub).serial_number(random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1)).not_valid_after(datetime.now(timezone.utc)+timedelta(days=valid_days)).add_extension(BasicConstraints(ca=False,path_length=None),critical=True).sign(ca_priv,None).public_bytes(Encoding.DER))
def validate_keys(prv,pub,cert=None):
    pub_bytes = load_keys(pub,type=2).public_bytes(Encoding.Raw,PublicFormat.Raw)
    if not hmac.compare_digest(load_keys(prv,type=1).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw), pub_bytes):return False
    if cert!=None:
        if not hmac.compare_digest(load_keys(cert,type=3).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw), pub_bytes):return False
    return True
def load_keys(key,password=None,type=0, *, _retry=True):
    if isinstance(key,str) and os.path.exists(key):
        with open(key,'rb') as f:key=f.read()
    k=key.lstrip() if isinstance(key,bytes) else key
    if isinstance(key,(bytes,bytearray)):
        if k.startswith(b'-----BEGIN'):
            if type in(0,1) and b'PRIVATE KEY' in k:return load_pem_private_key(key,password=password)
            if type in(0,2) and b'PUBLIC KEY' in k:return load_pem_public_key(key)
            if type in(0,3) and b'CERTIFICATE' in k:return load_pem_x509_certificate(key)
        for n,c in ((32,ed25519),(57,ed448)):
            if len(key)==n:
                if type in(0,1):
                    if password!=None:
                        try:return c.Ed25519PrivateKey.from_private_bytes(decryptGCM(key,password)) if n==32 else c.Ed448PrivateKey.from_private_bytes(decryptGCM(key,password))
                        except:pass
                    try:return c.Ed25519PrivateKey.from_private_bytes(key) if n==32 else c.Ed448PrivateKey.from_private_bytes(key)
                    except:pass
                if type in(0,2):
                    try:return c.Ed25519PublicKey.from_public_bytes(key) if n==32 else c.Ed448PublicKey.from_public_bytes(key)
                    except:pass
        if type in(0,1):
            try:return load_der_private_key(key,password=password)
            except:pass
        if type in(0,2):
            try:return load_der_public_key(key)
            except:pass
        if type in(0,3):
            try:return load_der_x509_certificate(key)
            except:pass
    if _retry:
        if password!=None:
            try:return load_keys(key,type=type,_retry=False)
            except ValueError:pass
        if type!=0:
            try:return load_keys(key,password=password,type=0,_retry=False)
            except ValueError:pass
        if password!=None and type!=0:
            return load_keys(key,_retry=False)
    raise ValueError("Unsupported key format")
import os, hmac, json, threading, traceback, base64, re, pyotp, backend, Encryption, util, subprocess, time, getpass
from zxcvbn import zxcvbn
try:Encryption.decryptGCM(b'X' * 100, b'X' * 100)
except Exception as e:DecryptionError = type(e)
SALT_SIZE = 64
MAX_TIMEOUT = 10
EID_SIZE = 8
class ProtocolError(Exception):pass
def _new_eid():return os.urandom(EID_SIZE)
def _derive_at_rest_key(password, salt_or_path):
    if not password:raise ValueError('Password cannot be empty.')
    result = zxcvbn(password)
    guesses_log10 = result.get('guesses_log10', 0)
    if guesses_log10 <= 9:raise ValueError(f'Password too weak (log10 guesses: {guesses_log10:.2f}). Must be > 9.')
    if isinstance(salt_or_path, bytes):
        salt = salt_or_path
        if len(salt) != SALT_SIZE:raise ValueError(f'Salt must be exactly {SALT_SIZE} bytes.')
    else:
        salt_file = os.fspath(salt_or_path)
        if os.path.exists(salt_file):
            with open(salt_file, 'rb') as f:salt = f.read()
            if len(salt) != SALT_SIZE:raise ValueError(f'Salt file must contain exactly {SALT_SIZE} bytes.')
        else:
            salt = os.urandom(SALT_SIZE)
            with open(salt_file, 'wb') as f:f.write(salt)
    return Encryption.kdf_slow(password.encode('utf-8'), salt)
def validate_auth_keys(at_rest_key):
    directory='./auth keys'
    os.makedirs(directory, exist_ok=True)
    os.makedirs('./server keys', exist_ok=True)
    for filename in os.listdir(directory):
        path = os.path.join(directory, filename)
        if (os.path.isfile(path) and not filename.endswith(('.prv', '.pub'))):os.remove(path)
    stems = {os.path.splitext(filename)[0] for filename in os.listdir(directory) if filename.endswith(('.prv', '.pub'))}
    pairs = []
    for stem in stems:
        prv = os.path.join(directory, stem + '.prv')
        pub = os.path.join(directory, stem + '.pub')
        if os.path.isfile(prv) and os.path.isfile(pub):
            try:
                with open(prv, 'rb') as f:p_bytes = Encryption.decryptGCM(f.read(), at_rest_key)
                with open(pub, 'rb') as f:b_bytes = Encryption.decryptGCM(f.read(), at_rest_key)
                tmp_key = Encryption.gen_x25519(True)
                if Encryption.shared_secret(tmp_key[0], b_bytes) == Encryption.shared_secret(p_bytes, tmp_key[1]):
                    pairs.append((prv, pub))
                    continue
            except DecryptionError:raise
            except Exception:pass
        for path in (prv, pub):
            if os.path.exists(path):os.remove(path)
    return pairs
class TCPServer:
    def __init__(self, host, port, password, newTOTP=False, on_exchange=None, simult_exchanges=4):
        self.on_exchange = on_exchange
        self.newTOTP = newTOTP
        self.last_bootstrap=0
        self.last_admin=0
        self._enable_bootstrap = False
        os.makedirs('./auth keys', exist_ok=True)
        os.makedirs('./server keys', exist_ok=True)
        self.at_rest_key = _derive_at_rest_key(password, './server keys/server_salt.bin')
        validate_auth_keys(self.at_rest_key)
        self.bootstrap_totp_path = './server keys/BOOTSTRAP - TOTP.bin'
        self.admin_totp_path = './server keys/ADMIN - TOTP.bin'
        self._sig_keys = ['./server keys/SIGNING KEY.pub','./server keys/SIGNING KEY.prv']
        if any([not os.path.exists(x) for x in self._sig_keys]):
            try:os.remove(self._sig_keys[0])
            except:pass
            try:os.remove(self._sig_keys[1])
            except:pass
            keys=Encryption.gen_ed25519(True)
            with open(self._sig_keys[0],'wb') as f:f.write(Encryption.encryptGCM(keys[0],self.at_rest_key))
            with open(self._sig_keys[1],'wb') as f:f.write(Encryption.encryptGCM(keys[1],self.at_rest_key))
        with open(self._sig_keys[0],'rb') as f:prv=Encryption.decryptGCM(f.read(),self.at_rest_key)
        with open(self._sig_keys[1],'rb') as f:pub=Encryption.decryptGCM(f.read(),self.at_rest_key)
        self.signing_keys=(prv,pub)
        if self.newTOTP or not os.path.exists(self.admin_totp_path):
            totp_secret_bytes = os.urandom(20)
            base32_secret = base64.b32encode(totp_secret_bytes).decode('utf-8')
            encrypted_totp = Encryption.encryptGCM(totp_secret_bytes, self.at_rest_key)
            with open(self.admin_totp_path, 'wb') as f:f.write(encrypted_totp)
            print(f'--- NEW TOTP SECRET (Base32): {base32_secret} ---')
            print('Console will be cleared in 30 seconds for security.')
            def clear_console():
                try:subprocess.run('cls' if os.name == 'nt' else 'clear',shell=True)
                except Exception:pass
                print(f'Server Certificate: {util.to_hex(pub)}')
            threading.Timer(30.0, clear_console).start()
        print(f'Server Certificate: {util.to_hex(pub)}')
        self._lock = threading.RLock()
        self._backend = backend.Server(host, port, handshake_worker=self._hs_worker, on_exchange=self._backend_on_exchange, on_disconnect=self._backend_on_disconnect, simult_handshakes=1, simult_exchanges=simult_exchanges)
        self._keys = {}
        self._counters = {}
        self._admin = {}
        self._usernames = {}
        self._pending_bootstrap_totp = {}
        self._backend.start()
    def start(self):self._backend.start()
    def _send_handshake(self, temp_cid, data):self._backend.send_handshake(temp_cid, data)
    def _recv_handshake(self, temp_cid, timeout=1):return self._backend.recv_handshake(temp_cid, timeout=timeout)
    def _hs_worker(self, temp_cid):
        is_bootstrap = False
        is_admin = False
        try:
            self._send_handshake(temp_cid, self.signing_keys[1])
            client_pub = self._recv_handshake(temp_cid, timeout=1)
            if client_pub is None:raise ProtocolError('Handshake timed out')
            if client_pub.startswith(b'REQ_ADMIN'):
                if time.time() - self.last_admin < 30:raise ProtocolError('Admin authentication is on cooldown')
                is_admin = True
                client_init_pub = client_pub[len(b'REQ_ADMIN'):]
                init_key = Encryption.gen_x25519(True)
                tss = Encryption.shared_secret(init_key[0], client_init_pub)
                ekey_defined = False
                sc, rc = 1, 0
                def send_enc(data):
                    nonlocal sc, ekey_defined
                    ctr = sc.to_bytes(8, 'big')
                    sc += 1
                    if ekey_defined:self._send_handshake(temp_cid, ctr + Encryption.encryptGCM(data, ekey, aad=ctr + b'1'))
                    else:self._send_handshake(temp_cid, ctr + Encryption.encryptGCM(data, tss, aad=ctr + b'1'))
                def recv_enc(timeout=1):
                    nonlocal rc, ekey_defined
                    payload = self._recv_handshake(temp_cid, timeout=timeout)
                    if payload is None:raise ProtocolError('Timed out')
                    ctr = payload[:8]
                    counter = int.from_bytes(ctr, 'big')
                    if counter != rc + 1:raise ProtocolError('Counter Error')
                    if ekey_defined:out = Encryption.decryptGCM(payload[8:], ekey, aad=ctr + b'0')
                    else:out = Encryption.decryptGCM(payload[8:], tss, aad=ctr + b'0')
                    rc = counter
                    return out
                tss_salt = os.urandom(64)
                self._send_handshake(temp_cid, Encryption.ed25519_sign(self.signing_keys[0], init_key[1] + tss_salt))
                with open(self.admin_totp_path, 'rb') as f:code = pyotp.TOTP(base64.b32encode(Encryption.decryptGCM(f.read(), self.at_rest_key)).decode('utf-8')).now()
                self.last_admin = time.time()
                tss = Encryption.kdf(util.str_to_bytes(code), tss_salt + tss, 5)
                nonce1 = os.urandom(32)
                send_enc(nonce1)
                nonce2 = recv_enc(timeout=5)
                nhash = Encryption.basic_kdf(nonce1 + nonce2, b'', 64)
                if recv_enc() != nhash:raise ProtocolError('Auth Failed')
                send_enc(Encryption.basic_kdf(nhash, b'', 64))
                ekey = tss
                ekey_defined = True
                _hash = temp_cid
                auth_file = ''
            else:
                auth_file = ''
                for filename in os.listdir('./auth keys'):
                    if not filename.endswith('.pub'):continue
                    auth_path = os.path.join('./auth keys', filename)
                    with open(auth_path, 'rb') as f:stored_pub = Encryption.ed25519_verify(self.signing_keys[1],f.read())
                    if hmac.compare_digest(stored_pub, client_pub):
                        auth_file = auth_path
                        break
                if auth_file:
                    self._send_handshake(temp_cid, b'ACK')
                    keys = Encryption.gen_x25519(True)
                    self._send_handshake(temp_cid, Encryption.ed25519_sign(self.signing_keys[0], keys[1]))
                    signed_client_ephemeral = self._recv_handshake(temp_cid, timeout=5)
                    if signed_client_ephemeral is None:raise ProtocolError('Handshake timed out')
                    client_ephemeral_pub = Encryption.ed25519_verify(client_pub, signed_client_ephemeral)
                    if client_ephemeral_pub is None:raise ProtocolError('Auth Failed')
                    ekey = Encryption.shared_secret(keys[0], client_ephemeral_pub)
                    sc, rc = 1, 0
                    _hash = Encryption.basic_kdf(client_pub, b'', 6)
                else:
                    if not self._enable_bootstrap:raise ProtocolError('Bootstrap authentication is disabled')
                    if time.time() - self.last_bootstrap < 30:raise ProtocolError('Bootstrap authentication is on cooldown')
                    self.last_bootstrap = time.time()
                    is_bootstrap = True
                    self._send_handshake(temp_cid, b'NACK')
                    init_key = Encryption.gen_x25519(True)
                    tss_salt = os.urandom(64)
                    self._send_handshake(temp_cid, Encryption.ed25519_sign(self.signing_keys[0], init_key[1] + tss_salt))
                    signed_client_ephemeral = self._recv_handshake(temp_cid, timeout=5)
                    if signed_client_ephemeral is None:raise ProtocolError('Handshake timed out')
                    client_ephemeral_pub = Encryption.ed25519_verify(client_pub, signed_client_ephemeral)
                    if client_ephemeral_pub is None:raise ProtocolError('Auth Failed')
                    tss = Encryption.shared_secret(init_key[0], client_ephemeral_pub)
                    with open(self.bootstrap_totp_path, 'rb') as f:code = pyotp.TOTP(base64.b32encode(Encryption.decryptGCM(f.read(), self.at_rest_key)).decode('utf-8')).now()
                    tss = Encryption.kdf(util.str_to_bytes(code), tss_salt + tss, 5)
                    sc, rc = 1, 0
                    def send_enc(data):
                        nonlocal sc
                        ctr = sc.to_bytes(8, 'big')
                        sc += 1
                        self._send_handshake(temp_cid, ctr + Encryption.encryptGCM(data, tss, aad=ctr + b'1'))
                    def recv_enc(timeout=1):
                        nonlocal rc
                        payload = self._recv_handshake(temp_cid, timeout=timeout)
                        if payload is None:raise ProtocolError('Timed out')
                        ctr = payload[:8]
                        counter = int.from_bytes(ctr, 'big')
                        if counter != rc + 1:raise ProtocolError('Counter Error')
                        out = Encryption.decryptGCM(payload[8:], tss, aad=ctr + b'0')
                        rc = counter
                        return out
                    nonce1 = os.urandom(32)
                    send_enc(nonce1)
                    nonce2 = recv_enc(timeout=5)
                    nhash = Encryption.basic_kdf(nonce1 + nonce2, b'', 64)
                    if recv_enc() != nhash:raise ProtocolError('Auth Failed')
                    send_enc(Encryption.basic_kdf(nhash, b'', 64))
                    init_key2 = Encryption.gen_x25519(True)
                    self._send_handshake(temp_cid, Encryption.ed25519_sign(self.signing_keys[0], init_key2[1]))
                    signed_client_ephemeral2 = self._recv_handshake(temp_cid, timeout=5)
                    if signed_client_ephemeral2 is None:raise ProtocolError('Handshake timed out')
                    client_ephemeral_pub2 = Encryption.ed25519_verify(client_pub, signed_client_ephemeral2)
                    if client_ephemeral_pub2 is None:raise ProtocolError('Auth Failed')
                    ekey = Encryption.shared_secret(init_key2[0], client_ephemeral_pub2)
                    fid = os.urandom(16).hex()
                    with open(os.path.join('./auth keys', fid + '.pub'), 'wb') as f:f.write(Encryption.ed25519_sign(self.signing_keys[0],client_pub))
                    _hash = Encryption.basic_kdf(client_pub, b'', 6)
            with self._lock:
                self._keys[_hash] = ekey
                self._counters[_hash] = [sc, rc]
                self._admin[_hash] = is_admin
                try:
                    if auth_file:self._usernames[_hash] = auth_file[:-4]
                    elif is_bootstrap:self._usernames[_hash] = os.path.join('./auth keys', fid)
                except:pass
                self._backend.auth_finished(temp_cid, _hash)
        except Exception as exc:traceback.print_exception(exc)
    def _admin_send_json(self, result, eid, cid):
        header = json.dumps(result, separators=(',', ':')).encode('utf-8')
        packet = len(header).to_bytes(4, 'big') + header
        self.send(packet, eid, cid)
    def _admin_require(self, cid):
        if not self._admin.get(cid, False):raise ProtocolError('Not Admin')
    def setup_bootstrap_totp(self, cid, eid):
        self._admin_require(cid)
        secret_bytes = os.urandom(20)
        with self._lock:self._pending_bootstrap_totp[cid] = secret_bytes
        self._admin_send_json({'status':'ok','secret':base64.b32encode(secret_bytes).decode('ascii'),'message':'Pending verification; the active secret is unchanged until verified.'}, eid, cid)
    def bootstrapping_enabled(self,cid,eid):
        if self._enable_bootstrap:self._admin_send_json({'status':'ok', 'enabled':True},eid,cid)
        else:self._admin_send_json({'status':'ok', 'enabled':False},eid,cid)
    def bootstrap_status(self, cid, eid):
        self._admin_require(cid)
        self._admin_send_json({'status':'ok','enabled':bool(self._enable_bootstrap),'totp_configured':os.path.isfile(self.bootstrap_totp_path)}, eid, cid)
    def verify_bootstrap_totp(self, cid, eid, code):
        self._admin_require(cid)
        code = str(code).strip().replace(' ', '')
        with self._lock:secret_bytes = self._pending_bootstrap_totp.get(cid)
        if secret_bytes is None:raise ProtocolError('No pending bootstrap TOTP setup. Generate a new secret first.')
        totp = pyotp.TOTP(base64.b32encode(secret_bytes).decode('ascii'))
        if not (code.isdigit() and len(code) == totp.digits and totp.verify(code, valid_window=1)):raise ProtocolError('TOTP verification failed; check the authenticator time and try again.')
        temp_path = self.bootstrap_totp_path + '.tmp'
        try:
            with open(temp_path, 'wb') as stream:
                stream.write(Encryption.encryptGCM(secret_bytes, self.at_rest_key))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_path, self.bootstrap_totp_path)
        except Exception:
            try:os.remove(temp_path)
            except OSError:pass
            raise
        with self._lock:self._pending_bootstrap_totp.pop(cid, None)
        self._admin_send_json({'status':'ok','verified':True,'message':'Bootstrap TOTP verified and saved.'}, eid, cid)
    def enable_bootstrap(self,cid,eid):
        self._admin_require(cid)
        self._enable_bootstrap=True
        self._admin_send_json({'status':'ok', 'enabled':True},eid,cid)
    def disable_bootstrap(self,cid,eid):
        self._admin_require(cid)
        self._enable_bootstrap=False
        self._admin_send_json({'status':'ok', 'enabled':False},eid,cid)
    def _admin_parse_client_id(self, client_id):
        if isinstance(client_id, bytes):return client_id
        if isinstance(client_id, str):
            try:return bytes.fromhex(client_id)
            except ValueError:raise ProtocolError('Invalid client ID')
        raise ProtocolError('Invalid client ID')
    def _admin_validate_username(self, username):
        if not isinstance(username, str):raise ProtocolError('Invalid username')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', username):raise ProtocolError('Invalid username')
        if username in ('.', '..'):raise ProtocolError('Invalid username')
        return username
    def _admin_validate_stored_username(self, username):
        if not isinstance(username, str) or not username:raise ProtocolError('Invalid stored username')
        if '/' in username or '\\' in username:
            username = username.replace('\\', '/').rsplit('/', 1)[-1]
            username = os.path.splitext(username)[0]
        if username in ('', '.', '..') or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', username):raise ProtocolError('Invalid stored username')
        return username
    def list_users(self,cid,eid):
        self._admin_require(cid)
        tmp=set()
        users=set()
        for x in os.listdir('./auth keys'):
            name=x[:-4]
            if x.endswith('.prv') or x.endswith('.pub'):
                if name in tmp:users.add(name);tmp.discard(name)
                else:tmp.add(x[:-4])
        self._admin_send_json({'status':'ok', 'users':sorted(users)},eid,cid)
    def list_connections(self, cid, eid):
        self._admin_require(cid)
        with self._lock:connections = [{'cid':client_id.hex() if isinstance(client_id, bytes) else str(client_id),'username':self._usernames[client_id],} for client_id in self._keys if client_id in self._usernames]
        connections.sort(key=lambda client:client['username'].lower())
        self._admin_send_json({'status':'ok', 'connections':connections},eid,cid)
    def server_cert(self,cid,eid):self._admin_send_json({'status':'ok', 'cert':util.to_hex(self.signing_keys[1])},eid,cid)
    def rename_username(self, cid, eid, target_cid, new_username):
        self._admin_require(cid)
        new_username = self._admin_validate_username(new_username)
        with self._lock:
            connected_id = None
            if isinstance(target_cid, bytes):
                if target_cid in self._usernames and target_cid in self._keys:connected_id = target_cid
                else:raise ProtocolError('Unknown connected client')
            elif isinstance(target_cid, str):
                try:parsed_id = bytes.fromhex(target_cid)
                except ValueError:parsed_id = None
                if parsed_id is not None and parsed_id in self._usernames and parsed_id in self._keys:connected_id = parsed_id
            if connected_id is not None:old_username = self._admin_validate_stored_username(self._usernames[connected_id])
            elif isinstance(target_cid, str):old_username = self._admin_validate_stored_username(target_cid)
            else:raise ProtocolError('Invalid client identifier')
            old_prv = os.path.join('./auth keys', old_username + '.prv')
            old_pub = os.path.join('./auth keys', old_username + '.pub')
            new_prv = os.path.join('./auth keys', new_username + '.prv')
            new_pub = os.path.join('./auth keys', new_username + '.pub')
            if old_username == new_username:result = {'ok':True,'username':new_username,'connected':connected_id is not None,'renamed_files':False,}
            else:
                if not os.path.isfile(old_prv) or not os.path.isfile(old_pub):raise ProtocolError('Client key files not found')
                if os.path.exists(new_prv) or os.path.exists(new_pub):raise ProtocolError('Username already exists')
                try:
                    os.rename(old_prv, new_prv)
                    try:os.rename(old_pub, new_pub)
                    except Exception:
                        os.rename(new_prv, old_prv)
                        raise
                except Exception as exc:raise ProtocolError(f'Rename failed:{exc}') from exc
                for live_id, stored_username in list(self._usernames.items()):
                    if live_id not in self._keys:continue
                    try:normalized = self._admin_validate_stored_username(stored_username)
                    except ProtocolError:continue
                    if normalized == old_username:self._usernames[live_id] = new_username
                result = {'ok':True,'old_username':old_username,'username':new_username,'connected':connected_id is not None,'renamed_files':True,}
        result['status'] = 'ok'
        self._admin_send_json(result, eid, cid)
    def deauth_client(self, cid, eid, target_cid):
        self._admin_require(cid)
        target_cid = self._admin_parse_client_id(target_cid)
        with self._lock:
            if target_cid not in self._usernames:raise ProtocolError('Unknown client')
            username = self._admin_validate_stored_username(self._usernames[target_cid])
            prv = os.path.join('./auth keys', username + '.prv')
            pub = os.path.join('./auth keys', username + '.pub')
            if not os.path.isfile(prv) or not os.path.isfile(pub):raise ProtocolError('Client key files not found')
            os.remove(prv)
            os.remove(pub)
        self._admin_send_json({'status':'ok', 'deauthenticated':True, 'username':username},eid,cid)
    def disconnect_client(self, cid, eid, target_cid):
        self._admin_require(cid)
        target_cid = self._admin_parse_client_id(target_cid)
        with self._lock:
            if target_cid not in self._usernames:raise ProtocolError('Unknown client')
            if target_cid not in self._keys:raise ProtocolError('Client is not connected')
        close_client = getattr(self._backend, 'close_client', None)
        if not callable(close_client):raise ProtocolError('Backend does not support close_client(client_id)')
        try:close_client(target_cid)
        except Exception as exc:raise ProtocolError(f'Disconnect failed: {exc}') from exc
        with self._lock:self._usernames.pop(target_cid, None)
        self.close_client(target_cid,False)
        self._admin_send_json({'status':'ok', 'disconnected':True},eid,cid)
    def _backend_on_disconnect(self, client_id):self.close_client(client_id,False)
    def _backend_on_exchange(self, cid, eid):
        try:
            data = self.recv(cid, eid=eid, timeout=1)
            if data is None:return
            if self.on_exchange is not None:self.on_exchange(self, eid, data, cid)
        except Exception:traceback.print_exc()
    def send(self, payload, eid=None, client_id=None):
        if eid is not None and (not isinstance(eid, bytes) or len(eid) != EID_SIZE):raise ValueError('eid must be exactly 8 bytes')
        with self._lock:
            if client_id is None:raise ValueError('client_id is required when starting a server exchange')
            if client_id not in self._keys:raise ProtocolError('Client is not authenticated')
            ekey = self._keys[client_id]
            sc, rc = self._counters[client_id]
            self._counters[client_id][0] += 1
        if eid is None:eid = _new_eid()
        ctr = sc.to_bytes(8, 'big')
        return self._backend.send(ctr + Encryption.encryptGCM(payload, ekey, aad=eid + ctr + b'1'), client_id, eid=eid)
    def recv(self, client_id, eid, timeout=MAX_TIMEOUT):
        if not isinstance(eid, bytes) or len(eid) != EID_SIZE:raise ValueError('eid must be exactly 8 bytes')
        with self._lock:
            if client_id not in self._keys:raise ProtocolError('Client is not authenticated')
            ekey = self._keys[client_id]
        raw = self._backend.recv(client_id, eid=eid, timeout=min(timeout, MAX_TIMEOUT))
        if raw is None:return None
        ctr = raw[:8]
        counter = int.from_bytes(ctr, 'big')
        data=Encryption.decryptGCM(raw[8:], ekey, aad=eid + ctr + b'0')
        with self._lock:
            sc, rc = self._counters[client_id]
            if counter <= rc:raise ProtocolError('Counter Error')
            self._counters[client_id][1] = counter
        return data
    def close_client(self, client_id, close=True):
        try:
            if close:self._backend.close_client(client_id)
        finally:
            with self._lock:
                self._keys.pop(client_id, None)
                self._counters.pop(client_id, None)
                self._admin.pop(client_id, None)
                self._usernames.pop(client_id, None)
    def set_backpressure(self, client_id, enabled=True):self._backend.set_backpressure(client_id, enabled)
    def close(self):
        self._backend.stop()
        with self._lock:
            self._keys.clear()
            self._admin.clear()
            self._usernames.clear()
            self._counters.clear()
class TCPClient:
    def __init__(self, host, port, password, admin_auth_code = None, on_exchange=None, simult_exchanges=4):
        self.on_exchange = on_exchange
        self.admin_auth_code=admin_auth_code
        self.host=host
        self.port=port
        self.simult_exchanges=simult_exchanges
        self._lock = threading.RLock()
        self.sc = 1
        self.rc = 0
        self.ekey = None
        self.at_rest_key = None
        self.server_cert=b''
        if admin_auth_code is None:
            os.makedirs('./client keys',exist_ok=True)
            self.salt=os.urandom(SALT_SIZE)
            try:
                with open('./client keys/auth_key', 'rb') as f:
                    self.salt = f.read(SALT_SIZE)
                    encrypted_prv = f.read()
                if len(self.salt) != SALT_SIZE:raise ProtocolError('Invalid auth_key: missing salt')
                if not encrypted_prv:raise ProtocolError('Invalid auth_key: missing key data')
            except:pass
            try:
                try:self.at_rest_key = _derive_at_rest_key(password, self.salt)
                except:pass
                self.sig_prv = Encryption.decryptGCM(encrypted_prv, self.at_rest_key)
                self.pub_key = Encryption.get_pub(self.sig_prv)
                try:
                    if os.path.exists('./client keys/Server cert.pub'):
                        with open('./client keys/Server cert.pub','rb') as f:self.server_cert=Encryption.ed25519_verify(self.pub_key,f.read())
                except:pass
            except:pass
        if self.server_cert==b'':self.server_cert=util.from_hex(input('The server cannot be verified as there isn\'t a saved certificate.\nPlease paste the certificate here: '))
        try:self._authenticate()
        except Exception:
            self.close()
            raise
    def _send_handshake(self, payload):self._backend.send_handshake(payload)
    def _recv_handshake(self, timeout=1):return self._backend.recv_handshake(timeout=timeout)
    def _authenticate(self):
        is_admin = isinstance(self.admin_auth_code, str)
        is_bootstrap = not is_admin and not os.path.exists('./client keys/auth_key')
        if is_bootstrap:totp_code = getpass.getpass('Auth Key Security Code: ')
        self._backend = backend.Client(self.host, self.port, on_exchange=self._backend_on_exchange, simult_exchanges=self.simult_exchanges)
        if is_admin:
            init_key = Encryption.gen_x25519(True)
            if not self.admin_auth_code:raise ValueError('admin_auth_code must not be empty')
            self._send_handshake(b'REQ_ADMIN' + init_key[1])
            server_cert = self._recv_handshake(timeout=1)
            if self.server_cert != server_cert:raise ProtocolError('Server certificate is invalid')
            response = Encryption.ed25519_verify(server_cert, self._recv_handshake(timeout=1))
            if response is None:raise ProtocolError('Handshake timed out')
            tss = Encryption.kdf(util.str_to_bytes(self.admin_auth_code), response[-64:] + Encryption.shared_secret(init_key[0], response[:-64]), 5)
            sc, rc = 1, 0
            def _send_enc(payload):
                nonlocal sc
                ctr = sc.to_bytes(8, 'big')
                sc += 1
                self._send_handshake(ctr + Encryption.encryptGCM(payload, tss, aad=ctr + b'0'))
            def _recv_enc(timeout=1):
                nonlocal rc
                payload = self._recv_handshake(timeout=timeout)
                if payload is None:raise ProtocolError('Timed out')
                ctr = payload[:8]
                counter = int.from_bytes(ctr, 'big')
                if counter != rc + 1:raise ProtocolError('Counter Error')
                out = Encryption.decryptGCM(payload[8:], tss, aad=ctr + b'1')
                rc = counter
                return out
            nonce2 = os.urandom(32)
            _send_enc(nonce2)
            nhash = Encryption.basic_kdf(_recv_enc() + nonce2, b'', 64)
            _send_enc(nhash)
            if _recv_enc() != Encryption.basic_kdf(nhash, b'', 64):raise ProtocolError('Auth Failed')
            self.ekey = tss
            self.sc, self.rc = sc, rc
        else:
            if is_bootstrap:
                sig_keys = Encryption.gen_ed25519(True)
                self.sig_prv, self.pub_key = sig_keys[0], sig_keys[1]
            self._send_handshake(self.pub_key)
            server_cert = self._recv_handshake(timeout=1)
            if self.server_cert != server_cert:raise ProtocolError('Server certificate is invalid')
            with open('./client keys/Server cert.pub', 'wb') as f:f.write(server_cert)
            status = self._recv_handshake(timeout=5)
            if status == b'ACK':
                with open('./client keys/Server cert.pub', 'wb') as f:f.write(server_cert)
                response = Encryption.ed25519_verify(server_cert, self._recv_handshake(timeout=5))
                if response is None:raise ProtocolError('Handshake timed out')
                server_ephemeral_pub = response
                keys = Encryption.gen_x25519(True)
                self._send_handshake(Encryption.ed25519_sign(self.sig_prv, keys[1]))
                self.ekey = Encryption.shared_secret(keys[0], server_ephemeral_pub)
                self.sc, self.rc = 1, 0
            elif status == b'NACK':
                with open('./client keys/Server cert.pub', 'wb') as f:f.write(server_cert)
                response = Encryption.ed25519_verify(server_cert, self._recv_handshake(timeout=5))
                if response is None:raise ProtocolError('Handshake timed out')
                server_ephemeral_pub = response[:-64]
                tss_salt = response[-64:]
                keys = Encryption.gen_x25519(True)
                self._send_handshake(Encryption.ed25519_sign(self.sig_prv, keys[1]))
                tss = Encryption.shared_secret(keys[0], server_ephemeral_pub)
                tss = Encryption.kdf(util.str_to_bytes(totp_code), tss_salt + tss, 5)
                sc, rc = 1, 0
                def _send_enc(payload):
                    nonlocal sc
                    ctr = sc.to_bytes(8, 'big')
                    sc += 1
                    self._send_handshake(ctr + Encryption.encryptGCM(payload, tss, aad=ctr + b'0'))
                def _recv_enc(timeout=1):
                    nonlocal rc
                    payload = self._recv_handshake(timeout=timeout)
                    if payload is None:raise ProtocolError('Timed out')
                    ctr = payload[:8]
                    counter = int.from_bytes(ctr, 'big')
                    if counter != rc + 1:raise ProtocolError('Counter Error')
                    out = Encryption.decryptGCM(payload[8:], tss, aad=ctr + b'1')
                    rc = counter
                    return out
                nonce2 = os.urandom(32)
                _send_enc(nonce2)
                nhash = Encryption.basic_kdf(_recv_enc() + nonce2, b'', 64)
                _send_enc(nhash)
                if _recv_enc() != Encryption.basic_kdf(nhash, b'', 64):raise ProtocolError('Auth Failed')
                server_cert2 = self._recv_handshake(timeout=5)
                response2 = Encryption.ed25519_verify(server_cert, server_cert2)
                if response2 is None:raise ProtocolError('Handshake timed out')
                server_ephemeral_pub2 = response2
                keys2 = Encryption.gen_x25519(True)
                self._send_handshake(Encryption.ed25519_sign(self.sig_prv, keys2[1]))
                self.ekey = Encryption.shared_secret(keys2[0], server_ephemeral_pub2)
                self.sc, self.rc = sc, rc
                with open('./client keys/auth_key', 'wb') as f:
                    f.write(self.salt)
                    f.write(Encryption.encryptGCM(self.sig_prv, self.at_rest_key))
            else:raise ProtocolError('Auth Denied')
        self._backend.auth_finished()
    def send(self, payload, eid=None):
        if eid is not None and (not isinstance(eid, bytes) or len(eid) != EID_SIZE):raise ValueError('eid must be exactly 8 bytes')
        with self._lock:
            if self.ekey is None:raise ProtocolError('Client is not authenticated')
            if eid is None:eid = _new_eid()
            ctr = self.sc.to_bytes(8, 'big')
            encrypted = ctr + Encryption.encryptGCM(payload, self.ekey, aad=eid + ctr + b'0')
            self.sc += 1
            return self._backend.send(encrypted, eid=eid)
    def recv(self, eid, timeout=MAX_TIMEOUT):
        if not isinstance(eid, bytes) or len(eid) != EID_SIZE:raise ValueError('eid must be exactly 8 bytes')
        with self._lock:
            if self.ekey is None:raise ProtocolError('Client is not authenticated')
            ekey = self.ekey
        effective_timeout = None if timeout is None else min(timeout, MAX_TIMEOUT)
        raw = self._backend.recv(eid, timeout=effective_timeout)
        if raw is None:return None
        if len(raw) < 8:raise ProtocolError('Invalid encrypted response: missing counter')
        ctr = raw[:8]
        counter = int.from_bytes(ctr, 'big')
        with self._lock:
            if counter <= self.rc:raise ProtocolError('Counter Error')
            self.rc = counter
        return Encryption.decryptGCM(raw[8:], ekey, aad=eid + ctr + b'1')
    def _backend_on_exchange(self, eid):
        try:
            data = self.recv(eid, timeout=1)
            if data is None:return
            if self.on_exchange is not None:self.on_exchange(self, eid, data)
        except Exception:traceback.print_exc()
    def set_backpressure(self, enabled=True):self._backend.set_backpressure(enabled)
    def close(self):
        backend_client = getattr(self, '_backend', None)
        try:
            if backend_client is not None:backend_client.close()
        finally:
            lock = getattr(self, '_lock', None)
            if lock is not None:
                with lock:
                    self.ekey = None
                    self.at_rest_key = None
                    self.sc = 1
                    self.rc = 0
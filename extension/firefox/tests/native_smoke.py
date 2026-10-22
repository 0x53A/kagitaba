"""Real Firefox -> compiled native host -> synthetic Unix socket gateway.

Build target/debug/kagitaba-app and the extension first. Run in nix-shell with
geckodriver: uv run --with selenium --with cryptography extension/firefox/tests/native_smoke.py.
No physical key, real wallet, user Firefox profile or persistent host registration.
"""
import base64
import hashlib
import datetime
import http.server
import json
import os
from pathlib import Path
import queue
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.support.ui import WebDriverWait

ROOT = Path(__file__).resolve().parents[3]


def receive(stream):
    def exact(size):
        result = b""
        while len(result) < size:
            chunk = stream.recv(size - len(result))
            if not chunk:
                raise EOFError
            result += chunk
        return result
    size, = struct.unpack("=I", exact(4))
    assert 0 < size <= 65536
    return json.loads(exact(size))


def main():
    binary = ROOT / "target/debug/kagitaba-app"
    assert binary.is_file(), "Build the native application first"
    with tempfile.TemporaryDirectory(prefix="kagitaba-native-") as temporary:
        root = Path(temporary)
        home, runtime = root / "home", root / "runtime"
        home.mkdir(mode=0o700)
        runtime.mkdir(mode=0o700)
        (runtime / "kagitaba").mkdir(mode=0o700)
        subprocess.run(["uv", "run", "--no-project", str(ROOT / "tools/install_native_host.py"),
                        str(binary), "--directory", str(home / ".mozilla/native-messaging-hosts")], check=True)
        listener = socket.socket(socket.AF_UNIX)
        path = runtime / "kagitaba/browser.sock"
        listener.bind(str(path))
        path.chmod(0o600)
        listener.listen()
        received, approvals, cancelled = queue.Queue(), queue.Queue(), queue.Queue()

        passkey = ec.generate_private_key(ec.SECP256R1())
        def b64(value):
            return base64.urlsafe_b64encode(value).decode().rstrip("=")

        def gateway():
            for mode in ["approve", "cancel", "passkey"]:
                stream, _ = listener.accept()
                with stream:
                    stream.settimeout(15)
                    request = receive(stream)
                    received.put(request)
                    if mode == "approve":
                        approvals.get(timeout=15)
                        wire = json.dumps(dict(version=1, username="synthetic-user", password="synthetic-password")).encode()
                        stream.sendall(struct.pack("=I", len(wire)) + wire)
                    elif mode == "passkey":
                        client = json.dumps(dict(type="webauthn.get", challenge=request["input"]["challenge"], origin=request["origin"], crossOrigin=False)).encode()
                        auth = hashlib.sha256(b"example.test").digest() + bytes([5]) + bytes(4)
                        signature = passkey.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
                        wire = json.dumps(dict(version=1, credential=dict(id=b64(b"synthetic-id"), response=dict(clientDataJSON=b64(client), authenticatorData=b64(auth), signature=b64(signature), userHandle=b64(b"synthetic-user")), extensions={}))).encode()
                        stream.sendall(struct.pack("=I", len(wire)) + wire)
                    else:
                        cancelled.put(stream.recv(1) == b"")
        thread = threading.Thread(target=gateway, daemon=True)
        # A non-JSON payload proves that the executable bridge is opaque.
        opaque = b"\xffopaque transport\x00"
        process = subprocess.Popen([str(binary), "--native-messaging", "firefox@kagitaba.local"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env={**os.environ,"XDG_RUNTIME_DIR":str(runtime)})
        try:
            process.stdin.write(struct.pack("=I", len(opaque)) + opaque)
            process.stdin.flush()
            stream, _ = listener.accept()
            with stream:
                stream.settimeout(5)
                wire = b""
                while len(wire) < len(opaque)+4:
                    wire += stream.recv(len(opaque)+4-len(wire))
                assert wire == struct.pack("=I", len(opaque)) + opaque
                stream.sendall(wire)
                assert process.stdout.read(len(wire)) == wire
            assert process.wait(timeout=5) == 0
        finally:
            if process.poll() is None:
                process.kill()
            process.stdin.close()
            process.stdout.close()
        thread.start()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
                .not_valid_after(now+datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.test")]), critical=False).sign(key,hashes.SHA256()))
        (root / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (root / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))

        class Page(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b'<!doctype html><title>Gateway test</title><form><input autocomplete="username"><input type="password"></form>')
            def log_message(self, *args):
                pass

        website = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Page)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(root / "cert.pem", root / "key.pem")
        website.socket = tls.wrap_socket(website.socket, server_side=True)
        threading.Thread(target=website.serve_forever, daemon=True).start()
        origin = f"https://example.test:{website.server_port}"
        xpi = root / "extension.xpi"
        with zipfile.ZipFile(xpi, "w") as archive:
            for source in (ROOT / "extension/firefox/dist").iterdir():
                archive.write(source, source.name)
        options = Options()
        options.add_argument("-headless")
        options.add_argument("-remote-allow-system-access")
        options.binary_location = shutil.which("firefox")
        options.set_preference("network.dns.localDomains", "example.test")
        service = Service(log_output=str(root / "geckodriver.log"), env={**os.environ, "HOME":str(home), "XDG_RUNTIME_DIR":str(runtime)})
        driver = webdriver.Firefox(options=options, service=service)
        try:
            driver.install_addon(str(xpi), temporary=True)
            driver.set_context("chrome")
            uuids = json.loads(driver.execute_script("return Services.prefs.getStringPref('extensions.webextensions.uuids');"))
            driver.set_context("content")
            driver.get(origin)
            site_handle = driver.current_window_handle
            driver.switch_to.new_window("tab")
            driver.get(f"moz-extension://{uuids['firefox@kagitaba.local']}/app.html")
            app_handle = driver.current_window_handle
            driver.set_script_timeout(15)
            def send(message):
                result = driver.execute_async_script("const done=arguments[arguments.length-1];browser.runtime.sendMessage(arguments[0]).then(value=>done({value}),error=>done({error:error.message}));",message)
                assert "error" not in result, "Extension operation failed"
                return result.get("value")
            assert send({"type":"status"})["installation"] is None
            WebDriverWait(driver,15).until(lambda d:d.execute_script("const b=[...document.querySelectorAll('button')].find(b=>b.textContent==='Use native client');if(!b||b.disabled)return false;b.click();return true;"))
            WebDriverWait(driver,15).until(lambda d: "Use your native wallet" in d.find_element("id","app").text)
            tab_id = driver.execute_async_script("const done=arguments[arguments.length-1];browser.tabs.query({}).then(tabs=>done(tabs.find(t=>t.url.startsWith(arguments[0])).id));",origin)
            driver.get(f"moz-extension://{uuids['firefox@kagitaba.local']}/app.html?tab={tab_id}")
            def begin(use_ui=False):
                if use_ui:
                    WebDriverWait(driver,15).until(lambda d:d.execute_script("const b=[...document.querySelectorAll('button')].find(b=>b.textContent==='Choose login in native client');if(!b||b.disabled)return false;b.click();return true;"))
                else:
                    driver.execute_script("window.nativeResult=null;browser.runtime.sendMessage({type:'native-fill',tabId:arguments[0]}).then(()=>window.nativeResult='filled',()=>window.nativeResult='denied');",tab_id)
                assert received.get(timeout=15) == dict(version=1,operation="login",origin=origin)
            begin(use_ui=True)
            approvals.put(True)
            WebDriverWait(driver,15).until(lambda d:"Login filled" in d.find_element("id","notice").text)
            driver.switch_to.window(site_handle)
            assert driver.execute_script("return document.querySelector('input[type=password]').value") == "synthetic-password"
            driver.get(origin + "/second")
            driver.switch_to.window(app_handle)
            begin()
            driver.switch_to.window(site_handle)
            driver.get(origin + "/third")
            assert cancelled.get(timeout=15), "Navigation did not close the native socket"
            driver.switch_to.window(app_handle)
            WebDriverWait(driver,15).until(lambda d:d.execute_script("return window.nativeResult") == "denied")
            assert send({"type":"status"})["installation"] is None
            driver.switch_to.window(site_handle)
            def begin_passkey():
                driver.execute_script("window.passkeyResult=null;window.passkeyAbort=new AbortController();navigator.credentials.get({signal:window.passkeyAbort.signal,publicKey:{challenge:new Uint8Array(32).fill(7),rpId:'example.test',userVerification:'required'}}).then(c=>window.passkeyResult=c.toJSON(),e=>window.passkeyResult={error:e.name});")
            def choice(backend):
                return WebDriverWait(driver,15).until(lambda d:d.execute_script("return document.querySelector('#kagitaba-passkey-chooser')?.shadowRoot.querySelector(arguments[0])", f'[data-backend={backend}]'))
            begin_passkey()
            native_button = choice('native')
            if os.environ.get('KAGITABA_CHOOSER_SCREENSHOT'):
                driver.save_screenshot(os.environ['KAGITABA_CHOOSER_SCREENSHOT'])
            assert received.empty(), 'The native app was contacted before selection'
            # Page scripts must not be able to select a backend by dispatching a click.
            driver.execute_script('arguments[0].click()',native_button)
            assert received.empty()
            native_button.click()
            result = WebDriverWait(driver,15).until(lambda d:d.execute_script('return window.passkeyResult'))
            assert "error" not in result, result
            request = received.get(timeout=15)
            assert request["operation"] == "passkey" and request["kind"] == "get" and request["origin"] == origin
            def decode(value):
                return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
            response = result["response"]
            client = decode(response["clientDataJSON"])
            assert json.loads(client)["origin"] == origin
            auth = decode(response["authenticatorData"])
            passkey.public_key().verify(decode(response["signature"]), auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
            assert not driver.execute_script("return !!document.querySelector('#kagitaba-passkey-chooser')")
            # The real host now has no socket to connect to, just like a stopped app.
            thread.join(timeout=5)
            assert not thread.is_alive()
            listener.close()
            path.unlink()
            begin_passkey()
            choice('native').click()
            WebDriverWait(driver,15).until(lambda d:'Open and unlock Kagitaba' in d.execute_script("return document.querySelector('#kagitaba-passkey-chooser')?.shadowRoot.textContent || ''"))
            assert driver.execute_script('return window.passkeyResult') is None
            choice('native').click()
            WebDriverWait(driver,15).until(lambda d:'Open and unlock Kagitaba' in d.execute_script("return document.querySelector('#kagitaba-passkey-chooser')?.shadowRoot.textContent || ''"))
            choice('cancel').click()
            assert WebDriverWait(driver,15).until(lambda d:d.execute_script('return window.passkeyResult')) == {'error':'NotAllowedError'}
            begin_passkey()
            choice('firefox').click()
            WebDriverWait(driver,15).until(lambda d:not d.execute_script("return !!document.querySelector('#kagitaba-passkey-chooser')"))
            driver.execute_script('window.passkeyAbort.abort()')
            fallback_result = WebDriverWait(driver,15).until(lambda d:d.execute_script('return window.passkeyResult'))
            # Firefox can reject this synthetic TLS/RP environment with
            # SecurityError, or lack of hardware with NotAllowedError, before
            # abort arrives. Preserve those native errors as well as AbortError.
            assert fallback_result in [{'error':name} for name in ['AbortError','NotAllowedError','SecurityError']], fallback_result
            print("PASS: real Firefox inline chooser, native bridge, signed assertion, stopped-app retry, Firefox fallback, cancellation and navigation; synthetic credentials only")
        finally:
            driver.quit()
            listener.close()
            website.shutdown()


if __name__ == "__main__":
    main()

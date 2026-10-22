"""Synthetic image and camera-stream tests, called by browser_smoke.py."""
import base64
import pathlib
from selenium.webdriver.support.ui import WebDriverWait

ROOT = pathlib.Path(__file__).resolve().parents[3]

def exercise_tools(driver, send, click, fixture):
    click("Edit entry")
    click("Generate…")
    click("Generate")
    password = WebDriverWait(driver, 20).until(lambda d: d.execute_script("return document.querySelector('dialog input[readonly]')?.value || false;"))
    assert len(password) == 12 and set(password) <= set("acdefhjkmnprtuvwxy347")
    assert any(c.isdigit() for c in password) and any(c.isalpha() for c in password)
    click("Use password")
    click("Import TOTP (camera / picture / URI)")
    driver.find_element("css selector", "dialog input[type=file]").send_keys(str(ROOT / "tests/fixtures/totp-qr.png"))
    click("Add to entry draft")
    # Real getUserMedia acquisition stays untested; use a real MediaStream from
    # a canvas so the actual video/canvas/WASM camera scan loop is exercised.
    image = base64.b64encode((ROOT / "tests/fixtures/totp-qr.png").read_bytes()).decode()
    driver.execute_async_script("""const done=arguments[arguments.length-1],image=new Image();image.onload=()=>{const canvas=document.createElement('canvas');canvas.width=image.width;canvas.height=image.height;canvas.getContext('2d').drawImage(image,0,0);window.qrCanvas=canvas;window.qrStream=canvas.captureStream(5);window.oldGetUserMedia=navigator.mediaDevices.getUserMedia;navigator.mediaDevices.getUserMedia=async()=>window.qrStream;done(true);};image.src='data:image/png;base64,'+arguments[0];""", image)
    click("Import TOTP (camera / picture / URI)")
    click("Scan camera")
    click("Add to entry draft")
    assert driver.execute_script("return window.qrStream.getTracks().every(t=>t.readyState==='ended');")
    driver.execute_script("navigator.mediaDevices.getUserMedia=window.oldGetUserMedia;window.qrCanvas.width=0;")
    # A permission result that arrives after cancellation must stop its tracks.
    driver.execute_script("window.lateCanvas=document.createElement('canvas');window.lateCanvas.width=16;window.lateCanvas.height=16;window.lateStream=window.lateCanvas.captureStream(1);navigator.mediaDevices.getUserMedia=()=>new Promise(resolve=>window.resolveCamera=resolve);")
    click("Import TOTP (camera / picture / URI)")
    click("Scan camera")
    click("Cancel")
    driver.execute_script("window.resolveCamera(window.lateStream);")
    WebDriverWait(driver, 10).until(lambda d: d.execute_script("return window.lateStream.getTracks().every(t=>t.readyState==='ended');"))
    driver.execute_script("navigator.mediaDevices.getUserMedia=window.oldGetUserMedia;window.lateCanvas.width=0;")
    # A password-only edit must retain full, non-HTTPS values in every row.
    urls = ["http://localhost:8080/path?q=a#b", "ssh://server", "bare host"]
    for value in urls:
        click("+ URL")
        driver.execute_script("const row=[...document.querySelectorAll('input[aria-label=URL]')].at(-1);row.value=arguments[0];row.dispatchEvent(new Event('input',{bubbles:true}));", value)
    row_count = len(driver.find_elements("css selector", ".url-row"))
    click("+ URL")
    driver.find_elements("css selector", ".url-row button[aria-label='Remove URL']")[-1].click()
    assert len(driver.find_elements("css selector", ".url-row")) == row_count
    assert driver.execute_script("return [...document.querySelectorAll('.url-row')].every(r=>{const [i,c,x]=[...r.children].map(v=>v.getBoundingClientRect());return i.width>0&&i.right<=c.left+1&&c.right<=x.left+1&&Math.abs(i.top-c.top)<1});")
    assert driver.execute_script("return getComputedStyle(document.querySelector('.url-add')).borderTopStyle==='dashed';")
    driver.execute_script("document.querySelector('.url-table').scrollIntoView({block:'center'});")
    driver.save_screenshot(str(ROOT / "target/firefox-url-table.png"))
    click("Save entry")
    WebDriverWait(driver, 20).until(lambda d: d.find_element("id", "notice").text == "Entry saved.")
    saved = send({"type": "entry", "id": fixture["entryId"]})
    assert saved["entity"]["scope"]["urls"][-3:] == urls
    assert saved["entity"]["credentials"][0]["password"]["value"] == password
    totps = [c for c in saved["entity"]["credentials"] if c["type"] == "totp"]
    assert len(totps) == 2 and all(c["period"] == 300 for c in totps)
    click("Edit entry")
    title = driver.execute_script("return [...document.querySelectorAll('label')].find(l=>l.textContent==='Title').control;")
    title.clear(); title.send_keys("Saved through the form")
    click("Save entry")
    WebDriverWait(driver, 20).until(lambda d: d.find_element("id", "notice").text == "Entry saved.")
    assert send({"type":"entry","id":fixture["entryId"]})["entity"]["scope"]["urls"] == saved["entity"]["scope"]["urls"]
    return saved

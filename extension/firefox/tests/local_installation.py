"""Seed installation-local state in disposable synthetic Firefox test profiles.

This bypasses hardware setup in tests; it is not a product recovery endpoint.
"""
import time


def seed_installation(driver, installation):
    result = driver.execute_async_script("""
        const installation=arguments[0], done=arguments[arguments.length-1];
        const request=indexedDB.open('kagitaba-installation',1);
        request.onupgradeneeded=()=>request.result.createObjectStore('records');
        request.onerror=()=>done(false);
        request.onsuccess=()=>{
            const db=request.result, tx=db.transaction('records','readwrite');
            tx.objectStore('records').put(installation,'installation');
            tx.onerror=()=>done(false);
            tx.oncomplete=async()=>{db.close();const bg=await browser.runtime.getBackgroundPage();bg.location.reload();done(true);};
        };
    """, installation)
    assert result
    for _ in range(100):
        status = driver.execute_async_script("""
            const done=arguments[arguments.length-1];
            browser.runtime.sendMessage({type:'status'}).then(s=>done(s?.installation?.participantId??null),()=>done(null));
        """)
        if status == installation["participantId"]:
            return
        time.sleep(0.1)
    raise AssertionError("Synthetic local installation did not load")

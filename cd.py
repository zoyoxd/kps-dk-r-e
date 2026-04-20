import hashlib
import json
import random
import sys
import time

def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _random_hex_id() -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(32))

def _pow_score(h: str) -> float:
    return 4503599627370496 / (int(h[:13], 16) + 1)

def _solve_pow(
    client_token: str,
    work_time: int,
    hex_id: str,
    kzx: str,
    ywq: str = "",
    jnf: int = 10,
    nrj: int = 2,
) -> list:
    uvw = "tp-v2-input" + client_token[:16]
    base = f"{uvw}, {work_time}, {hex_id}"
    if kzx:
        base += f", {kzx}"
    if ywq:
        base += f", {ywq}"
    rolling = _sha256(base)
    target = jnf / nrj
    answers = []
    for _ in range(nrj):
        nonce = 1
        while True:
            attempt = _sha256(f"{nonce}, {rolling}")
            if _pow_score(attempt) >= target:
                answers.append(nonce)
                rolling = attempt
                break
            nonce += 1
    return answers

def generate_cd(
    client_token: str,
    kzx: str = "f1a70f72d5da700e63df37b4258df651eee6abfd0053738ad7287fa86a0edf16",
    work_time: int | None = None,
    hex_id: str | None = None,
) -> str:
    now = int(time.time() * 1000)
    st = now - random.randint(15000, 60000)
    rst = st + random.randint(800, 1500)
    d = random.randint(900, 1600)
    if work_time is None:
        work_time = now - d
    if hex_id is None:
        hex_id = _random_hex_id()
    t0 = time.perf_counter()
    answers = _solve_pow(client_token, work_time, hex_id, kzx)
    dur_ms = (time.perf_counter() - t0) * 1000
    duration = round(dur_ms + random.uniform(20, 70))
    payload = {
        "workTime": work_time,
        "id": hex_id,
        "answers": answers,
        "duration": duration,
        "d": d,
        "st": st,
        "rst": rst,
    }
    return json.dumps(payload, separators=(",", ":"))

if __name__ == "__main__":
    ct = sys.argv[1]
    print(generate_cd(ct))

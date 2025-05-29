import os
import math
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse
from sympy import isprime
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# === Load PEM-format public key ===

def load_pem_public_key(path):
    with open(path, 'rb') as f:
        key = RSA.import_key(f.read())
    return key.n, key.e

# === Pollard’s p-1 Attack ===

def pollards_p_minus_1(n, log):
    log.append("  [*] Trying Pollard's p-1 attack...")
    a = 2
    for j in range(2, 100000):
        a = pow(a, j, n)
        d = math.gcd(a - 1, n)
        if 1 < d < n:
            log.append(f"  [+] Pollard succeeded: p = {d}")
            return d
    log.append("  [-] Pollard failed.")
    return None

# === Wiener's Attack ===

def continued_fraction(n, d):
    while d:
        q = n // d
        yield q
        n, d = d, n - q * d

def convergents(cf):
    p0, p1 = 1, 0
    q0, q1 = 0, 1
    for a in cf:
        p = a * p0 + p1
        q = a * q0 + q1
        yield p, q
        p1, p0 = p0, p
        q1, q0 = q0, q

def wiener_attack(e, n, log):
    log.append("  [*] Trying Wiener's attack...")
    for k, d in convergents(continued_fraction(e, n)):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        b = -(n - phi + 1)
        discriminant = b * b - 4 * n
        if discriminant >= 0:
            root = math.isqrt(discriminant)
            if root * root == discriminant:
                p = (-b + root) // 2
                q = (-b - root) // 2
                if p * q == n:
                    log.append(f"  [+] Wiener succeeded: p = {p}")
                    return p
    log.append("  [-] Wiener failed.")
    return None

# === Dixon's Trial Attack ===

def trial_dixon(n, log, bound=10000):
    log.append("  [*] Trying Dixon's method (trial)...")
    for x in range(2, bound):
        x2 = pow(x, 2, n)
        g = math.gcd(x2 - 1, n)
        if 1 < g < n:
            log.append(f"  [+] Dixon succeeded: p = {g}")
            return g
    log.append("  [-] Dixon failed.")
    return None

# === Recover Private Key ===

def recover_private_key(n, e, p, q, out_file, log):
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    key = RSA.construct((n, e, d, p, q))
    with open(out_file, 'wb') as f:
        f.write(key.export_key())
    log.append(f"  [+] Private key saved to {out_file}")

# === Process a Single .pub File ===

def process_pub_file(file_path):
    log = []
    log.append(f"[*] Processing: {file_path}")
    try:
        n, e = load_pem_public_key(file_path)
    except Exception as ex:
        log.append(f"  [-] Failed to read key: {ex}")
        write_log(file_path, log)
        return

    log.append(f"  [*] Key size: {n.bit_length()} bits")

    p = pollards_p_minus_1(n, log)
    if not p:
        p = wiener_attack(e, n, log)
    if not p:
        p = trial_dixon(n, log)

    if not p:
        log.append("  [-] All attacks failed.")
        write_log(file_path, log)
        return

    q = n // p
    if p * q != n:
        log.append("  [-] Invalid factorization (p * q != n).")
        write_log(file_path, log)
        return

    base = os.path.splitext(file_path)[0]
    priv_path = f"{base}_private.pem"
    recover_private_key(n, e, p, q, priv_path, log)
    write_log(file_path, log)

def write_log(file_path, log):
    base = os.path.splitext(file_path)[0]
    log_path = f"{base}.log"
    with open(log_path, 'w') as f:
        f.write(f"[Log created: {datetime.now()}]\n\n")
        f.write('\n'.join(log))
    print(f"[+] Log written to {log_path}")

# === Main Function ===

def main():
    folder = input("Enter path to folder containing .pub files: ").strip()
    if not os.path.isdir(folder):
        print("[-] Invalid folder path.")
        return

    pub_files = [f for f in os.listdir(folder) if f.endswith('.pub')]
    if not pub_files:
        print("[-] No .pub files found in the folder.")
        return

    print(f"[+] Found {len(pub_files)} .pub file(s). Starting processing...\n")

    full_paths = [os.path.join(folder, f) for f in pub_files]

    # Change max_workers for parallelism
    with ThreadPoolExecutor(max_workers=4) as executor:
        executor.map(process_pub_file, full_paths)

    print("\n[*] Finished processing all files.")

if __name__ == "__main__":
    main()

# RSA_Attack

This Python script scans a folder for RSA `.pub` files, attempts to factor each public key using several known attacks, and generates the corresponding private key if successful.

A Python-based tool to break RSA public keys using classic attacks:
- Pollard’s p-1
- Wiener's attack
- Trial Dixon’s method

It recovers the private key

---

## Features

- Scans all `.pub` files in a directory
- Performs multiple factoring attacks:
  - Pollard's p-1 Attack
  - Wiener's Attack (for small d)
  - Trial-based Dixon-like Attack
- Recovers and exports the private key as a `.pem` file
- Creates detailed logs for each attempt
- Multithreaded for faster processing

## Requirements

- Python 3.8+
- See `requirements.txt` for dependencies

## Installation

1. **Clone the Repository**

```bash
git clone https://github.com/pedramm7/rsa-key-cracker.git
cd rsa-key-cracker

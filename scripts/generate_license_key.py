import hashlib, secrets, string
chars = string.ascii_uppercase + string.digits
segments = [secrets.token_hex(3)[:5].upper() for _ in range(4)]
body = "-".join(segments)
h = hashlib.sha256((body + "rfshare-pro-salt").encode()).hexdigest().upper()
key = body + "-" + h[:5]
print(key)  # e.g. A3F2B-9K1LP-X7Q4R-2MN8V-A1B2C

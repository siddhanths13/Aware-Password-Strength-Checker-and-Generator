import re, secrets, string

def is_sequential(password):
    S = "abcdefghijklmnopqrstuvwxyz0123456789"
    p = password.lower()
    return any(S[i:i+3] in p for i in range(len(S)-2))

def generate_strong_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+{}[]<>?/|"
    while True:
        pwd = "".join(secrets.choice(chars) for _ in range(length))
        if (re.search(r"[A-Z]", pwd) and re.search(r"[a-z]", pwd) and
            re.search(r"[0-9]", pwd) and re.search(r"[!@#$%^&*()\-\_=+\[\]\{\}<>?/|]", pwd) and
            not is_sequential(pwd) and not re.search(r"(.)\1\1", pwd)):
            return pwd

def normalize(s):
    return re.sub(r'\W+', '', s).lower()

def username_issues(password, username):
    issues = []
    u = normalize(username)
    p = normalize(password)
    if not u:
        return issues

    if u in p:
        issues.append("Password contains username")
    if u[::-1] in p:
        issues.append("Password contains username reversed")

    subs = [u[i:i+3] for i in range(len(u)-2)]
    sub_hits = [s for s in subs if s in p]
    if sub_hits:
        issues.append("Contains username parts: " + ",".join(sub_hits))

    # simple leet substitutions
    lmap = { '@':'a','4':'a','0':'o','1':'l','!':'i','$':'s','3':'e' }
    temp = p
    for k,v in lmap.items():
        temp = temp.replace(k, v)
    if u in temp:
        issues.append("Looks like username after substitutions")

    # prefix/suffix similarity
    pref = sum(a==b for a,b in zip(u, p))
    suf = sum(a==b for a,b in zip(u[::-1], p[::-1]))

    if pref >= 4:
        issues.append(f"Shares {pref}-char prefix with username")
    if suf >= 4:
        issues.append(f"Shares {suf}-char suffix with username")

    return issues

def check_password_strength(password):
    score = 0
    rpt = []

    L = len(password)
    if L >= 16: score += 3; rpt.append("✔ length ≥ 16")
    elif L >= 12: score += 2; rpt.append("✔ length ≥ 12")
    elif L >= 8: score += 1; rpt.append("✔ length ≥ 8")
    else: rpt.append("❌ too short")

    # char checks
    if re.search(r"[A-Z]", password): score += 1; rpt.append("✔ uppercase")
    else: rpt.append("❌ no uppercase")

    if re.search(r"[a-z]", password): score += 1; rpt.append("✔ lowercase")
    else: rpt.append("❌ no lowercase")

    if re.search(r"[0-9]", password): score += 1; rpt.append("✔ digit")
    else: rpt.append("❌ no digit")

    if re.search(r"[!@#$%^&*()\-\_=+\[\]\{\}<>?/|]", password): score += 1; rpt.append("✔ special char")
    else: rpt.append("❌ no special char")

    if re.search(r"(.)\1\1", password): score -= 1; rpt.append("❌ triple repeated chars")
    if is_sequential(password): score -= 1; rpt.append("❌ sequential pattern")
    if any(w in password.lower() for w in ("password","123456","qwerty","letmein")):#
        score -= 2
        rpt.append("❌ common weak word")

    rating = "🟢 Strong" if score >= 7 else ("🟡 Medium" if score >= 4 else "🔴 Weak")

    return rating, score, rpt

# -------- MAIN FUNCTION (call this manually) -------- #

def run_checker():
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    rating, score, details = check_password_strength(password)
    u_issues = username_issues(password, username)

    print("\nPassword Strength:", rating)
    print("Details:")
    for x in details:
        print("-", x)

    if u_issues:
        print("\nUsername Issues:")
        for x in u_issues:
            print("-", x)

    # Suggest password if Weak or Medium
    if not rating.startswith("🟢"):
        print("\nSuggested Strong Password:", generate_strong_password())
    else:
        print("\nYour password is strong!")

# Just call run_checker() manually
run_checker()

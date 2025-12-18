#!/usr/bin/env python3
import re
import secrets
import string

# ---------- Utilities ----------

def is_sequential(password):
    sequences = "abcdefghijklmnopqrstuvwxyz0123456789"
    p = password.lower()
    for i in range(len(sequences) - 2):
        seq = sequences[i:i+3]
        if seq in p:
            return True
    return False

def has_triple_repeat(s):
    return bool(re.search(r"(.)\1\1", s))

def generate_strong_password(length=16):
    if length < 12:
        length = 12
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+{}[]<>?/|"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        # must include categories
        checks = [
            re.search(r"[A-Z]", pwd),
            re.search(r"[a-z]", pwd),
            re.search(r"[0-9]", pwd),
            re.search(r"[!@#$%^&*()\-\_=+\[\]\{\}<>?/|]", pwd),
        ]
        if all(checks) and not is_sequential(pwd) and not has_triple_repeat(pwd):
            return pwd

# ---------- Username-related checks ----------

def normalize(s):
    return re.sub(r'\W+', '', s).lower()  # remove non-alphanumeric, lowercase

def username_similarity_issues(password, username):
    """
    Return a list of issues (strings). Empty list => no username-related issues.
    """
    issues = []
    u_norm = normalize(username)
    p_norm = normalize(password)

    if not u_norm:
        return issues  # nothing to compare

    # 1) username present in password
    if u_norm and u_norm in p_norm:
        issues.append("Password contains the username (or exact characters from it).")

    # 2) reversed username present
    if u_norm and u_norm[::-1] in p_norm:
        issues.append("Password contains the username reversed.")

    # 3) any substring of username length >=3 present in password
    min_sub = 3
    found_sub = []
    for i in range(len(u_norm) - (min_sub - 1)):
        sub = u_norm[i:i+min_sub]
        if sub in p_norm:
            found_sub.append(sub)
    if found_sub:
        issues.append(f"Password contains substring(s) of username: {', '.join(sorted(set(found_sub)))}")

    # 4) simple character-substitution check (e.g., 'a'->'@', 'o'->'0')
    # We'll map common leet-char and see if replacing them in password reveals the username
    leet_map = str.maketrans("@4", "aa")  # very basic; can be expanded
    # A slightly more thorough approach:
    subs = { '@': 'a', '4': 'a', '0': 'o', '1': 'l', '!': 'i', '$': 's', '3': 'e' }
    p_mapped = p_norm
    for k, v in subs.items():
        p_mapped = p_mapped.replace(k, v)
    if u_norm and u_norm in p_mapped:
        issues.append("After common character substitutions, password still contains the username.")

    # 5) too-similar check: long common prefix or suffix
    # common prefix
    pref_len = 0
    for a, b in zip(u_norm, p_norm):
        if a == b:
            pref_len += 1
        else:
            break
    if pref_len >= 4:
        issues.append(f"Password shares a long prefix ({pref_len} chars) with username.")

    # common suffix
    suf_len = 0
    for a, b in zip(u_norm[::-1], p_norm[::-1]):
        if a == b:
            suf_len += 1
        else:
            break
    if suf_len >= 4:
        issues.append(f"Password shares a long suffix ({suf_len} chars) with username.")

    return issues

# ---------- Strength analyzer (same logic as before, but returns numeric score too) ----------

def check_password_strength(password):
    score = 0
    report = []

    # Length scoring
    L = len(password)
    if L >= 16:
        score += 3
        report.append("✔ Excellent length (16+)")
    elif L >= 12:
        score += 2
        report.append("✔ Good length (12+)")
    elif L >= 8:
        score += 1
        report.append("✔ Minimum length passed (8+)")
    else:
        report.append("❌ Password too short")

    # Uppercase
    if re.search(r"[A-Z]", password):
        score += 1
        report.append("✔ Contains uppercase letters")
    else:
        report.append("❌ Missing uppercase letters")

    # Lowercase
    if re.search(r"[a-z]", password):
        score += 1
        report.append("✔ Contains lowercase letters")
    else:
        report.append("❌ Missing lowercase letters")

    # Digit
    if re.search(r"[0-9]", password):
        score += 1
        report.append("✔ Contains digits")
    else:
        report.append("❌ Missing digits")

    # Special characters
    if re.search(r"[!@#$%^&*(),.?\":{}|<>/_\-=\[\]{}+\\|]", password):
        score += 1
        report.append("✔ Contains special characters")
    else:
        report.append("❌ Missing special characters")

    # Repeated chars
    if re.search(r"(.)\1\1", password):
        score -= 1
        report.append("❌ Contains repeating characters (aaa, 111 etc.)")

    # Sequential chars
    if is_sequential(password):
        score -= 1
        report.append("❌ Contains sequential patterns (abc, 123 etc.)")

    # Weak patterns
    weak_patterns = ["password", "123456", "qwerty", "letmein"]
    if any(w in password.lower() for w in weak_patterns):
        score -= 2
        report.append("❌ Contains common weak patterns")

    # Final rating
    if score >= 7:
        rating = "🟢 Strong Password"
    elif score >= 4:
        rating = "🟡 Medium Password"
    else:
        rating = "🔴 Weak Password"

    return rating, score, report

# ---------- CLI flow ----------

def main():
    print("=== Username-aware Password Checker ===")
    username = input("Enter username: ").strip()
    if not username:
        print("Username should not be empty. Exiting.")
        return

    pwd = input("Enter password to check: ").strip()
    if not pwd:
        print("Password should not be empty. Exiting.")
        return

    rating, score, details = check_password_strength(pwd)
    uname_issues = username_similarity_issues(pwd, username)

    print("\nPassword Strength:", rating)
    print("Details:")
    for d in details:
        print("-", d)

    if uname_issues:
        print("\nUsername-related issues found:")
        for u in uname_issues:
            print("-", u)
    else:
        print("\nNo username-related issues detected.")

    # Suggest a strong password unless rating is already Strong
    suggestion = None
    if not rating.startswith("🟢"):
        suggestion = generate_strong_password()
        print("\n🔧 Suggested Strong Password:")
        print(suggestion)
    else:
        print("\nNo suggestion needed — password is strong.")

    # Extra: brief summary/warning if username issues present even when strong
    if rating.startswith("🟢") and uname_issues:
        print("\n⚠ Note: Although overall strength is strong, password is related to the username — consider changing it to avoid targeted guessing.")

if __name__ == "__main__":
    main()

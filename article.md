---
title: The asterisk key that unlocked Alpine Linux
summary: Setting an account password to an asterisk is supposed to lock it forever. Here is how three separate features across 14 years lined up to let any long password walk straight into Alpine Linux OpenSSH.
tags: [Security, Linux, Vulnerability]
---

In Linux systems, there is an old convention everyone relies on: if you do not want an account to ever log in with a password, you put an asterisk (`*`) in its password field inside `/etc/shadow`.

An asterisk is not a password hash. No real password can hash to a single symbol. For decades, system administrators, cloud providers, and distributions have used `*` to say: *passwords are off for this user; use an SSH key or stay out.*

On November 5, 2026, Alpine Linux published a security notice showing that on systems running their standard OpenSSH daemon, that assumption broke down completely.

Any password between 257 and 1024 characters long could log right in.

## What I found

When I saw the advisory, it sounded almost impossible. How could a 300-character line of text ever match a single star?

I built an isolated lab to test it on real Alpine packages:

1. I set up a user named `victim` with an asterisk (`*`) as its shadow password.
2. I set up another user named `donor` who had a normal password hash.
3. I connected to OpenSSH from a terminal and sent a password made of 300 `A`s.

On the first try, the server said *Permission denied*.

I typed the exact same 300 `A`s a second time into the same prompt.

The server answered with a shell:

```text
victim@127.0.0.1's password: 
Permission denied, please try again.
victim@127.0.0.1's password: 
fe68d7376998:~$ whoami
victim
fe68d7376998:~$ id
uid=1001(victim) gid=1001(victim)
```

No SSH key, no real password. Just 300 characters of anything.

> Setting a password to an asterisk was meant to close the door. Instead, it turned the door into a lock that opens whenever a key is too long to fit.

## Why this happens

Nobody wrote a backdoor. What happened is much more interesting: three good ideas written years apart accidentally combined into a skeleton key.

Here is how the chain fits together:

### 1. musl libc cut long passwords to protect against CPU exhaustion
Alpine Linux does not use the standard GNU C library (`glibc`); it uses `musl libc`. Back in 2012, musl added a simple limit: if anyone passes a password longer than 256 bytes into modern hashing algorithms (`$5$` or `$6$`), stop immediately and return an error.

Instead of returning an empty value or `NULL`, musl returned the string literal `"*"`:

```text
Password > 256 bytes  ──►  musl crypt()  ──►  "*"
```

### 2. OpenSSH tried to stop attackers from guessing usernames
In 2016, OpenSSH fixed a timing leak (CVE-2016-6210). If an attacker tries to guess whether an account exists, rejecting accounts with no password too fast gives away who is on the machine.

To make the timing look normal, OpenSSH's `pick_salt()` looks at the system, finds another account that *does* have a password hash, and "borrows" its salt.

### 3. The fatal comparison
When OpenSSH checks the password for an asterisk account:

1. It sees the account has no real salt, so it borrows one from an account that does.
2. It asks musl to hash the 300-byte password using that borrowed salt.
3. musl sees a password longer than 256 bytes, refuses to hash it, and returns `"*"`.
4. OpenSSH takes musl's result (`"*"`) and compares it to the password stored in `/etc/shadow` (`"*"`).

Because `*` equals `*`, the server decides the password is correct and grants access.

The 256-character boundary is exact. When I tested with 256 bytes, login failed. At 257 bytes, musl triggered the fallback and login succeeded.

```
+-------------------------------------------------------------------------+
|                        The Collision Equation                           |
|                                                                         |
| Password (257–1024 bytes) + Borrowed Salt ($6$)                         |
|          │                                                              |
|          ▼                                                              |
| musl crypt() rejects (> 256 bytes)  ───────►  returns "*"               |
|                                                │                        |
| Shadow entry for victim:            ───────►  contains "*"              |
|                                                │                        |
| OpenSSH comparison:                 ───────►  "*" == "*" (MATCH!)       |
+-------------------------------------------------------------------------+
```

## The prompt quirk

There was one puzzle in my testing: why did the first password prompt fail, and only the second one work?

In musl libc, `getspnam()` stores user shadow records in one shared, temporary buffer. On prompt 1, when OpenSSH borrowed the salt from `donor`, it accidentally wiped `victim`'s record from that buffer.

On prompt 2, OpenSSH already had the salt cached in memory. It did not have to look up the donor again, the temporary buffer stayed intact, and the asterisk match went through cleanly.

## What is affected

This flaw (CVE-2026-123158) requires a specific combination:

* **Alpine Linux** or another musl-based system
* **OpenSSH built without PAM** (the standard `openssh-server` on Alpine)
* **`PasswordAuthentication yes`** enabled in SSH settings
* **At least one user with `*`** who is allowed to log in
* **At least one other user with a standard password hash** to donate the salt

Systems like Ubuntu, Debian, and Fedora are not affected because `glibc` returns `NULL` or `"*0"` on error, neither of which matches a single asterisk.

## How to protect yourself

If you run Alpine Linux servers or containers that expose SSH to a network, take these steps:

### 1. Upgrade OpenSSH immediately
Alpine released an update (`openssh-server-9.9_p2-r1`) that enforces a minimum password hash length, ensuring single-character placeholders like `*` can never match:

```bash
apk update && apk upgrade openssh-server openssh
rc-service sshd restart
```

> Merely upgrading the package does not reload the running process. Restarting `sshd` is mandatory.

### 2. Turn off password authentication
If you use SSH keys (which you should), disable password logins altogether:

```bash
mkdir -p /etc/ssh/sshd_config.d
echo "PasswordAuthentication no" > /etc/ssh/sshd_config.d/00-no-passwords.conf
sshd -t && rc-service sshd restart
```

### 3. Check for accounts using asterisk
Audit `/etc/shadow` on your servers. If you need an account locked, use an exclamation mark (`!`) instead of an asterisk:

```bash
# Find users with '*'
awk -F: '$2 == "*" {print $1}' /etc/shadow

# Lock account safely with '!'
passwd -l <username>
```

`!` is safe because musl never returns an exclamation mark on error, so it can never match.

## If you build software

| Habit | Why it matters |
| --- | --- |
| Never use magic error strings that resemble valid data | Returning `"*"` created an accidental master key |
| Return `NULL` or dedicated status codes on failure | Ambiguous return values turn errors into valid states |
| Enforce minimum hash lengths before string comparison | A 1-character token should never be treated as a cryptographic digest |
| Copy strings from static C library buffers | Shared static buffers in standard libraries get clobbered silently |
| Disable password authentication by default on servers | If passwords cannot be sent, password-handling bugs cannot be reached |

## Try it in your own lab

The best way to really understand a vulnerability like this is to see it happen in front of you. 

I packaged the entire reproduction setup into a self-contained, isolated Docker environment. You can spin it up locally in less than a minute, run the automated payload boundary tests, test your own manual SSH connections, and verify how the patched version stops the bypass in its tracks.

You can grab the full lab and scripts from the repository here:

👉 **[akarkode/alpine-openssh-sshole-auth-bypass](https://github.com/akarkode/alpine-openssh-sshole-auth-bypass)**

All you need is Docker:

```bash
git clone https://github.com/akarkode/alpine-openssh-sshole-auth-bypass.git
cd alpine-openssh-sshole-auth-bypass/lab
./run.sh
```

## References

For those interested in digging into the raw advisories, CVE records, and original source commits:

* **CVE Record:** [CVE-2026-123158 on NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-123158) and [CVE.org](https://www.cve.org/CVERecord?id=CVE-2026-123158)
* **Alpine Linux Advisory:** [OpenSSH password authentication bypass (2026-11-05)](https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/)
* **OpenSSH Announcement:** [OpenSSH 10.6p2 Release Notes](https://www.openssh.com/txt/release-10.6p2)
* **Upstream Fix Commit:** [OpenSSH Portable Commit 4353fdc](https://github.com/openssh/openssh-portable/commit/4353fdc43ef646c43a8dda7025cc1a898caf1482)
* **Underlying Logic:** [musl libc crypt_sha512.c source](https://git.musl-libc.org/cgit/musl/tree/src/crypt/crypt_sha512.c) and [CVE-2016-6210 timing disclosure](https://nvd.nist.gov/vuln/detail/CVE-2016-6210)
* **Community Research & PoC:** [schappim/sshole-audit](https://github.com/schappim/sshole-audit)

## The takeaway

Security bugs do not always come from complex zero-days or careless mistakes.

Here, three well-intentioned defensive decisions—protecting against DoS attacks in 2012, protecting against username discovery in 2016, and using an asterisk to turn off passwords—silently aligned over a decade until they opened a door.

Whenever software uses placeholder symbols to mean *"disabled"*, ask: *can anything in the system ever produce that exact same symbol?*

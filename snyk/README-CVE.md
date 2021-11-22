# CVE-2021-41773

CVE-2021-41773 is a CVE within the Apache HTTP Server, specifically version 2.4.49. 

> A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

[National Institute of Standards and Technology](https://nvd.nist.gov/vuln/detail/CVE-2021-41773)


## CVE Lab

This lab contains a vulnerable Dockerfile, which includes the Apache 2.4.49 package and its associated configuratons which this CVE required to be installed.

We can


## Scanning with Snyk 

To use Snyk, you must first:

* Sign up for Snyk
* Install the CLI agent using Node (must have NPM installed) `npm install -g snyk`
* Authenticate with snyk `snyk auth "<API KEY>"`

You can now start to scan local images using Snyk. Snyk will analyise the dependencies installed in the image, and scan them against its backend database of vulnerabilities.


### Updating the dependency 

In the Dockerfile



## Making it safe 

There are two directories within the Docker directory, both containing a Dockerfile and a set of dependencies.

* vulnerable
* safe.

To build the vulnerable image, run the following command:

```
$ docker build vulnerable -t apache-vulnerable
```

This will create a Docker image using the Dockerfile located in the `vulnerable` directory, and tag it `apache-vulnerable`.

Now you have built the vulnerable Docker image, it's time to scan this using Snyk. To scan a Docker image, run the following:

```
$ snyk container test apache-vulnerable


Testing cve-2021...

✗ Low severity vulnerability found in tar
  Description: CVE-2005-2541
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-TAR-312332
  Introduced through: meta-common-packages@meta
  From: meta-common-packages@meta > tar@1.34+dfsg-1

✗ Low severity vulnerability found in systemd/libsystemd0
  Description: Authentication Bypass
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-SYSTEMD-1291057
  Introduced through: apt@2.3.11, util-linux@2.37.2-4, util-linux/bsdutils@1:2.37.2-4, apache2@2.4.49-4, systemd/libudev1@249.5-2
  From: apt@2.3.11 > systemd/libsystemd0@249.5-2
  From: util-linux@2.37.2-4 > systemd/libsystemd0@249.5-2
  From: util-linux/bsdutils@1:2.37.2-4 > systemd/libsystemd0@249.5-2
  and 5 more...

✗ Low severity vulnerability found in systemd/libsystemd0
  Description: Link Following
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-SYSTEMD-305145
  Introduced through: apt@2.3.11, util-linux@2.37.2-4, util-linux/bsdutils@1:2.37.2-4, apache2@2.4.49-4, systemd/libudev1@249.5-2
  From: apt@2.3.11 > systemd/libsystemd0@249.5-2
  From: util-linux@2.37.2-4 > systemd/libsystemd0@249.5-2
  From: util-linux/bsdutils@1:2.37.2-4 > systemd/libsystemd0@249.5-2
  and 5 more...

✗ Low severity vulnerability found in shadow/passwd
  Description: Time-of-check Time-of-use (TOCTOU)
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-SHADOW-306211
  Introduced through: shadow/passwd@1:4.8.1-1.1, adduser@3.118, shadow/login@1:4.8.1-1.1
  From: shadow/passwd@1:4.8.1-1.1
  From: adduser@3.118 > shadow/passwd@1:4.8.1-1.1
  From: shadow/login@1:4.8.1-1.1

✗ Low severity vulnerability found in shadow/passwd
  Description: Access Restriction Bypass
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-SHADOW-306251
  Introduced through: shadow/passwd@1:4.8.1-1.1, adduser@3.118, shadow/login@1:4.8.1-1.1
  From: shadow/passwd@1:4.8.1-1.1
  From: adduser@3.118 > shadow/passwd@1:4.8.1-1.1
  From: shadow/login@1:4.8.1-1.1

✗ Low severity vulnerability found in shadow/passwd
  Description: Incorrect Permission Assignment for Critical Resource
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-SHADOW-539863
  Introduced through: shadow/passwd@1:4.8.1-1.1, adduser@3.118, shadow/login@1:4.8.1-1.1
  From: shadow/passwd@1:4.8.1-1.1
  From: adduser@3.118 > shadow/passwd@1:4.8.1-1.1
  From: shadow/login@1:4.8.1-1.1

✗ Low severity vulnerability found in perl/perl-modules-5.32
  Description: Link Following
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-PERL-327794
  Introduced through: apache2@2.4.49-4, perl@5.32.1-6, meta-common-packages@meta
  From: apache2@2.4.49-4 > mime-support@3.66 > mailcap@3.70 > perl@5.32.1-6 > perl/perl-modules-5.32@5.32.1-6
  From: apache2@2.4.49-4 > mime-support@3.66 > mailcap@3.70 > perl@5.32.1-6 > perl/libperl5.32@5.32.1-6 > perl/perl-modules-5.32@5.32.1-6
  From: apache2@2.4.49-4 > mime-support@3.66 > mailcap@3.70 > perl@5.32.1-6 > perl/libperl5.32@5.32.1-6
  and 3 more...
  Image layer: 'RUN |1 version=2.4.49-4 /bin/sh -c apt install -y perl libxml2 libaprutil1-dbd-sqlite3 libnghttp2-14 libaprutil1-ldap libbrotli1 libcurl4 libjansson4 liblua5.3-0 procps mime-support '

✗ Low severity vulnerability found in pcre3/libpcre3
  Description: Out-of-Bounds
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-PCRE3-345327
  Introduced through: grep@3.7-1, apache2@2.4.49-4
  From: grep@3.7-1 > pcre3/libpcre3@2:8.39-13
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > pcre3/libpcre3@2:8.39-13

✗ Low severity vulnerability found in pcre3/libpcre3
  Description: Out-of-Bounds
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-PCRE3-345359
  Introduced through: grep@3.7-1, apache2@2.4.49-4
  From: grep@3.7-1 > pcre3/libpcre3@2:8.39-13
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > pcre3/libpcre3@2:8.39-13

✗ Low severity vulnerability found in pcre3/libpcre3
  Description: Uncontrolled Recursion
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-PCRE3-345503
  Introduced through: grep@3.7-1, apache2@2.4.49-4
  From: grep@3.7-1 > pcre3/libpcre3@2:8.39-13
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > pcre3/libpcre3@2:8.39-13

✗ Low severity vulnerability found in pcre3/libpcre3
  Description: Out-of-Bounds
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-PCRE3-345531
  Introduced through: grep@3.7-1, apache2@2.4.49-4
  From: grep@3.7-1 > pcre3/libpcre3@2:8.39-13
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > pcre3/libpcre3@2:8.39-13

✗ Low severity vulnerability found in pcre3/libpcre3
  Description: Out-of-bounds Read
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-PCRE3-572365
  Introduced through: grep@3.7-1, apache2@2.4.49-4
  From: grep@3.7-1 > pcre3/libpcre3@2:8.39-13
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > pcre3/libpcre3@2:8.39-13

✗ Low severity vulnerability found in openssl/libssl1.1
  Description: Cryptographic Issues
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-OPENSSL-374710
  Introduced through: cyrus-sasl2/libsasl2-modules@2.1.27+dfsg-2.3, apache2@2.4.49-4, ca-certificates@20210119, openssl@1.1.1l-1
  From: cyrus-sasl2/libsasl2-modules@2.1.27+dfsg-2.3 > openssl/libssl1.1@1.1.1l-1
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > openssl/libssl1.1@1.1.1l-1
  From: apache2@2.4.49-4 > apache2/apache2-utils@2.4.49-4 > openssl/libssl1.1@1.1.1l-1
  and 7 more...

✗ Low severity vulnerability found in openssl/libssl1.1
  Description: Cryptographic Issues
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-OPENSSL-374997
  Introduced through: cyrus-sasl2/libsasl2-modules@2.1.27+dfsg-2.3, apache2@2.4.49-4, ca-certificates@20210119, openssl@1.1.1l-1
  From: cyrus-sasl2/libsasl2-modules@2.1.27+dfsg-2.3 > openssl/libssl1.1@1.1.1l-1
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > openssl/libssl1.1@1.1.1l-1
  From: apache2@2.4.49-4 > apache2/apache2-utils@2.4.49-4 > openssl/libssl1.1@1.1.1l-1
  and 7 more...

✗ Low severity vulnerability found in openldap/libldap-2.4-2
  Description: Improper Initialization
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-OPENLDAP-304608
  Introduced through: apache2@2.4.49-4, openldap/libldap-common@2.4.59+dfsg-1
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > openldap/libldap-2.4-2@2.4.59+dfsg-1
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > apr-util/libaprutil1-ldap@1.6.1-5 > openldap/libldap-2.4-2@2.4.59+dfsg-1
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > curl/libcurl4@7.79.1-2 > openldap/libldap-2.4-2@2.4.59+dfsg-1
  and 1 more...

✗ Low severity vulnerability found in openldap/libldap-2.4-2
  Description: Cryptographic Issues
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-OPENLDAP-304655
  Introduced through: apache2@2.4.49-4, openldap/libldap-common@2.4.59+dfsg-1
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > openldap/libldap-2.4-2@2.4.59+dfsg-1
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > apr-util/libaprutil1-ldap@1.6.1-5 > openldap/libldap-2.4-2@2.4.59+dfsg-1
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > curl/libcurl4@7.79.1-2 > openldap/libldap-2.4-2@2.4.59+dfsg-1
  and 1 more...

✗ Low severity vulnerability found in openldap/libldap-2.4-2
  Description: Out-of-Bounds
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-OPENLDAP-304668
  Introduced through: apache2@2.4.49-4, openldap/libldap-common@2.4.59+dfsg-1
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > openldap/libldap-2.4-2@2.4.59+dfsg-1
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > apr-util/libaprutil1-ldap@1.6.1-5 > openldap/libldap-2.4-2@2.4.59+dfsg-1
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > curl/libcurl4@7.79.1-2 > openldap/libldap-2.4-2@2.4.59+dfsg-1
  and 1 more...

✗ Low severity vulnerability found in openldap/libldap-2.4-2
  Description: Improper Certificate Validation
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-OPENLDAP-584925
  Introduced through: apache2@2.4.49-4, openldap/libldap-common@2.4.59+dfsg-1
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > openldap/libldap-2.4-2@2.4.59+dfsg-1
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > apr-util/libaprutil1-ldap@1.6.1-5 > openldap/libldap-2.4-2@2.4.59+dfsg-1
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > curl/libcurl4@7.79.1-2 > openldap/libldap-2.4-2@2.4.59+dfsg-1
  and 1 more...

✗ Low severity vulnerability found in ncurses/libtinfo6
  Description: Out-of-bounds Write
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-NCURSES-1655740
  Introduced through: bash@5.1-3.1, ncurses/ncurses-bin@6.2+20201114-4, psmisc@23.4-2, util-linux@2.37.2-4, apache2@2.4.49-4, ncurses/ncurses-base@6.2+20201114-4
  From: bash@5.1-3.1 > ncurses/libtinfo6@6.2+20201114-4
  From: ncurses/ncurses-bin@6.2+20201114-4 > ncurses/libtinfo6@6.2+20201114-4
  From: psmisc@23.4-2 > ncurses/libtinfo6@6.2+20201114-4
  and 8 more...

✗ Low severity vulnerability found in lua5.3/liblua5.3-0
  Description: CVE-2021-43519
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-LUA53-1914020
  Introduced through: lua5.3/liblua5.3-0@5.3.6-1, apache2@2.4.49-4
  From: lua5.3/liblua5.3-0@5.3.6-1
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > lua5.3/liblua5.3-0@5.3.6-1

✗ Low severity vulnerability found in libsepol/libsepol1
  Description: Use After Free
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-LIBSEPOL-1315631
  Introduced through: libsepol/libsepol1@3.1-1, adduser@3.118
  From: libsepol/libsepol1@3.1-1
  From: adduser@3.118 > shadow/passwd@1:4.8.1-1.1 > libsemanage/libsemanage1@3.1-2 > libsepol/libsepol1@3.1-1
  Fixed in: 3.3-1

✗ Low severity vulnerability found in libsepol/libsepol1
  Description: Use After Free
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-LIBSEPOL-1315633
  Introduced through: libsepol/libsepol1@3.1-1, adduser@3.118
  From: libsepol/libsepol1@3.1-1
  From: adduser@3.118 > shadow/passwd@1:4.8.1-1.1 > libsemanage/libsemanage1@3.1-2 > libsepol/libsepol1@3.1-1
  Fixed in: 3.3-1

✗ Low severity vulnerability found in libsepol/libsepol1
  Description: Use After Free
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-LIBSEPOL-1315637
  Introduced through: libsepol/libsepol1@3.1-1, adduser@3.118
  From: libsepol/libsepol1@3.1-1
  From: adduser@3.118 > shadow/passwd@1:4.8.1-1.1 > libsemanage/libsemanage1@3.1-2 > libsepol/libsepol1@3.1-1
  Fixed in: 3.3-1

✗ Low severity vulnerability found in libsepol/libsepol1
  Description: Out-of-bounds Read
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-LIBSEPOL-1315640
  Introduced through: libsepol/libsepol1@3.1-1, adduser@3.118
  From: libsepol/libsepol1@3.1-1
  From: adduser@3.118 > shadow/passwd@1:4.8.1-1.1 > libsemanage/libsemanage1@3.1-2 > libsepol/libsepol1@3.1-1
  Fixed in: 3.3-1

✗ Low severity vulnerability found in libgcrypt20/libgcrypt20
  Description: Use of a Broken or Risky Cryptographic Algorithm
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-LIBGCRYPT20-391903
  Introduced through: apt@2.3.11, apache2@2.4.49-4
  From: apt@2.3.11 > apt/libapt-pkg6.0@2.3.11 > libgcrypt20/libgcrypt20@1.9.4-3+b1
  From: apt@2.3.11 > gnupg2/gpgv@2.2.27-2 > libgcrypt20/libgcrypt20@1.9.4-3+b1
  From: apache2@2.4.49-4 > procps@2:3.3.17-5 > procps/libprocps8@2:3.3.17-5 > systemd/libsystemd0@249.5-2 > libgcrypt20/libgcrypt20@1.9.4-3+b1

✗ Low severity vulnerability found in krb5/libgssapi-krb5-2
  Description: CVE-2004-0971
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-KRB5-395884
  Introduced through: apache2@2.4.49-4, adduser@3.118
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > curl/libcurl4@7.79.1-2 > krb5/libgssapi-krb5-2@1.18.3-7
  From: adduser@3.118 > shadow/passwd@1:4.8.1-1.1 > pam/libpam-modules@1.4.0-10 > libnsl/libnsl2@1.3.0-2 > libtirpc/libtirpc3@1.3.2-2 > krb5/libgssapi-krb5-2@1.18.3-7
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > curl/libcurl4@7.79.1-2 > krb5/libgssapi-krb5-2@1.18.3-7 > krb5/libkrb5support0@1.18.3-7
  and 5 more...

✗ Low severity vulnerability found in krb5/libgssapi-krb5-2
  Description: Integer Overflow or Wraparound
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-KRB5-395958
  Introduced through: apache2@2.4.49-4, adduser@3.118
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > curl/libcurl4@7.79.1-2 > krb5/libgssapi-krb5-2@1.18.3-7
  From: adduser@3.118 > shadow/passwd@1:4.8.1-1.1 > pam/libpam-modules@1.4.0-10 > libnsl/libnsl2@1.3.0-2 > libtirpc/libtirpc3@1.3.2-2 > krb5/libgssapi-krb5-2@1.18.3-7
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > curl/libcurl4@7.79.1-2 > krb5/libgssapi-krb5-2@1.18.3-7 > krb5/libkrb5support0@1.18.3-7
  and 5 more...

✗ Low severity vulnerability found in jansson/libjansson4
  Description: Out-of-bounds Read
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-JANSSON-1264525
  Introduced through: jansson/libjansson4@2.13.1-1.1, apache2@2.4.49-4
  From: jansson/libjansson4@2.13.1-1.1
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > jansson/libjansson4@2.13.1-1.1

✗ Low severity vulnerability found in gnutls28/libgnutls30
  Description: Improper Input Validation
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-GNUTLS28-340756
  Introduced through: apt@2.3.11, apache2@2.4.49-4
  From: apt@2.3.11 > gnutls28/libgnutls30@3.7.2-2
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > apr-util/libaprutil1-ldap@1.6.1-5 > openldap/libldap-2.4-2@2.4.59+dfsg-1 > gnutls28/libgnutls30@3.7.2-2
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > curl/libcurl4@7.79.1-2 > rtmpdump/librtmp1@2.4+20151223.gitfa8646d.1-2+b2 > gnutls28/libgnutls30@3.7.2-2

✗ Low severity vulnerability found in gmp/libgmp10
  Description: CVE-2021-43618
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-GMP-1920940
  Introduced through: coreutils@8.32-4.1, apache2@2.4.49-4
  From: coreutils@8.32-4.1 > gmp/libgmp10@2:6.2.1+dfsg-2
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > curl/libcurl4@7.79.1-2 > rtmpdump/librtmp1@2.4+20151223.gitfa8646d.1-2+b2 > gmp/libgmp10@2:6.2.1+dfsg-2
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > apr-util/libaprutil1-ldap@1.6.1-5 > openldap/libldap-2.4-2@2.4.59+dfsg-1 > gnutls28/libgnutls30@3.7.2-2 > gmp/libgmp10@2:6.2.1+dfsg-2
  and 1 more...
  Fixed in: 2:6.2.1+dfsg-3

✗ Low severity vulnerability found in glibc/libc-bin
  Description: CVE-2021-43396
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-GLIBC-1911971
  Introduced through: glibc/libc-bin@2.32-4, meta-common-packages@meta
  From: glibc/libc-bin@2.32-4
  From: meta-common-packages@meta > glibc/libc6@2.32-4

✗ Low severity vulnerability found in glibc/libc-bin
  Description: Uncontrolled Recursion
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-GLIBC-338097
  Introduced through: glibc/libc-bin@2.32-4, meta-common-packages@meta
  From: glibc/libc-bin@2.32-4
  From: meta-common-packages@meta > glibc/libc6@2.32-4

✗ Low severity vulnerability found in glibc/libc-bin
  Description: Uncontrolled Recursion
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-GLIBC-338174
  Introduced through: glibc/libc-bin@2.32-4, meta-common-packages@meta
  From: glibc/libc-bin@2.32-4
  From: meta-common-packages@meta > glibc/libc6@2.32-4

✗ Low severity vulnerability found in glibc/libc-bin
  Description: Resource Management Errors
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-GLIBC-356736
  Introduced through: glibc/libc-bin@2.32-4, meta-common-packages@meta
  From: glibc/libc-bin@2.32-4
  From: meta-common-packages@meta > glibc/libc6@2.32-4

✗ Low severity vulnerability found in glibc/libc-bin
  Description: Out-of-Bounds
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-GLIBC-452130
  Introduced through: glibc/libc-bin@2.32-4, meta-common-packages@meta
  From: glibc/libc-bin@2.32-4
  From: meta-common-packages@meta > glibc/libc6@2.32-4

✗ Low severity vulnerability found in glibc/libc-bin
  Description: Use of Insufficiently Random Values
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-GLIBC-452151
  Introduced through: glibc/libc-bin@2.32-4, meta-common-packages@meta
  From: glibc/libc-bin@2.32-4
  From: meta-common-packages@meta > glibc/libc6@2.32-4

✗ Low severity vulnerability found in glibc/libc-bin
  Description: Information Exposure
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-GLIBC-452711
  Introduced through: glibc/libc-bin@2.32-4, meta-common-packages@meta
  From: glibc/libc-bin@2.32-4
  From: meta-common-packages@meta > glibc/libc6@2.32-4

✗ Low severity vulnerability found in glibc/libc-bin
  Description: Access Restriction Bypass
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-GLIBC-452916
  Introduced through: glibc/libc-bin@2.32-4, meta-common-packages@meta
  From: glibc/libc-bin@2.32-4
  From: meta-common-packages@meta > glibc/libc6@2.32-4

✗ Low severity vulnerability found in expat/libexpat1
  Description: XML External Entity (XXE) Injection
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-EXPAT-358080
  Introduced through: apache2@2.4.49-4
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > apr-util/libaprutil1@1.6.1-5 > expat/libexpat1@2.4.1-3

✗ Low severity vulnerability found in curl/libcurl4
  Description: Improper Validation of Integrity Check Value
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-CURL-1322653
  Introduced through: curl/libcurl4@7.79.1-2, apache2@2.4.49-4
  From: curl/libcurl4@7.79.1-2
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > curl/libcurl4@7.79.1-2

✗ Low severity vulnerability found in curl/libcurl4
  Description: Insufficiently Protected Credentials
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-CURL-1322668
  Introduced through: curl/libcurl4@7.79.1-2, apache2@2.4.49-4
  From: curl/libcurl4@7.79.1-2
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4 > curl/libcurl4@7.79.1-2

✗ Low severity vulnerability found in coreutils
  Description: Improper Input Validation
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-COREUTILS-317471
  Introduced through: coreutils@8.32-4.1
  From: coreutils@8.32-4.1

✗ Low severity vulnerability found in coreutils
  Description: Race Condition
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-COREUTILS-317495
  Introduced through: coreutils@8.32-4.1
  From: coreutils@8.32-4.1

✗ Low severity vulnerability found in apt/libapt-pkg6.0
  Description: Improper Verification of Cryptographic Signature
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-APT-407503
  Introduced through: apt/libapt-pkg6.0@2.3.11, apt@2.3.11
  From: apt/libapt-pkg6.0@2.3.11
  From: apt@2.3.11 > apt/libapt-pkg6.0@2.3.11
  From: apt@2.3.11

✗ Low severity vulnerability found in apache2/apache2-bin
  Description: Arbitrary Code Injection
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-APACHE2-391439
  Introduced through: apache2/apache2-bin@2.4.49-4, apache2@2.4.49-4, apache2/apache2-data@2.4.49-4, apache2/apache2-utils@2.4.49-4
  From: apache2/apache2-bin@2.4.49-4
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4
  From: apache2/apache2-data@2.4.49-4
  and 4 more...

✗ Low severity vulnerability found in apache2/apache2-bin
  Description: Session Fixation
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-APACHE2-391451
  Introduced through: apache2/apache2-bin@2.4.49-4, apache2@2.4.49-4, apache2/apache2-data@2.4.49-4, apache2/apache2-utils@2.4.49-4
  From: apache2/apache2-bin@2.4.49-4
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4
  From: apache2/apache2-data@2.4.49-4
  and 4 more...

✗ Low severity vulnerability found in apache2/apache2-bin
  Description: Resource Exhaustion
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-APACHE2-391523
  Introduced through: apache2/apache2-bin@2.4.49-4, apache2@2.4.49-4, apache2/apache2-data@2.4.49-4, apache2/apache2-utils@2.4.49-4
  From: apache2/apache2-bin@2.4.49-4
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4
  From: apache2/apache2-data@2.4.49-4
  and 4 more...

✗ Low severity vulnerability found in apache2/apache2-bin
  Description: Arbitrary Code Injection
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-APACHE2-391539
  Introduced through: apache2/apache2-bin@2.4.49-4, apache2@2.4.49-4, apache2/apache2-data@2.4.49-4, apache2/apache2-utils@2.4.49-4
  From: apache2/apache2-bin@2.4.49-4
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4
  From: apache2/apache2-data@2.4.49-4
  and 4 more...

✗ Low severity vulnerability found in apache2/apache2-bin
  Description: Numeric Errors
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-APACHE2-391575
  Introduced through: apache2/apache2-bin@2.4.49-4, apache2@2.4.49-4, apache2/apache2-data@2.4.49-4, apache2/apache2-utils@2.4.49-4
  From: apache2/apache2-bin@2.4.49-4
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4
  From: apache2/apache2-data@2.4.49-4
  and 4 more...

✗ Low severity vulnerability found in apache2/apache2-bin
  Description: CVE-2003-1307
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-APACHE2-391698
  Introduced through: apache2/apache2-bin@2.4.49-4, apache2@2.4.49-4, apache2/apache2-data@2.4.49-4, apache2/apache2-utils@2.4.49-4
  From: apache2/apache2-bin@2.4.49-4
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4
  From: apache2/apache2-data@2.4.49-4
  and 4 more...

✗ Low severity vulnerability found in apache2/apache2-bin
  Description: CVE-2007-1743
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-APACHE2-391734
  Introduced through: apache2/apache2-bin@2.4.49-4, apache2@2.4.49-4, apache2/apache2-data@2.4.49-4, apache2/apache2-utils@2.4.49-4
  From: apache2/apache2-bin@2.4.49-4
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4
  From: apache2/apache2-data@2.4.49-4
  and 4 more...

✗ Low severity vulnerability found in apache2/apache2-bin
  Description: Cross-site Scripting (XSS)
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-APACHE2-391822
  Introduced through: apache2/apache2-bin@2.4.49-4, apache2@2.4.49-4, apache2/apache2-data@2.4.49-4, apache2/apache2-utils@2.4.49-4
  From: apache2/apache2-bin@2.4.49-4
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4
  From: apache2/apache2-data@2.4.49-4
  and 4 more...

✗ High severity vulnerability found in apache2/apache2-bin
  Description: Directory Traversal
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-APACHE2-1728102
  Introduced through: apache2/apache2-bin@2.4.49-4, apache2@2.4.49-4, apache2/apache2-data@2.4.49-4, apache2/apache2-utils@2.4.49-4
  From: apache2/apache2-bin@2.4.49-4
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4
  From: apache2/apache2-data@2.4.49-4
  and 4 more...
  Fixed in: 2.4.50-1

✗ High severity vulnerability found in apache2/apache2-bin
  Description: NULL Pointer Dereference
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-APACHE2-1728105
  Introduced through: apache2/apache2-bin@2.4.49-4, apache2@2.4.49-4, apache2/apache2-data@2.4.49-4, apache2/apache2-utils@2.4.49-4
  From: apache2/apache2-bin@2.4.49-4
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4
  From: apache2/apache2-data@2.4.49-4
  and 4 more...
  Fixed in: 2.4.50-1

✗ Critical severity vulnerability found in apache2/apache2-bin
  Description: Directory Traversal
  Info: https://snyk.io/vuln/SNYK-DEBIANUNSTABLE-APACHE2-1729585
  Introduced through: apache2/apache2-bin@2.4.49-4, apache2@2.4.49-4, apache2/apache2-data@2.4.49-4, apache2/apache2-utils@2.4.49-4
  From: apache2/apache2-bin@2.4.49-4
  From: apache2@2.4.49-4 > apache2/apache2-bin@2.4.49-4
  From: apache2/apache2-data@2.4.49-4
  and 4 more...
  Fixed in: 2.4.51-1



Organization:      ecsdcmhrpr
Package manager:   deb
Project name:      docker-image|cve-2021
Docker image:      cve-2021
Platform:          linux/amd64
Licenses:          enabled

Tested 146 dependencies for known issues, found 55 issues.

Pro tip: use `--file` option to get base image remediation advice.
Example: $ snyk test --docker cve-2021 --file=path/to/Dockerfile

To remove this message in the future, please run `snyk config set disableSuggestions=true`

```
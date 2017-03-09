### Post-recon
Post-recon is a post-exploitation reconnaissance toolkit that helps in gathering further info about target network and uses Gmail as a C&C server.



### Requirements

* A Gmail account (Use a dedicated account! Do not use your personal one!)
* Turn on "Access for less secure apps" under the security settings of the account. [less secure apps](https://www.google.com/settings/security/lesssecureapps)
* You may also have to enable IMAP in the account settings.
* Visual C++ toolset v140 (VS 2015).
* libcurl 7.xx.x



### Gmail servers for libcurl

* smtp://smtp.gmail.com:587			(25,587/TLS)
* smtps://smtp.gmail.com:465		(465/SSL)
* imaps://imap.gmail.com:993/INBOX	(993/SSL)



### Disable protocols

* Open file \curl\lib\config-win32.h for editing.
* Append the following code, before last endif line. (*#endif /* HEADER_CURL_CONFIG_WIN32_H */*):

```cpp
/* ---------------------------------------------------------------- */
/*                       DISABLE PROTOCOLS                          */
/* ---------------------------------------------------------------- */

//#define HTTP_ONLY
#define CURL_DISABLE_FTP //disables FTP
#define CURL_DISABLE_LDAP //disables LDAP
#define CURL_DISABLE_TELNET //disables TELNET
#define CURL_DISABLE_DICT //disables DICT
#define CURL_DISABLE_FILE //disables FILE
#define CURL_DISABLE_TFTP //disables TFTP
#define CURL_DISABLE_HTTP //disables HTTP
//#define CURL_DISABLE_IMAP //disables IMAP
#define CURL_DISABLE_POP3 //disables POP3
//#define CURL_DISABLE_SMTP
```



### Build libcurl for Windows

* Open VS2015 x86 Open Native Tools Command Prompt.

```bash
cd \curl\winbuild\
```

* Clean/Delete any previous builds

#### Build DLL

```bash
nmake /f Makefile.vc mode=dll VC=14 ENABLE_SSPI=yes ENABLE_IPV6=no ENABLE_IDN=no ENABLE_WINSSL=yes GEN_PDB=no DEBUG=no MACHINE=x86
```

#### Build LIB

```bash
nmake /f Makefile.vc mode=static VC=14 ENABLE_SSPI=yes ENABLE_IPV6=no ENABLE_IDN=no ENABLE_WINSSL=yes GEN_PDB=no DEBUG=no MACHINE=x86
```

#### Output path

* \curl\builds\


#### CURL_STATICLIB

* Add CURL_STATICLIB definition
* GoTo Post-recon Project -> Properties -> C/C++ -> Preprocessor -> Preprocessor Definitions -> add CURL_STATICLIB



### MSVCRT Warning (Debug)

*LINK : warning LNK4098: defaultlib 'MSVCRT' conflicts with use of other libs; use /NODEFAULTLIB:library*

* GoTo Post-recon Project -> Properties -> Linker -> Input -> Ignore Specific Default Libraries -> add MSVCRT.lib



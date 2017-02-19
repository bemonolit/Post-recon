### Post-recon
Post-recon is a post-exploitation reconnaissance toolkit that helps in gathering further info about target network.


### Requirements

* A Gmail account (Use a dedicated account! Do not use your personal one!)
* Turn on "Access for less secure apps" under the security settings of the account. [less secure apps](https://www.google.com/settings/security/lesssecureapps)
* You may also have to enable IMAP in the account settings.
* Visual C++ toolset v140 (VS 2015)
* libcurl 7.52.1 [curl-7.52.1](https://curl.haxx.se/download/curl-7.52.1.zip)


### Gmail Servers for libcurl

* smtp://smtp.gmail.com:587		(25,587/TLS)
* smtps://smtp.gmail.com:465	(465/SSL)


### Build libcurl for Windows

```bash
* Open VS2015 x86 Open Native Tools Command Prompt
* cd \path\to\Downloads\curl-7.52.1\winbuild\
```

#### Build DLL

```bash
nmake /f Makefile.vc mode=dll VC=14 ENABLE_SSPI=yes ENABLE_IPV6=no ENABLE_IDN=no ENABLE_WINSSL=yes GEN_PDB=no DEBUG=no MACHINE=x86
```

#### Build LIB

```bash
nmake /f Makefile.vc mode=static VC=14 ENABLE_SSPI=yes ENABLE_IPV6=no ENABLE_IDN=no ENABLE_WINSSL=yes GEN_PDB=no DEBUG=no MACHINE=x86
```

#### Output path

*\path\to\Downloads\curl-7.52.1\builds*

#### CURL_STATICLIB

* Add CURL_STATICLIB definition
* GoTo Project -> Properties -> C/C++ -> Preprocessor -> Preprocessor Definitions -> add CURL_STATICLIB


### MSVCRT Warning (Debug)

*LINK : warning LNK4098: defaultlib 'MSVCRT' conflicts with use of other libs; use /NODEFAULTLIB:library*

* GoTo Project -> Properties -> Linker -> Input -> Ignore Specific Default Libraries -> add MSVCRT.lib


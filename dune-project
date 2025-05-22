(lang dune 3.18)

(name OTP)
(version %%VERSION%%)

(generate_opam_files true)

(source
 (github Heyji2/OTP))

(authors "Heyji2 <heyji2@github.com>")

(maintainers "Heyji2 <heyji2@github.com>")

(license GPL-3.0-only)

(documentation https://heyji2.github.io)

(package
 (name OTP)
 (synopsis "Time-base One Time Password (OTP) based on RFC6238 with an HMAC-SHA1 algorithm and a 6 digits code in OCAML")
 (description "It relies on the Cryptokit library for cryptography operations, as well as the Base32 
               library for base32 encoding. The library generate a QR Code with the qrc library. It is 
               tested against all test vectors provided in RFC 6238 and the test suite provides as well 
               a dynamic test which requires the use of an client authenticator (like Google Authenticator 
               or Microsoft Authenticator) as a final test.")
 (depends ocaml)
 (tags
  ("OTP" "TOTP" "HMAC-SHA1" "One Time Password")))

; See the complete stanza docs at https://dune.readthedocs.io/en/stable/reference/dune-project/index.html

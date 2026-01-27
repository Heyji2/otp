This OCaml library implements the Time-based One Time Password RFC 6238 with an HMAC-SHA1 algorithm and a 6 digits code. 
It relies on the Cryptokit library for cryptography operations, as well as the Base32 library for base32 encoding. 
The library generate a QR Code with the qrc library.
It is tested against all test vectors provided in RFC 6238 and the test suite provides as well a dynamic test 
which requires the use of an client authenticator (like Google Authenticator or Microsoft Authenticator) as a final
test. 

# Get Started

There are two phases to setup an OTP : 
1. the registration : that's where a secret is shared by the server to the client. 
2. the authentication : that's when the client enters the 6 digits code to authenticate. 

## Registration 
On the server side : 
    
```ocaml
let rng = Cryptokit.Random.secure_rng in             (* create a random generator                                                            *)
let s = generate_secret rng in                       (* generate a secret                                                                    *)
let u = generate_totp_uri "MyWebSite" s "Michel" in  (* embeds this secret into a specificaly crafted URI that authenticators can understand *)
let qr = Otp.uri2qrcode u in                         (* transform this URI into a QRCode that can be displayed in an html page               *)
let file = open_out "test.html" in 
let fmt = Format.formatter_of_out_channel file in 
let () = Format.fprintf fmt 
    "<html>
        <head></head>
        <body>
          <h1> TOTP QRCode </h1> %s
        </body>
      </html>" qr in 
let () = Format.pp_print_flush fmt () in 
let () = close_out file in 
let () = print_endline "\nOpen the file test.html and scann the QRCode with a client OTP (like Microsoft Authenticator)" 
```
    

## Authentication 
Then for the authentication : 
    
```ocaml
print_endline "Enter the six digit code to authenticate Michel on MyWebSite"
let code = read_line () in 
if ((String.length code) != 6) then 
  print_endline "Error, the code must have 6 and only 6 digits" 
else 
  let digits = Int32.to_int (Int32.of_string code) in  
  let c = totp_counter () in 
  let r = verify s c digits in
  match r with 
  |   Result.Error e -> print_endline e 
  |   Result.Ok resync -> Printf.printf "The code is good, Michel is authenticated on MyWebSite. Number of unsynchronised steps : %d" resync 
```

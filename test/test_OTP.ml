open Otp
open OUnit2

(* hex string to byte string 
   "0b0b" => "\011\011"
*)
let hstr2bstr h = 
  String.of_bytes (Hex.to_bytes (`Hex h))

(* byte string to hex string *)
let bstr2hstr b = 
  Hex.show (Hex.of_bytes b)

(* string to hex string *)
let str2hstr s = 
  Hex.show (Hex.of_bytes (String.to_bytes s))

(* Test vector and output 
  key    : "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
  data   : "Hi There" 
  result : "b617318655057264e28bc0b6fb378c8ef146be00" *)
let test_hmac_sha1 key data output ctxt = 
  let hmac = Core.hmac_sha1 key (Counter (String.to_bytes data)) in 
  let hmac_b = String.to_bytes hmac in 
  assert_equal ~ctxt:ctxt ~cmp:(fun a b -> (String.compare a b)=0) ~printer:(fun x -> x) output (bstr2hstr hmac_b)  

let test_totp time digits ctxt = 
  let t = Stdint.Uint64.of_int ((Float.to_int @@ Float.trunc @@ (Unix.time ()))-time) in 
  let c = Otp.totp_counter ~t0:t ~drift:Stdint.Uint64.zero () in 
  let k = "12345678901234567890" in 
  let hmac = Otp.Core.hmac_sha1 k c in  
  let d = Otp.Core.dynamic_truncation hmac 8 in 
  assert_equal ~ctxt:ctxt ~cmp:(Int.equal) ~printer:string_of_int digits d  

let test_authenticator ctxt = 
  let rng = Cryptokit.Random.secure_rng in 
  let s = generate_secret rng in 
  let v = generate_totp_uri "Test_totp" s "www.test.totp" in 
  let file = open_out "test.html" in 
  let fmt = Format.formatter_of_out_channel file in 
  let () = Format.fprintf fmt "<html><head></head><body><h1>TOTP QRCode</h1>%s</body></html>" (Otp.uri2qrcode v) in 
  let () = Format.pp_print_flush fmt () in 
  let () = close_out file in 
  let () = print_endline "\nOpen test.html and scann the QRCode with an OTP client (like Microsoft Authenticator) and enter the totp code for www.test.totp : " in
  let code = read_line () in 
  if ((String.length code) != 6) then 
    print_endline "Error, code must have 6 and only six characters" 
  else 
    let digits = Int32.to_int (Int32.of_string code) in  
    let c = totp_counter () in 
    let r = verify s c digits in
    let () = assert_equal 
        ~ctxt:    ctxt 
        ~cmp:    (fun r1 r2 -> match (r1,r2) with 
                               | Result.Ok _, Result.Ok _ -> true 
                               | _ -> false ) 
        ~printer:(fun x -> match x with 
                           | Result.Error e -> e 
                           | Result.Ok d -> string_of_int d) 
        r
        (Result.Ok digits) 
         
      in 
    match r with 
    | Result.Error e -> print_endline e 
    | Result.Ok resync -> Printf.printf "Valid code. Drift : %d steps" resync  

let suite = 
  "otp suite">:::
    ["hmac sha1 test 1">:: test_hmac_sha1 (hstr2bstr "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b") 
                                          "Hi There" 
                                          "b617318655057264e28bc0b6fb378c8ef146be00";
     "hmac sha1 test 2">:: test_hmac_sha1 "Jefe" 
                                          "what do ya want for nothing?" 
                                          "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79";
     "hmac sha1 test 3">:: test_hmac_sha1 (hstr2bstr "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") 
                                          (hstr2bstr (String.make 100 'd')) 
                                          "125d7342b9ac11cd91a39af48aa17b4f63f175d3";
     "hmac sha1 test 4">:: test_hmac_sha1 (hstr2bstr "0102030405060708090a0b0c0d0e0f10111213141516171819") 
                                          (hstr2bstr (String.concat "" (List.init 50 (fun _ -> "cd")))) 
                                          "4c9007f4026250c6bc8414f9bf50c86c2d7235da";
     "hmac sha1 test 5">:: test_hmac_sha1 (hstr2bstr "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")
                                          "Test With Truncation"
                                          "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04";
     "hmac sha1 test 6">:: test_hmac_sha1 (hstr2bstr (String.concat "" (List.init 80 (fun _ -> "aa"))))
                                          "Test Using Larger Than Block-Size Key - Hash Key First"
                                          "aa4ae5e15272d00e95705637ce8a3b55ed402112";
     "hmac sha1 test 7">:: test_hmac_sha1 (hstr2bstr (String.concat "" (List.init 80 (fun _ -> "aa"))))
                                          "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
                                          "e8e99d0f45237d786d6bbaa7965c7808bbff1a91";
      "hmac sha1 test 8">:: test_hmac_sha1 (hstr2bstr (String.concat "" (List.init 80 (fun _ -> "aa"))))
                                          "Test Using Larger Than Block-Size Key - Hash Key First"
                                          "aa4ae5e15272d00e95705637ce8a3b55ed402112";
      "hmac sha1 test 9">:: test_hmac_sha1 (hstr2bstr (String.concat "" (List.init 80 (fun _ -> "aa"))))
                                          "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
                                          "e8e99d0f45237d786d6bbaa7965c7808bbff1a91";
      "totp test 1">:: test_totp 59          94287082; 
      "totp test 2">:: test_totp 1111111109  07081804;
      "totp test 3">:: test_totp 1111111111  14050471;
      "totp test 4">:: test_totp 1234567890  89005924;
      "totp test 5">:: test_totp 2000000000  69279037;
      "totp test 6">:: test_totp 20000000000 65353130;
      (*"authenticator test 1">:: test_authenticator;*) (* <= dynamic test that cannot be included into a test suite. But you can run it on your own to see how it works *)
    ]



   
let () = 
  run_test_tt_main suite




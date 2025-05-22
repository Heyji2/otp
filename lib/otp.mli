(**
    This library implements the Time-based One Time Password RFC 6238 with an HMAC-SHA1 algorithm and a 6 digits code. 
    It relies on the Cryptokit library for cryptography operations, as well as the Base32 library for base32 encoding. 
    It is tested against all test vectors provided in RFC 6238 and the test suite provides as well a dynamic test 
    which requires the use of an client authenticator (like Google Authenticator or Microsoft Authenticator) as a final
    test. 
*)

open Stdint
type counter = Counter of bytes 

val generate_secret : ?nb_bits:int -> Cryptokit.Random.rng -> string
(**
    Generate a random string of nb_bits bits. If nb_bits is not a multiple of 8, the length of the
    string is rounded to the nearest integer toward 0. 
    nb_bits : number of bits of the generated secrets. Default to 160 bits. Must be a multiple of 8
    rng     : a random generator, as for instance, provided by Cryptokit.Randome.secure_rng 
 *)

val generate_totp_uri : ?algo:string -> ?nb_digits:int -> ?period:uint64 -> string -> string -> string -> string
(**
    [generate_totp_uri algo nb_digits period label secret issuer]
    generates an uri following the {{: https://github.com/google/google-authenticator/wiki/Key-Uri-Format} Key Uri Format}
    @param algo Only support SHA1 (as most of authenticator clients) which is the default
    @param nb_digits Number of digits of the generated one-time-password. The default is 6 digits
    @param period The time step equivalent of the counter increment in second. Default value is 30 seconds, as in most authenticator clients. Refered to as "X" in the RFC 6238.  
    @param label A name of the account the client with register an OTP for. 
    @param secret The secret to be shared with the authenticator client. 
    @param issuer The name of the issuer of the OTP. (e.g. the name of the website)
 *)
 
val totp_counter : ?period:uint64 -> ?t0:uint64 -> ?drift:uint64 -> unit -> counter
(**
   Generate a counter to be used in the time-based one time password procedure 
   with a secret to {!verify} a given code. The counter can also be incremented 
   using the function {!Core.increment}. 
   @param period The time step equivalent of the counter increment in seconds. Default 
   value is 30 seconds, as in most authenticator clients. Refered to as "X" in 
   the RFC 6238.  
   @param t0 The Unix time to start counting time steps (default value is 0, i.e., the 
   Unix epoch) and is also a system parameter. 
   @param drift This parameter account for a possible clock drifts between a client and 
   a validation server. This drift is the maximum number of backward time step to 
   from which the verification process must start with. The total number of steps
   (or increments) that will be used to check a given code/digits is the threshold 
   argument of the {!verify} function.  
   @return A counter to be use with a secret to verify a code/digits. 
 *)

val verify : ?threshold:int -> string -> counter -> int -> (int,string) result
(**
   [verify threshold secret counter digits] verifies that the digits are correct 
   given the secret and the counter by computing the digits and comparing them with 
   the one provided.
   @param threshold Synchronization threshold corresponding to the maximum number of 
   successive increments and verifications tried until concluding the digits are 
   not correct. Default value is seuil_synchro.
   @param secret The secret initially shared with the authenticator client and used to 
   compute the digits on the server side. 
   @param counter The counter used to compute the digits. It should be provided by the 
   [totp_counter] function. 
   @param digits The digits to be verified, provided by the authenticator client. 
   @return {!Result.Ok} with an integer mentioning the number of successive 
   increments of the counter that have been needed to validate the digits.
   This number must be less then {!seuil_synchro}. Should not be more than 
   2 for well synchronised clocks and no latency on the network. {!Result.Error} 
   otherwise with a message indicating "Invalid code".  

 *)

val uri2qrcode : string -> string
(**
   Transform an uri provided by {!generate_totp_uri} into a 50x50 mm2 qrcode
   embedded into an html svg element (container) that can be imported into
   any html page. 

   {[
   <svg xmlns='http://www.w3.org/2000/svg' version='1.1' width='50mm' height='50mm' viewBox='0 0 53 53'>
     <rect width='53' height='53' fill='white'/> <path fill='black' d='
      M 4,4 l 1,0 0,1 -1,0 z
      M 5,4 l 1,0 0,1 -1,0 z
      M 6,4 l 1,0 0,1 -1,0 z
      ...
      M 43,48 l 1,0 0,1 -1,0 z
      M 45,48 l 1,0 0,1 -1,0 z
     ' />
   </svg>
   ]}
 *)


(**
   This module is the core of the library and its functions are not exposed except 
   for testing purpose. Do note rely on it for production.

 *)
module Core : sig

val increment : counter -> counter
(**
   Increment a counter by one step.
 *)

val hmac_sha1 : string -> counter -> string
(**
  Compute the hashed message authentication code given a 
  secret (string) and a counter, according to RFC 2104.
  Validated with RFC 2202 tests vectors. 
 *)

val dynamic_truncation : string -> int -> int 
(**
  Compute the dynamic truncation function mentioned in 
  RFC4226. The function has been tested with the example
  given in section 5.4.  
  @param 1 HS = HMAC-SHA1(key,counter) as described in section 5.3
  @param 2 Number of digits of the code ('Digit' variable in section 5.3)
  Must be 6, 7 or 8.   
  @return Hashed Message Authentication Code (HMAC). 
 *)

val hotp : ?nb_digits:int -> string -> counter -> int
(**
 Compute the HMAC from the number of digits, the shared secret and the counter. 
 This is a combination of the [hmac_sha1] followed by [dynamic_truncation] functions.
 @param nb_digits Number of digits of the HMAC. 
 @param : The shared secret
 @param : the counter
 @return Hashed Message Authentication Code (HMAC)
 *)

val mk_time : float -> string
(**
  Helper function to display a date from a Unix time value (provided by e.g. [Unix.time])
 *)

val c2is : counter -> string 
(**
  Helper function to display a counter as an integer string 
 *)


val c2bs : counter -> string
(**
  Helper function to display a counter as a byte string
 *)


end
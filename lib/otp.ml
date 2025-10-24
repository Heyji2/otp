open Stdint

(* Paramètres de l'OTP *)
let shared_secret_length = 160              (* bits : doit être un multiple de 8                       *)
let counter_length       = 8                (* longueur du compteur en octets                          *)

let totp_max_drift       = Uint64.of_int 2  (* latence en nombre de step entre le client et le serveur *)
let digit                = 6                (* doit pouvoir être 6, 7 ou 8                             *)

let default_period       = Uint64.of_int 30 (* temps en secondes d'un pallier (step)                   *)
let default_date         = Uint64.zero      (* horodatage par default de date d'enregistrement de l'OTP 
                                               au format Unix epoch (en seconde depuis 1970)           *)
let seuil_synchro        = 15               (* le nombre maximum de fois ou le compteur est incrémenté 
                                               pour vérifier le code                                   *)

type counter = Counter of bytes 

module Core = struct 

(* fonction de debug pour afficher une date correspondant à un compteur (float) *)
let mk_time t = 
  let tm = Unix.localtime t in 
  let y = tm.tm_year + 1900 in 
  let m = tm.tm_mon + 1 in 
  Printf.sprintf "%d-%d-%d %2d:%2d:%2d" y m tm.tm_mday tm.tm_hour tm.tm_min tm.tm_sec 

(* counter to integer string conversion *)
let c2is counter = 
  let Counter c = counter in 
  Uint64.to_string (Uint64.of_bytes_big_endian c 0)

(* counter to byte string conversion *)
let c2bs counter = 
  let Counter c = counter in 
  Bytes.to_string c

(* calcul du hmac_sha1 à partir d'un secret et d'un compteur *)
let hmac_sha1 secret counter = 
  let hash = Cryptokit.MAC.hmac_sha1 secret in 
  Cryptokit.hash_string hash (c2bs counter)  

(* hs (hmac string) doit avoir 20 octets et digit ne peut être que 6, 7 ou 8 *)
let dynamic_truncation hs nb_digits = 
  let l = String.length hs in 
  let offset = String.get_uint8 hs (l-1) land 0xf in        (* 4 bits de poid faibles du dernier octet                            *) 
  let p = String.get_int32_be (String.sub hs offset 4) 0 in (* 4 octets à l'offset calculé précédemment                           *)
  let snum = Int32.logand p 0x7fffffffl in                  (* masque du bit de poid fort (signe)                                 *)
  let rec pow10 e =                                         (* définition de la fonction puissance 10 pour les entiers de 32 bits *)
    if (e=0) then 1l 
    else (Int32.mul 10l (pow10 (e-1))) in  
  let m = pow10 nb_digits in                                (* calcul du modulo : 10^digit                                        *)
  Int32.to_int (Stdlib.Int32.unsigned_rem snum m)           (* snum % 10^digit                                                    *)

(* calcul le hotp 
   k : le secret (la clé : key)
   c : le compteur
   nb_digits : le nombre de digits : 6, 7 ou 8
*)
let hotp ?(nb_digits=digit) k c = 
  let hs = hmac_sha1 k c in 
  dynamic_truncation hs nb_digits 
(* pour incrémenter un compteur *)
let increment counter  = 
  match counter with 
  | Counter c -> 
    let i = Uint64.of_bytes_big_endian c 0 in 
    let j = Uint64.add i Uint64.one in 
    let () = Uint64.to_bytes_big_endian j c 0 in 
    Counter c 

(* pour debug : affiche tous les paramètres *)
let debug_check d_server d s c = 
  let t = mk_time (Float.mul (Float.of_string (c2is c)) 30.0) in 
  Printf.printf "server code : %6d - client code : %6d - secret : %s - counter : %s - time : %s\n" d_server d (Base32.encode_string s) (c2is c) t 

end 

(* Génération d'un secret aléatoire *)
let generate_secret ?(nb_bits=shared_secret_length) rng = 
  let byte_length = nb_bits / 8 in 
  Cryptokit.Random.string rng byte_length

(* génère un compteur totp
   period : la durée, en seconde, de l'incrément du compteur [30s par défaut]. Cela permet de prendre en compte la latence du réseau. 
   t0 : la date initial (au format Unix epoch) d'enregistrement de l'OTP [0 par défaut]. Cela ajoute de l'aléa dans le processus. 
   drift : le nombre d'incréments (period) autorisés entre le client et le serveur, lié à une dérive [2 par defaut, ce qui correspond à 2x30+29 = 89s au max]

*)
let totp_counter ?(period=default_period) ?(t0=default_date) ?(drift = totp_max_drift) () = 
  let open Stdint in  
  let t1 = Uint64.of_float @@ Float.trunc @@ Unix.time () in 
  let step = Uint64.sub (Uint64.div (Uint64.sub t1 t0) period) drift in 
  let b = Bytes.create 8 in 
  let () = Uint64.to_bytes_big_endian step b 0 in  
  Counter b 

(*
   s : le secret
   c : le compteur
   d : les digits (le code)
*)
let check s c d = 
  let nb_digit = String.length (string_of_int d) in
  let d_server = Core.hotp ~nb_digits:nb_digit s c in 
  (*let () = debug_check d_server d s c in*)
  d_server = d


(* vérifie le code en resynchronisant, au besoin, les compteurs.  
    s : secret
    c : compteur
    d : digits (code)
    threshold : le nombre d'incréments maximum effectués pour vérifier le code si la première vérification échoue. 
    retour : le nombre de fois où le compteur doit être incrémenté pour être synchronisé. 
    si le seuil maximal de resynchronisation est atteint, renvoie une erreur. Sinon 
    retourne retourne le nombre d'incrément nécessaire à la synchronisation.  
*)
let rec verify ?(threshold=seuil_synchro) s c d = 
  match threshold with
  | 0 ->  Result.Error "Invalid threshold"  
  | _ ->  if ( d < 100000 || d > 99999999) then Result.Error "Invalid number of digits in the code. Must be 6, 7 or 8 digits" else 
          if (check s c d) then (Result.Ok (seuil_synchro - threshold)) 
          else verify ~threshold:(threshold-1) s (Core.increment c) d 

(* Génère une uri au format clé pour les clients authenticator. 
   Testé avec :
   - Google Authenticator 
   - Microsoft Authenticator
   - Synology Secure Sign In 
*)
let generate_totp_uri  ?(algo="SHA1") ?(nb_digits=digit) ?(period=default_period) label secret issuer = 
  let b32_secret = Base32.encode_string secret in 
  let a = if algo="SHA1" then algo else "SHA1" in  (* SHA1 only for the time being *)
  let n = Int.to_string nb_digits in 
  let p = Uint64.to_string period in  
  "otpauth://totp/" ^ 
  issuer ^ ":"  ^ label      ^ "?" ^ 
  "secret="     ^ b32_secret ^ 
  "&issuer="    ^ issuer     ^ 
  "&algorithm=" ^ a          ^ 
  "&digit="     ^ n          ^ 
  "&period="    ^ p 

(* Transforme une uri en un qrcode sous la forme d'une balise html intégrable dans un fichier html *)
let uri2qrcode uri = 
  match Qrc.encode uri with 
  | None -> "Capacité maximale atteinte"
  | Some m -> Qrc.Matrix.to_svg m 

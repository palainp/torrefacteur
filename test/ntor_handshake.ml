(*
   To perform the handshake, the client needs to know an identity key
   digest for the server, and an ntor onion key (a curve25519 public
   key) for that server. Call the ntor onion key "B".  The client
   generates a temporary keypair:

       x,X = KEYGEN()

   and generates a client-side handshake with contents:

       NODEID      Server identity digest  [ID_LENGTH bytes]
       KEYID       KEYID(B)                [H_LENGTH bytes]
       CLIENT_KP   X                       [G_LENGTH bytes]
*)
let create server_id server_ntor_pubkey client_ephemeral_pubkey =
  Cstruct.concat [
      server_id ;
      server_ntor_pubkey ;
      client_ephemeral_pubkey ;
  ]
in

let protoid   = "ntor-curve25519-sha256-1" in
let t_mac    = Cstruct.of_string (protoid ^ ":mac") in
let _t_key     = Cstruct.of_string (protoid ^ ":key_extract") in
let t_verify = Cstruct.of_string (protoid ^ ":verify") in
let _m_expand  = Cstruct.of_string (protoid ^ ":key_expand") in

(*

   The server generates a keypair of y,Y = KEYGEN(), and uses its ntor
   private key 'b' to compute:

     secret_input = EXP(X,y) | EXP(X,b) | ID | B | X | Y | PROTOID
     KEY_SEED = H(secret_input, t_key)
     verify = H(secret_input, t_verify)
     auth_input = verify | ID | B | Y | X | PROTOID | "Server"
*)
let server_handshake server_id (server_ntor_privkey, server_ntor_pubkey) client_ephemeral_pubkey x (server_ephemeral_privkey, server_ephemeral_pubkey) =
  let xy = match Mirage_crypto_ec.X25519.key_exchange server_ephemeral_privkey client_ephemeral_pubkey with
  | Error _ -> assert false
  | Ok r -> r
  in
  let xb = match Mirage_crypto_ec.X25519.key_exchange server_ntor_privkey client_ephemeral_pubkey with
  | Error _ -> assert false
  | Ok r -> r
  in
  let secret_input = Cstruct.concat [
      xy ;
      xb ;
      server_id ;
      server_ntor_pubkey ;
      client_ephemeral_pubkey ;
      server_ephemeral_pubkey ;
      Cstruct.of_string protoid ;
  ] in
  let verify = Mirage_crypto.Hash.mac `SHA256 ~key:t_verify secret_input in
  let auth_input = Cstruct.concat [
      verify ;
      server_id ;
      server_ntor_pubkey ;
      server_ephemeral_pubkey ;
      client_ephemeral_pubkey ;
      Cstruct.of_string protoid ;
      Cstruct.of_string "Server" ;
  ] in
  Mirage_crypto.Hash.mac `SHA256 ~key:t_mac auth_input
in

(*
   The client then checks Y is in G^* [see NOTE below], and computes

     secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
     KEY_SEED = H(secret_input, t_key)
     verify = H(secret_input, t_verify)
     auth_input = verify | ID | B | Y | X | PROTOID | "Server"
*)
let client_handshake server_id server_ntor_pubkey server_ephemeral_pubkey (client_ephemeral_privkey, client_ephemeral_pubkey) x =
  let yx = match Mirage_crypto_ec.X25519.key_exchange client_ephemeral_privkey server_ephemeral_pubkey with
  | Error _ -> assert false
  | Ok r -> r
  in
  let bx = match Mirage_crypto_ec.X25519.key_exchange client_ephemeral_privkey server_ntor_pubkey with
  | Error _ -> assert false
  | Ok r -> r
  in
  let secret_input = Cstruct.concat [
      yx ;
      bx ;
      server_id ;
      server_ntor_pubkey ;
      client_ephemeral_pubkey ;
      server_ephemeral_pubkey ;
      Cstruct.of_string protoid ;
  ] in
  let verify = Mirage_crypto.Hash.mac `SHA256 ~key:t_verify secret_input in
  let auth_input = Cstruct.concat [
      verify ;
      server_id ;
      server_ntor_pubkey ;
      server_ephemeral_pubkey ;
      client_ephemeral_pubkey ;
      Cstruct.of_string protoid ;
      Cstruct.of_string "Server" ;
  ] in
  Mirage_crypto.Hash.mac `SHA256 ~key:t_mac auth_input
in

let base16_decode str =
  let fg = `Hex str in
  Hex.to_string fg
in

let sec_pub_of_cs cs = match Mirage_crypto_ec.X25519.secret_of_cs cs with
  | Error _ -> assert false
  | Ok k -> k
in

let cs_of_str str = Cstruct.of_string str in

(* **************** *)
(* from https://github.com/tallaproject/onion/blob/develop/src/onion_ntor.erl#L259-L273 *)
let server_id = cs_of_str "iToldYouAboutStairs." in
let test_server_ntor_key = base16_decode "b878405ccfe99f9b888be56c80121bfb5ba5bf4e765774f75dbcec901d70044a"  in
let test_client_ephemeral_key = base16_decode "b85baebae6149867de41c9e4fc33f7ab9abe3fa146b3dfb0408ca49942841479" in
let test_server_ephemeral_key = base16_decode "2830171ac0af06c98c44f6a3e05a29cc81dd67ae41ae43f11816b989055d636d" in

let (server_ntor_privkey, server_ntor_pubkey) = sec_pub_of_cs (cs_of_str test_server_ntor_key) in
let test_server_ntor_pubkey = cs_of_str (base16_decode "0e3b9a3638cbb26225986f1b47890960a5356b947c32e470f12774015bcf1114" in
assert (Cstruct.equal server_ntor_pubkey test_server_ntor_pubkey);

let (client_ephemeral_privkey, client_ephemeral_pubkey) = sec_pub_of_cs (cs_of_str test_client_ephemeral_key) in
let test_client_ephemeral_pubkey = cs_of_str (base16_decode "09fb2509c1c42bf4851fdeed00a0c243afd0740c0425c200eaf1ce3c6f27a244" in
assert (Cstruct.equal server_ntor_pubkey test_server_ntor_pubkey);

let (server_ephemeral_privkey, server_ephemeral_pubkey) = sec_pub_of_cs (cs_of_str test_server_ephemeral_key) in
let test_server_ephemeral_pubkey = cs_of_str (base16_decode "e34b5fb453038cee794ba20496e47db1b5ad4592ceac21c4530129afc7951f68" in
assert (Cstruct.equal server_ntor_pubkey test_server_ntor_pubkey);

let _client_keypair = create server_id server_ntor_pubkey client_ephemeral_pubkey in
let shared_secret_a = server_handshake server_id (server_ntor_privkey, server_ntor_pubkey) client_ephemeral_pubkey x (server_ephemeral_privkey, server_ephemeral_pubkey) in
let shared_secret_b = client_handshake server_id server_ntor_pubkey server_ephemeral_pubkey (client_ephemeral_privkey, client_ephemeral_pubkey) x in

assert (Cstruct.equal shared_secret_a shared_secret_b);
Logs.info(fun f -> f "test handshake is ok !");

module Main (Time : Mirage_time.S) = struct

  let start _  =
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
    
    
    let hmac_verify = Mirage_crypto.Hash.mac `SHA256 ~key:t_verify in
    let hmac_mac = Mirage_crypto.Hash.mac `SHA256 ~key:t_mac in
    (*
       The server generates a keypair of y,Y = KEYGEN(), and uses its ntor
       private key 'b' to compute:
    
         secret_input = EXP(X,y) | EXP(X,b) | ID | B | X | Y | PROTOID
         KEY_SEED = H(secret_input, t_key)
         verify = H(secret_input, t_verify)
         auth_input = verify | ID | B | Y | X | PROTOID | "Server"
    *)
    let server_handshake server_id (server_ntor_privkey, server_ntor_pubkey) client_ephemeral_pubkey (server_ephemeral_privkey, server_ephemeral_pubkey) =
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
      let verify = hmac_verify secret_input in
      let auth_input = Cstruct.concat [
          verify ;
          server_id ;
          server_ntor_pubkey ;
          server_ephemeral_pubkey ;
          client_ephemeral_pubkey ;
          Cstruct.of_string protoid ;
          Cstruct.of_string "Server" ;
      ] in
      Cstruct.concat [
        server_ephemeral_pubkey ;
        hmac_mac auth_input ;
      ]
    in
    
    (*
       The client then checks Y is in G^* [see NOTE below], and computes
    
         secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
         KEY_SEED = H(secret_input, t_key)
         verify = H(secret_input, t_verify)
         auth_input = verify | ID | B | Y | X | PROTOID | "Server"
    *)
    let client_handshake server_id server_ntor_pubkey server_ephemeral_pubkey (client_ephemeral_privkey, client_ephemeral_pubkey) =
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
      let verify = hmac_verify secret_input in
      let auth_input = Cstruct.concat [
          verify ;
          server_id ;
          server_ntor_pubkey ;
          server_ephemeral_pubkey ;
          client_ephemeral_pubkey ;
          Cstruct.of_string protoid ;
          Cstruct.of_string "Server" ;
      ] in
      hmac_mac auth_input
    in
    
    let base16_decode str =
      let fg = `Hex str in
      Cstruct.of_string (Hex.to_string fg)
    in
    
    let sec_pub_of_cs check_pub cs = match Mirage_crypto_ec.X25519.secret_of_cs cs with
      | Error _ -> assert false
      | Ok (s, p) -> 
        assert (Cstruct.equal p check_pub);
        (s, p)
    in
    
    (* **************** *)
    (* from https://github.com/tallaproject/onion/blob/develop/src/onion_ntor.erl#L259-L273 *)
    let server_id = Cstruct.of_string "iToldYouAboutStairs." in
    
    (* test create *)
    let server_ntor_pubkey  = base16_decode "122fcc3441833e6240940c0a695dcfab70bcd4ce81f3a2d880ca66b55a7f9056" in
    let (_client_ephemeral_secret, client_ephemeral_pubkey) = sec_pub_of_cs
                         (base16_decode "d56771c950f82086cc698e807107d81b0570dfef16b9bc1c49415f98186fd65e") (* pub *)
                         (base16_decode "10586a2a14d8cf85a52d488e999c29bc1ab64bd4082d66a33e20601db2cdc973") (* secret *)
                         in
    let client1 = create server_id server_ntor_pubkey client_ephemeral_pubkey in
    let test_create = Cstruct.concat [
        base16_decode "69546f6c64596f7541626f75745374616972732e12" ;
        base16_decode "2fcc3441833e6240940c0a695dcfab70bcd4ce81f3" ;
        base16_decode "a2d880ca66b55a7f9056d56771c950f82086cc698e" ;
        base16_decode "807107d81b0570dfef16b9bc1c49415f98186fd65e" ;
    ] in
    assert (Cstruct.equal client1 test_create);
    Logs.info (fun f -> f "Test create is ok!");

    (* test server handshake *)
    let (server_ntor_secret, server_ntor_pubkey) = sec_pub_of_cs
                         (base16_decode "e0ee36663df2062500f3ba3ea93829ef1319a85c5e4a31cbb771208952bf681a") (* pub *)
                         (base16_decode "6010b2d3d047e7a5b31c13b5c7e9c7041431ef6732e750654750c7dd2c7fd569") (* secret *)
                         in
    let client_ephemeral_pubkey = base16_decode "968cd69194860780dd05d99e992c52bb48f0ed8bd11ee4d274a735d07e7e042a" in
    let (server_ephemeral_secret, server_ephemeral_pubkey) = sec_pub_of_cs
                         (base16_decode "3afbc0ae70195b88b30a77186372a48978b671bb0ed6b67de7ab33e04c5b9c02") (* pub *)
                         (base16_decode "f81bced970948eb5c334ae14168e987516bb23f2130c74bcc2312f609b851871") (* secret *)
                         in
    let server_reply = server_handshake server_id (server_ntor_secret, server_ntor_pubkey) client_ephemeral_pubkey (server_ephemeral_secret, server_ephemeral_pubkey) in
    let test_server_handshake = base16_decode "3afbc0ae70195b88b30a77186372a48978b671bb0ed6b67de7ab33e04c5b9c024ce6b76a222ae4b8ed04681287e95731d701302e8b87e3b7ef823c0d62aa0dbc" in
    assert (Cstruct.equal server_reply test_server_handshake);
    Logs.info (fun f -> f "Test server handshake is ok!");
    
    (* test client handshake *)
    let server_ntor_pubkey = base16_decode "e0ee36663df2062500f3ba3ea93829ef1319a85c5e4a31cbb771208952bf681a" in
    let server_ephemeral_pubkey = base16_decode "3afbc0ae70195b88b30a77186372a48978b671bb0ed6b67de7ab33e04c5b9c02" in
    let (client_ephemeral_secret, client_ephemeral_pubkey) = sec_pub_of_cs
                         (base16_decode "968cd69194860780dd05d99e992c52bb48f0ed8bd11ee4d274a735d07e7e042a") (* pub *)
                         (base16_decode "803c44b41a780e7986e0835ad321db5c81aec58f3cb8644255d5b17318335b55") (* secret *)
                         in
    let auth = base16_decode "4ce6b76a222ae4b8ed04681287e95731d701302e8b87e3b7ef823c0d62aa0dbc" in
    let client_auth = client_handshake server_id server_ntor_pubkey server_ephemeral_pubkey (client_ephemeral_secret, client_ephemeral_pubkey) in
    assert (Cstruct.equal client_auth auth);
    Logs.info (fun f -> f "Test client handshake is ok!");
    
    (* test handshake *)    
    let (server_ntor_secret, server_ntor_pubkey) = sec_pub_of_cs
                         (base16_decode "0e3b9a3638cbb26225986f1b47890960a5356b947c32e470f12774015bcf1114") (* pub *)
                         (base16_decode "b878405ccfe99f9b888be56c80121bfb5ba5bf4e765774f75dbcec901d70044a") (* secret *)
                         in
    let (client_ephemeral_secret, client_ephemeral_pubkey) = sec_pub_of_cs
                         (base16_decode "09fb2509c1c42bf4851fdeed00a0c243afd0740c0425c200eaf1ce3c6f27a244") (* pub *)
                         (base16_decode "b85baebae6149867de41c9e4fc33f7ab9abe3fa146b3dfb0408ca49942841479") (* secret *)
                         in
    let (server_ephemeral_secret, server_ephemeral_pubkey) = sec_pub_of_cs
                         (base16_decode "e34b5fb453038cee794ba20496e47db1b5ad4592ceac21c4530129afc7951f68") (* pub *)
                         (base16_decode "2830171ac0af06c98c44f6a3e05a29cc81dd67ae41ae43f11816b989055d636d") (* secret *)
                         in
    
    let server_reply = server_handshake server_id (server_ntor_secret, server_ntor_pubkey) client_ephemeral_pubkey (server_ephemeral_secret, server_ephemeral_pubkey) in
    let shared_secret_a = Cstruct.sub server_reply 32 32 in
    let shared_secret_b = client_handshake server_id server_ntor_pubkey server_ephemeral_pubkey (client_ephemeral_secret, client_ephemeral_pubkey) in
    
    assert (Cstruct.equal shared_secret_a shared_secret_b);
    Logs.info (fun f -> f "Test full handshake is ok!");

    (* test hmac *)
    assert (Cstruct.equal (hmac_verify (Cstruct.of_string "")) (base16_decode "1e2a1675024656f174fd05d95f26aaa7f9531677e4eed4e76da02269b85a34c4"));
    assert (Cstruct.equal (hmac_verify (Cstruct.of_string "foobar")) (base16_decode "e00972e74219a0f97c349e73552b1734896a6f74291a00dd09ff2870410bd059"));
    assert (Cstruct.equal (hmac_verify (Cstruct.of_string "aaa bbb ccc")) (base16_decode "b132b5cda3f0f84ea6bad8723eade941679c53de778d2bf1f97a1b5ec0256c76"));
    assert (Cstruct.equal (hmac_verify (Cstruct.of_string "aaabbbccc")) (base16_decode "5cee70f6c77d10b65b0d0b1c20c7db7891786534df76c180965dc40eedeb33b9"));
    assert (Cstruct.equal (hmac_verify (Cstruct.of_string (String.make 4 '\000'))) (base16_decode "c0abbff504a2db4b2c52a1ff1af36785d4dc9619579dc2f10141c149de906ff6"));
    Logs.info (fun f -> f "Test hmac_verify ok!");
    
    assert (Cstruct.equal (hmac_mac (Cstruct.of_string "")) (base16_decode "796ff498cb2ab62b568f4e5c6657b24711a1bc516a6639559af0c3e67ed40149"));
    assert (Cstruct.equal (hmac_mac (Cstruct.of_string "foobar")) (base16_decode "f54d5357308dc2ace62c226920ecab7dff8d162faf992d0497745b7da18a4d06"));
    assert (Cstruct.equal (hmac_mac (Cstruct.of_string "aaa bbb ccc")) (base16_decode "c7f8db82993bdb9beb1ad8ea8267a76bb10cb5ed960077de350a48538435379f"));
    assert (Cstruct.equal (hmac_mac (Cstruct.of_string "aaabbbccc")) (base16_decode "24389641b1edd9f569bf6d2570aeb6aabae1875c50f5c1ce66a5e21107139a31"));
    assert (Cstruct.equal (hmac_mac (Cstruct.of_string (String.make 4 '\000'))) (base16_decode "188504215739fca18d43fd06988d37ba8df17a5d47557d5379f76ebb2fb3b9e6"));
    Logs.info (fun f -> f "Test hmac_mac ok!");
    
    (* **************** *)
    (* A test where we don't control the server ntor priv key nor ephemeral priv key. Values were extracted from ntor_ref.py *)
    let server_id = base16_decode "74686973697361746f726e6f646569642423255e" in
    let server_ntor_pubkey = base16_decode "11e474752f5c59807d43f3362722acef7344463e110ac4219759e2ee5b76c470" in
    let (client_ephemeral_secret, client_ephemeral_pubkey) = sec_pub_of_cs
                         (base16_decode "b2bbe943016107e307bbf13c96047c47d4f48223e2d7a38d7f663bc906e56742") (* pub *)
                         (base16_decode "d8d98204e6a5dabe1e86e4acb439be0200db7e7bb54012b4d58e0c7989d5ef72") (* secret *)
                         in
    
    (* payload is the handshake reply from a router *)
    let payload = base16_decode "5927288db99da867962accf7cbe991b94686d8f48912dc1aa33fde4bf3bdaa1019b54b74780c9aa9dd507a07e37bae6724fa5e6311c686e5c6352aa5ad5260e3" in
    
    let server_ephemeral_pubkey = Cstruct.sub payload 0 32 in
    let shared_secret_a = Cstruct.sub payload 32 32 in
    let shared_secret_b = client_handshake server_id server_ntor_pubkey server_ephemeral_pubkey (client_ephemeral_secret, client_ephemeral_pubkey) in
    
    assert (Cstruct.equal shared_secret_a shared_secret_b);
    
    Logs.info(fun f -> f "tests handshake are ok !");
    
    Lwt.return_unit
end

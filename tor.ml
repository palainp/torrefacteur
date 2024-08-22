(*
 * Copyright (c) 2022 Pierre Alain <pierre.alain@tuta.io>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

open Lwt.Infix
open Helpers
open Circuits
open Tor_constants

(*
   The following should be compatible with:
   https://gitlab.torproject.org/tpo/core/torspec
*)
module Make (Rand: Mirage_random.S) (Stack: Tcpip.Stack.V4V6) (Clock: Mirage_clock.PCLOCK) = struct

    let log_src = Logs.Src.create "tor-protocol" ~doc:"Tor protocol"
    module Log = (val Logs.src_log log_src : Logs.LOG)

    module TCP = Stack.TCP
    module TLS = Tls_mirage.Make(TCP)
    module NSS = Ca_certs_nss.Make (Clock)

    type cell = {
       circID : Int.t ;
       command : tor_command ;
       payload : Cstruct.t ;
       padding : Cstruct.t ;
    }

    let write tls cell =
        let buf = Cstruct.concat [
            uint16_to_cs cell.circID ;
            uint8_to_cs (tor_command_to_uint8 cell.command) ;
            cell.payload ;
            cell.padding ;
        ] in
        TLS.write tls buf >>= function
        | Ok () -> Log.info(fun f -> f "send %s" (escape_data buf)); Lwt.return (Ok())
        | Error e -> Log.info(fun f -> f "send err: %a" TLS.pp_write_error e); Lwt.return (Error e)

    let read tls =
        TLS.read tls >>= function
        | Ok (`Data buf) -> Log.info(fun f -> f "recv %s" (escape_data buf)); Lwt.return (Ok buf)
        | Ok `Eof -> Log.info(fun f -> f "recv eof"); Lwt.return (Ok Cstruct.empty)
        | Error e -> Log.info(fun f -> f "recv err: %a" TLS.pp_error e); Lwt.return (Error e)

    let send_cell tls cell cb =
        write tls cell >>= fun _ ->
        read tls >>= function
        | Error e ->
            Log.err (fun m -> m "error %a while receiving packets" TLS.pp_error e ) ;
            assert false
        | Ok data ->
            cb data

    let payload_len = 509
    let hash_len = 20
    let key_len = 32

    let random_cs ?(len = Random.int 128) () =
        let cs = Cstruct.create len in
        for i = 0 to len - 1 do Cstruct.set_uint8 cs i (Random.int 256) done;
        cs

    let create_packet ?(padding = true) ?(random_padding = false) circID command payload =
        (* assert don't allow padding is false and random_padding is true *)
        let padding = if padding then
                let len = Cstruct.length payload in
                if random_padding then
                    random_cs ~len:(payload_len-len) ()
                else
                    Cstruct.create (payload_len-len)
            else Cstruct.empty
        in
        {
            circID ;
            command ;
            payload ;
            padding ;
        }

    (* VERSIONS is a variable len packet => add the len size right after the command field *)
    let version circID =
        let v = Cstruct.concat [
            uint16_to_cs 2 ;                 (* length of the packet, specific to the versions packet *)
            uint16_to_cs 3 ;                 (* claims to be a version 3 client only *)
        ] in
        create_packet circID VERSIONS v ~padding:false

    (* NETINFO is a fixed len packet => do not add the len size right after the command field *)
    let netinfo circID my_addr router_addr =
        let payload = Cstruct.concat [
        	uint32_to_cs 0l ; (* client should use 0 for timestamp to avoid fingerprinting *)
            uint8_to_cs 4 ; (* ATYPE = IPv4 *)
            uint8_to_cs 4 ; (* ALEN = 4 for IPv4 *)
        	router_addr ;
            uint8_to_cs 1 ; (* NMYADDR = 1 *)
            uint8_to_cs 4 ; (* ATYPE = IPv4 *)
            uint8_to_cs 4 ; (* ALEN = 4 for IPv4 *)
        	my_addr ;
        ] in
        create_packet circID NETINFO payload ~padding:true

    let handshake_client nodeid ntor_onion_key my_pubkey =
        let hdata = Cstruct.concat [
            nodeid ;
            ntor_onion_key ;
            my_pubkey ;
        ] in
        let len = Cstruct.length hdata in
        Cstruct.concat [
            uint16_to_cs 2 ;   (* HTYPE 0==legacy TAP, 1==reserved, 2==ntor*)
            uint16_to_cs len ; (* HLEN *)
            hdata ;            (* HDATA *)
        ]

    (* CREATE2 is a fixed len packet => do not add the len size after the command field *)
    let create2 circID nodeid ntor_onion_key my_pubkey =
        let payload = handshake_client nodeid ntor_onion_key my_pubkey in
        create_packet circID CREATE2 payload ~padding:true

    (* 5.1.2. EXTEND and EXTENDED *
       6.1. Relay cells *)
    let extend2 : Int.t -> Mirage_crypto_ec.Ed25519.priv list -> Cstruct.t -> Cstruct.t -> Nodes.Relay.t -> cell =
    fun circID kf_list last_df my_pubkey next_relay ->
        let spec = Cstruct.concat [
            uint8_to_cs 1 ;                   (* NSPEC *)
            uint8_to_cs 0 ;                   (* [00] TLS-over-TCP, IPv4 address *)
            uint8_to_cs 6 ;
            uint32_to_cs (* (Ipaddr.to_int32 next_relay.ip_addr) *) 0l ;
            uint16_to_cs (next_relay.port) ;
        ] in
        let next_nodeid = Cstruct.of_string (Hex.to_string next_relay.fingerprint) in
        let next_ntor_onion_key = Cstruct.of_string next_relay.ntor_onion_key in
        let handshake = handshake_client next_nodeid next_ntor_onion_key my_pubkey in
        let extend2_payload = Cstruct.concat [
            spec ;
            handshake ;
        ] in
        let len = Cstruct.length extend2_payload in
        let payload = Cstruct.concat [
            (* 6.1. Relay cells *)
            uint8_to_cs (tor_relay_command_to_uint8 RELAY_EXTEND2) ;
            uint16_to_cs 0 ;    (* 0: unencrypted for the destination relay *)
            uint16_to_cs 1024 ; (* chose a random streamID ? *)
            uint32_to_cs 0l ;   (* ! TODO: digest ! *)
            uint16_to_cs len ;
            extend2_payload ;
            Cstruct.create (payload_len-11-len) ;
        ] in
        let updated_digest = Cstruct.sub (Cstruct.concat [ last_df ; payload ]) 0 4 in
        let payload = Cstruct.concat [
            (* 6.1. Relay cells *)
            uint8_to_cs (tor_relay_command_to_uint8 RELAY_EXTEND2) ;
            uint16_to_cs 0 ;
            uint16_to_cs 1024 ;
            updated_digest ;
            uint16_to_cs len ;
            extend2_payload ;
            Cstruct.create (payload_len-11-len) ;
        ] in
        let rec skinify kf_list payload =
            match kf_list with
            | [] -> payload
            | kf::t ->
                let signed = Mirage_crypto_ec.Ed25519.sign ~key:kf payload in
                skinify t signed
        in
        let onion_skin = skinify kf_list payload in
        create_packet circID RELAY_EARLY onion_skin ~padding:true ~random_padding:true

(*
5.3. Creating circuits

   When creating a circuit through the network, the circuit creator
   (OP) performs the following steps:

      1. Choose an onion router as an end node (R_N):
         * N MAY be 1 for non-anonymous directory mirror, introduction point,
           or service rendezvous connections.
         * N SHOULD be 3 or more for anonymous connections.
         Some end nodes accept streams (see 6.1), others are introduction
         or rendezvous points (see rend-spec-{v2,v3}.txt).

      2. Choose a chain of (N-1) onion routers (R_1...R_N-1) to constitute
         the path, such that no router appears in the path twice.
*)
    let create_circuit exit relay n =
        (* assert n>= 1 *)
        (* 1. *)
        let rnd_exit = Random.int (List.length exit) in
        let circuit = Circuits.create (List.nth exit rnd_exit) in
        (* 2. *)
        let rec add_relays n circuit =
            match n with
            | 0 -> circuit
            | x ->
                let rnd_relay = Random.int (List.length relay) in
                (* TODO: ensure that no router appears in the path twice *)
                let circuit = Circuits.add_relay circuit (List.nth relay rnd_relay) in
                add_relays (x-1) circuit
        in
        Lwt.return (add_relays (n-1) circuit)


    let negotiate_version tls circID payload =
      let rec proceed_next tls circID payload =
          let len_payload = Cstruct.length payload in
          if len_payload < 3 then Lwt.return Cstruct.empty
          else begin
            let _id = Cstruct.sub payload 0 2 in
            let typ = tor_command_of_uint8 (Cstruct.get_uint8 payload 2) in
            let payload = Cstruct.shift payload 3 in
            match typ with

            (* Variable sized commands always start with the length (2 bytes):
               let len = Cstruct.BE.get_uint16 payload 0 in
            *)

            | VERSIONS ->
                Log.info (fun m -> m "VERSIONS received...");
                let len = Cstruct.BE.get_uint16 payload 0 in
                let _versions = Cstruct.sub payload 2 len in
                proceed_next tls circID (Cstruct.shift payload (2+len))

            | CERTS ->
                Log.info (fun m -> m "CERTS received...");
                let len = Cstruct.BE.get_uint16 payload 0 in
                let ncerts = Cstruct.get_uint8 payload 2 in
                let rec parse_certs n payload consumed_size =
                    match n with
                    | 0 ->
                        consumed_size
                    | n ->
                        let _cert_type = Cstruct.get_uint8 payload 0 in
                        let clen = Cstruct.BE.get_uint16 payload 1 in
                        let _cert = Cstruct.sub payload 3 clen in
                        parse_certs (n-1) (Cstruct.shift payload (3+clen)) (consumed_size+3+clen)
                in
                let consumed_size = parse_certs ncerts (Cstruct.shift payload 3) 0 in
                assert(1+consumed_size = len); (* adds 1B for the number of certs *)
                proceed_next tls circID (Cstruct.shift payload (2+len))

            | AUTH_CHALLENGE ->
                Log.info (fun m -> m "AUTH_CHALLENGE received...");
                let len = Cstruct.BE.get_uint16 payload 0 in
                let _challenge = Cstruct.sub payload 2 32 in
                let n_methods = Cstruct.BE.get_uint16 payload 34 in
                let rec parse_methods n payload consumed_size =
                    match n with
                    | 0 ->
                        consumed_size
                    | n ->
                        let _method = Cstruct.BE.get_uint16 payload 0 in
                        parse_methods (n-1) (Cstruct.shift payload 2) (consumed_size+2)
                in
                let consumed_size = parse_methods n_methods (Cstruct.shift payload 8) 0 in
                assert(32+2+consumed_size = len); (* adds 32+2B for the header *)
                proceed_next tls circID (Cstruct.shift payload (2+len))

            | NETINFO ->
                Log.info (fun m -> m "NETINFO received...");
                Cstruct.hexdump payload ;
                let ip_len_of_cstruct v =
                    match v with
                        | 4 -> 4
                        | 6 | 16 -> 16
                        | _ -> Log.err (fun m -> m "Unexpected value when reading the IP addr size (%d)" v); 0
                in
                let _timestamp = Cstruct.BE.get_uint32 payload 0 in
                (* in the tor-spec, those are refered as other_* but as we received this packet, this is us *)
                let _my_atype = Cstruct.get_uint8 payload 4 in
                let my_alen = ip_len_of_cstruct (Cstruct.get_uint8 payload 5) in
                let my_aval = Cstruct.sub payload 6 my_alen in

                let rec parse_my_addr n payload consumed_size addr =
                    match n with
                    | 0 ->
                        (consumed_size, addr)
                    | n ->
                        let _router_atype = Cstruct.get_uint8 payload 0 in
                        let router_alen = ip_len_of_cstruct (Cstruct.get_uint8 payload 1) in
                        let router_aval = Cstruct.sub payload (2+router_alen) my_alen in
                        parse_my_addr (n-1) (Cstruct.shift payload (2+router_alen)) (consumed_size+2+router_alen) (Cstruct.concat [addr ; router_aval])
                in
                let n_router_addr = Cstruct.get_uint8 payload (6+my_alen) in
                let (consumed_size, router_aval) = parse_my_addr n_router_addr (Cstruct.shift payload (6+my_alen+1)) 0 Cstruct.empty in
                Logs.info ( fun f -> f "n_router_addr is %d" n_router_addr);
                   Cstruct.hexdump router_aval;

                (* for testing purpose, suppose we only have 1 IPv4 at the begining in router_aval... *)
                write tls (netinfo circID my_aval (Cstruct.sub router_aval 0 4)) >>= fun _ ->

                proceed_next tls circID (Cstruct.shift payload (Int.max payload_len (6+my_alen+1+consumed_size)))
            | DESTROY ->
                let reason = Cstruct.get_uint8 payload 0 in
                Log.info (fun m -> m "DESTROY received during version negotiation: %s" (tor_error_to_string (uint8_to_tor_error reason))) ;
                proceed_next tls circID (Cstruct.shift payload payload_len)

            | _ ->
                Log.info (fun m -> m "Received UNK packet...");
                Cstruct.hexdump payload ;
                assert false
          end
      in
      proceed_next tls circID payload

    let to_cs s =
      let line = String.split_on_char ' ' s in
      let c = String.concat "" line in
      let fg = `Hex c in
      Cstruct.of_string (Hex.to_string fg)

    let extract_keys nodeid ntor_onion_key secret my_pubkey payload =
      let rec proceed_next payload nodeid ntor_onion_key secret my_pubkey =
          let len_payload = Cstruct.length payload in
          if len_payload < 3 then Lwt.return Cstruct.empty
          else begin
            let _id = Cstruct.sub payload 0 2 in
            let typ = tor_command_of_uint8 (Cstruct.get_uint8 payload 2) in
            let payload = Cstruct.shift payload 3 in
            match typ with
            | CREATED2 ->
                let protoid   = "ntor-curve25519-sha256-1" in
                let t_mac    = Cstruct.of_string (protoid ^ ":mac") in
                let t_key     = Cstruct.of_string (protoid ^ ":key_extract") in
                let t_verify = Cstruct.of_string (protoid ^ ":verify") in
                let m_expand  = Cstruct.of_string (protoid ^ ":key_expand") in

(* This is for testing purpose, and should be removed, just needed to verify that we compute the right thing *)
(* ----------------- *)
(*
                let x  = to_cs "98 71 82 35 9d 3a c0 07 b1 f3 2b 51 a0 cd e9 ab 81 e6 d5 1e cc 91 e8 02 96 23 7a e9 43 53 d5 69" in
                let (x, _) = match Mirage_crypto_ec.X25519.secret_of_cs x with
                | Error _ -> assert false
                | Ok k -> k
                in
                let nodeid = to_cs "61 62 63 64 65 66 6f 75 41 62 6f 75 74 53 74 61 69 72 73 2e" in 
                let kB =     to_cs "81 99 d0 fe c5 ce 80 1b 0c 10 17 f9 99 0f c4 9e b9 b9 7a f7 a7 79 ef ec 7e 6b e8 f8 a5 65 a8 27" in 
                let kX =     to_cs "0e b6 2f d1 a8 b7 c5 65 3d 05 e6 5e ae 2f 5d 77 75 20 11 3c bf 2f 06 50 08 f6 15 55 da 34 ca 7b" in 
                let kY =     to_cs "64 87 b5 a7 d0 a3 02 d9 1f e4 ba 1a 17 56 ea 3c 83 e1 27 20 6f 03 53 a1 08 ef 26 14 e2 3e 54 27" in 

                let yx = match Mirage_crypto_ec.X25519.key_exchange x kY with
                | Error _ -> assert false
                | Ok r -> r
                in
                let yx_expected = to_cs "12 86 ce 57 90 9b 30 ce 84 c3 48 b8 8d ec e0 01 50 c3 c4 4e ea 23 20 c0 7f cf 0d fe 8b 1b fa 10" in
                assert (yx_expected = yx);

                let bx = match Mirage_crypto_ec.X25519.key_exchange x kB with
                | Error _ -> assert false
                | Ok r -> r
                in
                let bx_expected = to_cs "0f 06 cd cf 9c 00 73 9e 32 71 53 b2 0d 80 1d 97 17 fb 3c e3 d7 b0 36 c9 7e 42 94 16 5d 12 85 3d" in 
                assert (bx_expected = bx);

                let secret_input = Cstruct.concat [
                    yx ;
                    bx ;
                    nodeid ;
                    kB ;
                    kX ;
                    kY ;
                    Cstruct.of_string protoid ;
                ] in

                let secret_input_expected = to_cs "12 86 ce 57 90 9b 30 ce 84 c3 48 b8 8d ec e0 01 50 c3 c4 4e ea 23 20 c0 7f cf 0d fe 8b 1b fa 10 0f 06 cd cf 9c 00 73 9e 32 71 53 b2 0d 80 1d 97 17 fb 3c e3 d7 b0 36 c9 7e 42 94 16 5d 12 85 3d 61 62 63 64 65 66 6f 75 41 62 6f 75 74 53 74 61 69 72 73 2e 81 99 d0 fe c5 ce 80 1b 0c 10 17 f9 99 0f c4 9e b9 b9 7a f7 a7 79 ef ec 7e 6b e8 f8 a5 65 a8 27 0e b6 2f d1 a8 b7 c5 65 3d 05 e6 5e ae 2f 5d 77 75 20 11 3c bf 2f 06 50 08 f6 15 55 da 34 ca 7b 64 87 b5 a7 d0 a3 02 d9 1f e4 ba 1a 17 56 ea 3c 83 e1 27 20 6f 03 53 a1 08 ef 26 14 e2 3e 54 27 6e 74 6f 72 2d 63 75 72 76 65 32 35 35 31 39 2d 73 68 61 32 35 36 2d 31" in
                assert (secret_input_expected = secret_input);

                let verify = Mirage_crypto.Hash.mac `SHA256 ~key:t_verify secret_input in
                let verify_expected = to_cs "af aa 0f 40 8e 63 ba 84 ab cd 2e 37 fc ab 51 88 a1 64 8b 1f 22 62 15 3c 9a 66 60 d0 c8 aa 7b 99" in
                assert (verify_expected = verify);
                
                let auth_input = Cstruct.concat [
                    verify ;
                    nodeid ;
                    kB ;
                    kY ;
                    kX ;
                    Cstruct.of_string protoid ;
                    Cstruct.of_string "Server" ;
                ] in
                let auth_input_expected = to_cs "af aa 0f 40 8e 63 ba 84 ab cd 2e 37 fc ab 51 88 a1 64 8b 1f 22 62 15 3c 9a 66 60 d0 c8 aa 7b 99 61 62 63 64 65 66 6f 75 41 62 6f 75 74 53 74 61 69 72 73 2e 81 99 d0 fe c5 ce 80 1b 0c 10 17 f9 99 0f c4 9e b9 b9 7a f7 a7 79 ef ec 7e 6b e8 f8 a5 65 a8 27 64 87 b5 a7 d0 a3 02 d9 1f e4 ba 1a 17 56 ea 3c 83 e1 27 20 6f 03 53 a1 08 ef 26 14 e2 3e 54 27 0e b6 2f d1 a8 b7 c5 65 3d 05 e6 5e ae 2f 5d 77 75 20 11 3c bf 2f 06 50 08 f6 15 55 da 34 ca 7b 6e 74 6f 72 2d 63 75 72 76 65 32 35 35 31 39 2d 73 68 61 32 35 36 2d 31 53 65 72 76 65 72" in
                assert (auth_input_expected = auth_input);

                let h_auth_input = Mirage_crypto.Hash.mac `SHA256 ~key:t_mac auth_input in
                let h_auth_input_expected = to_cs "b6 cb eb ba ef d5 e5 f0 d0 7f 99 a0 eb 66 36 98 32 e1 8b e2 c0 13 f8 f8 2e 3c aa 58 9d d2 46 1a" in                
                assert (h_auth_input = h_auth_input_expected);
*)

(*
let nodeid = to_cs "74 68 69 73 69 73 61 74 6f 72 6e 6f 64 65 69 64 24 23 25 5e" in
let kB =     to_cs "11 e4 74 75 2f 5c 59 80 7d 43 f3 36 27 22 ac ef 73 44 46 3e 11 0a c4 21 97 59 e2 ee 5b 76 c4 70" in
let x =      to_cs "d8 d9 82 04 e6 a5 da be 1e 86 e4 ac b4 39 be 02 00 db 7e 7b b5 40 12 b4 d5 8e 0c 79 89 d5 ef 72" in
let (x, xpub) = match Mirage_crypto_ec.X25519.secret_of_cs x with
| Error _ -> assert false
| Ok k -> k
in
let kX =      to_cs "b2 bb e9 43 01 61 07 e3 07 bb f1 3c 96 04 7c 47 d4 f4 82 23 e2 d7 a3 8d 7f 66 3b c9 06 e5 67 42" in
assert(Cstruct.equal kX xpub);
let payload = to_cs "59 27 28 8d b9 9d a8 67 96 2a cc f7 cb e9 91 b9 46 86 d8 f4 89 12 dc 1a a3 3f de 4b f3 bd aa 10 19 b5 4b 74 78 0c 9a a9 dd 50 7a 07 e3 7b ae 67 24 fa 5e 63 11 c6 86 e5 c6 35 2a a5 ad 52 60 e3" in
*)

(* ----------------- *)
(* Here we can continue as usual, H and EXP are the good ones... *)

                Log.info (fun m -> m "CREATED2 received...");
                let x = secret in
                let kX = my_pubkey in
                let kB = ntor_onion_key in
Cstruct.hexdump kB;
Cstruct.hexdump nodeid;

                let kY = Cstruct.sub payload 0 32 in

                let h_auth_expected = Cstruct.sub payload 32 32 in

                let yx = match Mirage_crypto_ec.X25519.key_exchange x kY with
                | Error _ -> assert false
                | Ok r -> r
                in

                let bx = match Mirage_crypto_ec.X25519.key_exchange x kB with
                | Error _ -> assert false
                | Ok r -> r
                in

                let secret_input = Cstruct.concat [
                    yx ;
                    bx ;
                    nodeid ;
                    kB ;
                    kX ;
                    kY ;
                    Cstruct.of_string protoid ;
                ] in

                let verify = Mirage_crypto.Hash.mac `SHA256 ~key:t_verify secret_input in

                let auth_input = Cstruct.concat [
                    verify ;
                    nodeid ;
                    kB ;
                    kY ;
                    kX ;
                    Cstruct.of_string protoid ;
                    Cstruct.of_string "Server" ;
                ] in

                let h_auth_input = Mirage_crypto.Hash.mac `SHA256 ~key:t_mac auth_input in

                Log.info( fun f -> f "h_auth_expected is:");
                Cstruct.hexdump h_auth_expected ;
                Log.info( fun f -> f "h_auth_input is:");
                Cstruct.hexdump h_auth_input ;
                assert(Cstruct.equal   h_auth_expected h_auth_input);

                let key_seed = Mirage_crypto.Hash.mac `SHA256 ~key:t_key secret_input in
(*
                let verify = HMAC_SHA256(secret_input, "ntor-curve25519-sha256-1:verify")
                let auth_input = verify | id | ntor_onion_key | server_pub_key | client_pub_key | "ntor-curve25519-sha256-1" | "Server"

     assert auth = HMAC_SHA256(auth_input, "ntor-curve25519-sha256-1:mac")

then:
   In RFC5869's vocabulary, this is HKDF-SHA256 with info == "ntor-curve25519-sha256-1:key_expand",
   salt == "ntor-curve25519-sha256-1:key_extract", and IKM == secret_input.

                let Df = HMAC_SHA256("ntor-curve25519-sha256-1:key_expand" | INT8(1) , KEY_SEED)
                let Db = HMAC_SHA256(Df | "ntor-curve25519-sha256-1:key_expand" | INT8(2) , KEY_SEED)
                let Kf = HMAC_SHA256(Db | "ntor-curve25519-sha256-1:key_expand" | INT8(3) , KEY_SEED)
                let Kb = HMAC_SHA256(Kf | "ntor-curve25519-sha256-1:key_expand" | INT8(4) , KEY_SEED)
                let KH =
*)
                let k1 = Mirage_crypto.Hash.mac `SHA256 ~key:key_seed (Cstruct.concat [m_expand; uint8_to_cs 1]) in
                let k2 = Mirage_crypto.Hash.mac `SHA256 ~key:key_seed (Cstruct.concat [k1 ; m_expand; uint8_to_cs 2]) in
                let k3 = Mirage_crypto.Hash.mac `SHA256 ~key:key_seed (Cstruct.concat [k2 ; m_expand; uint8_to_cs 3]) in
                let k4 = Mirage_crypto.Hash.mac `SHA256 ~key:key_seed (Cstruct.concat [k3 ; m_expand; uint8_to_cs 4]) in
                let k = Cstruct.concat [ k1 ; k2 ; k3 ; k4 ] in

                let df = Cstruct.sub k 0 hash_len in
                let db = Cstruct.sub k (2*hash_len) hash_len in
                let kf = Cstruct.sub k (2*hash_len) key_len in
                let kb = Cstruct.sub k (2*hash_len+key_len) key_len in

                let cs = Cstruct.concat [df ; db ; kf ; kb] in
                Lwt.return cs

            | DESTROY ->
                let reason = Cstruct.get_uint8 payload 0 in
                Log.info (fun m -> m "extract keys DESTROY received: %s" (tor_error_to_string (uint8_to_tor_error reason))) ;
                proceed_next (Cstruct.shift payload payload_len) nodeid ntor_onion_key secret my_pubkey

            | _ ->
                Log.info (fun m -> m "Received UNK packet...");
                Cstruct.hexdump payload ;
                assert false
          end
      in
      proceed_next payload nodeid ntor_onion_key secret my_pubkey

(*
      3. If not already connected to the first router in the chain,
         open a new connection to that router.

      4. Choose a circID not already in use on the connection with the
         first router in the chain; send a CREATE/CREATE2 cell along
         the connection, to be received by the first onion router.

      5. Wait until a CREATED/CREATED2 cell is received; finish the
         handshake and extract the forward key Kf_1 and the backward
         key Kb_1.

      6. For each subsequent onion router R (R_2 through R_N), extend
         the circuit to R.
*)
    let connect_circuit stack circuit _g =
        (* TODO: if circuit.relay is empty, only use the exit node... *)
        (* 3. *)
        let first_node = List.hd circuit.relay in
        TCP.create_connection (Stack.tcp stack) (first_node.ip_addr, first_node.port) >>= function
        | Error e ->
            Log.err (fun m -> m "error %a while establishing TCP connection to %a:%d"
                    TCP.pp_error e Ipaddr.pp first_node.ip_addr first_node.port) ;
            assert false
        | Ok flow ->
            Log.info (fun m -> m "established new outgoing TCP connection to %a:%d"
                      Ipaddr.pp first_node.ip_addr first_node.port);
            let conf = Tls.Config.client ~authenticator:(fun ?ip:_ ~host:_ _ -> Ok None) () in

            TLS.client_of_flow conf flow >>= function
            | Error e ->
                Log.err (fun m -> m "error %a while establishing TLS connection to %a:%d"
                        TLS.pp_write_error e Ipaddr.pp first_node.ip_addr first_node.port) ;
                assert false
            | Ok tls ->
                Log.info (fun m -> m "established TLS connection to %a:%d"
                      Ipaddr.pp first_node.ip_addr first_node.port);
        (* 4 & 5. *)
                (* let (secret, my_pubkey) = Mirage_crypto_ec.X25519.gen_key ~g () in *)
let x =      to_cs "d8 d9 82 04 e6 a5 da be 1e 86 e4 ac b4 39 be 02 00 db 7e 7b b5 40 12 b4 d5 8e 0c 79 89 d5 ef 72" in
let (secret, my_pubkey) = match Mirage_crypto_ec.X25519.secret_of_cs x with
| Error _ -> assert false
| Ok k -> k
in
let kX =      to_cs "b2 bb e9 43 01 61 07 e3 07 bb f1 3c 96 04 7c 47 d4 f4 82 23 e2 d7 a3 8d 7f 66 3b c9 06 e5 67 42" in
assert(Cstruct.equal kX my_pubkey);

                let circID = 1024 in
                (* assert circID <> 0 and was never used with the first node *)

                send_cell tls (version circID) (negotiate_version tls circID) >>= fun _ ->

                (* let second_node = List.hd (List.tl circuit.relay) in *)
                let nodeid = Cstruct.of_string (Hex.to_string first_node.fingerprint) in
                let ntor_onion_key = Cstruct.of_string first_node.ntor_onion_key in

                let create2_pkt = create2 circID nodeid ntor_onion_key my_pubkey in
                send_cell tls create2_pkt (extract_keys nodeid ntor_onion_key secret my_pubkey) >>= fun cs ->

                let df = Cstruct.sub cs 0 hash_len in
                let kf = Cstruct.sub cs (2*hash_len) key_len in
                match Mirage_crypto_ec.Ed25519.priv_of_cstruct kf with
                | Error _ -> assert false
                | Ok kf ->
        (* 6. *)
                let rec extend_circuit tls circID secret my_pubkey kf_list last_df node_list =
Log.info (fun m -> m "will extend nodes");
                    match node_list with
                    | [] -> (* node more nodes to extend *)
                        Lwt.return kf_list
                    | h::t -> (* extend to h and rec on t *)
                        let onion_skin = extend2 circID kf_list last_df my_pubkey h in
                        let nodeid = Cstruct.of_string (Hex.to_string h.fingerprint) in
                        let ntor_onion_key = Cstruct.of_string h.ntor_onion_key in
                        send_cell tls onion_skin (extract_keys nodeid ntor_onion_key secret my_pubkey) >>= fun cs ->
                        let df = Cstruct.sub cs 0 hash_len in
                        let kf = Cstruct.sub cs (2*hash_len) key_len in
                        match Mirage_crypto_ec.Ed25519.priv_of_cstruct kf with
                        | Error _ -> Log.err (fun m -> m "Error with priv_of_cstruct"); assert false
                        | Ok kf ->
                        extend_circuit tls circID secret my_pubkey(List.cons kf kf_list) df t
                in
                extend_circuit tls circID secret my_pubkey [kf] df (List.tl circuit.relay) >>= fun _kf_list ->
Log.info (fun m -> m "then extend to exit");

                Lwt.return_unit
end

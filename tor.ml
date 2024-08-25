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
        | Ok () -> Log.info(fun f -> f "sending:"); Cstruct.hexdump buf; Lwt.return (Ok())
        | Error e -> Log.info(fun f -> f "send err: %a" TLS.pp_write_error e); Lwt.return (Error e)

    let read tls =
        TLS.read tls >>= function
        | Ok (`Data buf) -> Log.info(fun f -> f "reading:"); Cstruct.hexdump buf; Lwt.return (Ok buf)
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
(* To extend the circuit by a single onion router R_M, the OP performs
   these steps:

      1. Create an onion skin, encrypted to R_M's public onion key.
*)
        let next_nodeid = Cstruct.of_string (Hex.to_string next_relay.fingerprint) in
        let next_ntor_onion_key = Cstruct.of_string next_relay.ntor_onion_key in
        let handshake = handshake_client next_nodeid next_ntor_onion_key my_pubkey in
        (* let handshake_enc = Mirage_crypto_pk.Rsa.encypt ~key:next_relay.public_onion_key handshake in *)

(*
      2. Send the onion skin in a relay EXTEND/EXTEND2 cell along
         the circuit (see sections 5.1.2 and 5.5).
*)
        let spec = Cstruct.concat [
            uint8_to_cs 1 ;                   (* NSPEC *)
            uint8_to_cs 0 ;                   (* [00] TLS-over-TCP, IPv4 address *)
            uint8_to_cs 6 ;
            uint32_to_cs (Ipaddr.to_int32 next_relay.ip_addr) ;
            uint16_to_cs (next_relay.port) ;
        ] in
        let extend2_payload = Cstruct.concat [
            spec ;
            handshake ;
        ] in
        let len = Cstruct.length extend2_payload in
        let payload = Cstruct.concat [
            (* 6.1. Relay cells *)
            uint8_to_cs (tor_relay_command_to_uint8 RELAY_EXTEND2) ;
            uint16_to_cs 0 ;    (* 0: unencrypted for the destination relay *)
            uint16_to_cs 1234 ; (* chose a random streamID ? *)
            uint32_to_cs 0l ;   (* ! TODO: digest ! *)
            uint16_to_cs len ;
            extend2_payload ;
            Cstruct.make 4 '\000' ; (* Implementations SHOULD fill this field with four zero-valued bytes *)
            Cstruct.create (payload_len-11-len-2) ;
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

                let rec parse_router_addr n payload consumed_size addr =
                    match n with
                    | 0 ->
                        (consumed_size, addr)
                    | n ->
                        let _router_atype = Cstruct.get_uint8 payload 0 in
                        let router_alen = ip_len_of_cstruct (Cstruct.get_uint8 payload 1) in
                        let router_aval = Cstruct.sub payload 2 router_alen in
                        parse_router_addr (n-1) (Cstruct.shift payload (2+router_alen)) (consumed_size+2+router_alen) (Cstruct.concat [addr ; router_aval])
                in
                let n_router_addr = Cstruct.get_uint8 payload (6+my_alen) in
                let (consumed_size, router_aval) = parse_router_addr n_router_addr (Cstruct.shift payload (6+my_alen+1)) 0 Cstruct.empty in

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

    let extract_keys nodeid ntor_onion_key secret my_pubkey payload =
      let rec proceed_next payload nodeid ntor_onion_key secret my_pubkey =
          let len_payload = Cstruct.length payload in
          if len_payload < 3 then Lwt.return Cstruct.empty
          else begin
            let _circuit_id = Cstruct.sub payload 0 2 in
            let typ = tor_command_of_uint8 (Cstruct.get_uint8 payload 2) in
            let len = Cstruct.BE.get_uint16 payload 3 in
            let payload = Cstruct.shift payload 5 in
            match typ with
            | CREATED2 ->
                assert (len = 64);
                let protoid   = "ntor-curve25519-sha256-1" in
                let t_mac    = Cstruct.of_string (protoid ^ ":mac") in
                let t_key     = Cstruct.of_string (protoid ^ ":key_extract") in
                let t_verify = Cstruct.of_string (protoid ^ ":verify") in
                let m_expand  = Cstruct.of_string (protoid ^ ":key_expand") in

(*
                let verify = HMAC_SHA256(secret_input, "ntor-curve25519-sha256-1:verify")
                let auth_input = verify | id | ntor_onion_key | server_pub_key | client_pub_key | "ntor-curve25519-sha256-1" | "Server"

     assert auth = HMAC_SHA256(auth_input, "ntor-curve25519-sha256-1:mac")
*)
                Log.info (fun m -> m "CREATED2 received...");
                let x = secret in
                let kX = my_pubkey in
                let kB = ntor_onion_key in

(*
    let base16_decode str =
      let fg = `Hex str in
      Cstruct.of_string (Hex.to_string fg)
    in
    let sec_pub_of_cs cs = match Mirage_crypto_ec.X25519.secret_of_cs cs with
      | Error _ -> assert false
      | Ok (s, p) -> 
        (s, p)
    in
    let payload = base16_decode "b11dfd0426546dc3ccd566bc044623071cfa6c0cdc5031f6e4d4726d5060ae064edda9c2bb8828b7c7b4451937a429a14a0d7c89c8a828f6e7f551f575069a87" in
    let (x, kX) = sec_pub_of_cs (base16_decode "04e3c082528c10cdfae075d38f8d23c8127793d2426ad269260643f3dd1754e1") in
    let kB      = base16_decode "ff4d8905ba8401757f3095a25141ae7724d6a5b1790db8460dec0c0df904582e" in
    let nodeid  = base16_decode "49367166a01d6f33df01efc56467336dcdd47547" in
    let cokm    = base16_decode "3750e6a4d5a696113c6e0546870ce65b233ed329ff8dc5b52f79ce73cb6d871e539372aa4024adab0d403e1de998433f28b1eeaafb1e9878bb49742c12c7230f73bc1125e2a5a78d" in
*)
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
                assert(Cstruct.equal h_auth_expected h_auth_input);

(*
                then:
                   In RFC5869's vocabulary, this is HKDF-SHA256 with info == "ntor-curve25519-sha256-1:key_expand",
                   salt == "ntor-curve25519-sha256-1:key_extract", and IKM == secret_input.
*)
                (* let key_seed = Mirage_crypto.Hash.mac `SHA256 ~key:t_key secret_input in *)

                let cprk = Hkdf.extract ~hash:`SHA256 ~salt:t_key secret_input in
                let cokm = Hkdf.expand ~hash:`SHA256 ~prk:cprk ~info:m_expand (2*hash_len+2*key_len(*+digest_len*)) in
   
                Lwt.return cokm

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
    let connect_circuit stack circuit g =
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
                let (secret, my_pubkey) = Mirage_crypto_ec.X25519.gen_key ~g () in
                let circID = 1024 in (* TODO: chose at random, and not already used with this router *)
                (* assert circID <> 0 and was never used with the first node *)

                send_cell tls (version circID) (negotiate_version tls circID) >>= fun _ ->

                let nodeid = Cstruct.of_string (Hex.to_string first_node.fingerprint) in
                let ntor_onion_key = Cstruct.of_string first_node.ntor_onion_key in

                let create2_pkt = create2 circID nodeid ntor_onion_key my_pubkey in
                send_cell tls create2_pkt (extract_keys nodeid ntor_onion_key secret my_pubkey) >>= fun cs ->

Logs.info(fun f -> f "df-kdf is:");
    Cstruct.hexdump cs ;

                let df = Cstruct.sub cs 0 hash_len in
                let db = Cstruct.sub cs hash_len hash_len in
                let kf = Cstruct.sub cs (2*hash_len) key_len in
                let kb = Cstruct.sub cs (2*hash_len+key_len) key_len in

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
                        extend_circuit tls circID secret my_pubkey (List.cons kf kf_list) df t
                in
                extend_circuit tls circID secret my_pubkey [kf] df (List.tl circuit.relay) >>= fun _kf_list ->
Log.info (fun m -> m "then extend to exit");

                Lwt.return_unit
end

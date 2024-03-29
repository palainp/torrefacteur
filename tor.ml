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

    let handshake_client fingerprint key_serv ec_pub =
        let id = Cstruct.of_string (Hex.to_string fingerprint) in
        let h = Cstruct.of_string key_serv in
        let g = Mirage_crypto_ec.Ed25519.pub_to_cstruct ec_pub in
        let hdata = Cstruct.concat [
            id ;
            h ;
            g ;
        ] in
        let len = Cstruct.length hdata in
        Cstruct.concat [
            uint16_to_cs 2 ;   (* HTYPE 0==legacy TAP, 1==reserved, 2==ntor*)
            uint16_to_cs len ; (* HLEN *)
            hdata ;            (* HDATA *)
        ]

    (* CREATE2 is a fixed len packet => do not add the len size after the command field *)
    let create2 circID fingerprint key_serv ec_pub =
        let payload = handshake_client fingerprint key_serv ec_pub in
        create_packet circID CREATE2 payload ~padding:true

    (* 5.1.2. EXTEND and EXTENDED *
       6.1. Relay cells *)
    let extend2 : Int.t -> Mirage_crypto_ec.Ed25519.priv list -> Cstruct.t -> Mirage_crypto_ec.Ed25519.pub -> Nodes.Relay.t -> cell =
    fun circID kf_list last_df ec_pub next_relay ->
        let spec = Cstruct.concat [
            uint8_to_cs 1 ;                   (* NSPEC *)
            uint8_to_cs 0 ;                   (* [00] TLS-over-TCP, IPv4 address *)
            uint8_to_cs 6 ;
            uint32_to_cs (* (Ipaddr.to_int32 next_relay.ip_addr) *) 0l ;
            uint16_to_cs (next_relay.port) ;
        ] in
        let handshake = handshake_client next_relay.fingerprint next_relay.ntor_onion_key ec_pub in
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
                let _consumed_size = parse_certs ncerts (Cstruct.shift payload 3) 0 in
                (* assert _consumed_size == len *)
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
                let _consumed_size = parse_methods n_methods (Cstruct.shift payload 8) 0 in
                (* assert _consumed_size == len *)
                proceed_next tls circID (Cstruct.shift payload (2+len))

            | NETINFO ->
                Log.info (fun m -> m "NETINFO received...");
                Cstruct.hexdump payload ;
                let ip_len_of_cstruct v =
                    match v with
                        | 4 -> 4
                        | 6 -> 16
                        | _ -> Log.err (fun m -> m "Unexpected value when reading the IP addr size"); 0
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

                (* for testing purpose, suppose we onlly have 1 IPv4 at the begining in router_aval... *)
                write tls (netinfo circID my_aval (Cstruct.sub router_aval 0 4)) >>= fun _ ->

                proceed_next tls circID (Cstruct.shift payload (Int.max payload_len (6+my_alen+1+consumed_size)))
            | DESTROY ->
                let reason = Cstruct.get_uint8 payload 0 in
                Log.info (fun m -> m "DESTROY received: %s" (tor_error_to_string (uint8_to_tor_error reason))) ;
                proceed_next tls circID (Cstruct.shift payload payload_len)

            | _ ->
                Log.info (fun m -> m "Received UNK packet...");
                Cstruct.hexdump payload ;
                assert false
          end
      in
      proceed_next tls circID payload

    let extract_keys fingerprint ntor_onion_key client_pub_key client_priv_key payload =
      let rec proceed_next payload fingerprint client_pub_key client_priv_key ntor_onion_key =
          let len_payload = Cstruct.length payload in
          if len_payload < 3 then Lwt.return Cstruct.empty
          else begin
            let _id = Cstruct.sub payload 0 2 in
            let typ = tor_command_of_uint8 (Cstruct.get_uint8 payload 2) in
            let payload = Cstruct.shift payload 3 in
            match typ with
            | CREATED2 ->
                Log.info (fun m -> m "CREATED2 received...");
                let server_pubkey = Cstruct.sub payload 0 32 in
                let _auth = Cstruct.sub payload 32 32 in

                let protoid   = "ntor-curve25519-sha256-1" in
                let _t_mac    = Cstruct.of_string (String.concat "" [protoid ; ":mac"]) in
                let t_key     = Cstruct.of_string (String.concat "" [protoid ; ":key_extract"]) in
                let _t_verify = String.concat "" [protoid ; ":verify"] in
                let m_expand  = Cstruct.of_string (String.concat "" [protoid ; ":key_expand"]) in

                let id = Cstruct.of_string (Hex.to_string fingerprint) in
                let m1 = Mirage_crypto_ec.Ed25519.sign ~key:client_priv_key server_pubkey in
                let ntor_onion_key = Cstruct.of_string ntor_onion_key in
                let m2 = Mirage_crypto_ec.Ed25519.sign ~key:client_priv_key ntor_onion_key in
                let secret_input = Cstruct.concat [
                    id ;
                    m1 ;
                    m2 ;
                    ntor_onion_key ;
                    Mirage_crypto_ec.Ed25519.pub_to_cstruct client_pub_key ;
                    server_pubkey ;
                    Cstruct.of_string protoid ;
                ] in
                let key_seed = Mirage_crypto.Hash.mac `SHA256 ~key:secret_input t_key in
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
                Log.info (fun m -> m "DESTROY received: %s" (tor_error_to_string (uint8_to_tor_error reason))) ;
                proceed_next (Cstruct.shift payload payload_len) fingerprint client_pub_key client_priv_key ntor_onion_key

            | _ ->
                Log.info (fun m -> m "Received UNK packet...");
                Cstruct.hexdump payload ;
                assert false
          end
      in
      proceed_next payload fingerprint client_pub_key client_priv_key ntor_onion_key

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
                let (ec_priv, ec_pub) = Mirage_crypto_ec.Ed25519.generate ~g () in
                let circID = 1024 in
                (* assert circID <> 0 and was never used with the first node *)

                send_cell tls (version circID) (negotiate_version tls circID) >>= fun _ ->

                let create2_pkt = create2 circID first_node.fingerprint first_node.ntor_onion_key ec_pub in
                send_cell tls create2_pkt (extract_keys first_node.fingerprint first_node.ntor_onion_key ec_pub ec_priv) >>= fun cs ->

                let df = Cstruct.sub cs 0 hash_len in
                let kf = Cstruct.sub cs (2*hash_len) key_len in
                match Mirage_crypto_ec.Ed25519.priv_of_cstruct kf with
                | Error _ -> assert false
                | Ok kf ->
        (* 6. *)
Log.info (fun m -> m "will extend nodes");
                let rec extend_circuit tls circID ec_pub ec_priv kf_list last_df node_list =
                    match node_list with
                    | [] -> (* node more nodes to extend *)
                        Lwt.return kf_list
                    | h::t -> (* extend to h and rec on t *)
                        let onion_skin = extend2 circID kf_list last_df ec_pub h in
                        send_cell tls onion_skin (extract_keys h.fingerprint h.ntor_onion_key ec_pub ec_priv) >>= fun cs ->
                        let df = Cstruct.sub cs 0 hash_len in
                        let kf = Cstruct.sub cs (2*hash_len) key_len in
                        match Mirage_crypto_ec.Ed25519.priv_of_cstruct kf with
                        | Error _ -> assert false
                        | Ok kf ->
                        extend_circuit tls circID ec_pub ec_priv (List.cons kf kf_list) df t
                in
                extend_circuit tls circID ec_pub ec_priv [kf] df (List.tl circuit.relay) >>= fun _kf_list ->
Log.info (fun m -> m "then extend to exit");

                Lwt.return_unit
end

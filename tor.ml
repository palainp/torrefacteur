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
open Circuits
open Tor_constants

(*
   The following should be compatible with:
   https://gitlab.torproject.org/tpo/core/torspec
*)
module Make (Rand: Mirage_random.S) (Stack: Tcpip.Stack.V4) (Clock: Mirage_clock.PCLOCK) = struct

    let log_src = Logs.Src.create "tor-protocol" ~doc:"Tor protocol"
    module Log = (val Logs.src_log log_src : Logs.LOG)

    module TCP = Stack.TCPV4
    module TLS = Tls_mirage.Make(TCP)
    module NSS = Ca_certs_nss.Make (Clock)

    let escape_data buf = String.escaped (Cstruct.to_string buf)

    let write tls buf =
        TLS.write tls buf >>= function
        | Ok () -> Log.info(fun f -> f "send %s" (escape_data buf)); Lwt.return (Ok())
        | Error e -> Log.info(fun f -> f "send err: %a" TLS.pp_write_error e); Lwt.return (Error e)

    let read tls =
        TLS.read tls >>= function
        | Ok (`Data buf) -> Log.info(fun f -> f "recv %s" (escape_data buf)); Lwt.return (Ok buf)
        | Ok `Eof -> Log.info(fun f -> f "recv eof"); Lwt.return (Ok Cstruct.empty)
        | Error e -> Log.info(fun f -> f "recv err: %a" TLS.pp_error e); Lwt.return (Error e)

    let uint8_to_cs i =
        let cs = Cstruct.create 1 in
        Cstruct.set_uint8 cs 0 i;
        cs

    let uint16_to_cs i =
        let cs = Cstruct.create 2 in
        Cstruct.BE.set_uint16 cs 0 i;
        cs

    let uint32_to_cs i =
        let cs = Cstruct.create 4 in
        Cstruct.BE.set_uint32 cs 0 i;
        cs

    let payload_len = 509

    let create_packet circID command ?padding payload =
        let pad = match padding with
        | None | Some true ->
            let len = Cstruct.length payload in
            Cstruct.create (payload_len-len)
        | Some false -> Cstruct.empty
        in
        Cstruct.concat [
            circID ;
            uint8_to_cs (tor_command_to_uint8 command) ;
            payload ;
            pad ;
        ]

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

    (* 5.1.2. EXTEND and EXTENDED cells *)
    let extend2 : Cstruct.t -> Hex.t -> string -> Mirage_crypto_ec.Ed25519.pub -> Nodes.Relay.t -> Cstruct.t =
    fun circID fingerprint key_serv ec_pub next_relay ->
        let spec = Cstruct.concat [
            uint8_to_cs 2 ;                   (* NSPEC *)
            uint8_to_cs 0 ;                   (* [00] TLS-over-TCP, IPv4 address *)
            uint8_to_cs 6 ;
            uint32_to_cs (Ipaddr.V4.to_int32 next_relay.ip_addr) ;
            uint16_to_cs (next_relay.port) ;
            uint8_to_cs 3 ;                   (* [03] Ed25519 identity *)
            uint8_to_cs 32 ;
            Cstruct.of_string next_relay.ntor_onion_key ;
        ] in
        let handshake = handshake_client fingerprint key_serv ec_pub in
        let extend2_payload = Cstruct.concat [
            spec ;
            handshake ;
        ] in

        let len = Cstruct.length extend2_payload in
        let payload = Cstruct.concat [
            (* 6.1. Relay cells *)
            uint8_to_cs (tor_relay_command_to_uint8 RELAY_EXTEND2) ;
            uint16_to_cs 0 ;    (* 0 for unencrypted *)
            uint16_to_cs 1024 ; (* streamID *)
            uint32_to_cs 0l ;   (* digest *)
            uint16_to_cs len ;
            extend2_payload ;
        ] in
        create_packet circID RELAY payload ~padding:true

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
        Log.info (fun f->f "len = %d" (List.length exit));
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


    let deal_pack tls circID payload =
      let rec proceed_next tls circID payload =
          let len_payload = Cstruct.length payload in
          if len_payload < 3 then Lwt.return_unit
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

                proceed_next tls circID (Cstruct.shift payload (6+my_alen+1+consumed_size))

            | CREATED2 ->
                Log.info (fun m -> m "CREATED2 received...");
                let _server_pubkey = Cstruct.sub payload 0 32 in
                let _auth = Cstruct.sub payload 32 32 in
                proceed_next tls circID (Cstruct.shift payload payload_len)

            | RELAY ->
                Log.info (fun m -> m "RELAY received...");
                proceed_next tls circID (Cstruct.shift payload payload_len)

            | DESTROY ->
                let reason = Cstruct.get_uint8 payload 0 in
                Log.info (fun m -> m "DESTROY received: %s" (tor_error_to_string (uint8_to_tor_error reason))) ;
                proceed_next tls circID (Cstruct.shift payload payload_len)

            | _ ->
                Log.info (fun m -> m "Received UNK packet...");
                Cstruct.hexdump payload ;
                Lwt.return_unit
          end
      in
      proceed_next tls circID payload


    (* 4. Negotiating and initializing connections
       When the in-protocol handshake is used, the initiator sends a
   VERSIONS cell to indicate that it will not be renegotiating.  The
   responder sends a VERSIONS cell, a CERTS cell (4.2 below) to give the
   initiator the certificates it needs to learn the responder's
   identity, an AUTH_CHALLENGE cell (4.3) that the initiator must include
   as part of its answer if it chooses to authenticate, and a NETINFO
   cell (4.5). *)
    let send_version tls circID =
        write tls (version circID) >>= fun _ ->
        read tls >|= function
        | Error e ->
            Log.err (fun m -> m "error %a while receiving packets" TLS.pp_error e ) ;
            Lwt.return_unit
        | Ok data ->
            deal_pack tls circID data

    let connect_first_node tls circID fingerprint ntor_onion_key ec_pub =
        write tls (create2 circID fingerprint ntor_onion_key ec_pub) >>= fun _ ->
        read tls >|= function
        | Error e ->
            Log.err (fun m -> m "error %a while receiving packets" TLS.pp_error e ) ;
            Lwt.return_unit
        | Ok data ->
            deal_pack tls circID data

    let extend2_one_node tls circID fingerprint ntor_onion_key ec_pub extended_circuit =
        Log.info (fun m -> m "extend one more time");
        write tls (extend2 circID fingerprint ntor_onion_key ec_pub extended_circuit) >>= fun _ ->
        read tls >|= function
        | Error e ->
            Log.err (fun m -> m "error %a while receiving packets" TLS.pp_error e ) ;
            Lwt.return_unit
        | Ok data ->
            deal_pack tls circID data

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
        TCP.create_connection (Stack.tcpv4 stack) (first_node.ip_addr, first_node.port) >>= function
        | Error e ->
            Log.err (fun m -> m "error %a while establishing TCP connection to %a:%d"
                    TCP.pp_error e Ipaddr.V4.pp first_node.ip_addr first_node.port) ;
            Lwt.return_unit
        | Ok flow ->
            Log.info (fun m -> m "established new outgoing TCP connection to %a:%d"
                      Ipaddr.V4.pp first_node.ip_addr first_node.port);
            let conf = Tls.Config.client ~authenticator:(fun ?ip:_ ~host:_ _ -> Ok None) () in

            TLS.client_of_flow conf flow >>= function
            | Error e ->
                Log.err (fun m -> m "error %a while establishing TLS connection to %a:%d"
                        TLS.pp_write_error e Ipaddr.V4.pp first_node.ip_addr first_node.port) ;
                Lwt.return_unit
            | Ok tls ->
                Log.info (fun m -> m "established TLS connection to %a:%d"
                      Ipaddr.V4.pp first_node.ip_addr first_node.port);
        (* 4 & 5. *)
                let (_ec_priv, ec_pub) = Mirage_crypto_ec.Ed25519.generate ~g () in
                let circID = uint16_to_cs (1024) in
                (* assert circID <> 0 and was never used with the first node *)
                send_version tls circID >>= fun _ ->
                connect_first_node tls circID first_node.fingerprint first_node.ntor_onion_key ec_pub >>= fun _ ->
        (* 6. *)
                let rec extend2_next_nodes tls circID fingerprint ntor_onion_key ec_pub remaining =
                    match remaining with
                    | [] -> Lwt.return_unit
                    | h::t ->
                        extend2_one_node tls circID fingerprint ntor_onion_key ec_pub h >>= fun _ ->
                        extend2_next_nodes tls circID h.fingerprint h.ntor_onion_key ec_pub t
                in
Log.info (fun m -> m "will extend nodes");
                (* now we can extend our circuit to all nodes:
                   send extend2 one hop at a time, starting from the first router *)
                extend2_next_nodes tls circID first_node.fingerprint first_node.ntor_onion_key ec_pub (List.tl circuit.relay) >>= fun _ ->
(*Log.info (fun m -> m "will extend exit");
                write tls (extend2_exit_node circID circuit.exit) >>= fun _ ->*)
                Lwt.return_unit
end

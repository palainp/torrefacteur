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
module Make (Rand: Mirage_random.S) (Stack: Tcpip.Stack.V4) (KV: Mirage_kv.RO) (Clock: Mirage_clock.PCLOCK) (Cohttp: Cohttp_lwt.S.Client) = struct

    let log_src = Logs.Src.create "tor-protocol" ~doc:"Tor protocol"
    module Log = (val Logs.src_log log_src : Logs.LOG)

    module TCP = Stack.TCPV4
    module TLS = Tls_mirage.Make(TCP)
    module NSS = Ca_certs_nss.Make (Clock)
    module X509 = Tls_mirage.X509 (KV)(Clock)

    let get_file ctx fname =
        Log.debug (fun f -> f "try to open: %s" fname );
        let http_fetch ctx link =
          Log.info (fun f -> f "fetching %s" link) ;
          let uri = Uri.of_string link in
          Cohttp.get ~ctx uri >>= fun (_, body) ->
          Cohttp_lwt.Body.to_string body >|= fun body ->
          body
        in
        http_fetch ctx fname

    let get_in_array json pos =
        let list x = match x with
            | `A x -> x
            | _ -> []
        in
        List.nth (list json) pos

    let get_last_in_array json =
        let list x = match x with
            | `A x -> x
            | _ -> []
        in
        List.hd (List.rev (list json))

    let get_last_exit_list ctx cfg =
        let get_last_exit_list_info cfg =
            let get s t = Ezjsonm.find t [s] in
            let recent = get_in_array (get "directories" cfg ) 1 in
            (* assert path=="recent" *)
            let exit_lists = get_in_array (get "directories" recent ) 4 in
            (* assert path=="exit-lists" *)
            let last_list = get "files" exit_lists in
            Lwt.return (get_last_in_array last_list)
        in
        get_last_exit_list_info cfg >>= fun last_list_info ->
        Log.debug (fun f -> f "last exit-lists info list: %s" (Ezjsonm.value_to_string last_list_info) );
        let list_name = Ezjsonm.value_to_string (Ezjsonm.find last_list_info ["path"]) in
        (* TODO: remove heading and trailing quote in list_name (in a better way) *)
        let list_name = String.sub list_name 1 ((String.length list_name)-2) in
        let path = String.concat "/" ["https://collector.torproject.org/recent/"; "exit-lists"; list_name] in 
        get_file ctx path >>= fun nodes ->
        (* TODO: check for the sha256 against the result in last_list_info *)
        Lwt.return nodes

    let get_last_relay_list ctx cfg =
        let get_last_relay_list_info cfg =
            let get s t = Ezjsonm.find t [s] in
            let recent = get_in_array (get "directories" cfg ) 1 in
            (* assert path=="recent" *)
            let relay_desc_lists = get_in_array (get "directories" recent ) 6 in
            (* assert path=="relay-descriptors" *)
            let server_desc_lists = get_in_array (get "directories" relay_desc_lists ) 5 in
            (* assert path=="server-descriptors" *)
            let last_list = get "files" server_desc_lists in
            Lwt.return (get_last_in_array last_list)
        in
        get_last_relay_list_info cfg >>= fun last_list_info ->
        Log.debug (fun f -> f "last server-descriptors info list: %s" (Ezjsonm.value_to_string last_list_info) );
        let list_name = Ezjsonm.value_to_string (Ezjsonm.find last_list_info ["path"]) in
        (* TODO: remove heading and trailing quote in list_name (in a better way) *)
        let list_name = String.sub list_name 1 ((String.length list_name)-2) in
        let path = String.concat "/" ["https://collector.torproject.org/recent/"; "relay-descriptors"; "server-descriptors"; list_name] in 
        get_file ctx path >>= fun nodes ->
        (* TODO: check for the sha256 against the result in last_list_info *)
        Lwt.return nodes



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

    let version circID =
        let v = Cstruct.concat [
            uint16_to_cs 3;                 (* claims to be a version 3 client only *)
        ] in
        let len = Cstruct.length v in
        let payload = Cstruct.concat [
            circID ;
            uint8_to_cs (tor_command_to_uint8 VERSIONS) ;
            uint16_to_cs len ;
            v ;
        ] in
        payload

    (* 5.1 CREATE and CREATED cells *)
    let create2 cirdID hdata =
        let len = Cstruct.length hdata in
        let payload = Cstruct.concat [
            cirdID ;
            uint8_to_cs (tor_command_to_uint8 CREATE2) ;
            uint16_to_cs 0 ;   (* HTYPE *)
            uint16_to_cs len ; (* HLEN *)
            hdata              (* HDATA *)
        ] in
        payload

    let created2 cirdID hdata =
        let len = Cstruct.length hdata in
        Cstruct.concat [
            cirdID ;
            uint8_to_cs (tor_command_to_uint8 CREATED2) ;
            uint16_to_cs len ; (* HLEN *)
            hdata              (* HDATA *)
        ]

    (* 5.1 CREATE and CREATED cells *)
    let extend2 cirdID lspec hdata =
        let rec lspec_to_cstruct lspec acc =
            match lspec with
            | [] -> acc
            | lspec::t ->
                Cstruct.concat [lspec ; lspec_to_cstruct t acc]
        in
        let _len = Cstruct.length hdata in
        Cstruct.concat [
            cirdID ;
            uint8_to_cs (tor_command_to_uint8 CREATED2) ;
            uint8_to_cs (List.length lspec) ;
            lspec_to_cstruct lspec hdata
        ]


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


    let parse_pack payload =
      let rec consume_message payload acc =
          let len_payload = Cstruct.length payload in
          if len_payload < 3 then Lwt.return acc
          else begin
            let _id = Cstruct.sub payload 0 2 in
            let typ = tor_command_of_uint8 (Cstruct.get_uint8 payload 2) in
            let payload = Cstruct.shift payload 3 in
            match typ with

            | VERSIONS ->
                let len = Cstruct.BE.get_uint16 payload 0 in
                let _versions = Cstruct.sub payload 2 len in
                consume_message (Cstruct.shift payload (2+len)) (List.cons (VERSIONS, Cstruct.sub payload 0 (2+len)) acc)

            | CERTS ->
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
                consume_message (Cstruct.shift payload (2+len)) (List.cons (CERTS, Cstruct.sub payload 0 (2+len)) acc)

            | AUTH_CHALLENGE ->
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
                consume_message (Cstruct.shift payload (2+len)) (List.cons (AUTH_CHALLENGE, Cstruct.sub payload 0 (2+len)) acc)

            | NETINFO ->
                let ip_len_of_cstruct v =
                    match v with
                        | 4 -> 4
                        | 6 -> 16
                        | _ -> Log.err (fun m -> m "Unexpected value when reading the IP addr size"); 0
                in
                let _timestamp = Cstruct.BE.get_uint32 payload 0 in
                let _other_atype = Cstruct.get_uint8 payload 4 in
                let other_alen = ip_len_of_cstruct (Cstruct.get_uint8 payload 5) in
                let _other_aval = Cstruct.sub payload 6 other_alen in

                let rec parse_my_addr n payload consumed_size =
                    match n with
                    | 0 ->
                        consumed_size
                    | n ->
                        let _my_atype = Cstruct.get_uint8 payload 0 in
                        let my_alen = ip_len_of_cstruct (Cstruct.get_uint8 payload 1) in
                        let _my_aval = Cstruct.sub payload (2+other_alen) my_alen in
                        parse_my_addr (n-1) (Cstruct.shift payload (2+my_alen)) (consumed_size+2+my_alen)
                in
                let n_my_addr = Cstruct.get_uint8 payload (6+other_alen) in
                let consumed_size = parse_my_addr n_my_addr (Cstruct.shift payload (6+other_alen+1)) 0 in

                consume_message (Cstruct.shift payload (6+other_alen+1+consumed_size)) (List.cons (AUTH_CHALLENGE, Cstruct.sub payload 0 (6+other_alen+1+consumed_size)) acc)

            | _ ->
                Cstruct.hexdump payload ;
                Lwt.return acc
          end
      in
      consume_message payload []


    (* 4. Negotiating and initializing connections
       When the in-protocol handshake is used, the initiator sends a
   VERSIONS cell to indicate that it will not be renegotiating.  The
   responder sends a VERSIONS cell, a CERTS cell (4.2 below) to give the
   initiator the certificates it needs to learn the responder's
   identity, an AUTH_CHALLENGE cell (4.3) that the initiator must include
   as part of its answer if it chooses to authenticate, and a NETINFO
   cell (4.5). *)
    let negotiate_version tls circID =
        write tls (version circID) >>= fun _ ->
        read tls >|= function
        | Error e ->
            Log.err (fun m -> m "error %a while receiving packets" TLS.pp_error e ) ;
            Lwt.return_unit
        | Ok data ->
            parse_pack data >>= fun packets ->
            Log.info (fun m -> m "got %d packets" (List.length packets));
            Lwt.return_unit


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
    let connect_circuit stack _kv circuit =
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
        (* 4. *)
                let circID = uint16_to_cs (1024) in
                (* assert circID <> 0 and was never used with the first node *)
                negotiate_version tls circID >>= fun _ ->
        (* 5. *)
        (* 6. *)
                Lwt.return_unit
end

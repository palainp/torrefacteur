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

let src = Logs.Src.create "tor-nodes" ~doc:"Nodes for tor protocol"
module Log = (val Logs.src_log src : Logs.LOG)

module Exit = struct

    type t = {
        id : Hex.t ;
        ip_addr : Ipaddr.V4.t list ;
    }

    (* Format is:
       @type tordnsel 1.0
       Downloaded AAAA-MM-DD HH:MM:SS
       ExitNode ID_AS_HEX_STRING
       Published AAAA-MM-DD HH:MM:SS
       LastStatus AAAA-MM-DD HH:MM:SS
       ExitAddress IPV4 AAAA-MM-DD HH:MM:SS
       ExitNode ID_AS_HEX_STRING
       ...
    *)
    let parse_db db =
        let db = String.split_on_char '\n' db in
        let read_header db =
            match db with
            | _type::_downloaded::db ->
                (* assert String.starts_with ~prefix:"@type" _type) *)
                (* assert String.starts_with ~prefix:"Downloaded" _downloaded) *)
                db
            | _ (* this is a malformed list, thow exn ? *) -> []
        in
        let rec read_entries db acc =
            match db with
            | s::db ->
                if ( String.starts_with ~prefix:"ExitNode" s ) then (* a new id *)
                    let line = String.split_on_char ' ' s in
                    let id = List.nth line 1 in
                    read_entries db (List.cons {id=Hex.of_string id ; ip_addr=[]} acc)
                else if ( String.starts_with ~prefix:"ExitAddress" s ) then (* add a new ip for the last id *)
                    (* what should we have to do with those multiple ips ? *)
                    let last_item = List.hd acc in
                    let line = String.split_on_char ' ' s in
                    let ip = List.nth line 1 in
                    Log.debug (fun f -> f "Adding/Updating exit node %s (%s/%s)" s (Hex.to_string last_item.id) ip) ;
                    read_entries db (List.cons {last_item with ip_addr=List.cons (Ipaddr.V4.of_string_exn ip) last_item.ip_addr} (List.tl acc))
                else
                    read_entries db acc
            | [] -> acc
        in
        let db = read_header db in
        read_entries db []

    let to_string node =
        Ipaddr.V4.to_string (List.hd node.ip_addr) (* print the first ip... *)

    let rec print_list db =
        let rec print_ip iplist =
            match iplist with
            | i::t -> Log.debug (fun f -> f "\t %s" (Ipaddr.V4.to_string i)); print_ip t
            | [] -> ()
        in
        match db with
        | e::db -> Log.info (fun f -> f "Exit Node %s : " (Hex.to_string e.id)); print_ip (e.ip_addr) ; print_list db
        | [] -> ()

end

module Relay = struct

    type t = {
        id : String.t ;
        ip_addr : Ipaddr.V4.t ;
        port : Int.t ;
        identity_digest : String.t ;
        ntor_onion_key : String.t ;
    }

    (* Format is:
    @type server-descriptor 1.0
    router NAME IPV4 9001 0 0
    identity-ed25519
    -----BEGIN ED25519 CERT-----
    .....
    -----END ED25519 CERT-----
    master-key-ed25519 KEY
    or-address IPV6:9001
    platform Informational
    proto Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1 HSDir=1-2 HSIntro=3-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-3
    published AAAA-MM-DD HH:MM:SS
    fingerprint 0712 88B2 1827 11E5 2842 4813 7048 E0FB BFB3 6233
    uptime 64862
    bandwidth 409600 819200 430535
    extra-info-digest HEX KEY
    onion-key
    -----BEGIN RSA PUBLIC KEY-----
    ...
    -----END RSA PUBLIC KEY-----
    signing-key
    -----BEGIN RSA PUBLIC KEY-----
    ...
    -----END RSA PUBLIC KEY-----
    onion-key-crosscert
    -----BEGIN CROSSCERT-----
    ...
    -----END CROSSCERT-----
    ntor-onion-key-crosscert 1
    -----BEGIN ED25519 CERT-----
    ...
    -----END ED25519 CERT-----
    hidden-service-dir
    contact Informational
    ntor-onion-key KEY
    reject *:*
    router-sig-ed25519 KEY
    router-signature
    -----BEGIN SIGNATURE-----
    ...
    -----END SIGNATURE-----
    
    *)

    let parse_db db =
        let db = String.split_on_char '\n' db in
        let rec read_entries db acc =
            match db with
            | s::db ->
                if ( String.starts_with ~prefix:"router " s ) then begin (* a new id, beware! router-sig* also exists, thus checks for "router " *)
                    let line = String.split_on_char ' ' s in
                    let id = List.nth line 1 in
                    let ip = List.nth line 2 in
                    let port = List.nth line 3 in
                    Log.debug (fun f -> f "Adding relay node %s (%s/%s:%s)" s id ip port) ;
                    read_entries db (List.cons {id=id ; ip_addr=Ipaddr.V4.of_string_exn ip ; port=int_of_string port ; identity_digest = "" ; ntor_onion_key=""} acc)
                end else if ( String.starts_with ~prefix:"ntor-onion-key " s ) then begin
                    let last_item = List.hd acc in
                    let line = String.split_on_char ' ' s in
                    let key = List.nth line 1 in
                    Log.debug (fun f -> f "Adding relay node info ntor-onion-key %s (%s)" key last_item.id) ;
                    read_entries db (List.cons {last_item with ntor_onion_key=key} (List.tl acc))
                end else
                    read_entries db acc
            | [] -> acc
        in
        read_entries db []

    let to_string node =
        String.concat ":" [(Ipaddr.V4.to_string node.ip_addr) ; (Int.to_string node.port)]

    let rec print_list db =
        match db with
        | e::db -> Log.info (fun f -> f "Relay Node %s : %s" (e.id) (to_string e)) ; print_list db
        | [] -> ()

end

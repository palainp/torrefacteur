
let src = Logs.Src.create "tor-nodes" ~doc:"Nodes for tor protocol"
module Log = (val Logs.src_log src : Logs.LOG)
	
type exit_node = {
    id : Hex.t ;
    ip_addr : Ipaddr.V4.t ;
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
let parse_exit_db db =
    let db = String.split_on_char '\n' db in
    let read_header db =
        match db with
        | _type::_downloaded::db -> db
        | _ (* this is a malformed list, thow exn ? *) -> []
    in
    let rec read_entries db acc =
        match db with
        | s::db ->
            if ( String.starts_with ~prefix:"ExitNode" s ) then (* a new id *)
                let line = String.split_on_char ' ' s in
                let id = List.nth line 1 in
                read_entries db (List.cons {id=Hex.of_string id ; ip_addr=Ipaddr.V4.make 127 0 0 1} acc) (* this ip should be replaced later... *)
            else if ( String.starts_with ~prefix:"ExitAddress" s ) then (* set a new ip for the last id *)
                let last_item = List.hd acc in
                let line = String.split_on_char ' ' s in
                let ip = List.nth line 1 in
                Log.debug (fun f -> f "Adding exit node %s : %s" (Hex.to_string last_item.id) ip);
                read_entries db (List.cons {id=last_item.id ; ip_addr=Ipaddr.V4.of_string_exn ip} (List.tl acc))
            else
                read_entries db acc
        | [] -> acc
    in
    let db = read_header db in
    read_entries db []

let parse_relay_db _db =
    []

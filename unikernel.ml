open Lwt.Infix

module Main (Time : Mirage_time.S) (S: Tcpip.Stack.V4V6) (C : Cohttp_lwt.S.Client) = struct

  module Tor = Tor.Make(S)(C)

  let log_src = Logs.Src.create "torrefacteur" ~doc:"Tor test & dev"
  module Log = (val Logs.src_log log_src : Logs.LOG)

  let start _time _stack ctx =

(*    Tor.get_file ctx "https://collector.torproject.org/index/index.json" >>= fun str ->*)
    Tor.get_file ctx "./site/index/index.json" >>= fun str ->
    let cfg_json = Ezjsonm.from_string str in

    Tor.get_last_exit_list ctx cfg_json >>= fun exit_nodes ->
    let exit_nodes = Nodes.parse_exit_db exit_nodes in
    Tor.get_last_relay_list ctx cfg_json >>= fun relay_nodes ->
    let relay_nodes = Nodes.parse_relay_db relay_nodes in

    Tor.create_circuit exit_nodes relay_nodes >>= fun circuit ->
    (* as a current testing code create circuit outputs a string with all ips in the circuit... *)
    Log.debug (fun f -> f "The circuit is %s" circuit);

    Lwt.return_unit
end

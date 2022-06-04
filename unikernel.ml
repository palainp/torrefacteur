open Lwt.Infix

module Main (Time : Mirage_time.S) (S: Tcpip.Stack.V4V6) (C : Cohttp_lwt.S.Client) = struct

  module Tor = Tor.Make(S)(C)

  let log_src = Logs.Src.create "torrefacteur" ~doc:"Tor test & dev"
  module Log = (val Logs.src_log log_src : Logs.LOG)

  let start _time _stack ctx =

    Tor.update_routers ctx >>= fun cfg_json ->
    let rev = Cow.Json.find cfg_json ["build_revision"] in
	Log.info (fun f -> f "the revision is %s" (Cow.Json.to_string rev) );

    Tor.create_circuit cfg_json >>= fun () ->

	Lwt.return_unit
end

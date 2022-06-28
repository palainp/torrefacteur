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

module Main (Rand: Mirage_random.S) (Time: Mirage_time.S) (Clock: Mirage_clock.PCLOCK) (Stack: Tcpip.Stack.V4) (Cohttp: Cohttp_lwt.S.Client) = struct

    module Tor = Tor.Make(Rand)(Stack)(Clock)(Cohttp)

    let log_src = Logs.Src.create "torrefacteur" ~doc:"Tor test & dev"
    module Log = (val Logs.src_log log_src : Logs.LOG)

    let start _random _time _pclock stack ctx =
        (* When testing, it can be useful to always have the same randomized nodes selection.
           Remove this later...
        Random.self_init () ;
        *)
        let g = Mirage_crypto_rng.(create ~seed:(Cstruct.of_string "111213") (module Fortuna)) in

        Tor.get_file ctx "https://collector.torproject.org/index/index.json" >>= fun str ->
        let cfg_json = Ezjsonm.from_string str in

        Tor.get_last_exit_list ctx cfg_json >>= fun exit_nodes ->
        let exit_nodes = Nodes.Exit.parse_db exit_nodes in
        (*Nodes.Exit.print_list exit_nodes ;*)

        Tor.get_last_relay_list ctx cfg_json >>= fun relay_nodes ->
        let relay_nodes = Nodes.Relay.parse_db relay_nodes in
        (*Nodes.Relay.print_list relay_nodes ;*)

        Tor.create_circuit exit_nodes relay_nodes 3 >>= fun circuit ->
        (* as a current testing code create circuit outputs a string with all ips in the circuit... *)
        Log.info (fun f -> f "The circuit is %s" (Circuits.to_string circuit));
        Tor.connect_circuit stack circuit g >>= fun _ ->

        Lwt.return_unit
end

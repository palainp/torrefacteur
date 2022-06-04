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

(*
   The following should be compatible with:
   https://gitlab.torproject.org/tpo/core/torspec
*)
module Make (S: Tcpip.Stack.V4V6) (C : Cohttp_lwt.S.Client) = struct

  let log_src = Logs.Src.create "tor-protocol" ~doc:"Tor protocol"
  module Log = (val Logs.src_log log_src : Logs.LOG)


(*
    Actually https leads to Fatal error: exception Failure("connect: authentication failure: invalid certificate chain")
    For the time being, I use unix direct file access...
*)
let update_routers _ctx = 
(* https://metrics.torproject.org/collector.html#index-json
   https://collector.torproject.org/index/index.json *)
(*
    let http_fetch ctx link =
      Log.info (fun f -> f "fetching %s" link) ;
      let uri = Uri.of_string link in
      C.get ~ctx uri >>= fun (_, body) ->
      Cohttp_lwt.Body.to_string body >|= fun body ->
      body
    in
*)

    let unix_fetch path =
      Lwt.catch (fun () ->
        Lwt_unix.openfile path [Lwt_unix.O_RDONLY] 0 >>= fun fd ->
        Lwt.finalize (fun () ->
          Lwt_unix.LargeFile.fstat fd >>= fun stat ->
          if stat.Lwt_unix.LargeFile.st_kind = Lwt_unix.S_REG then
            Lwt_unix.LargeFile.fstat fd >>= fun stat ->
            let size64 = stat.Lwt_unix.LargeFile.st_size in
            if size64 > Int64.of_int Sys.max_string_length then
              Lwt.return (Error "file too large to process")
            else
              let size = Int64.to_int size64 in
              let buffer = Bytes.create size in
              Lwt_unix.read fd buffer 0 size >|= fun read_bytes ->
              if read_bytes = size then
                Ok (Bytes.unsafe_to_string buffer)
              else
                Error (Printf.sprintf "could not read %d bytes" size)
          else
            Lwt.return (Error (Printf.sprintf "file %s not found" path)))
        (fun () -> Lwt_unix.close fd))
      (function
        | Unix.Unix_error (Unix.ENOENT, _, _) ->
          Lwt.return (Error (Printf.sprintf "file %s not found" path))
        | Unix.Unix_error (_, _, _) ->
          Lwt.return (Error "storage error")
        | e -> Lwt.fail e)
    in

(*
    http_fetch ctx "https://collector.torproject.org/index/index.json" >>= fun str ->
*)    
    unix_fetch "index.json" >>= function
    | Error _ -> 
        let empty = Cow.Json.from_string("") in
        Log.warn (fun f -> f "oups") ;
        Lwt.return empty
    | Ok str ->
        let tor_cfg = Cow.Json.from_string(str) in
        Lwt.return tor_cfg

(*     5. Circuit management *)
let create_circuit _cfg =
        Log.warn (fun f -> f "not done yet") ;
        Lwt.return_unit

end

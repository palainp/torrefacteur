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
module Make (Rand: Mirage_random.S) (Stack: Tcpip.Stack.V4V6) (Cohttp: Cohttp_lwt.S.Client) = struct

    let log_src = Logs.Src.create "tor-protocol" ~doc:"Tor protocol"
    module Log = (val Logs.src_log log_src : Logs.LOG)

    (*
        Currently https leads to Fatal error: exception Failure("connect: authentication failure: invalid certificate chain")
        For the time being, I use unix direct file access...

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
    *)
    let get_file _ctx fname =
        Log.debug (fun f -> f "try to open: %s" fname );
        let unix_fetch path =
          Lwt.catch (fun () ->
            Lwt_unix.openfile path [Lwt_unix.O_RDONLY] 0 >>= fun fd ->
            Lwt.finalize (fun () ->
              Lwt_unix.LargeFile.fstat fd >>= fun stat ->
              if stat.Lwt_unix.LargeFile.st_kind = Lwt_unix.S_REG then begin
                Lwt_unix.LargeFile.fstat fd >>= fun stat ->
                let size64 = stat.Lwt_unix.LargeFile.st_size in
                if size64 > Int64.of_int Sys.max_string_length then begin
                  Lwt.return (Error "file too large to process")
                end else begin
                  let size = Int64.to_int size64 in
                  let buffer = Bytes.create size in
                  Lwt_unix.read fd buffer 0 size >|= fun read_bytes ->
                  if read_bytes = size then begin
                    Ok (Bytes.unsafe_to_string buffer)
                  end else begin
                    Error (Printf.sprintf "could not read %d bytes" size)
                  end
                end
              end else begin
                Lwt.return (Error (Printf.sprintf "file %s not found" path))
              end)
            (fun () -> Lwt_unix.close fd))
          (function
            | Unix.Unix_error (Unix.ENOENT, _, _) ->
              Lwt.return (Error (Printf.sprintf "file %s not found" path))
            | Unix.Unix_error (_, _, _) ->
              Lwt.return (Error "storage error")
            | e -> Lwt.fail e)
        in
        unix_fetch fname >>= function
        | Error e ->
            Log.debug (fun f -> f "%s: %s" fname e);
            Lwt.return ""
        | Ok str ->
            Lwt.return str

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
        (* TODO: remove heading and trailing quote in list_name *)
    (*  let path = String.concat "/" ["https://collector.torproject.org/index/"; path; list_name] in *)
        let path = String.concat "/" ["./site"; "exit-lists"; list_name] in
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
        (* TODO: remove heading and trailing quote in list_name *)
    (*  let path = String.concat "/" ["https://collector.torproject.org/index/"; path; list_name] in *)
        let path = String.concat "/" ["./site"; "relay-descriptors"; "server-descriptors"; list_name] in
        get_file ctx path >>= fun nodes ->
        (* TODO: check for the sha256 against the result in last_list_info *)
        Lwt.return nodes

    let create_circuit exit relay n =
        let rnd_exit = Random.int (List.length exit) in
        let circuit = Circuits.create (List.nth exit rnd_exit) in
        let rec add_relays n circuit =
            match n with
            | 0 -> circuit
            | x -> 
                let rnd_relay = Random.int (List.length relay) in
                let circuit = Circuits.add_relay circuit (List.nth relay rnd_relay) in
                add_relays (x-1) circuit
        in
        Lwt.return (add_relays n circuit)

end

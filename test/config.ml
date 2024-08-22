(* mirage >= 4.5.0 & < 4.7.0 *)

open Mirage

let main =
  main
    ~packages:[
      package "hex" ;
      package "mirage-crypto" ;
      package "mirage-crypto-ec" ;
    ]
    "Ntor_handshake.Main" ( time @-> job)

let () =
  register "test" [ main $ default_time ]

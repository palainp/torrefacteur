open Mirage

let secrets_dir = "certs"

let main =
  foreign
    ~packages:[
      package "duration" ;
      package "ethernet";
      package ~min:"6.0.0" "mirage-protocols";
      package ~min:"5.1.1" "conduit";
      package "cohttp-mirage";
      package "ezjsonm" ;
    ]
    "Unikernel.Main" (random @-> time @-> pclock @-> stackv4v6 @-> http_client @-> job)

let () =
  let stack = generic_stackv4v6 default_network in
  let res_dns = resolver_dns stack in
  let conduit = conduit_direct ~tls:true stack in
  register "torrefacteur" [ main $ default_random $ default_time $ default_posix_clock $ stack $ cohttp_client res_dns conduit ]

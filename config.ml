open Mirage

let secrets_dir = "certs"

let main =
  foreign
    ~packages:[
      package "duration" ;
      package "ethernet";
      package ~min:"6.0.0" "mirage-protocols";
      package "cohttp-mirage";
      package "ezjsonm" ;
      package "ca-certs-nss" ;
    ]
    "Unikernel.Main" (random @-> time @-> pclock @-> stackv4 @-> kv_ro @-> http_client @-> job)

let disk = generic_kv_ro secrets_dir

let () =
  let stackv4 = generic_stackv4 default_network in
  let stack = generic_stackv4v6 default_network in
  let res_dns = resolver_dns stack in
  let conduit = conduit_direct ~tls:true stack in
  register "torrefacteur" [ main $ default_random $ default_time $ default_posix_clock $ stackv4 $ disk $ cohttp_client res_dns conduit ]

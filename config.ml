open Mirage

let main =
  foreign
    ~packages:[
      package "duration" ;
      package "ethernet";
      package ~min:"6.0.0" "mirage-protocols";
      package "cohttp-mirage";
      package "ezjsonm" ;
    ]
    "Unikernel.Main" (random @-> time @-> stackv4v6 @-> http_client @-> job)

let () =
  let stack = generic_stackv4v6 default_network in
  let res_dns = resolver_dns stack in
  let conduit = conduit_direct ~tls:true stack in
  register "torrefacteur" [ main $ default_random $ default_time $ stack $ cohttp_client res_dns conduit ]

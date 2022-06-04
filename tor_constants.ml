(* from: https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/tor-spec.txt
   The 'Command' field of a fixed-length cell holds one of the following
   values:

         0 -- PADDING     (Padding)                 (See Sec 7.2)
         1 -- CREATE      (Create a circuit)        (See Sec 5.1)
         2 -- CREATED     (Acknowledge create)      (See Sec 5.1)
         3 -- RELAY       (End-to-end data)         (See Sec 5.5 and 6)
         4 -- DESTROY     (Stop using a circuit)    (See Sec 5.4)
         5 -- CREATE_FAST (Create a circuit, no PK) (See Sec 5.1)
         6 -- CREATED_FAST (Circuit created, no PK) (See Sec 5.1)
         8 -- NETINFO     (Time and address info)   (See Sec 4.5)
         9 -- RELAY_EARLY (End-to-end data; limited)(See Sec 5.6)
         10 -- CREATE2    (Extended CREATE cell)    (See Sec 5.1)
         11 -- CREATED2   (Extended CREATED cell)    (See Sec 5.1)
         12 -- PADDING_NEGOTIATE   (Padding negotiation)    (See Sec 7.2)

    Variable-length command values are:

         7 -- VERSIONS    (Negotiate proto version) (See Sec 4)
         128 -- VPADDING  (Variable-length padding) (See Sec 7.2)
         129 -- CERTS     (Certificates)            (See Sec 4.2)
         130 -- AUTH_CHALLENGE (Challenge value)    (See Sec 4.3)
         131 -- AUTHENTICATE (Client authentication)(See Sec 4.5)
         132 -- AUTHORIZE (Client authorization)    (Not yet used)
*)

  type tor_command =
    | PADDING
    | CREATE
    | CREATED
    | RELAY
    | DESTROY
    | CREATE_FAST
    | CREATED_FAST
    | NETINFO
    | RELAY_EARLY
    | CREATE2
    | CREATED2
    | PADDING_NEGOTIATE
    | VERSIONS
    | VPADDING
    | CERTS
    | AUTH_CHALLENGE
    | AUTHENTICATE
    | AUTHORIZE
    | MUST_BE_DROP

  let tor_command_to_uint32 = function
    | PADDING -> 0l
    | CREATE -> 1l
    | CREATED -> 2l
    | RELAY -> 3l
    | DESTROY -> 4l
    | CREATE_FAST -> 5l
    | CREATED_FAST -> 6l
    | NETINFO -> 8l
    | RELAY_EARLY -> 9l
    | CREATE2 -> 10l
    | CREATED2 -> 11l
    | PADDING_NEGOTIATE -> 12l
    | VERSIONS -> 7l
    | VPADDING -> 128l
    | CERTS -> 129l
    | AUTH_CHALLENGE -> 130l
    | AUTHENTICATE -> 131l
    | AUTHORIZE -> 132l
    | MUST_BE_DROP -> 4096l

  let tor_command_of_uint32 = function
    | 0l -> PADDING
    | 1l -> CREATE
    | 2l -> CREATED
    | 3l -> RELAY
    | 4l -> DESTROY
    | 5l -> CREATE_FAST
    | 6l -> CREATED_FAST
    | 8l -> NETINFO
    | 9l -> RELAY_EARLY
    | 10l -> CREATE2
    | 11l -> CREATED2
    | 12l -> PADDING_NEGOTIATE
    | 7l -> VERSIONS
    | 128l -> VPADDING
    | 129l -> CERTS
    | 130l -> AUTH_CHALLENGE
    | 131l -> AUTHENTICATE
    | 132l -> AUTHORIZE
    | _ -> MUST_BE_DROP

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

  let tor_command_to_uint8 = function
    | PADDING -> 0
    | CREATE -> 1
    | CREATED -> 2
    | RELAY -> 3
    | DESTROY -> 4
    | CREATE_FAST -> 5
    | CREATED_FAST -> 6
    | NETINFO -> 8
    | RELAY_EARLY -> 9
    | CREATE2 -> 10
    | CREATED2 -> 11
    | PADDING_NEGOTIATE -> 12
    | VERSIONS -> 7
    | VPADDING -> 128
    | CERTS -> 129
    | AUTH_CHALLENGE -> 130
    | AUTHENTICATE -> 131
    | AUTHORIZE -> 132
    | MUST_BE_DROP -> 255

  let tor_command_of_uint8 = function
    | 0 -> PADDING
    | 1 -> CREATE
    | 2 -> CREATED
    | 3 -> RELAY
    | 4 -> DESTROY
    | 5 -> CREATE_FAST
    | 6 -> CREATED_FAST
    | 8 -> NETINFO
    | 9 -> RELAY_EARLY
    | 10 -> CREATE2
    | 11 -> CREATED2
    | 12 -> PADDING_NEGOTIATE
    | 7 -> VERSIONS
    | 128 -> VPADDING
    | 129 -> CERTS
    | 130 -> AUTH_CHALLENGE
    | 131 -> AUTHENTICATE
    | 132 -> AUTHORIZE
    | _ -> MUST_BE_DROP

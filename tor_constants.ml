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

(*
   The error codes are:

     0 -- NONE            (No reason given.)
     1 -- PROTOCOL        (Tor protocol violation.)
     2 -- INTERNAL        (Internal error.)
     3 -- REQUESTED       (A client sent a TRUNCATE command.)
     4 -- HIBERNATING     (Not currently operating; trying to save bandwidth.)
     5 -- RESOURCELIMIT   (Out of memory, sockets, or circuit IDs.)
     6 -- CONNECTFAILED   (Unable to reach relay.)
     7 -- OR_IDENTITY     (Connected to relay, but its OR identity was not
                           as expected.)
     8 -- CHANNEL_CLOSED  (The OR connection that was carrying this circuit
                           died.)
     9 -- FINISHED        (The circuit has expired for being dirty or old.)
    10 -- TIMEOUT         (Circuit construction took too long)
    11 -- DESTROYED       (The circuit was destroyed w/o client TRUNCATE)
    12 -- NOSUCHSERVICE   (Request for unknown hidden service)
*)

  type tor_error =
    | NONE
    | PROTOCOL
    | INTERNAL
    | REQUESTED
    | HIBERNATING
    | RESOURCELIMIT
    | CONNECTFAILED
    | OR_IDENTITY
    | CHANNEL_CLOSED
    | FINISHED
    | TIMEOUT
    | DESTROYED
    | NOSUCHSERVICE
    | UNK_TOR_ERROR

  let tor_error_to_uint8 = function
    | NONE -> 0
    | PROTOCOL -> 1
    | INTERNAL -> 2
    | REQUESTED -> 3
    | HIBERNATING -> 4
    | RESOURCELIMIT -> 5
    | CONNECTFAILED -> 6
    | OR_IDENTITY -> 7
    | CHANNEL_CLOSED -> 8
    | FINISHED -> 9
    | TIMEOUT -> 10
    | DESTROYED -> 11
    | NOSUCHSERVICE -> 12
    | UNK_TOR_ERROR -> 255

  let uint8_to_tor_error = function
    |  0 -> NONE
    |  1 -> PROTOCOL
    |  2 -> INTERNAL
    |  3 -> REQUESTED
    |  4 -> HIBERNATING
    |  5 -> RESOURCELIMIT
    |  6 -> CONNECTFAILED
    |  7 -> OR_IDENTITY
    |  8 -> CHANNEL_CLOSED
    |  9 -> FINISHED
    | 10 -> TIMEOUT
    | 11 -> DESTROYED
    | 12 -> NOSUCHSERVICE
    | _ -> UNK_TOR_ERROR

(*
   The relay commands are:

         1 -- RELAY_BEGIN     [forward]
         2 -- RELAY_DATA      [forward or backward]
         3 -- RELAY_END       [forward or backward]
         4 -- RELAY_CONNECTED [backward]
         5 -- RELAY_SENDME    [forward or backward] [sometimes control]
         6 -- RELAY_EXTEND    [forward]             [control]
         7 -- RELAY_EXTENDED  [backward]            [control]
         8 -- RELAY_TRUNCATE  [forward]             [control]
         9 -- RELAY_TRUNCATED [backward]            [control]
        10 -- RELAY_DROP      [forward or backward] [control]
        11 -- RELAY_RESOLVE   [forward]
        12 -- RELAY_RESOLVED  [backward]
        13 -- RELAY_BEGIN_DIR [forward]
        14 -- RELAY_EXTEND2   [forward]             [control]
        15 -- RELAY_EXTENDED2 [backward]            [control]

        16..18 -- Reserved for UDP; Not yet in use, see prop339.

        32..40 -- Used for hidden services; see rend-spec-{v2,v3}.txt.

        41..42 -- Used for circuit padding; see Section 3 of padding-spec.txt.

        43..44 -- Used for flow control; see Section 4 of prop324.
*)

  type tor_relay_command =
    | RELAY_BEGIN
    | RELAY_DATA
    | RELAY_END
    | RELAY_CONNECTED
    | RELAY_SENDME
    | RELAY_EXTEND
    | RELAY_EXTENDED
    | RELAY_TRUNCATE
    | RELAY_TRUNCATED
    | RELAY_DROP
    | RELAY_RESOLVE
    | RELAY_RESOLVED
    | RELAY_BEGIN_DIR
    | RELAY_EXTEND2
    | RELAY_EXTENDED2
    | UNK_RELAY_COMMAND

  let tor_relay_command_to_uint8 = function
    | RELAY_BEGIN -> 1
    | RELAY_DATA -> 2
    | RELAY_END -> 3
    | RELAY_CONNECTED -> 4
    | RELAY_SENDME -> 5
    | RELAY_EXTEND -> 6
    | RELAY_EXTENDED -> 7
    | RELAY_TRUNCATE -> 8
    | RELAY_TRUNCATED -> 9
    | RELAY_DROP -> 10
    | RELAY_RESOLVE -> 11
    | RELAY_RESOLVED -> 12
    | RELAY_BEGIN_DIR -> 13
    | RELAY_EXTEND2 -> 14
    | RELAY_EXTENDED2 -> 15
    | UNK_RELAY_COMMAND -> 255

  let tor_relay_command_of_uint8 = function
    | 1 -> RELAY_BEGIN
    | 2 -> RELAY_DATA
    | 3 -> RELAY_END
    | 4 -> RELAY_CONNECTED
    | 5 -> RELAY_SENDME
    | 6 -> RELAY_EXTEND
    | 7 -> RELAY_EXTENDED
    | 8 -> RELAY_TRUNCATE
    | 9 -> RELAY_TRUNCATED
    | 10 -> RELAY_DROP
    | 11 -> RELAY_RESOLVE
    | 12 -> RELAY_RESOLVED
    | 13 -> RELAY_BEGIN_DIR
    | 14 -> RELAY_EXTEND2
    | 15 -> RELAY_EXTENDED2
    | _ -> UNK_RELAY_COMMAND

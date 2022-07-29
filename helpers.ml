    let escape_data buf = String.escaped (Cstruct.to_string buf)

    let uint8_to_cs i =
        let cs = Cstruct.create 1 in
        Cstruct.set_uint8 cs 0 i;
        cs

    let uint16_to_cs i =
        let cs = Cstruct.create 2 in
        Cstruct.BE.set_uint16 cs 0 i;
        cs

    let uint32_to_cs i =
        let cs = Cstruct.create 4 in
        Cstruct.BE.set_uint32 cs 0 i;
        cs


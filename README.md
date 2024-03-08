# rustybfd

A not so serious Rust implementation of the BFD network protocol.

# Status

Currently no Auth and MD5 Auth implemented.

MD5 Auth was tested on a Cisco router:

```
Switch#sh version
! ....
! ....
! ....
Switch Ports Model                     SW Version            SW Image
------ ----- -----                     ----------            ----------
*    1 12    WS-C3560CX-8XPD-S         15.2(4.5.14)E2        C3560CX-UNIVERSALK9-M


Switch#sh bfd neighbors

IPv4 Sessions
NeighAddr                              LD/RD         RH/RS     State     Int
172.30.135.50                           1/1          Up        Up        Vl1
```

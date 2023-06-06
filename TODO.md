# TODO

## Known limitations

- SCTP server does not work on CORE, using TCP
- Only one flag can be read. Will do some testing of an 10 UE configuration with attackinfo to indicate which has the current flag.
- Successful PDUSessEstResponse currently does not do anything, but will allow UE to do a proxy HTTP request through gNB and CORE in the future.

## Plan

- Handle errors by issuing an "Error" protocol message and removing state.
- Implement SecCapType EA and IA encoding to scheme in comment
- Maybe add message length to "headers" of messages, so TCP message buffers can be the correct size with no extra 0 bytes.
- Putnoise/getnoise will validate that 0 encryption is not turned off completely.

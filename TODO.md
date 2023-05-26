# TODO

## Known limitations

- Only one flag can be read. Will do some testing of an 10 UE configuration with attackinfo to indicate which has the current flag.
- Messages can be sent in arbitrary order (this does kinda lead to many ways of exploitation, and the service does not make sense per now)
- Successful PDUSessEstResponse currently does not do anything, but will allow UE to do a proxy HTTP request through gNB and CORE in the future.
- Currently one gNB corresponds to one UE. Want to support multiple UEs by one gNB connection, can be solved by issuing unique NgapId (hardcoded for now).

## Plan

- Move state of CORE and UE to a context (stop using maps of connections).
- Handle state correctly, only allowing messages to be sent in order that is intended of the protocol.
- Handle errors by issuing an "Error" protocol message and removing state.
- Implement SecCapType EA and IA encoding to scheme in comment
- Move secrets to env file
- Maybe add message length to "headers" of messages, so TCP message buffers can be the correct size with no extra 0 bytes.
- Putnoise/getnoise will validate that 0 encryption is not turned off completely.

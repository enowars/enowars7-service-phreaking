# TODO

## Known limitations

- SCTP server does not work on CORE, using TCP

## Plan

- Handle errors by issuing an "Error" protocol message and removing state.
- Implement SecCapType EA and IA encoding to scheme in comment
- Putnoise/getnoise will validate that 0 encryption is not turned off completely.

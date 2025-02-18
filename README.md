# LockSmith
A CLI based password generator written in Go!

## Installation

To install it in your system

```bash
go install ./locksmith@latest
```

## Planned featres:

To lock a particular file
```bash
locksmith lock ./*
```
This should ask the user for a password (default would be master password) and encrypt all the files bundled into a single file.

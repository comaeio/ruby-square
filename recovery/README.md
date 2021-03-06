# Install the dependencies

```
virtualenv -p python3 .
source ./bin/activate  # or Scripts\activate.bat
pip3 install -r requirements.txt
```

# Run the program

Example:
```
python main.py COM6 recovery_dir appdevelopment.cfg
```

`recovery_dir` is the extracted recovery image directory (see `azsphere dev
recover --help`).  It must contain files `recovery-1bl-rtm.bin`,
`recovery-runtime.bin`, etc.

`appdevelopment.cfg` is the device capability file (see `azsphere dev cap download
--help`).

# Example output

```
[>] Output: b'CCCCCCC'
[<] Sending recovery 1BL
[>] Output: b'+GOOD\r\n'
[>] Output: b'[1BL] BOOT: 380a0300/00000001/02000000\r\n'
[>] Output: b'\x02\x89\x02\x01\x02\x85\x02\x01\x01\x01\x81006fe629beb69fc3bb06cf8494ccc25461f597aae076aa0d1f9b49656d60b63557becad65b338a1a5b4104f769649aaa35340eca1f1899df610305506cd7bee8\x03\xbe\x03\x00'
[>] Decoded COBS: b'\x89\x00\x01\x00\x85\x00\x01\x00\x00\x00006fe629beb69fc3bb06cf8494ccc25461f597aae076aa0d1f9b49656d60b63557becad65b338a1a5b4104f769649aaa35340eca1f1899df610305506cd7bee8\x00\xbe\x03'
[>] Decoded UART: b'\x01\x00\x85\x00\x01\x00\x00\x00006fe629beb69fc3bb06cf8494ccc25461f597aae076aa0d1f9b49656d60b63557becad65b338a1a5b4104f769649aaa35340eca1f1899df610305506cd7bee8\x00'
[>] Leftovers: b''
[<] Payload: b'\xa0\x00\x00\x00'
[<] Encoded UART: b'\x04\x00\xa0\x00\x00\x00\xd7\xec'
[<] Encoded COBS: b'\x02\x04\x02\xa0\x01\x01\x03\xd7\xec\x00'
[>] Output: b'\x02\x05\x02\x0b\x02\x01\x04\x01I\xb2\x00\x02\x04\x02\t\x01\x01\x03\xd6\xf5\x00'
[>] Decoded COBS: b'\x05\x00\x0b\x00\x01\x00\x01I\xb2'
[>] Decoded UART: b'\x0b\x00\x01\x00\x01'
[>] Leftovers: b'\x02\x04\x02\t\x01\x01\x03\xd6\xf5\x00'
[>] Decoded COBS: b'\x04\x00\t\x00\x00\x00\xd6\xf5'
[>] Decoded UART: b'\t\x00\x00\x00'
[>] Leftovers: b''
[<] Payload: b'\xa3\x00\x01\x00\x00'
[<] Encoded UART: b'\x05\x00\xa3\x00\x01\x00\x00!\x8a'
[<] Encoded COBS: b'\x02\x05\x02\xa3\x02\x01\x01\x03!\x8a\x00'
[>] Output: b'\x02\x0c\x02\x04\x02\x08\x01\x01\x01\x01\x07\xff\xff\xff\xff\x9e\xc8\x00'
[>] Decoded COBS: b'\x0c\x00\x04\x00\x08\x00\x00\x00\x00\x00\xff\xff\xff\xff\x9e\xc8'
[>] Decoded UART: b'\x04\x00\x08\x00\x00\x00\x00\x00\xff\xff\xff\xff'
[>] Leftovers: b''
[<] Payload: b'\xa4\x00\x0c\x00\x00\x00\x00\x00\x88\x01\x00\x00\x88\x01\x00\x00'
[<] Encoded UART: b'\x10\x00\xa4\x00\x0c\x00\x00\x00\x00\x00\x88\x01\x00\x00\x88\x01\x00\x00w\x1e'
[<] Encoded COBS: b'\x02\x10\x02\xa4\x02\x0c\x01\x01\x01\x01\x03\x88\x01\x01\x03\x88\x01\x01\x03w\x1e\x00'
[<] Sending device capabilities
[>] Output: b'\x02\x05\x02\x0b\x02\x01\x04\x02*\x82\x00\x02\x05\x02\x0b\x02\x01\x04\x03\x0b\x92\x00\x02!\x02\x07\x02\x1d\x01\x01\x01\x01\x19\xff\xff\xff\xffrecovery-runtime.bin\x03A\xf0\x00'
[>] Decoded COBS: b'\x05\x00\x0b\x00\x01\x00\x02*\x82'
[>] Decoded UART: b'\x0b\x00\x01\x00\x02'
[>] Leftovers: b'\x02\x05\x02\x0b\x02\x01\x04\x03\x0b\x92\x00\x02!\x02\x07\x02\x1d\x01\x01\x01\x01\x19\xff\xff\xff\xffrecovery-runtime.bin\x03A\xf0\x00'
[>] Decoded COBS: b'\x05\x00\x0b\x00\x01\x00\x03\x0b\x92'
[>] Decoded UART: b'\x0b\x00\x01\x00\x03'
[>] Leftovers: b'\x02!\x02\x07\x02\x1d\x01\x01\x01\x01\x19\xff\xff\xff\xffrecovery-runtime.bin\x03A\xf0\x00'
[>] Decoded COBS: b'!\x00\x07\x00\x1d\x00\x00\x00\x00\x00\xff\xff\xff\xffrecovery-runtime.bin\x00A\xf0'
[>] Decoded UART: b'\x07\x00\x1d\x00\x00\x00\x00\x00\xff\xff\xff\xffrecovery-runtime.bin\x00'
[>] Leftovers: b''
[<] Payload: b'\xa4\x00\x0c\x00\x00\x00\x00\x00\xa4\xed\x00\x00\xa4\xed\x00\x00'
[<] Encoded UART: b'\x10\x00\xa4\x00\x0c\x00\x00\x00\x00\x00\xa4\xed\x00\x00\xa4\xed\x00\x00\x0c\x93'
[<] Encoded COBS: b'\x02\x10\x02\xa4\x02\x0c\x01\x01\x01\x01\x03\xa4\xed\x01\x03\xa4\xed\x01\x03\x0c\x93\x00'
[<] Sending recovery runtime
[>] Output: b'\x02\x04\x02\t\x01\x01\x03\xd6\xf5\x00'
[>] Decoded COBS: b'\x04\x00\t\x00\x00\x00\xd6\xf5'
[>] Decoded UART: b'\t\x00\x00\x00'
[>] Leftovers: b''
[<] Payload: b'\xa3\x00\x01\x00\x00'
[<] Encoded UART: b'\x05\x00\xa3\x00\x01\x00\x00!\x8a'
[<] Encoded COBS: b'\x02\x05\x02\xa3\x02\x01\x01\x03!\x8a\x00'
[>] Output: b'\x02\x05\x02\x0b\x02\x01\x04\x06\xae\xc2\x00\x02\x04\x02\x03\x01\x01\x03}\x9d\x00'
[>] Decoded COBS: b'\x05\x00\x0b\x00\x01\x00\x06\xae\xc2'
[>] Decoded UART: b'\x0b\x00\x01\x00\x06'
[>] Leftovers: b'\x02\x04\x02\x03\x01\x01\x03}\x9d\x00'
[>] Decoded COBS: b'\x04\x00\x03\x00\x00\x00}\x9d'
[>] Decoded UART: b'\x03\x00\x00\x00'
[>] Leftovers: b''
[<] Payload: b'\xa3\x00\x01\x00\x00'
[<] Encoded UART: b'\x05\x00\xa3\x00\x01\x00\x00!\x8a'
[<] Encoded COBS: b'\x02\x05\x02\xa3\x02\x01\x01\x03!\x8a\x00'
[>] Output: b'\x02\x05\x02\x0b\x02\x01\x04\x07\x8f\xd2\x00'
[>] Decoded COBS: b'\x05\x00\x0b\x00\x01\x00\x07\x8f\xd2'
[>] Decoded UART: b'\x0b\x00\x01\x00\x07'
[>] Leftovers: b''
[i] Waiting for flash erase to complete
[>] Output: b''
[>] Output: b''
[>] Output: b''
[>] Output: b''
[>] Output: b''
[>] Output: b''
[>] Output: b''
[>] Output: b''
[>] Output: b''
[>] Output: b'\x02\x05\x02\x0b\x02\x01\x04\x08`#\x00\x02#\x02\x07\x02\x1f\x01\x01\x01\x01\x1b\xff\xff\xff\xffrecovery.imagemanifest\x03\xa4\x10\x00'
[>] Decoded COBS: b'\x05\x00\x0b\x00\x01\x00\x08`#'
[>] Decoded UART: b'\x0b\x00\x01\x00\x08'
[>] Leftovers: b'\x02#\x02\x07\x02\x1f\x01\x01\x01\x01\x1b\xff\xff\xff\xffrecovery.imagemanifest\x03\xa4\x10\x00'
[>] Decoded COBS: b'#\x00\x07\x00\x1f\x00\x00\x00\x00\x00\xff\xff\xff\xffrecovery.imagemanifest\x00\xa4\x10'
[>] Decoded UART: b'\x07\x00\x1f\x00\x00\x00\x00\x00\xff\xff\xff\xffrecovery.imagemanifest\x00'
[>] Leftovers: b''
```

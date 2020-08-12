## Convert the pluton binary to ELF

Make `PlutonCommandHandler` at `0x10bd44` the new entrypoint:
```
./elf_wrapper.py \
  -t 0x108000 \
  -e 0x3d44 \
  -m arm \
  -u \
  -i bin/09a87fd5eea743799cf162994e0b1958_pluton_runtime.bin \
  -o bin/09a87fd5eea743799cf162994e0b1958_pluton_runtime.bin_elf
```

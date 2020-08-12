# Ruby Square
## Getting Started
```
$ virtualenv -p python3 .
$ source ./bin/activate
$ pip3 install -r requirements.txt
```

## Usage
### Rename and unpack everything
Unzip the mt3620anb.zip file in a folder and provide the path to ruby square
```
python.exe .\ruby-square.py --input D:\azure-sphere\mt3620an_20.06\ --godmode
```

#### Output
```
PS D:\azure-sphere\workspace\tools\ruby-square> ls D:\azure-sphere\mt3620an_20.06.test\


    Directory: D:\azure-sphere\mt3620an_20.06.test


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        6/30/2020   1:26 PM                3aded48abba146a89898994059afc548_RootFs_Firmware_nw-root-filesystem
d-----        6/30/2020   1:26 PM                59af9abaf46e480caed08cef0aabab58_Services_Firmware_gatewayd
d-----        6/30/2020   1:26 PM                743f011fa0ff4d058719d869991915b1_Services_Firmware_azured
d-----        6/30/2020   1:26 PM                80e6c2a25100416e91a91c195e067f6f_Services_Firmware_azcore
d-----        6/30/2020   1:26 PM                d98ec5f3fafb424e87ee2ed482d1b17d_Services_Firmware_networkd
d-----        6/30/2020   1:26 PM                e3180ce9c9564b54b5a5d9bbd126e184_Services_Firmware_rng-tools
d-----        6/30/2020   1:26 PM                e5a6b6eed0ef432ba24c9e07f4198d30_UpdateCertStore_Firmware_update-cert-store
-a----         6/5/2020   3:39 PM        1577196 3aded48abba146a89898994059afc548_RootFs_Firmware_nw-root-filesystem_.bin
-a----         6/5/2020   3:39 PM          98516 59af9abaf46e480caed08cef0aabab58_Services_Firmware_gatewayd_.bin
-a----         6/5/2020   3:39 PM          65748 743f011fa0ff4d058719d869991915b1_Services_Firmware_azured_.bin
-a----         6/5/2020   3:39 PM          16596 80e6c2a25100416e91a91c195e067f6f_Services_Firmware_azcore_.bin
-a----         6/5/2020   3:39 PM            392 85a5dc4e7ad34cbd8a58912d1b116a8d_BootManifest_Firmware_device-capability_.bin
-a----         6/5/2020   3:39 PM           2376 92854503e1a4425ab9a81f990b6f03bc_TrustedKeystore_Firmware_trusted-keystore_.bin
-a----         6/5/2020   3:39 PM          16932 93d26089b31f47959c42a8caa98b315d_NormalWorldLoader_Firmware_a7-nw-loader_.bin
-a----         6/5/2020   3:39 PM          26860 b8d1898d61d14c7d96ee1c387658f816_PlutonRuntime_Firmware_pluton-runtime_.bin
-a----         6/5/2020   3:39 PM        2491164 bec9744660fd40f7abd8ef396c36e88e_NormalWorldKernel_Firmware_nw-kernel_.bin
-a----         6/5/2020   3:40 PM         114900 d36848d9dad148b8abda510da53bd623_Applications_Firmware_security-monitor_.bin
-a----         6/5/2020   3:40 PM         269980 d77ab2e3bbde4c8fab42821a45b39368_WifiFirmware_Firmware_n9-wifi-firmware_.bin
-a----         6/5/2020   3:40 PM         614620 d98ec5f3fafb424e87ee2ed482d1b17d_Services_Firmware_networkd_.bin
-a----         6/5/2020   3:40 PM           8396 e3180ce9c9564b54b5a5d9bbd126e184_Services_Firmware_rng-tools_.bin
-a----         6/5/2020   3:40 PM          24576 e5a6b6eed0ef432ba24c9e07f4198d30_UpdateCertStore_Firmware_update-cert-store_.bin
-a----         6/5/2020   3:40 PM          16384 e6159560434f47e89376b67d030628f8_OneBL_BootloaderOneBackup_1bl_.bin
-a----         6/5/2020   3:40 PM          29732 e7a7ab1c642e43b996694c29739c5056_NormalWorldDTB_Firmware_nw-device-tree_.bin
-a----         6/5/2020   3:40 PM          16384 recovery-1bl-rtm_recovery-1bl_.bin
-a----         6/5/2020   3:40 PM          60836 recovery-runtime_recovery-rt_.bin
-a----         6/5/2020   3:40 PM           1496 recovery.imagemanifest


PS D:\azure-sphere\workspace\tools\ruby-square> 
```

### Unpacking
If no `-o` option is provided, the utility only display the information of the file.

```
python .\ruby-square.py --unpack -i D:\azure-sphere\wizio\azure-sphere-reverse-engineering\packer\ruby.img
```

### Packing
```
python .\ruby-square.py --pack -i D:\azure-sphere\wizio\azure-sphere-reverse-engineering\packer -o D:\azure-sphere\wizio\azure-sphere-reverse-engineering\packer\ruby.img                                                 
```
## This script uses to collect the packages' names and version information.
## Usage:
## 	Please put this file in your VxWorks installer folder (for Windows, the default path is "C:\WindRiver").
##	If your host has installed Python, you can run this file directly, and it will generate a "pkg_ver_info.txt" file in the current path.
##	If you don't have Python, please use Workbench's python environment.
##	In VxWorks22.09, the python path is "C:\WindRier\workbench-4\22.09\x86_64-win32\bin\wrpython27.exe".
##	Start a cmd terminal and into the python exe path.
##	Here is my cmd "C:\WindRier\workbench-4\22.09\x86_64-win32\bin\wrpython27.exe  C:\WindRiver\gen_pkg_ver_info.py".
##	After this script running is done, please share the pkg_ver_info.txt back to us, thanks.

import os
import json
import re
import sys

dict = {"INTRINSICS_GNU" : "OnlyForVx",  # many of them from SR0660   # use the below gnu
        "WRA" : "OnlyForVx",     # many of them from SR0540   # Wind River EMS Agent
        "HDC" : "OnlyForVx",     # the Device Cloud library for VxWorks
        "NODEJS" : "nodejs",
        "AGENT" : "OnlyForVx",
        "ENGINE" : "OnlyForVx",
        "WRSNMP" : "OnlyForVx",
        "BACKPLANE" : "OnlyForVx",
        "CLI" : "OnlyForVx",     # this is a subpackage for webcli
        "COMMON" : "OnlyForVx",
        "CURL" : "curl",
        "XML" : "expat",
        "UBOOT_WRSBCPQ2" : "OnlyForVx",  # use the below uboot version
        "OPCUA" : "opcua",
        "STACK" : "OnlyForVx",
        "DEVICE" : "OnlyForVx",
        "SDHC" : "OnlyForVx",
        "TIMMCHS" : "OnlyForVx",
        "CCORE" : "OnlyForVx",
        "CLASS" : "OnlyForVx",
        "HELPER" : "OnlyForVx",
        "HID" : "OnlyForVx",
        "KEYBOARD" : "OnlyForVx",
        "MOUSE" : "OnlyForVx",
        "PRINTER" : "OnlyForVx",
        "SERIAL" : "OnlyForVx",
        "UVC" : "OnlyForVx",
        "HCORE" : "OnlyForVx",
        "TCORE" : "OnlyForVx",
        "FUNCTION" : "OnlyForVx",
        "HLP" : "OnlyForVx",
        "KBD" : "OnlyForVx",
        "PRINT" : "OnlyForVx",
        "SER" : "OnlyForVx",
        "DSI" : "OnlyForVx",
        "DSI_USER" : "OnlyForVx",
        "MIPC" : "OnlyForVx",
        "TIPC" : "OnlyForVx",
        "TIPC_KERNEL_INVENTORYSIM_DEMO" : "OnlyForVx",
        "TIPC_KERNEL_TESTSUIT_DEMO" : "OnlyForVx",
        "TIPC_KERNEL" : "OnlyForVx",
        "TIPC_USER" : "OnlyForVx",
        "LIB" : "OnlyForVx",
        "IPNET" : "OnlyForVx",
        "AAA" : "ipnet_aaa",
        "DIAMETER" : "OnlyForVx",
        "RADIUS" : "OnlyForVx",
        "DHCPC" : "OnlyForVx",      # All the dhcp write by WindRiver. Not from upstream
        "DHCPC6" : "OnlyForVx",
        "DHCPR" : "OnlyForVx",
        "DHCPS" : "OnlyForVx",
        "DHCPS6" : "ipnet_dhcp",
        "DNSC" : "ipnet_dnsc",
        "FTP" : "ipnet_ftp",
        "SNTP" : "ipnet_sntp",
        "TFTP" : "ipnet_tftp",
        "COREIP" : "ipnet_coreip",
        "CRYPTO" : "OnlyForVx",
        "IPCRYPTO" : "OnlyForVx",
        "EAP" : "ipnet_eap",
        "FIREWALL" : "ipnet_firewall",
        "IPSECIKE" : "ipnet_ipsecike",
        "IPSEC" : "OnlyForVx",
        "GODI" : "OnlyForVx",
        "BRIDGE" : "OnlyForVx",
        "PPP" : "OnlyForVx",
        "ROHC" : "OnlyForVx",
        "MOBILITY" : "OnlyForVx",
        "8021X" : "ipnet_8021x",
        "DOT1X" : "OnlyForVx",
        "WLAN" : "wlan",          # Note this package had been removed in some VX version.
        "WLANDRV" : "OnlyForVx",
        "(Deprecated)" : "OnlyForVx",
        "WPS" : "OnlyForVx",
        "QOS" : "ipnet_qos",
        "ROUTEPROTO" : "ipnet_routeproto",
        "RIP" : "OnlyForVx",
        "RIPNG" : "OnlyForVx",
        "SSH" : "ipnet_ssh",
        "SSL" : "OnlyForVx",
        "CLOCK" : "OnlyForVx",
        "QAVQBV" : "OnlyForVx",
        "STREAM" : "OnlyForVx",
        "USRSPACE" : "ipnet_usrspace",
        "VRRP" : "ipnet_vrrp",
        "KERNEL" : "OnlyForVx",
        "ARMBASE" : "OnlyForVx",
        "ARMV7A" : "OnlyForVx",
        "ARMV7M" : "OnlyForVx",
        "ARMV8A" : "OnlyForVx",
        "MATH_fp" : "OnlyForVx",
        "USER" : "OnlyForVx",
        "VXTEST" : "OnlyForVx",
        "60x" : "OnlyForVx",
        "BASE" : "OnlyForVx",
        "E500" : "OnlyForVx",
        "CORE_IO" : "OnlyForVx",
        "CORE_KERNEL" : "OnlyForVx",
        "LIBDL" : "OnlyForVx",
        "6X" : "OnlyForVx",
        "7X" : "OnlyForVx",
        "CORE_RTP" : "OnlyForVx",
        "CORE_SAFETY" : "OnlyForVx",
        "VXWORKS" : "OnlyForVx",
        "CORE_USER" : "OnlyForVx",
        "APPS" : "OnlyForVx",
        "CORE_DUMP" : "OnlyForVx",
        "VXDBG" : "OnlyForVx",
        "BUSLIB" : "OnlyForVx",
        "SUBSYSTEM" : "OnlyForVx",
        "VXTEST_SUBSYSTEM" : "OnlyForVx",
        "VXBUS_LEGACY" : "OnlyForVx",
        "ACPICA" : "OnlyForVx",
        "ACPI_4" : "OnlyForVx",
        "ACPI_5_1" : "OnlyForVx",
        "ACPI_6_1" : "OnlyForVx",
        "LANG_LIB_CPLUS" : "OnlyForVx",
        "CPLUS_USER_2011" : "OnlyForVx",
        "CPLUS_USER" : "OnlyForVx",
        "LANG_LIB_LIBC" : "OnlyForVx",
        "LIBC_KERNEL" : "OnlyForVx",
        "VXTEST_KERNEL" : "OnlyForVx",
        "LIBC_USER" : "OnlyForVx",
        "VXTEST_USER" : "OnlyForVx",
        "LANG_LIB_TOOL" : "OnlyForVx",
        "TOOLSRC_COMMON" : "OnlyForVx",
        "TOOLSRC_COMMON_KERNEL" : "OnlyForVx",
        "TOOLSRC_COMMON_USER" : "OnlyForVx",
        "TOOLSRC_CERT" : "OnlyForVx",
        "TOOLSRC_DIAB" : "OnlyForVx",
        "TOOLSRC_DIAB_KERNEL" : "OnlyForVx",
        "TOOLSRC_DIAB_USER" : "OnlyForVx",
        "TOOLSRC_GNU" : "OnlyForVx",
        "TOOLSRC_GNU_KERNEL" : "OnlyForVx",
        "TOOLSRC_GNU_USER" : "OnlyForVx",
        "TOOLSRC_ICC" : "OnlyForVx",
        "TOOLSRC_ICC_KERNEL" : "OnlyForVx",
        "TOOLSRC_ICC_USER" : "OnlyForVx",
        "TOOLSRC_LLVM" : "OnlyForVx",
        "TOOLSRC_LLVM_KERNEL" : "OnlyForVx",
        "TOOLSRC_LLVM_USER" : "OnlyForVx",
        "CONFIG_LEGACY" : "OnlyForVx",
        "ALTERA_SOC_ARRIA10" : "OnlyForVx",
        "ALT_SOC" : "OnlyForVx",
        "INTEL" : "OnlyForVx",
        "TI_AM3XXX" : "OnlyForVx",
        "CTXA8" : "OnlyForVx",
        "CTXA9" : "OnlyForVx",
        "ARCHIVE" : "OnlyForVx",
        "BOARDLIB" : "OnlyForVx",
        "JSON" : "jansson",
        "TBB" : "onetbb",
        "STACKTRACE" : "OnlyForVx",
        "HASH" : "OnlyForVx",
        "BOOT_LOADERS" : "OnlyForVx",
        "OPENSSL_FIPS" : "openssl",
        "OPTEE" : "OnlyForVx",
        "SEC_EVENT" : "OnlyForVx",
        "SSH_CLIENT" : "OnlyForVx",
        "tpm2-tss"  : "OnlyForVx",
        "TROUSERS" : "OnlyForVx",
        "USER_MANAGEMENT_LDAP" : "OnlyForVx",
        "USER_MANAGEMENT_POLICY" : "OnlyForVx",
        "File" : "OnlyForVx",
        "USR" : "OnlyForVx",
        "MTD" : "OnlyForVx",
        "TFFS_DRIVER" : "OnlyForVx",
        "XBD" : "OnlyForVx",
        "COMMON" : "OnlyForVx",
        "DEVFS" : "OnlyForVx",
        "VDFS" : "OnlyForVx",
        "VFS" : "OnlyForVx",
        "FSL_SGTL5000" : "OnlyForVx",
        "TI_AIC3106" : "OnlyForVx",
        "TI_MCASP" : "OnlyForVx",
        "WM8962" : "OnlyForVx",
        "EETI_EXC7200_TS" : "OnlyForVx",
        "FSL_CRTOUCH_TS" : "OnlyForVx",
        "FT_5X06_TS" : "OnlyForVx",
        "TI_AM335X_TS" : "OnlyForVx",
        "TI_TSC2004_TS" : "OnlyForVx",
        "VIRTUAL_KBD" : "OnlyForVx",
        "VIRTUAL_PTR" : "OnlyForVx",
        "VXSIM_KBD" : "OnlyForVx",
        "VXSIM_PTR" : "OnlyForVx",
        "DEMOS" : "OnlyForVx",
        "FSLDCUFB" : "OnlyForVx",
        "FSLIPUFB" : "OnlyForVx",
        "ITLGCFB" : "OnlyForVx",
        "ITLGMCFB" : "OnlyForVx",
        "ITLVIPSFBII" : "OnlyForVx",
        "SAMPLEFB" : "OnlyForVx",
        "SAMPLEFB" : "OnlyForVx",
        "VXSIMFB" : "OnlyForVx",
        "XLNXLCVCFB" : "OnlyForVx",
        "FONT" : "OnlyForVx",
        "COMMON" : "OnlyForVx",
        "FSLVIVGPU_DEMOS" : "OnlyForVx",
        "LIBDRM_DEMOS" : "OnlyForVx",
        "SAMPLEDRM" : "OnlyForVx",
        "IMAGE" : "OnlyForVx",
        "JPEG" : "libjpeg",
        "PNG" : "libpng",
        "MESA_DEMOS" : "OnlyForVx",
        "QTPRE" : "OnlyForVx",
        "SDL_DEMOS" : "OnlyForVx",
        "VG_DEMOS" : "OnlyForVx",
        "TILCDCFB" : "OnlyForVx",
        "FSAPP" : "OnlyForVx",
        "TFFS" : "OnlyForVx",
        "FSL_SSI" : "OnlyForVx",
        "ITL_COMMON" : "OnlyForVx",
        "PRNT" : "OnlyForVx",
        "DSI_KERNEL" : "OnlyForVx",
        "VSOMEIP" : "vsomeip",   # many of them from 22.04
        "PPCMATH" : "OnlyForVx",
        "ASAN" : "llvm",
        "AWS_IOT_DEVICE_SDK_FOR_C" : "aws-iot-device-sdk-embedded-C",
        "AZURE_SDK_FOR_C" : "azure-sdk-for-c",
        "BOOST" : "boost",
        "BZIP2" : "bzip2",
        "CIVETWEB" : "civetweb",
        "CJSON" : "cjson",
        "DRM" : "drm",      # Direct Rendering Manager (DRM)driver. From linux kernel.
        "EXPAT" : "expat",
        "FREETYPE2" : "freetype",
        "GSOAP" : "gsoap",
        "SOAP" : "gsoap",
        "ICU" : "icu",
        "INTEL_IPP" : "intel-oneapi-ipp",
        "INTEL_MKL" : "intel-oneapi-mkl",
        "ITLI915" : "OnlyForVx",
        "JANSSON" : "jansson",
        "KHRONOS" : "khronos",
        "LIBARCHIVE" : "libarchive",
        "LIBCURL" : "curl",
        "LIBDRM" : "libdrm",
        "LIBFFI" : "libffi",
        "LIBJPEG" : "libjpeg",
        "LIBPNG" : "libpng",
        "LZMA" : "xz",
        "MBEDTLS_HASH" : "mbedtls",
        "MESA" : "mesa",
        "MIMALLOC" : "mimalloc",
        "MOSQUITTO" : "mosquitto",
        "NTP" : "ipnet_ntp",    # ntp has both ntp-4.2.8pxx and 1.2.0 (old vx7) versions. So not follow upstream, just use VX cve report to monitor
        "IPNET_NTP" : "ipnet_ntp",
        "IPCF" : "ipcf",
        "ONETBB" : "onetbb",
        "OPEN62541" : "open62541",
        "OPENCV" : "opencv",
        "OPENMP" : "openmp",
        "OPENSSL" : "openssl",
        "PARG" : "parg",
        "PYTHON" : "python3",
        "CYTHON" : "cython",
        "DATEUTIL" : "python3-dateutil",
        "NUMPY" : "python3-numpy",
        "PANDAS" : "pandas",
        "PYTZ" : "python3-pytz",
        "SIX" : "python3-six",
        "SDL" : "libsdl",
        "SQLITE" : "sqlite3",
        "TCPLAY" : "tc-play",
        "TENSORFLOW_LITE" : "tensorflow-lite",
        "TPM2_TSS" : "tpm2-tss",
        "UZLIB" : "uzlib",
        "VI_EDITOR" : "OnlyForVx",
        "XRT" : "xrt",
        "ZLIB" : "zlib",
        "ARM" : "OnlyForVx",            # use the below hw-arch to instead
        "IA" : "OnlyForVx",               # use the below hw-arch to instead
        "PPC" : "OnlyForVx",              # use the below hw-arch to instead
        "MATH_FSLE500V2" : "OnlyForVx",
        "RISCV" : "OnlyForVx",
        "VXSIM" : "OnlyForVx",
        "CAN" : "OnlyForVx",
        "IEEE1394" : "OnlyForVx",
        "USB" : "OnlyForVx",
        "CTLR" : "OnlyForVx",
        "CDNSUSB3" : "OnlyForVx",
        "DWC2DR" : "OnlyForVx",
        "USBDWC3" : "OnlyForVx",
        "EHCI" : "OnlyForVx",
        "FSLDR" : "OnlyForVx",
        "MHDRC" : "OnlyForVx",
        "OHCI" : "OnlyForVx",
        "PCHUDC" : "OnlyForVx",
        "PLX" : "OnlyForVx",
        "RZN1" : "OnlyForVx",
        "UHCI" : "OnlyForVx",
        "XHCI" : "OnlyForVx",
        "HOST" : "OnlyForVx",
        "NETWORK" : "OnlyForVx",
        "STORAGE" : "OnlyForVx",
        "TOUCHSCREEN" : "OnlyForVx",
        "OTG" : "OnlyForVx",
        "PHY" : "OnlyForVx",
        "TARGET" : "OnlyForVx",
        "MSC" : "OnlyForVx",
        "NET" : "OnlyForVx",
        "TYPEC" : "OnlyForVx",
        "CONTAINER" : "OnlyForVx",
        "EXAMPLES" : "OnlyForVx",
        "LIFECYCLE_MANAGER" : "OnlyForVx",
        "MANAGER" : "OnlyForVx",
        "RUNTIME" : "OnlyForVx",
        "CORE" : "OnlyForVx",
        "RTP" : "OnlyForVx",
        "SAFETY" : "OnlyForVx",
        "SYSCALLS" : "OnlyForVx",
        "CUSTOM" : "OnlyForVx",
        "DEBUG" : "OnlyForVx",
        "SYSTEMVIEWER" : "OnlyForVx",
        "RTTOOLS" : "OnlyForVx",
        "DEBUG_AGENT" : "OnlyForVx",
        "RUNTIME_ANALYSIS" : "OnlyForVx",
        "STOP_MODE_DEBUG_AGENT" : "OnlyForVx",
        "SYSTEMVIEWER_AGENT" : "OnlyForVx",
        "VXBUS" : "OnlyForVx",
        "DRV" : "OnlyForVx",
        "ACPI" : "acpi",
        "EFI" : "OnlyForVx",
        "FDT" : "OnlyForVx",
        "PSCI" : "OnlyForVx",
        "SCMI" : "OnlyForVx",
        "GUEST_SUPPORT_VX7" : "OnlyForVx",
        "DSS" : "OnlyForVx",
        "HVIF" : "OnlyForVx",
        "SHMEM" : "OnlyForVx",
        "SYSTEMVIEWER" : "OnlyForVx",
        "THROTTLE" : "OnlyForVx",
        "VIRTIO" : "OnlyForVx",
        "VNIC" : "OnlyForVx",
        "GUEST_SUPPORT_VX7_BENCHMARKS" : "OnlyForVx",
        "GUEST_SUPPORT_VX7_SAFE" : "OnlyForVx",
        "APEX" : "OnlyForVx",
        "HM" : "OnlyForVx",
        "HVIF" : "OnlyForVx",
        "MPFS" : "OnlyForVx",
        "SAFEIPC" : "OnlyForVx",
        "SOCKET" : "OnlyForVx",
        "LIBC_BOOT" : "OnlyForVx",
        "LIBC_STD" : "OnlyForVx",
        "CPLUS_KERNEL" : "OnlyForVx",
        "LIBCPLUS_STD" : "OnlyForVx",
        "INTRINSICS_COMMON" : "OnlyForVx",
        "INTRINSICS_LLVM" : "OnlyForVx",
        "WEBCLI" : "webcli",
        "CLIDEMO" : "OnlyForVx",
        "HTTP" : "OnlyForVx",           # the http's pkg ver is SubLayer, so use the below http version
        "MIBWAY" : "OnlyForVx",
        "Webserver" : "OnlyForVx",
        "WEBDEMO" : "OnlyForVx",
        "AUDIO" : "OnlyForVx",
        "CAMERA" : "OnlyForVx",
        "EVDEV" : "OnlyForVx",
        "FBDEV" : "OnlyForVx",
        "GPUDEV" : "OnlyForVx",
        "FSLVIVGPU" : "OnlyForVx",
        "NXPVIVGPU" : "OnlyForVx",
        "RCAR_DU" : "OnlyForVx",
        "RASTER" : "OnlyForVx",
        "VG" : "OnlyForVx",
        "TILCON" : "OnlyForVx",
        "SNMP" : "OnlyForVx",
        "END" : "OnlyForVx",
        "GPTP" : "OnlyForVx",
        "IPNET_8021X" : "ipnet_8021x",
        "IPNET_AAA" : "ipnet_aaa",
        "IPNET_DHCP" : "ipnet_dhcp",
        "CLIENT" : "OnlyForVx",        # All the dhcp write by WindRiver. Not from upstream
        "CLIENT6" : "OnlyForVx",
        "RELAY" : "OnlyForVx",
        "SERVER" : "OnlyForVx",
        "SERVER6" : "OnlyForVx",
        "IPNET_DNSC" : "ipnet_dnsc",
        "IPNET_FTP" : "ipnet_ftp",
        "IPNET_SNTP" : "ipnet_sntp",
        "IPNET_TFTP" : "ipnet_tftp",
        "IPNET_COREIP" : "ipnet_coreip",
        "IPNET_EAP" : "ipnet_eap",
        "IPNET_FIREWALL" : "ipnet_firewall",
        "IPNET_IPSECIKE" : "ipnet_ipsecike",
        "GDOI" : "OnlyForVx",
        "IKE" : "OnlyForVx",            # the ike's pkg ver is SubLayer, so use the below ike version
        "This" : "OnlyForVx",
        "IPNET_QOS" : "ipnet_qos",
        "IPNET_ROUTEPROTO" : "ipnet_routeproto",
        "IPNET_SSH" : "ipnet_ssh",
        "IPNET_USRSPACE" : "ipnet_usrspace",
        "IPNET_VRRP" : "ipnet_vrrp",
        "MIB2" : "OnlyForVx",
        "NET_BASE" : "OnlyForVx",
        "PTP" : "OnlyForVx",
        "RTNET" : "OnlyForVx",          # WR real-time TCP/IP network stack
        "TSN" : "OnlyForVx",
        "ARM_UEFI" : "OnlyForVx",
        "FSL_IMX" : "OnlyForVx",
        "FSL_KINETIS" : "OnlyForVx",
        "FSL_PQ2" : "OnlyForVx",
        "FSL_QORIQ" : "OnlyForVx",
        "FSL_S32" : "OnlyForVx",
        "FSL_VYBRID" : "OnlyForVx",
        "ITL_SOC_ARRIA10" : "OnlyForVx",
        "ITL_SOC_COMMON" : "OnlyForVx",
        "ITL_SOC_CYCLONE5" : "OnlyForVx",
        "ITL_X86_COMMON" : "OnlyForVx",
        "MV_64360" : "OnlyForVx",
        "MCHP_PFSOC" : "OnlyForVx",
        "XEN" : "OnlyForVx",
        "RENESAS_COMMON" : "OnlyForVx",
        "RENESAS_RCAR" : "OnlyForVx",
        "RENESAS_RZ" : "OnlyForVx",
        "SIFIVE_RISCV" : "OnlyForVx",
        "TI_FIRMWARE" : "OnlyForVx",
        "TI_KEYSTONE" : "OnlyForVx",
        "TI_SITARA" : "OnlyForVx",
        "QSP" : "OnlyForVx",
        "XLNX_COMMON" : "OnlyForVx",
        "PSL_XLNX_VERSAL" : "OnlyForVx",
        "XLNX_ZYNQ" : "OnlyForVx",
        "CRYPTOMISC" : "OnlyForVx",
        "IAF" : "OnlyForVx",
        "IPFREESCALE" : "OnlyForVx",
        "IPHWCRYPTO" : "OnlyForVx",
        "TPM" : "OnlyForVx",
        "DISK_ENCRYPTION" : "disk-encryption",
        "LDAPC" : "openldap",
        "OP_TEE" : "optee-client",
        "DEMO" : "OnlyForVx",
        "SECURE_LOADER" : "OnlyForVx",
        "SECURITY_EVENT" : "OnlyForVx",
        "SECURITY_MISC" : "OnlyForVx",
        "SCEP" : "OnlyForVx",
        "SEC_CRYPTO" : "OnlyForVx",
        "SEC_HASH" : "OnlyForVx",
        "USER_MANAGEMENT" : "user_management",
        "LDAP" : "OnlyForVx",
        "POLICY" : "OnlyForVx",
        "USER_PRIVILEGES" : "OnlyForVx",
        "SERVICE" : "OnlyForVx",
        "EPOLL" : "OnlyForVx",
        "ERF" : "OnlyForVx",
        "JOBQUEUE" : "OnlyForVx",
        "REMOTEPROC" : "OnlyForVx",
        "RPC" : "OnlyForVx",          # the rpc's pkg ver is SubLayer, so use the below rpc version
        "RPMSG" : "OnlyForVx",
        "SOCKET" : "OnlyForVx",
        "UN" : "OnlyForVx",
        "VIRTIO" : "OnlyForVx",
        "BDM" : "OnlyForVx",
        "FLASH" : "OnlyForVx",
        "SIM" : "OnlyForVx",
        "LOOPFS" : "OnlyForVx",
        "NVME" : "OnlyForVx",
        "NVRAM" : "OnlyForVx",
        "SATA" : "OnlyForVx",
        "SDMMC" : "OnlyForVx",
        "FS" : "OnlyForVx",
        "CDROMFS" : "OnlyForVx",
        "DOSFS" : "OnlyForVx",
        "HRFS" : "OnlyForVx",
        "NFS" : "OnlyForVx",
        "OVERLAY" : "OnlyForVx",
        "ROMFS" : "OnlyForVx",
        "UTIL" : "OnlyForVx",
        "VRFS" : "OnlyForVx",
        "NVIDIA_TEGRA_X2" : "OnlyForVx",
        "RENESAS_RZ_G2" : "OnlyForVx",
        "BCM2837" : "OnlyForVx",
        "BCM2711" : "OnlyForVx",
        "TI_K3" : "OnlyForVx",
        "UTILS" : "OnlyForVx",
        "BOOTAPP" : "OnlyForVx",
        "CRC" : "OnlyForVx",
        "DEPLOY" : "OnlyForVx",
        "LOADER" : "OnlyForVx",
        "OSTOOLS" : "OnlyForVx",
        "RBUFF" : "OnlyForVx",
        "RUST" : "OnlyForVx",           # the rust's pkg ver is SubLayer, so use the below rust version
        "SHELL" : "OnlyForVx",
        "UNIX" : "OnlyForVx",
        "UTF" : "OnlyForVx",
        "UUID" : "OnlyForVx",
        "WRCC" : "OnlyForVx",
        "VIP_PROFILES" : "OnlyForVx",
        "PROFILES" : "OnlyForVx"}


def _get_os_version():

    vx_version = 'NULL'

    # if the version is 21 or 22.xx
    cur_path = os.path.dirname(os.path.realpath(__file__))
    vx_path = cur_path + '\\vxworks'

    for root, dirs, files in os.walk(vx_path):
        if dirs:
            vx_version = dirs[0]
            break

    if (vx_version != 'NULL'):
        return vx_version

    # if the version is SR05XX or SR06XX
    vx_path = cur_path + '\\maintenance\\wrInstaller\\installDirRepo\\Product'

    file_names = os.listdir(vx_path)
    for file_name in file_names:
        if "installset" in file_name:
            vx_path = vx_path + '\\' + file_name
            with open(vx_path, 'r') as fp:
                last_line = fp.readlines()[-1]
                temp = last_line.split('\\')[-1]
                vx_version = temp.split('.')[0]
                return vx_version

    return vx_version

def _get_info():
    file_type = 'layer.vsbl'
    keyword_name = "Layer"
    keyword_version = "VERSION"
    new_pkg_list = []
    need_to_investigate = []

    vx_version = _get_os_version()

    if (vx_version == 'NULL'):
        print("Error, get the OS version failed")
        exit(0)

    print("OS version: " +  vx_version)

    vx_path = os.path.dirname(os.path.realpath(__file__))

    fp_write = open(vx_path + '/VxWorks_7_' + vx_version + '_manifest.txt', "w")
    fp_write.write('DISTRO_NAME="VxWorks-7"\n')
    fp_write.write("DISTRO_VERSION=\"" + vx_version + "\"" + "\n")

    paths = os.walk(vx_path)

    # Search current floder and sub-floders
    for root,dirs,files in paths:
        for file in files:
            if file_type in file:
                #print(os.path.join(root,file))

                with open(os.path.join(root,file), 'r') as fp:
                    tmp1 = 0
                    tmp2 = 0
                    while True:
                        lines = fp.readline()
                        if not lines:
                            break

                        if '*' in lines:
                            continue

                        if keyword_name in lines:
                            tmp1 = lines.split()[1]

                        if keyword_version in lines:
                            tmp2 = lines.split()[1]
                            if (tmp2 == "NOT"):   # skip a special case.
                                continue
                    # if doesn't find the Name or Version in the file, report error.
                    if ((tmp1 == 0) or (tmp2 == 0)):
                        print("Can't find Package name or version in " + os.path.join(root,file))
                        sys.exit()

                    #print(tmp1,tmp2)

                    #fp_write.write(os.path.join(root,file) + '\n')
                    #print(dict.get(tmp1, 'FindANewPackage'))

                    pkg_name = dict.get(tmp1, 'FindANewPackage')

                    if pkg_name == "FindANewPackage":
                        print(os.path.join(root,file))
                        print(tmp1,tmp2)

                        pkg_name = tmp1         # change back to original name.
                        new_pkg_list.append(pkg_name)

                    if pkg_name == "SitllNeedInvestigate":
                        print(os.path.join(root,file))
                        print(tmp1,tmp2)

                        need_to_investigate.append(tmp1)
                        continue
                    if pkg_name == "OnlyForVx":
                        continue

                    # The pkg version for libjpeg is special, the version in layer.vsbl is not the true version.
                    if pkg_name == "libjpeg":
                        if (vx_version == "22.09") or (vx_version == "21.03"):
                            tmp2 = "9d"
                        else:
                            tmp2 = "9"
                    fp_write.write(pkg_name + ' ' + tmp2 + '\n')

    # add some package, which organized not by package, but still have CVEs. Note, the version info just use to follow the Thor format.
    fp_write.write("u-boot" + ' ' + "1.0" + '\n')
    fp_write.write("eclipse" + ' ' + "1.0" + '\n')
    fp_write.write("calloc" + ' ' + "1.0" + '\n')
    fp_write.write("memory" + ' ' + "1.0" + '\n')
    fp_write.write("gnu" + ' ' + "1.0" + '\n')
    fp_write.write("gcc" + ' ' + "1.0" + '\n')
    fp_write.write("java-se" + ' ' + "1.0" + '\n')
    fp_write.write("hw-arch" + ' ' + "1.0" + '\n')
    fp_write.write("wdb" + ' ' + "1.0" + '\n')

    # add some package, which have CVEs, but the package version is SubLayer in the source. Note, the version info just use to follow the Thor format.
    fp_write.write("http" + ' ' + "1.0" + '\n')
    fp_write.write("ike" + ' ' + "1.0" + '\n')
    fp_write.write("rpc" + ' ' + "1.0" + '\n')
    fp_write.write("rust" + ' ' + "1.0" + '\n')

    fp_write.close()
    print("\nResearching Done, please send the pkg_ver_info.txt to Wind River, thanks")

    if len(new_pkg_list) != 0:
        print("Find new package: (please tell WindRiver this msg, thanks)")
        for i in new_pkg_list:
            print(i)
    if len(need_to_investigate) != 0:
        print("\nNote! Still have pkg need to investigate!")
        for i in need_to_investigate:
            print(i)


def main():
    _get_info()


if __name__ == "__main__":
    main()
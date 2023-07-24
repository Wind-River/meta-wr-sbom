# How to build Petalinux v2019.2 with `meta-wr-sbom` layer

## Install Petalinux

### Download Petalinux v2019.2 and BSP file

Download Petalinux v2019.2 and BSP files from its offical [download](https://japan.xilinx.com/support/download/index.html/content/xilinx/ja/downloadNav/embedded-design-tools/archive.html) page:

* [petalinux-v2019.2-final-installer.run](https://japan.xilinx.com/member/forms/download/xef.html?filename=petalinux-v2019.2-final-installer.run)
* [xilinx-zcu102-v2019.2-final.bsp](https://japan.xilinx.com/member/forms/download/xef.html?filename=xilinx-zcu102-v2019.2-final.bsp)

### Install Petalinux locally

Create install path:

```
$ mkdir -p /opt/petalinux/2019.02
```

**NOTE**: You can choice to install Petalinux where you like, but you need to make sure you have proper permission to the install place and have enough free disk space (about 17G).

And install the Petalinux v2019.2:

```
$ bash petalinux-v2019.2-final-installer.run /opt/petalinux/2019.02
$ cp xilinx-zcu102-v2019.2-final.bsp /opt/petalinux/2019.02/
```

## Build default Petalinux project

Build default Petalinux project **without** `meta-wr-sbom` layer.

* Create workspace for new project

```
$ mkdir -p /opt/petalinux/workspace
$ cd /opt/petalinux/workspace
```

**NOTE**: You can choice where to build your new project, but you need to make sure you have proper permission to the workspace place and have enough free disk space (about 12G).

* initialize build environment

```
$ source /opt/petalinux/2019.02/settings.sh
```

* create new project

```
$ petalinux-create -t project -n peta-prj -s /opt/petalinux/2019.02/xilinx-zcu102-v2019.2-final.bsp
```

`petalinux-create` will create a directory with the same as the project name for this new project.

* build project

```
$ cd peta-prj
$ petalinux-build
```

## Build Petalinux project with `meta-wr-sbom` layer

Suppose that
* the current working directory is our Petalinux workspace, aka. `/opt/petalinux/workspace`;
* we already initialized our build environment, aka. `source /opt/petalinux/2019.02/settings.sh`.

### Get `meta-wr-sbom` layer

```
$ git clone https://github.com/Wind-River/meta-wr-sbom.git
```

### Build Petalinux project with `meta-wr-sbom` layer

* create new project

```
$ petalinux-create -t project -n peta-prj-sbom -s /opt/petalinux/2019.02/xilinx-zcu102-v2019.2-final.bsp
```

**NOTE**: Make sure you have enough free disk space (about 19G) for the new project.

And we better enter the new project directory:

```
$ cd peta-prj-sbom
```

* configure project to include `meta-wr-sbom` layer

```
$ petalinux-config
```

`petalinux-config` will start a TUI program, following `Yocto Settings -> User Layers` to add `meta-wr-sbom` layer.

See Section Adding Layers of Chapter 8 of [PetaLinux documentation](https://docs.xilinx.com/v/u/2019.2-English/ug1144-petalinux-tools-reference-guide) for further details.

**NOTE**: Do not edit `build/conf/bblayers.conf` manually to add extra layers, that file may be over-written by commands such as `petalinux-build`.

* edit `build/conf/local.conf` manually

    + comment out `require conf/locked-sigs.inc`
      ```
      # require conf/locked-sigs.inc
      ```
      
      Otherwise, you will see error messages similar to the following one:
      ```
      ERROR: update-rc.d-0.8-r0 do_configure: Taskhash mismatch a085926854bd559e523f5a06c898d165 versus 9312c768c12c78e5dd132174fa9101d0 for .../petalinux/2019.02/components/yocto/source/aarch64/layers/core/meta/recipes-core/update-rc.d/update-rc.d_0.8.bb.do_configure
      ```
    + append the following line
      ```
      INHERIT += "sls-create-spdx"
      ```

      If you see the following error when running `petalinux-build`:
      ```
      [INFO] building project
      [INFO] sourcing bitbake
      ERROR: Failed to add meta-plnx-generated layer:...
      ERROR: Failed to build project
      ```
      
      Try to remove the above `INHERIT` statement from `build/conf/local.conf` and append it to `meta-wr-sbom/conf/layer.conf`.

* build new project

```
$ petalinux-build
```

When `meta-wr-sbom` layer is enabled, instead of create rpm packages from sstate (as Bitbake did in the default Petalinux project case),
Bitbake will build all packages from source code, and you will see the following error of `qemu-xilinx-native`:

```
...
fatal: clone of 'git://git.qemu.org/capstone.git' into submodule path '.../build/tmp/work/x86_64-linux/qemu-xilinx-native/v2.11.1-xilinx-v2019.2+gitAUTOINC+6617fbc8be-r0/git/capstone' failed
...
fatal: clone of 'git://git.qemu.org/keycodemapdb.git' into submodule path '.../build/tmp/work/x86_64-linux/qemu-xilinx-native/v2.11.1-xilinx-v2019.2+gitAUTOINC+6617fbc8be-r0/git/ui/keycodemapdb' failed
...
```

The cause of the above error is the source code repository used by `qemu-xilinx-native` is a bit outdated, to workaround this issue,
try to manually apply the following changes to `build/tmp/work/x86_64-linux/qemu-xilinx-native/v2.11.1-xilinx-v2019.2+gitAUTOINC+6617fbc8be-r0/git/.git/config`:

```
[submodule "capstone"]
	active = true
-	url = git://git.qemu.org/capstone.git
+   url = https://gitlab.com/qemu-project/capstone.git
[submodule "ui/keycodemapdb"]
	active = true
-	url = git://git.qemu.org/keycodemapdb.git
+   url = https://gitlab.com/qemu-project/keycodemapdb.git
```

Then restart the build:

```
$ petalinux-build
```

## SBOM file generated by `meta-wr-sbom` layer

The final SBOM file generated by `meta-wr-sbom` layer is

```
$ ls build/tmp/deploy/images/zcu102-zynqmp/*.spdx.json
build/tmp/deploy/images/zcu102-zynqmp/petalinux-user-image-zcu102-zynqmp-20230712143753.spdx.json
build/tmp/deploy/images/zcu102-zynqmp/petalinux-user-image-zcu102-zynqmp.spdx.json
```

`petalinux-user-image-zcu102-zynqmp.spdx.json` is a symbolic link to `petalinux-user-image-zcu102-zynqmp-20230712143753.spdx.json`, so these are the same file.

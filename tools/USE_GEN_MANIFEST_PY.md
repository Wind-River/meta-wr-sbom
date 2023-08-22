
The gen_spdx.py script is for generate SBOM for wrlinux 5 - 8.

## Supported Wind River Linux versions

- [Wind River Linux 5](https://docs.windriver.com/category/os-wind_river_linux_5)
- [Wind River Linux 6](https://docs.windriver.com/category/os-wind_river_linux_6)
- [Wind River Linux 7](https://docs.windriver.com/category/os-wind_river_linux_7)
- [Wind River Linux 8](https://docs.windriver.com/category/os-wind_river_linux_8)

## Requirement

The project has been built completely.
Python 2.7 has been installed on the host.

## To use the script

Enter your project directory:
```
$ cd ${the_project_path}
```

Enter 'bitbake_build' directory and enter yocto mode:
```
$ make bbs
```

Download gen_spdx.py script to current directory:
```
$ wget https://raw.githubusercontent.com/Wind-River/meta-wr-sbom/main/tools/gen_spdx.py
```

Generate the SBOM file:
```
$ python ./gen_spdx.py 
```

The SBOM file of your WRLinux project will be generated as  **./${your_image_name}.spdx.json**.

# HMSDK

HMSDK stands for Heterogeneous Memory Software Development Kit and it is
especially designed to support CXL memory, which is a new promising memory
system based on a CXL(Compute Express Link) open industry standard.

The more explanation can be found at the [wiki page](https://github.com/skhynix/hmsdk/wiki).

## Download

HMSDK consists of multiple git submodules so please download it as follows.

    $ git clone --recursive --shallow-submodules https://github.com/skhynix/hmsdk.git

## News

- 2024-09-16: HMSDK v3.0 is released
  - Fully aligned with various open source projects, which allows us drop local patches
- 2024-07-03: HMSDK v2.0 kernel patches have landed into upstream Linux kernel (available from v6.11)
  - 7 commits including [migration core logic](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b51820ebea656be3b48bb16dcdc5ad3f203c4fd7) - [cover letter](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a00ce85af2a1be494d3b0c9457e8e81cdcce2a89)
- 2024-04-19: numactl supports [--weighted-interleave](https://github.com/numactl/numactl/commit/b67fb88e77b3c200b0e300e2e0edc4f66c1d9ea5) option
- 2024-02-22: HMSDK v1.1 kernel patches have landed into upstream Linux kernel (available from v6.9)
  - [MPOL_WEIGHTED_INTERLEAVE](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=fa3bea4e1f8202d787709b7e3654eb0a99aed758) memory policy and its [sysfs interface](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=dce41f5ae2539d1c20ae8de4e039630aec3c3f3c) (co-developed by [MemVerge](http://www.memverge.com))
- 2023-12-27: HMSDK v2.0 released - support [DAMON](https://sjp38.github.io/post/damon) based 2-tier memory management
- 2023-05-09: HMSDK v1.1 released - support bandwidth aware interleaving, user library and tools

## For PEBS enabled
```shell
cd linux
cp /boot/config-$(uname -r) .config
echo 'CONFIG_DAMON=y' >> .config
echo 'CONFIG_DAMON_VADDR=y' >> .config
echo 'CONFIG_DAMON_PADDR=y' >> .config
echo 'CONFIG_DAMON_SYSFS=y' >> .config
echo 'CONFIG_MEMCG=y' >> .config
echo 'CONFIG_MEMORY_HOTPLUG=y' >> .config
make menuconfig
```
in menuconfig, search PEBS_TEST to set CONFIG_PEBS_TEST=y
```shell
make -j$(nproc)
sudo make INSTALL_MOD_STRIP=1 modules_install
sudo make headers_install
sudo make install
```
set booting kernel to 
```shell
sudo grub-reboot "Advanced options for Ubuntu>Ubuntu, with Linux 6.12.0-pebs_git"
```


## License

The HMSDK is released under BSD 2-Clause license.
Please see [LICENSE file](LICENSE) for details.

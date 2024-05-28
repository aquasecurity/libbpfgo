# Vagrantfile

## Boxes

Currently there are two boxes available in [Vagrantfile-ubuntu](./../builder/Vagrantfile-ubuntu):

| Box                                                                                          | Providers                |
|----------------------------------------------------------------------------------------------|--------------------------|
| [generic/ubuntu2204](https://app.vagrantup.com/generic/boxes/ubuntu2204) (amd64)             | virtualbox, parallels    |
| [jharoian3/ubuntu-22.04-arm64](https://app.vagrantup.com/jharoian3/boxes/ubuntu-22.04-arm64) | parallels                |

It is recommended to use them through the respective [Makefile rules](../Readme.md#contributing) as they are or overriding the `ARCH` environment variable if your architecture and provider allow such virtualization. E.g.: `make vagrant-up ARCH=amd64`.

## Requirements

### Linux

Install them as per your flavour.

- Vagrant
- VirtualBox

### Darwin

- Vagrant

```shell
brew install vagrant
```

- Parallels

```shell
brew install --cask parallels
vagrant plugin install vagrant-parallels
```

## More information

For further information check:

- [Vagrant Documentation](https://www.vagrantup.com/docs)
- [Vagrant Boxes](https://app.vagrantup.com/boxes/search)
- [VirtualBox Documentation](https://www.virtualbox.org/wiki/Documentation)
- [Parallels](https://www.parallels.com)

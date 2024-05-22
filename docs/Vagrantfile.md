# Vagrantfile

## Boxes

Currently there is one box available in [Vagrantfile-ubuntu](./../builder/Vagrantfile-ubuntu):

| Box                                                                      | Providers                |
|--------------------------------------------------------------------------|--------------------------|
| [bento/ubuntu-24.04](https://app.vagrantup.com/bento/boxes/ubuntu-24.04) | virtualbox (amd64), parallels (arm64,amd64), ...|

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

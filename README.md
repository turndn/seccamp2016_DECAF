# Securiy camp 2016 (6, 7-F: なぜマルウェア解析は自動化できないのか)
## Usage
Build

    ./configure --decaf-path=<your decaf path> && make

Load plugin

    (qemu) load_plugin <your path>/my_plug.so
    (qemu) my_plug <target file>
    (qemu) unload_plugin

## Caution
This plugin needs `urlmon.dll` in dll_modules_list for VMI.
You should check `https://github.com/sycurelab/DECAF/pull/38`.

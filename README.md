# VortexPak

Tool to read Unreal PAK files and extract their contents.

## Usage

### Drag-and-drop

Drop a `.pak` file onto the executable to create a json file of it's contents in the same folder.

### Command Line

`PakReader <file> [options]`

#### Arguments

`<file>`: PAK file to parse

#### Options
```shell
-e, --extract   Extract PAK file contents [default: False]
--version       Show version information
-?, -h, --help  Show help and usage information
```
### Examples

`PakReader C:\Test\MyMod.pak` will output it's metadata to `C:\Test\MyMod.json`

`PakReader C:\Test\MyMod.pak -e` will output it's metadata to `C:\Test\MyMod.json` 
and extract it's contents to `C:\<pak mount path>\<pak file path>`
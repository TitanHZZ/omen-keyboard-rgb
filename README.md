# omen-keyboard-rgb
Simple C++ driver for omen laptops with 4 zone keyboard rgb.

## Index

* [About the Project](#about-the-project)
* [Built With](#built-with)
* [Installation](#installation)
* [Useful resources](#useful-resources)

### About the Project
This is a simple and lightweight WMI driver that allows you to control the backlight/rgb of newer omen laptops with 4 zone keyboards.

### Built With

* C++ 20
* CMake 3.5
* VS2022 Community

### Installation

1. Clone the repository and enter the directory created
```sh
git clone https://github.com/TitanHZZ/omen-keyboard-rgb.git
cd omen-keyboard-rgb
```
2. Generate VS2022 solution
```sh
mkdir build
cd build
cmake -G "Visual Studio 17 2022" -A x64 ..
```
**Note:** You should have at least *Desktop development with C++* installed with VS2022.

3. Build the project
```sh
cmake --build . --config Release
```

4. Run the code
```sh
cd Release
.\omen-keyboard-rgb.exe
```

### Useful resources
[omen-cli](https://github.com/thebongy/omen-cli) - C# version with cli tool  
[hp-omen-linux-module](https://github.com/pelrun/hp-omen-linux-module) - Linux driver with same purpose

# Ungrabber

[![](https://dcbadge.limes.pink/api/server/https://discord.gg/9kheda3rEZ)](https://discord.gg/9kheda3rEZ)



Ungrabber is a Python module designed for decompiling and extracting C2 (especially webhook) from info stealers.

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/lululepu/Ungrabber
   ```
2. Navigate to the repository directory:
   ```sh
   cd Ungrabber-main
   ```
3. Install the module:
   ```sh
   pip install .
   ```

## Usage

### 1. Direct Decompiling

Decompile a file and extract its data as a tuple:

```python
import Ungrabber

result = Ungrabber.decompile("filename")
print(result)  # The tuple of extracted data
```

### 2. Load as a Stub Object

Load a file as a stub object for further analysis:

```python
import Ungrabber

with open("filename", "rb") as f:
    stub = Ungrabber.load(f)

print(stub)  # The stub object
```

_Documentation will be added later_

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests to improve Ungrabber.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

## Contact

For any inquiries or support, please open an issue on [GitHub](https://github.com/lululepu/Ungrabber/issues).

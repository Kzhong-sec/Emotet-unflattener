# Emotet Control‑Flow Unflattener
A Python tool that recovers the original control flow of Emotet malware that has been obfuscated through control flow flattening, leveraging symbolic execution through Angr.


## Notes
- Supports both 32‑bit and 64‑bit Windows PE binaries
- Tested against Emotet binaries first submitted to VirusTotal in 2024
- Deobfuscation may take significant time (up to ~1 hour per binary), depending on sample complexity

## Prerequisites

- Python 3.10 or higher

## Installation
1. Clone the repository:

```bash
git clone https://github.com/Kzhong-sec/Emotet-unflattener.git
cd Emotet-unflattener
```

2. Install Python dependencies:

```bash
pip install -r requirements.txt
```

## Usage

This tool is executed via the `src/unflatten.py` entry point.

### Arguments
```bash
python unflatten.py --binary <path> [--function <addr>] [--output <path>]
```


- `--binary`, `-b`  
  **Required.** Path to the target Windows PE binary.

- `--function`, `-f`  
  Optional function address to unflatten (hex or decimal).  
  If omitted, all functions are processed.

- `--output`, `-o`  
  Optional output binary path.  
  Defaults to `<input>.unflattened`.


## Output
See the results of the tool below.

**Figure 1: Basic blocks before deobfuscation**  
![Basic blocks before deobfuscation](screenshots/blocks_original.png)

**Figure 2: Basic blocks after deobfuscation**  
![Basic blocks after deobfuscation](screenshots/blocks_unflattened.png)

**Figure 3: Decompilation before deobfuscation**  
![Decompilation before deobfuscation](screenshots/decompiler_original.png)

**Figure 4: Decompilation after deobfuscation**  
![Decompilation after deobfuscation](screenshots/decompiler_unflattened.png)


## Performance
The tool was evalauted against the following 9 Emotet samples:
```bash
C688E079A16B3345C83A285AC2AE8DD48680298085421C225680F26CEAE73EB7
9D5AF9E1EBE5E391B33B7A362E1125CE2842BA84E75E1AB1B043EEA695EA3995
3822FFA36B251A65AB4042D3C6F7457684ABB452366EF248868176B3D22C2AB2
E5C488C73F34F4DF7B85A0B6FA8F667FED7364DBCEEC8E18F426D53989AF9045
9BB1B20AB4A3355F2C62DD0E08159AB6392E9490961295DDB16984B573AF2775
3B6E3B851F5195C9D831D0958967B96C0A699B1CF8DE71218AC66F48CD009FEF
1C9D11817A98EC7E35B5177982B38DB5371E1806293F621E40D103053E886BCB
951DB530C6DCB5C56B376D3A2E2EFE3AC938B487CF7B7F29E6CE06FDEA46406C
5700694D1D78C952A81690CF0DFAD2B13F25B65D8C196481DC256B47550E33F1
```
Across these samples, approximately 98% of obfuscated functions were successfully deobfuscated. The functions on which the tool failed were primarily extremely large functions where symbolic execution timed out or excessive memory consumption occurred.

The rewritten and patched binaries executed successfully after deobfuscation and behaved as expected without crashing.
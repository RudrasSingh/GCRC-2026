# EXTERNAL TOOLS SETUP & EXECUTION GUIDE

This guide explains how to validate GCRC cipher results using industry-standard cryptographic testing tools.

---

## OVERVIEW

After running `academic_evaluation.py`, you'll have binary ciphertext files suitable for:

1. **NIST STS** - Official statistical test suite (NIST SP 800-22)
2. **PractRand** - Advanced randomness testing
3. **Dieharder** - Comprehensive statistical battery

These validate that your ciphertext is statistically indistinguishable from random.

---

## 1. NIST SP 800-22 STATISTICAL TEST SUITE

### What It Tests

Official NIST statistical tests for randomness:
- Frequency distribution
- Runs and longest runs
- Rank test (linear dependencies)
- Spectral test (periodicity)
- Entropy and correlation tests
- 13+ statistical tests total

**Reference:** https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf

### Installation

#### Linux/macOS

```bash
# Clone optimized NIST STS implementation
git clone https://github.com/kravietz/nist-sts.git
cd nist-sts

# Compile
make

# Verify
./assess --help
```

#### Windows

```bash
# Download source
# https://github.com/kravietz/nist-sts/releases

# Extract and compile using MinGW or MSVC
make

# Or download pre-compiled binary
# https://csrc.nist.gov/projects/random-bit-generation/testing/
```

### Usage

```bash
# Basic usage
./assess 1000000 < path/to/gcrc_random_ciphertexts_*.bin

# What it does:
# 1. Reads binary file
# 2. Applies statistical tests
# 3. Generates p-values for each test
# 4. Creates output report

# Expected output:
# "P-values Range: [0.0, 1.0]"
# "Proportion Rate: [85%, 100%]"  <- 95%+ is excellent
```

### Interpretation

**Pass Criteria:**
- **P-value ≥ 0.01**: Test PASSED (sequence appears random)
- **P-value < 0.01**: Test FAILED (sequence appears non-random)

**Results Summary:**
```
NIST Test Results:
✓ Frequency (Monobit): PASS (p=0.156)
✓ Frequency (Block): PASS (p=0.423)
✓ Runs: PASS (p=0.892)
✓ Longest Run: PASS (p=0.634)
✓ Rank: PASS (p=0.098)
✓ Spectral: PASS (p=0.876)
✓ Approximate Entropy: PASS (p=0.532)
✓ Cumulative Sums: PASS (p=0.445)

Pass Rate: 100% (8/8 tests passed)
```

**Publication Quality:**
- ✅ 95%+ pass rate = Excellent
- ⚠️  85-95% pass rate = Good
- ⚠️  70-85% pass rate = Investigate
- ❌ < 70% pass rate = Needs work

---

## 2. PractRand (Practical Randomness Testing)

### What It Tests

Advanced randomness testing that detects subtle patterns:
- Binary rank tests
- Spectral tests
- DFT anomalies
- Gap analysis
- Collision tests
- Pattern detection

**Key Advantage:** Detects weaknesses that NIST might miss

**Website:** http://pracrand.sourceforge.net/

### Installation

#### Linux/macOS

```bash
# Download source
wget http://pracrand.sourceforge.net/PractRand.zip
unzip PractRand.zip
cd PractRand

# Compile
make

# Test installation
./RNG_test --help
```

#### Windows

```bash
# Download pre-compiled binaries
# http://pracrand.sourceforge.net/

# Extract to directory
cd PractRand_bin_win64_x86

# Run tests directly
RNG_test.exe stdin64 < path\to\gcrc_*.bin
```

### Usage

```bash
# Basic test (64-bit input)
./RNG_test stdin64 < path/to/gcrc_random_ciphertexts_*.bin

# More thorough (128-bit input)
./RNG_test stdin128 < path/to/gcrc_random_ciphertexts_*.bin

# With file input instead of stdin
./RNG_test stdin64 -ffile path/to/gcrc_random_ciphertexts_*.bin

# Specify data size (stop after N bytes)
./RNG_test stdin64 < path/to/gcrc_random_ciphertexts_*.bin -maxmem 4g
```

### Interpretation

**Output Example:**
```
RNG_test using PractRand version 0.93
RNG = RNG_stdin64, seed = 0x12345678
test set = normal   length= 256 megabytes   time= 1.8 seconds
  A: [LSFR2+]            PASS    (p = 0.500)
  B: [DC6-9x1Bytes-1]    PASS    (p = 0.500)
  C: [Gap-16:A]          PASS    (p = 0.500)
  
No anomalies in 256 MB of data
RNG appears to be a good source
```

**Interpretation:**

| Result | Meaning |
|--------|---------|
| PASS | No anomalies detected |
| WEAK | Slight deviation (examine closely) |
| FAIL | Anomaly detected |

**Key Insight:** PractRand becomes progressively more demanding as data increases. If it doesn't fail on gigabytes of data, you have a very good RNG.

---

## 3. Dieharder (Comprehensive Statistical Battery)

### What It Tests

George Marsaglia's classic test battery:
- Birthdays
- Overlapping permutations (OPSO)
- Runs tests
- Craps
- Parking lot
- Minimum distance
- Random spheres
- SQUEeZe
- 3D spheres
- Count the 1s (bit stream)
- Count the 1s (byte stream)

**Website:** https://webhome.phy.duke.edu/~rgb/General/dieharder.php

### Installation

#### Linux (Debian/Ubuntu)

```bash
# Install via package manager
sudo apt-get install dieharder

# Verify
dieharder -h
```

#### Linux (Compile from source)

```bash
# Download
wget https://github.com/DavidWiggins/dieharder/archive/refs/heads/main.zip
unzip dieharder-main.zip
cd dieharder-main

# Build
./configure
make
sudo make install

# Verify
dieharder -h
```

#### macOS

```bash
# Using Homebrew
brew install dieharder

# Or compile from source
git clone https://github.com/DavidWiggins/dieharder.git
cd dieharder
./configure
make
sudo make install
```

#### Windows

```bash
# Download pre-compiled
# http://webhome.phy.duke.edu/~rgb/General/dieharder.php

# Or use WSL (Windows Subsystem for Linux)
wsl apt-get install dieharder
```

### Usage

```bash
# Run ALL tests
dieharder -a -g 201 -f path/to/gcrc_random_ciphertexts_*.bin

# Run specific test
dieharder -d 0 -g 201 -f path/to/gcrc_random_ciphertexts_*.bin

# Verbose output
dieharder -a -g 201 -f path/to/gcrc_random_ciphertexts_*.bin -v

# Test multiple files
dieharder -a -g 201 -f path/to/gcrc_*.bin

# Save results to file
dieharder -a -g 201 -f path/to/gcrc_random_ciphertexts_*.bin > results.txt
```

**Options:**
- `-a`: Run all tests
- `-d N`: Run specific test (0-100+)
- `-g 201`: Read from file
- `-f FILE`: Input file path
- `-v`: Verbose output

### Interpretation

**Output Example:**
```
DIEHARD tests
==============
diehard_birthdays   |   2            PASS  
diehard_opso        |   1            PASS  
diehard_runs        |   5            PASS  
diehard_craps       |   2            PASS  
diehard_parking_lot |   1            PASS  
diehard_minimize_distance | 5        PASS  
diehard_sphere3     |   4            PASS  
diehard_squeeze     |   1            PASS  
diehard_sums        |   1            PASS  
diehard_runs        |   2            PASS  
diehard_craps       |   2            PASS  
diehard_bitstream   |  12            PASS  
```

**Interpretation:**

| Result | p-value | Meaning |
|--------|---------|---------|
| PASS | 0.01 - 0.99 | Good |
| WEAK | 0.005 - 0.01 or 0.99 - 0.995 | Marginal |
| FAIL | < 0.005 or > 0.995 | Problematic |

**Publication Standard:** ≥95% of tests should PASS

---

## COMPLETE VALIDATION WORKFLOW

### Step 1: Generate Binary Dataset

```bash
cd dna_gcrc_project

# Run evaluation pipeline to generate binary files
python quick_eval.py --thorough

# Binary files created:
# evaluation_results/gcrc_random_ciphertexts_*.bin
# evaluation_results/gcrc_structured_ciphertexts_*.bin

# Get file information
ls -lh evaluation_results/gcrc_*.bin
file evaluation_results/gcrc_random_ciphertexts_*.bin
wc -c evaluation_results/gcrc_random_ciphertexts_*.bin
```

### Step 2: Run NIST STS

```bash
# Navigate to NIST directory
cd nist-sts

# Run assessment
./assess 1000000 < ../dna_gcrc_project/evaluation_results/gcrc_random_ciphertexts_*.bin

# Save output
./assess 1000000 < ../dna_gcrc_project/evaluation_results/gcrc_random_ciphertexts_*.bin > nist_results.txt

# Verify results
cat nist_results.txt | grep -E "PASSED|FAILED|Proportion"
```

### Step 3: Run PractRand

```bash
# Navigate to PractRand directory
cd PractRand

# Run practical randomness test
./RNG_test stdin64 < ../dna_gcrc_project/evaluation_results/gcrc_random_ciphertexts_*.bin

# Save output
./RNG_test stdin64 < ../dna_gcrc_project/evaluation_results/gcrc_random_ciphertexts_*.bin | tee practrand_results.txt

# Check for anomalies
tail -20 practrand_results.txt
```

### Step 4: Run Dieharder

```bash
# Run dieharder
dieharder -a -g 201 -f dna_gcrc_project/evaluation_results/gcrc_random_ciphertexts_*.bin

# Save output
dieharder -a -g 201 -f dna_gcrc_project/evaluation_results/gcrc_random_ciphertexts_*.bin > dieharder_results.txt

# Summarize results
grep -E "PASS|WEAK|FAIL" dieharder_results.txt | sort | uniq -c
```

### Step 5: Compile Results

```bash
# Create comprehensive report
cat > validation_summary.txt << EOF
====================================================
GCRC CIPHER - EXTERNAL VALIDATION RESULTS
====================================================

Date: $(date)
Binary File: gcrc_random_ciphertexts_*.bin
File Size: $(du -h evaluation_results/gcrc_random_ciphertexts_*.bin)

1. NIST SP 800-22
$(cat nist_results.txt | grep -A5 "Proportion")

2. PractRand
$(tail -5 practrand_results.txt)

3. Dieharder Summary
$(grep -E "PASS|WEAK|FAIL" dieharder_results.txt | sort | uniq -c)

====================================================
EOF

cat validation_summary.txt
```

---

## INTERPRETING COMBINED RESULTS

### Excellent Results

**All tests pass:**
```
NIST:     ✅ 95%+ pass rate
PractRand: ✅ No anomalies detected
Dieharder: ✅ 95%+ tests PASS
```

→ **Publication-ready results**

### Good Results

**Mostly passing with minor issues:**
```
NIST:     ✅ 85-95% pass rate
PractRand: ⚠️  WEAK in 1-2 tests
Dieharder: ✅ 85-95% tests PASS
```

→ **Investigate weak areas, but generally acceptable**

### Needs Improvement

**Significant failures:**
```
NIST:     ⚠️  < 85% pass rate
PractRand: ❌ FAIL on extended data
Dieharder: ⚠️  < 85% tests PASS
```

→ **Redesign cipher components**

---

## PUBLICATION REQUIREMENTS

### Essential Documentation

1. **Test Metadata**
   - Cipher implementation details
   - Binary file generation method
   - Sample size and parameters
   - Testing platform

2. **Results Tables**
   - NIST test results with p-values
   - Pass/fail counts
   - Comparison with reference values

3. **Figures**
   - P-value distribution histograms
   - Entropy measurements
   - Performance comparisons

4. **External Validation**
   - NIST STS results
   - PractRand anomaly detection
   - Dieharder test summary

### Example Publication Section

```markdown
## 5. Experimental Results

We evaluated the GCRC cipher using three industry-standard
randomness test suites:

### 5.1 NIST SP 800-22 Statistical Tests

Testing was performed on 1,000,000 bits of ciphertext generated
from 10,000 random plaintexts using a fixed key.

| Test | p-value | Result |
|------|---------|--------|
| Frequency (Monobit) | 0.523 | ✓ PASS |
| Frequency (Block) | 0.748 | ✓ PASS |
| Runs | 0.891 | ✓ PASS |
| Longest Run | 0.634 | ✓ PASS |
| Rank | 0.098 | ✓ PASS |
| Spectral (DFT) | 0.876 | ✓ PASS |
| Approximate Entropy | 0.532 | ✓ PASS |
| Cumulative Sums | 0.445 | ✓ PASS |

**Summary**: 8/8 tests passed (100% pass rate), indicating
excellent statistical properties.

### 5.2 PractRand Analysis

Running PractRand on 256 MB of ciphertext produced no anomalies,
demonstrating absence of detectable patterns even under intensive
scrutiny.

### 5.3 Dieharder Statistical Battery

Dieharder testing on 1 GB of ciphertext achieved a 98% pass rate
across all 18 statistical tests, with no FAIL results.
```

---

## TROUBLESHOOTING EXTERNAL TOOLS

### NIST STS Issues

**"Cannot open file"**
```bash
# Make sure file exists and is readable
ls -la path/to/gcrc_random_ciphertexts_*.bin

# Try absolute path
./assess 1000000 < /full/path/to/gcrc_random_ciphertexts_*.bin
```

**"Insufficient data"**
```bash
# Generate larger binary file
python quick_eval.py --thorough  # Creates ~50MB+ file

# Check file size
du -h evaluation_results/gcrc_*.bin
```

### PractRand Issues

**"Command not found"**
```bash
# Make sure it's compiled and in PATH
cd PractRand
make clean && make

# Or run with full path
./bin/RNG_test stdin64 < ../data.bin
```

### Dieharder Issues

**"Input file too short"**
```bash
# Dieharder needs 512 bytes minimum, 10+ KB recommended
dd if=gcrc_random_ciphertexts_*.bin bs=1M count=10 > test_sample.bin
dieharder -a -g 201 -f test_sample.bin
```

---

## BEST PRACTICES

1. **Use Consistent Dataset**
   - Same ciphertext file for all tests
   - Record file hash (sha256sum)
   
2. **Document Everything**
   - Cipher parameters
   - Plaintext generation method
   - Test platform/version
   - Exact commands run

3. **Run Multiple Configurations**
   - Different random keys
   - Different plaintext distributions
   - Various ciphertext lengths

4. **Compare Against Standards**
   - AES-256 (as reference)
   - Other published ciphers
   - Hardware RNG results

5. **Report Comprehensively**
   - Include all test results
   - Document any failures
   - Explain any anomalies
   - Provide raw data

---

**External Tools Reference v1.0**  
**Last Updated: 2026-05-13**

# ACADEMIC CRYPTOGRAPHIC EVALUATION PIPELINE
## Complete Implementation Guide

**Version**: 1.0  
**Last Updated**: 2026-05-13  
**Status**: Production Ready  

---

## 📋 TABLE OF CONTENTS

1. [Overview](#overview)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Pipeline Architecture](#pipeline-architecture)
5. [Running Evaluations](#running-evaluations)
6. [External Tools Integration](#external-tools-integration)
7. [Results Interpretation](#results-interpretation)
8. [Publication Workflow](#publication-workflow)
9. [Troubleshooting](#troubleshooting)

---

## 📖 OVERVIEW

This pipeline provides **production-grade cryptographic evaluation** suitable for academic publication. It evaluates the GCRC (DNA-based) cipher against industry standards and compares performance with established algorithms (AES-256, Triple DES).

### Key Features

✅ **NIST SP 800-22** compliant statistical testing  
✅ **Comparative benchmarking** with AES/DES  
✅ **Differential cryptanalysis** suite  
✅ **Binary dataset generation** for external tools  
✅ **Publication-ready reports** (HTML, JSON, Markdown)  
✅ **Academic-grade metrics** for peer review  

### Evaluation Phases

| Phase | Task | Time |
|-------|------|------|
| 1 | Dataset Generation | 2-5 min |
| 2 | NIST STS Testing | 5-10 min |
| 3 | Entropy Analysis | 3-5 min |
| 4 | Avalanche Effect | 2-4 min |
| 5 | Differential Analysis | 5-10 min |
| 6 | Comparative Benchmarking | 3-5 min |
| 7 | Report Generation | 1-2 min |
| **TOTAL** | | **20-40 min** |

---

## 🔧 INSTALLATION

### Prerequisites

```bash
# Python 3.8+
python --version

# Verify packages
pip list | grep numpy pandas scipy pycryptodome
```

### Required Packages

All essential packages are already in `requirements.txt`:

```bash
# Core cryptography
pycryptodome>=3.18.0
cryptography>=41.0.0

# Scientific computing
numpy>=2.4.0
scipy>=1.13.0
pandas>=2.3.0

# Visualization (optional but recommended)
matplotlib>=3.8.0
plotly>=6.6.0

# Data formats
jsonschema>=4.26.0
```

### Installation Steps

```bash
# 1. Navigate to project directory
cd "d:\folders\coding\projects\project Aegion\dna_gcrc_project"

# 2. Create virtual environment (recommended)
python -m venv venv
venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify installation
python -c "from academic_evaluation import AcademicCryptoEvaluator; print('✓ Installation successful')"
```

---

## 🚀 QUICK START

### Run Default Evaluation

```bash
# Start the pipeline with default parameters
python quick_eval.py

# Output:
# ✓ Dataset generation
# ✓ NIST STS tests
# ✓ Entropy analysis
# ✓ Avalanche testing
# ✓ Differential analysis
# ✓ Comparisons
# ✓ Reports generated
```

### Run in Specific Mode

```bash
# QUICK mode (~2-5 minutes) - for development
python quick_eval.py --fast

# DEFAULT mode (~15-25 minutes) - standard evaluation
python quick_eval.py

# THOROUGH mode (~40-60 minutes) - publication-quality
python quick_eval.py --thorough

# Custom parameters
python quick_eval.py --samples 5000 --nist-samples 200000
```

### Check Results

After completion, find results in:

```
evaluation_results/
├── complete_evaluation_results_TIMESTAMP.json  # Full results
├── academic_evaluation_report_TIMESTAMP.json   # Structured report
├── evaluation_report.html                       # View in browser
├── gcrc_random_ciphertexts_TIMESTAMP.bin       # For external tools
└── gcrc_datasets_metadata_TIMESTAMP.json       # Dataset details
```

Open the HTML report:
```bash
# Windows
start evaluation_results/evaluation_report.html

# macOS
open evaluation_results/evaluation_report.html

# Linux
xdg-open evaluation_results/evaluation_report.html
```

---

## 🏗️ PIPELINE ARCHITECTURE

### Module Structure

```
analysis/
├── nist_sp800_22.py              # NIST SP 800-22 tests
├── cipher_comparison.py          # AES/DES comparison
├── dataset_generator.py          # Binary file generation
├── differential_analysis_enhanced.py  # Differential cryptanalysis
├── avalanche.py                  # Avalanche effect (existing)
├── randomness.py                 # Entropy/statistics (existing)
└── metrics.py                    # Additional metrics

Top-level:
├── academic_evaluation.py        # Main orchestrator
├── academic_report_gen.py        # Report generation
└── quick_eval.py                 # Command-line interface
```

### Data Flow

```
Input Plaintexts
     ↓
GCRC Cipher
     ↓
Ciphertexts
     ↓
┌─────────────────────────────────────┐
│  Analysis Modules (Parallel)        │
├─────────────────────────────────────┤
│ • NIST STS                          │
│ • Entropy Analysis                  │
│ • Avalanche Effect                  │
│ • Differential Analysis             │
│ • Comparisons (AES/DES)             │
└─────────────────────────────────────┘
     ↓
Metrics Database
     ↓
Report Generation
     ↓
HTML/JSON/Markdown Reports
```

---

## 🔬 RUNNING EVALUATIONS

### Direct Python Usage

```python
from academic_evaluation import AcademicCryptoEvaluator

# Initialize evaluator
evaluator = AcademicCryptoEvaluator(
    output_dir='my_results',
    cipher_key='my-secret-key'
)

# Run full evaluation
report = evaluator.run_full_evaluation(
    num_samples=10000,      # Ciphertext samples
    nist_samples=1000000    # Bits for NIST testing
)

# Access individual results
print(evaluator.results['nist_sts']['summary'])
print(evaluator.results['entropy'])
print(evaluator.results['avalanche'])
```

### Command-Line Usage

```bash
# Show all options
python quick_eval.py --help-full

# Run with custom parameters
python quick_eval.py \
    --samples 5000 \
    --output my_evaluation \
    --key my-custom-key

# Run and save to custom location
python quick_eval.py --thorough --output publication_results
```

### Individual Phase Testing

```python
from academic_evaluation import AcademicCryptoEvaluator

evaluator = AcademicCryptoEvaluator()

# Run individual phases
evaluator.generate_datasets(num_samples=5000)
evaluator.run_nist_sts_tests(num_samples=100000)
evaluator.analyze_entropy(num_samples=5000)
evaluator.analyze_avalanche_effect(num_tests=1000)
evaluator.run_differential_analysis()
evaluator.compare_with_standards()
```

---

## 🛠️ EXTERNAL TOOLS INTEGRATION

### NIST STS (Official Reference)

```bash
# 1. Clone official NIST STS
git clone https://github.com/kravietz/nist-sts.git
cd nist-sts

# 2. Compile
make

# 3. Run assessment
./assess 1000000 < path/to/gcrc_random_ciphertexts_*.bin

# Expected input: BINARY file with 1,000,000+ bits
# Our pipeline generates: gcrc_random_ciphertexts_*.bin
```

### PractRand (Practical Randomness)

```bash
# 1. Download
# http://pracrand.sourceforge.net/

# 2. Compile (Linux/macOS)
tar xzf PractRand.zip
cd PractRand
make

# 3. Run analysis
# Start with smaller test:
./RNG_test stdin64 < gcrc_random_ciphertexts_*.bin

# Full analysis (slower, more thorough):
./RNG_test stdin128 < gcrc_random_ciphertexts_*.bin
```

### Dieharder (Statistical Battery)

```bash
# 1. Install
# Linux:
sudo apt-get install dieharder

# macOS:
brew install dieharder

# Windows: Download from http://webhome.phy.duke.edu/~rgb/

# 2. Run all tests
dieharder -a -g 201 -f path/to/gcrc_random_ciphertexts_*.bin

# Run specific test
dieharder -d 0 -g 201 -f path/to/gcrc_random_ciphertexts_*.bin
```

### FIPS 140-2 Validation

```bash
# Generate datasets for FIPS testing
python -c "
from analysis.dataset_generator import DatasetGenerator
from cipher.gcrc_cipher import GCRC

gen = DatasetGenerator(GCRC('fips-test-key'))
result = gen.create_ciphertext_stream(
    num_samples=20000,
    output_filename='fips_140_2_test.bin'
)
print(f'Test file: {result[\"output_file\"]}')
print(f'Size: {result[\"file_size_bytes\"]} bytes')
"
```

---

## 📊 RESULTS INTERPRETATION

### NIST STS Results

**Pass Rate Interpretation:**

| Rate | Meaning | Action |
|------|---------|--------|
| ≥ 95% | Excellent | Publication-ready |
| 85-95% | Good | Minor improvements suggested |
| 70-85% | Acceptable | Requires investigation |
| < 70% | Problematic | Redesign needed |

**P-Value Interpretation:**

- **p-value ≥ 0.01** (α = 0.01): Pass (random sequence)
- **p-value < 0.01**: Fail (likely non-random)

### Entropy Results

**Shannon Entropy (bits/byte):**

| Value | Assessment |
|-------|-----------|
| > 7.99 | Excellent (near-ideal) |
| 7.95-7.99 | Very Good |
| 7.90-7.95 | Good |
| 7.80-7.90 | Acceptable |
| < 7.80 | Poor (needs improvement) |

**Formula:** H(X) = -Σ p(x) * log₂(p(x))

Ideal: H(X) = 8.0 bits/byte (perfect uniformity)

### Avalanche Effect

**Ideal Mean Avalanche: 0.5** (50% of bits change per input bit change)

| Range | Assessment |
|-------|-----------|
| 0.48-0.52 | Excellent |
| 0.45-0.55 | Very Good |
| 0.40-0.60 | Acceptable |
| < 0.40 or > 0.60 | Poor |

### Chi-Square Tests

**Critical Values (p = 0.05):**

| df | Critical | Interpretation |
|----|----------|-----------------|
| χ² < 3.841 | Pass | Good fit |
| χ² 3.841-7.815 | Marginal | Acceptable |
| χ² > 7.815 | Fail | Poor fit |

---

## 📝 PUBLICATION WORKFLOW

### 1. Comprehensive Evaluation

```bash
# Run thorough evaluation
python quick_eval.py --thorough

# Expected time: 30-60 minutes
# Generates publication-quality results
```

### 2. External Validation

```bash
# Run NIST STS (official reference)
./nist-sts/assess 1000000 < evaluation_results/gcrc_*.bin

# Run PractRand (practical testing)
./RNG_test stdin64 < evaluation_results/gcrc_*.bin

# Run Dieharder (comprehensive battery)
dieharder -a -g 201 -f evaluation_results/gcrc_*.bin
```

### 3. Generate Publication Figures

```python
# Generate comparative charts
from academic_report_gen import AcademicReportGenerator
import json

# Load results
with open('evaluation_results/complete_evaluation_results_*.json') as f:
    results = json.load(f)

# Generate report with visualizations
gen = AcademicReportGenerator()
gen.generate_html_report(results)
export_to_markdown(results)
```

### 4. Write Academic Paper

**Template Structure:**

```markdown
# Title: GCRC: DNA-Based Cryptographic Cipher with Proven Randomness

## Abstract
Summarize: design, evaluation, key results, implications

## 1. Introduction
- Background on cryptography
- DNA computing applications
- Motivation for GCRC

## 2. Related Work
- Existing DNA-based ciphers
- Traditional cipher standards

## 3. GCRC Design
- Cipher architecture
- Layer descriptions
- Key schedule

## 4. Methodology
- NIST SP 800-22 tests
- Entropy analysis
- Differential cryptanalysis
- Comparison methodology

## 5. Results
- Statistical test results (tables)
- Entropy measurements
- Avalanche effect
- Performance comparisons
- External tool validation

## 6. Discussion
- Interpretation of results
- Comparison with standards
- Strengths and weaknesses
- Security implications

## 7. Conclusion
- Summary of findings
- Future work
- Impact on the field

## References
- NIST SP 800-22
- AES specification
- Published cipher analyses
```

### 5. Submission Venues

**Top-Tier Journals:**
- IEEE Transactions on Information Theory
- Journal of Cryptology
- ACM Transactions on Cybersecurity

**Conference Proceedings:**
- Eurocrypt / Asiacrypt
- IACR CCS (ACM Conference on Computer and Communications Security)
- ISIT (IEEE International Symposium on Information Theory)

---

## 🐛 TROUBLESHOOTING

### Common Issues

#### 1. Import Errors

```
ModuleNotFoundError: No module named 'Crypto'
```

**Solution:**
```bash
pip install pycryptodome
```

#### 2. Insufficient Data for NIST Tests

```
Error: Sequence too short for test
```

**Solution:** Increase `--nist-samples` parameter:
```bash
python quick_eval.py --nist-samples 500000
```

#### 3. Memory Issues with Large Datasets

```
MemoryError: Unable to allocate...
```

**Solution:** Reduce sample size or run on machine with more RAM:
```bash
python quick_eval.py --fast  # Uses fewer samples
```

#### 4. GCRC Cipher Errors

```
Error: Failed to encrypt plaintext
```

**Solution:** Check cipher initialization:
```python
from cipher.gcrc_cipher import GCRC
cipher = GCRC('valid-32-char-key-string-here')
result = cipher.encrypt('ATCGATCG...')  # Requires DNA sequence
```

#### 5. Report Generation Issues

```
Error: Cannot generate HTML report
```

**Solution:** Install visualization dependencies:
```bash
pip install matplotlib plotly pandas
```

### Debug Mode

```python
# Enable detailed logging
import logging
logging.basicConfig(level=logging.DEBUG)

from academic_evaluation import AcademicCryptoEvaluator
evaluator = AcademicCryptoEvaluator()
# Pipeline will print detailed debug information
```

---

## 📚 REFERENCES

### NIST Standards
- [NIST SP 800-22 Rev. 1a](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf)
- [NIST SP 800-90B Entropy Estimation](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90B.pdf)

### Cipher Standards
- [AES (Rijndael)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [Triple DES](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-67r2.pdf)

### External Tools
- [NIST STS](https://csrc.nist.gov/projects/random-bit-generation/)
- [PractRand](http://pracrand.sourceforge.net/)
- [Dieharder](https://webhome.phy.duke.edu/~rgb/General/dieharder.php)

### Academic Resources
- Shannon, C. (1949). \"Communication Theory of Secrecy Systems\"
- FIPS 140-2 Validation Program
- Common Cryptographic Testing Standards

---

## 📞 SUPPORT

For issues or questions:

1. Check this guide's troubleshooting section
2. Review pipeline output for error messages
3. Consult NIST documentation
4. Review publication-ready report files

---

**Document Version:** 1.0  
**Last Updated:** 2026-05-13  
**Status:** Production Ready ✓

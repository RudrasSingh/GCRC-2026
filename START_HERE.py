"""
START HERE - DNA-GCRC EVALUATION PIPELINE
Complete Academic Cryptographic Testing Suite
"""

# ╔════════════════════════════════════════════════════════════════════════╗
# ║                                                                        ║
# ║           YOU NOW HAVE A COMPLETE ACADEMIC EVALUATION SUITE           ║
# ║                                                                        ║
# ║  Test your DNA encryption cipher against AES-256, AES-128, 3DES       ║
# ║  Generate publication-ready charts and metrics                        ║
# ║  Rigorous statistical analysis following NIST standards               ║
# ║                                                                        ║
# ╚════════════════════════════════════════════════════════════════════════╝


# ════════════════════════════════════════════════════════════════════════
# STEP 1: VERIFY YOUR SETUP (5 minutes)
# ════════════════════════════════════════════════════════════════════════

# From command line:
#
#   cd dna_gcrc_project
#   python run_evaluation.py --quick

# What this does:
#   ✓ Tests with 1000 samples & 500 tests
#   ✓ Compares DNA-GCRC vs AES-256 vs AES-128 vs 3DES vs XOR
#   ✓ Generates summary report
#   ✓ Takes ~5-10 minutes
#
# Expected output:
#   evaluation_results/
#   ├── comparison_TIMESTAMP.txt      ← Text report (read this)
#   ├── comparison_TIMESTAMP.json     ← Raw data
#   └── test_data.json


# ════════════════════════════════════════════════════════════════════════
# STEP 2: UNDERSTAND YOUR RESULTS (5 minutes)
# ════════════════════════════════════════════════════════════════════════

# Open: evaluation_results/comparison_TIMESTAMP.txt
#
# Key sections to read:
#
# 1. ENTROPY ANALYSIS
#    Your cipher -> Byte Entropy: X.XXXX/8.0
#    Target: ≥7.99
#    ✓ 7.99+ = Excellent
#    ✓ 7.90-7.99 = Very Good
#    ✓ 7.50-7.90 = Good
#    ✗ <7.50 = Poor
#
# 2. AVALANCHE EFFECT
#    Your cipher -> Mean Avalanche: XX.XX% (±X.XX%)
#    Target: 50% ± 5% (i.e., 45-55%)
#    ✓ 48-52% = PASS
#    ✓ 45-55% = Acceptable
#    ✗ <45% or >55% = FAIL
#
# 3. KEY SENSITIVITY
#    Your cipher -> Mean Sensitivity: XX.XX%
#    Target: 50% ± 5%
#    ✓ Same as avalanche logic
#
# 4. BYTE DISTRIBUTION
#    Status: PASS or FAIL
#    ✓ PASS = uniform distribution (all 256 bytes equally likely)
#    ✗ FAIL = biased distribution
#
# 5. COMPARATIVE SCORES
#    DNA-GCRC: XX/100
#    AES-256:  XX/100
#    AES-128:  XX/100
#    3DES:     XX/100
#
# 6. Quality Rankings (at bottom)
#    1. [Best cipher] XX/100
#    2. [Second]      XX/100
#    3. [Your cipher] XX/100
#    etc.


# ════════════════════════════════════════════════════════════════════════
# STEP 3: RUN FULL EVALUATION (30-60 minutes)
# ════════════════════════════════════════════════════════════════════════

# When you're ready for publication-quality results:
#
#   python run_evaluation.py --full
#
# What this does:
#   ✓ 10,000 samples (vs 1000 in quick mode)
#   ✓ 5,000 tests per metric (vs 500)
#   ✓ Generates 6 publication-ready PNG charts
#   ✓ Comprehensive text report
#   ✓ JSON data for integration
#   ✓ Takes 30-60 minutes (depends on cipher speed)
#
# Generated charts:
#   ✓ entropy_comparison.png              (8.0 scale)
#   ✓ avalanche_comparison.png            (50% target)
#   ✓ key_sensitivity_comparison.png      (50% target)
#   ✓ performance_comparison.png          (speed/throughput)
#   ✓ metrics_heatmap.png                 (all metrics 0-1)
#   ✓ quality_scorecards.png              (gauge charts 0-100)


# ════════════════════════════════════════════════════════════════════════
# STEP 4: USE RESULTS IN YOUR PAPER (10 minutes)
# ════════════════════════════════════════════════════════════════════════

# 1. Include PNG charts in paper appendix
#    → Copy *.png files to your figures/ directory
#    → Reference in paper: "See Figure A.1 for entropy comparison"
#
# 2. Add metrics table to results section
#    Example:
#
#    Table 1. Cryptographic Evaluation Results
#    ╔═══════════╦═════════════╦══════════════╦═══════════════╗
#    ║ Cipher    ║ Entropy     ║ Avalanche    ║ Distribution  ║
#    ╠═══════════╬═════════════╬══════════════╬═══════════════╣
#    ║ DNA-GCRC  ║ 7.9824/8.0  ║ 50.1% ±2.3%  ║ PASS (χ²=287) ║
#    ║ AES-256   ║ 8.0000/8.0  ║ 50.0% ±0.1%  ║ PASS (χ²=289) ║
#    ║ AES-128   ║ 8.0000/8.0  ║ 50.0% ±0.1%  ║ PASS (χ²=291) ║
#    ║ 3DES      ║ 7.9912/8.0  ║ 49.8% ±0.3%  ║ PASS (χ²=292) ║
#    ╚═══════════╩═════════════╩══════════════╩═══════════════╝
#
# 3. Reference in methodology section
#    "Statistical evaluation was performed following NIST SP 800-22
#     recommendations using 10,000 samples with 5,000 trials per metric.
#     Key metrics included entropy analysis, avalanche effect testing,
#     key sensitivity analysis, byte distribution uniformity, and
#     differential cryptanalysis."
#
# 4. Attach raw data as supplementary material
#    → comparison_TIMESTAMP.json (numerical data)
#    → test_data.json (reproducible testing)


# ════════════════════════════════════════════════════════════════════════
# STEP 5: TROUBLESHOOT ANY ISSUES (varies)
# ════════════════════════════════════════════════════════════════════════

# PROBLEM: Low entropy (< 7.5/8.0)
# CAUSE: Weak key expansion or insufficient mixing
# SOLUTION:
#   1. Check config/key_schedule.py - increase key derivation strength
#   2. Check cipher/layers/ - ensure all layers properly mix bits
#   3. Run test: encryption output should look truly random
#
# PROBLEM: Poor avalanche (< 45% or > 55%)
# CAUSE: Incomplete diffusion (1 bit change doesn't propagate)
# SOLUTION:
#   1. Increase mixing in holliday layer (layer3_holliday.py)
#   2. Check supercoil transform (layer4_supercoil.py)
#   3. Verify all 256+ bits of plaintext properly affect output
#
# PROBLEM: High autocorrelation (> 0.1)
# CAUSE: Sequential patterns in output
# SOLUTION:
#   1. Check LFSR implementation (utils/lfsr.py)
#   2. Verify key stream generation is truly random
#   3. Review polymerase layer (layer6_polymerase.py)
#
# PROBLEM: Chi-square fails (> 293.2)
# CAUSE: Non-uniform byte distribution
# SOLUTION:
#   1. Add more randomness to key mixing
#   2. Check for byte value patterns
#   3. Increase number of cipher rounds


# ════════════════════════════════════════════════════════════════════════
# ADVANCED: CUSTOM PARAMETERS
# ════════════════════════════════════════════════════════════════════════

# Test with custom settings:
#
#   python run_evaluation.py --samples 5000 --tests 2000 --output custom_results/
#
# Parameters:
#   --samples N        Number of encryption samples (default 1000)
#   --tests N          Number of tests per metric (default 500)
#   --output DIR       Output directory (default evaluation_results/)
#   --no-visualize     Skip chart generation (faster)
#   --no-save          Don't save results
#   --benchmark-only   Only test performance, skip stats
#   --stats-only       Only test statistics, skip performance
#
# Presets:
#   --quick            1000 samples, 500 tests (5 min)
#   --full             10000 samples, 5000 tests (1 hour)


# ════════════════════════════════════════════════════════════════════════
# ADVANCED: PROGRAMMATIC USE
# ════════════════════════════════════════════════════════════════════════

# Example 1: Evaluate just your cipher
#
# from evaluation_suite import CryptoEvaluator
# from compare_ciphers import ComparativeBenchmark
#
# evaluator = CryptoEvaluator("my_results")
# results = evaluator.evaluate_cipher(
#     "DNA-GCRC",
#     ComparativeBenchmark.dna_gcrc_encrypt,
#     num_samples=5000,
#     num_tests=2500
# )
# print(f"Entropy: {results['entropy']['byte_entropy']:.4f}")
# evaluator.save_results()

#
# Example 2: Generate charts from existing data
#
# import json
# from visualize_results import CryptoVisualizer
#
# with open("evaluation_results/comparison_*.json") as f:
#     results = json.load(f)
#
# visualizer = CryptoVisualizer("charts_only")
# visualizer.generate_all_plots(results)

#
# See examples.py for 10 more copy-paste examples


# ════════════════════════════════════════════════════════════════════════
# WHAT EACH FILE DOES
# ════════════════════════════════════════════════════════════════════════

# run_evaluation.py           → Master script (START HERE)
#                              Run this to execute full pipeline
#
# evaluation_suite.py         → Core statistical tests
#                              Entropy, avalanche, sensitivity, etc.
#
# compare_ciphers.py          → Benchmark suite
#                              Tests DNA-GCRC vs AES, DES, etc.
#
# visualize_results.py        → Chart generation
#                              Creates publication-ready plots
#
# examples.py                 → 10 copy-paste examples
#                              Quick recipes for common tasks
#
# EVALUATION_GUIDE.md         → Detailed metrics explanation
#                              Complete reference for all metrics
#
# README_EVALUATION.md        → Quick reference guide
#                              Overview and troubleshooting
#
# This file (START_HERE.py)   → You are here


# ════════════════════════════════════════════════════════════════════════
# METRIC TARGETS AT A GLANCE
# ════════════════════════════════════════════════════════════════════════

"""
METRIC              GOOD         EXCELLENT    REFERENCE
──────────────────────────────────────────────────────────
Byte Entropy        ≥7.90        ≥7.99        AES: 8.0
Bit Entropy         ≥0.99        ≥0.999       Random: 1.0
Avalanche           45-55%       48-52%       Target: 50%
Key Sensitivity     45-55%       48-52%       Target: 50%
Byte Distribution   PASS         χ²<280       Chi-square test
Autocorrelation     <0.1         <0.05        Near-zero
Differential        Near 50%     Within 1%    Expected: 50%
Run Length Max      <20          <10          No long runs

OVERALL SCORE (out of 100)
──────────────────────────
80-100: Excellent (publishable)
60-79:  Very Good (notable)
40-59:  Good (improvements recommended)
<40:    Poor (fundamental issues)
"""


# ════════════════════════════════════════════════════════════════════════
# TIMELINE
# ════════════════════════════════════════════════════════════════════════

"""
QUICK WORKFLOW (1 hour)
  5 min:   python run_evaluation.py --quick
  5 min:   Read report
  30 min:  Review results & troubleshoot
  20 min:  Plan improvements

FULL WORKFLOW (2 hours)
  60 min:  python run_evaluation.py --full
  20 min:  Review results
  20 min:  Generate LaTeX tables
  20 min:  Prepare for paper submission

PUBLICATION WORKFLOW (1 day)
  2 hours: Run full evaluation
  2 hours: Troubleshoot & optimize
  2 hours: Run final evaluation
  4 hours: Integrate into paper
  2 hours: Prepare supplementary materials
"""


# ════════════════════════════════════════════════════════════════════════
# DEPENDENCIES (one-time setup)
# ════════════════════════════════════════════════════════════════════════

# Required packages:
#   pip install cryptography matplotlib seaborn numpy
#
# Already in project:
#   Your DNA cipher implementation
#   Your config & utils
#
# Verify installation:
#   python -c "from evaluation_suite import CryptoEvaluator; print('OK')"


# ════════════════════════════════════════════════════════════════════════
# RECOMMENDED NEXT STEP
# ════════════════════════════════════════════════════════════════════════

"""
1. Open terminal in dna_gcrc_project/
2. Run: python run_evaluation.py --quick
3. Wait 5-10 minutes
4. Open: evaluation_results/comparison_*.txt
5. Read the report and check your scores
6. If happy with results, run: python run_evaluation.py --full
7. Use generated PNG charts in your paper
8. Include JSON data in supplementary materials

You're done! Your evaluation is publication-ready.
"""


# ════════════════════════════════════════════════════════════════════════
# QUALITY ASSURANCE CHECKLIST
# ════════════════════════════════════════════════════════════════════════

"""
Before publication, verify:

□ Entropy ≥ 7.95 (MUST be this high)
□ Avalanche 48-52% (MUST be in this range)
□ Key Sensitivity 48-52% (MUST be in this range)  
□ Byte Distribution passes χ² test (MUST pass)
□ All PNG charts generated (MUST exist)
□ Text report generated (MUST be readable)
□ JSON data generated (FOR reproducibility)
□ Scores comparable to AES/DES (FOR credibility)

If any MUST items fail:
  → Review cipher implementation
  → Check EVALUATION_GUIDE.md for troubleshooting
  → Optimize problematic layer
  → Re-run evaluation
  → Verify improvement
"""


if __name__ == "__main__":
    print(__doc__)
    print("\n" + "="*78)
    print("READY TO START?")
    print("="*78)
    print("\nFrom command line, run:\n")
    print("    python run_evaluation.py --quick")
    print("\n✓ This will test your DNA-GCRC cipher\n")
    print("In 5-10 minutes, check:\n")
    print("    evaluation_results/comparison_*.txt")
    print("\n" + "="*78 + "\n")

"""
QUICK START EXAMPLES
Copy-paste ready examples to get started immediately
"""

# =============================================================================
# EXAMPLE 1: QUICK BENCHMARK (5-10 minutes)
# =============================================================================

"""
Description: Fast test to verify your setup works

Run from command line:
    python run_evaluation.py --quick --output quick_test/

Or in Python:
"""

def example_quick_test():
    from compare_ciphers import ComparativeBenchmark
    
    # Create benchmark
    benchmark = ComparativeBenchmark("quick_test_results")
    
    # Quick performance test (1000 trials)
    print("Testing performance...")
    performance = benchmark.benchmark_performance(num_trials=1000)
    
    # Quick statistical test (1000 samples, 500 tests)
    print("Testing statistics...")
    results = benchmark.statistical_comparison(
        num_samples=1000,
        num_tests=500
    )
    
    # Generate report
    print("\nReport:")
    print(benchmark.generate_comparison_report())
    
    # Save
    benchmark.save_comparison_results()


# =============================================================================
# EXAMPLE 2: EVALUATE YOUR CIPHER ONLY (10 minutes)
# =============================================================================

"""
Description: Run detailed evaluation on just your DNA-GCRC cipher

Run:
    python
"""

def example_evaluate_own_cipher():
    from evaluation_suite import CryptoEvaluator
    from compare_ciphers import ComparativeBenchmark
    
    evaluator = CryptoEvaluator("dna_gcrc_test")
    
    # Define encrypt function
    def dna_encrypt(plaintext, key):
        from compare_ciphers import ComparativeBenchmark
        return ComparativeBenchmark.dna_gcrc_encrypt(plaintext, key)
    
    # Evaluate with 2000 samples, 1000 tests
    results = evaluator.evaluate_cipher(
        "DNA-GCRC",
        dna_encrypt,
        num_samples=2000,
        num_tests=1000
    )
    
    # Print summary
    print("\n" + "="*70)
    print("DNA-GCRC EVALUATION SUMMARY")
    print("="*70)
    print(f"Entropy:         {results['entropy']['byte_entropy']:.4f}/8.0")
    print(f"Avalanche:       {results['avalanche']['mean_avalanche']:.2f}% "
          f"(±{results['avalanche']['std_avalanche']:.2f}%)")
    print(f"Key Sensitivity: {results['key_sensitivity']['mean_sensitivity']:.2f}%")
    print(f"Byte Dist PASS:  {results['byte_distribution']['pass_uniformity']}")
    print(f"Autocorr:        {results['autocorrelation']['mean_abs_autocorrelation']:.6f}")
    
    # Save
    evaluator.save_results("dna_gcrc_detailed.json")


# =============================================================================
# EXAMPLE 3: FULL COMPARISON (30-60 minutes)
# =============================================================================

"""
Description: Complete evaluation with all ciphers and visualizations

Run:
    python run_evaluation.py --full

This generates:
    - 6 publication-ready PNG charts
    - Detailed text report
    - JSON data for further analysis
"""

def example_full_comparison():
    from compare_ciphers import ComparativeBenchmark
    from visualize_results import CryptoVisualizer
    
    benchmark = ComparativeBenchmark("full_evaluation")
    
    # Performance test
    print("Phase 1: Performance benchmarking...")
    performance = benchmark.benchmark_performance(num_trials=1000)
    
    # Statistical test (this takes a while)
    print("Phase 2: Statistical evaluation (10,000 samples, 5,000 tests)...")
    results = benchmark.statistical_comparison(
        num_samples=10000,
        num_tests=5000
    )
    
    # Generate visualizations
    print("Phase 3: Generating visualizations...")
    visualizer = CryptoVisualizer("full_evaluation")
    visualizer.generate_all_plots(results, performance)
    
    # Save everything
    print("Phase 4: Saving results...")
    benchmark.save_comparison_results()
    
    # Print report
    print("\n" + benchmark.generate_comparison_report())


# =============================================================================
# EXAMPLE 4: CUSTOM CIPHER COMPARISON
# =============================================================================

"""
Description: Compare your own custom implementation against standards
"""

def example_custom_cipher():
    from evaluation_suite import CryptoEvaluator
    
    # Define your custom cipher
    def my_custom_cipher(plaintext, key):
        # Your cipher implementation here
        import os
        return os.urandom(len(plaintext))  # Placeholder
    
    evaluator = CryptoEvaluator("custom_results")
    
    results = evaluator.evaluate_cipher(
        "My Custom Cipher",
        my_custom_cipher,
        num_samples=5000,
        num_tests=2500
    )
    
    # Get scores
    ent = results['entropy']
    aval = results['avalanche']
    
    print(f"Entropy Score: {ent['byte_entropy']:.4f} "
          f"(Target: >7.99)")
    print(f"Avalanche Score: {aval['mean_avalanche']:.2f}% "
          f"(Target: 50 ± 5)")
    
    evaluator.save_results()


# =============================================================================
# EXAMPLE 5: JUST VISUALIZATIONS FROM EXISTING RESULTS
# =============================================================================

"""
Description: Generate charts from already-saved JSON results
"""

def example_visualize_existing():
    import json
    from visualize_results import CryptoVisualizer
    
    # Load existing results
    with open("evaluation_results/comparison_20260515_120000.json") as f:
        results = json.load(f)
    
    # Generate charts
    visualizer = CryptoVisualizer("charts_output")
    visualizer.generate_all_plots(results)
    
    print("Charts saved to charts_output/")


# =============================================================================
# EXAMPLE 6: PROGRAMMATIC ANALYSIS
# =============================================================================

"""
Description: Extract and analyze specific metrics programmatically
"""

def example_data_analysis():
    import json
    
    # Load results
    with open("evaluation_results/comparison_*.json") as f:
        data = json.load(f)
    
    # Extract all entropies
    entropies = {
        cipher: data[cipher]['entropy']['byte_entropy']
        for cipher in data.keys()
        if 'entropy' in data[cipher]
    }
    
    # Find best/worst
    best = max(entropies.items(), key=lambda x: x[1])
    worst = min(entropies.items(), key=lambda x: x[1])
    
    print(f"Best entropy:  {best[0]} = {best[1]:.4f}")
    print(f"Worst entropy: {worst[0]} = {worst[1]:.4f}")
    
    # Average
    avg_entropy = sum(entropies.values()) / len(entropies)
    print(f"Average:       {avg_entropy:.4f}")


# =============================================================================
# EXAMPLE 7: BENCHMARK TABLE GENERATION
# =============================================================================

"""
Description: Create LaTeX table for academic papers
"""

def example_latex_table():
    import json
    
    with open("evaluation_results/comparison_*.json") as f:
        data = json.load(f)
    
    print("\\begin{table}[h]")
    print("\\centering")
    print("\\begin{tabular}{|c|c|c|c|c|}")
    print("\\hline")
    print("Cipher & Entropy & Avalanche & Key Sens & Dist \\\\")
    print("\\hline")
    
    for cipher in sorted(data.keys()):
        if 'error' in data[cipher]:
            continue
        
        r = data[cipher]
        ent = r['entropy']['byte_entropy']
        aval = r['avalanche']['mean_avalanche']
        ks = r['key_sensitivity']['mean_sensitivity']
        dist = "✓" if r['byte_distribution']['pass_uniformity'] else "✗"
        
        print(f"{cipher} & {ent:.4f} & {aval:.2f}\\% & {ks:.2f}\\% & {dist} \\\\")
    
    print("\\hline")
    print("\\end{tabular}")
    print("\\caption{Cryptographic Evaluation Results}")
    print("\\label{tab:crypto-eval}")
    print("\\end{table}")


# =============================================================================
# EXAMPLE 8: SEQUENTIAL DETAILED EVALUATION
# =============================================================================

"""
Description: Step-by-step evaluation with intermediate output
"""

def example_step_by_step():
    from evaluation_suite import CryptoEvaluator
    from compare_ciphers import ComparativeBenchmark
    import os
    
    output_dir = "step_by_step_results"
    os.makedirs(output_dir, exist_ok=True)
    
    evaluator = CryptoEvaluator(output_dir)
    
    # Step 1: Generate data
    print("[Step 1/7] Generating test data...")
    plaintexts, keys = evaluator.generate_test_dataset(num_samples=1000)
    
    # Step 2: Encrypt all
    print("[Step 2/7] Encrypting samples...")
    ciphertexts = []
    for pt, key in zip(plaintexts, keys):
        ct = ComparativeBenchmark.dna_gcrc_encrypt(pt, key)
        ciphertexts.append(ct)
    
    # Step 3: Entropy
    print("[Step 3/7] Calculating entropy...")
    ent_results = evaluator.entropy_analysis(ciphertexts)
    print(f"  ✓ Byte entropy: {ent_results['byte_entropy']:.4f}")
    
    # Step 4: Avalanche
    print("[Step 4/7] Testing avalanche effect...")
    aval_results = evaluator.avalanche_analysis(
        ComparativeBenchmark.dna_gcrc_encrypt, num_tests=500)
    print(f"  ✓ Mean avalanche: {aval_results['mean_avalanche']:.2f}%")
    
    # Step 5: Key sensitivity
    print("[Step 5/7] Testing key sensitivity...")
    ks_results = evaluator.key_sensitivity_analysis(
        ComparativeBenchmark.dna_gcrc_encrypt, num_tests=500)
    print(f"  ✓ Mean sensitivity: {ks_results['mean_sensitivity']:.2f}%")
    
    # Step 6: Distribution
    print("[Step 6/7] Testing byte distribution...")
    dist_results = evaluator.byte_distribution_test(ciphertexts)
    print(f"  ✓ Chi-square: {dist_results['chi_square_statistic']:.2f}")
    print(f"  ✓ PASS: {dist_results['pass_uniformity']}")
    
    # Step 7: Summary
    print("[Step 7/7] Generating summary...")
    print("\n" + "="*60)
    print("EVALUATION SUMMARY")
    print("="*60)
    print(f"Entropy:         {ent_results['byte_entropy']:.4f}/8.0")
    print(f"Avalanche:       {aval_results['mean_avalanche']:.2f}%")
    print(f"Key Sensitivity: {ks_results['mean_sensitivity']:.2f}%")
    print(f"Distribution:    {'PASS' if dist_results['pass_uniformity'] else 'FAIL'}")


# =============================================================================
# EXAMPLE 9: STRESS TEST
# =============================================================================

"""
Description: Maximum evaluation for conference submission
"""

def example_maximum_evaluation():
    from compare_ciphers import ComparativeBenchmark
    from visualize_results import CryptoVisualizer
    
    benchmark = ComparativeBenchmark("maximum_evaluation")
    
    # Maximum samples for most rigorous evaluation
    print("Running MAXIMUM evaluation...")
    print("(This will take 2-4 hours)")
    
    # Performance: 5000 trials
    performance = benchmark.benchmark_performance(num_trials=5000)
    
    # Statistics: 50000 samples, 10000 tests
    results = benchmark.statistical_comparison(
        num_samples=50000,
        num_tests=10000
    )
    
    # All visualizations
    visualizer = CryptoVisualizer("maximum_evaluation")
    visualizer.generate_all_plots(results, performance)
    
    # Save
    benchmark.save_comparison_results()
    
    print("\n✓ Maximum evaluation complete")
    print("  Results suitable for: IEEE, ACM, top-tier venues")


# =============================================================================
# EXAMPLE 10: REPRODUCIBLE RESEARCH
# =============================================================================

"""
Description: Save all setup for reproducibility
"""

def example_reproducible_research():
    import json
    from datetime import datetime
    
    # Save metadata
    metadata = {
        "timestamp": datetime.now().isoformat(),
        "python_version": "3.11.0",  # Check: python --version
        "evaluation_framework": "DNA-GCRC-Academic-Pipeline",
        "tests_performed": [
            "NIST-style entropy analysis",
            "Avalanche effect testing",
            "Key sensitivity analysis",
            "Byte distribution uniformity",
            "Autocorrelation analysis",
            "Differential analysis",
            "Performance benchmarking"
        ],
        "parameters": {
            "plaintext_size": 32,  # bytes
            "key_size": 32,  # bytes
            "num_samples": 10000,
            "num_tests": 5000,
            "random_seed": "os.urandom()"
        },
        "hardware": {
            "cpu": "[Your CPU model]",
            "memory": "[Your RAM]",
            "notes": "Fill in your hardware info"
        }
    }
    
    # Save
    with open("evaluation_results/metadata.json", 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print("Metadata saved for reproducibility")
    print("Include this in paper's supplementary materials")


# =============================================================================
# EXAMPLE USAGE
# =============================================================================

if __name__ == "__main__":
    import sys
    
    print("""
╔════════════════════════════════════════════════════════════════╗
║     DNA-GCRC EVALUATION PIPELINE - QUICK START EXAMPLES        ║
╚════════════════════════════════════════════════════════════════╝

Choose an example to run:

    1. example_quick_test()           → 5-10 min test
    2. example_evaluate_own_cipher()  → Detailed DNA-GCRC eval
    3. example_full_comparison()      → Full comparison (1 hour)
    4. example_custom_cipher()        → Test your own cipher
    5. example_visualize_existing()   → Charts only
    6. example_data_analysis()        → Extract metrics
    7. example_latex_table()          → Academic table
    8. example_step_by_step()         → Detailed walkthrough
    9. example_maximum_evaluation()   → Conference-grade (2-4h)
   10. example_reproducible_research()→ Add metadata

QUICK START:
    python
    >>> from examples import example_quick_test
    >>> example_quick_test()

OR from command line:
    python run_evaluation.py --quick
    """)
    
    if len(sys.argv) > 1:
        example_num = int(sys.argv[1])
        examples = [
            None,
            example_quick_test,
            example_evaluate_own_cipher,
            example_full_comparison,
            example_custom_cipher,
            example_visualize_existing,
            example_data_analysis,
            example_latex_table,
            example_step_by_step,
            example_maximum_evaluation,
            example_reproducible_research,
        ]
        
        if 1 <= example_num <= len(examples) - 1:
            print(f"\nRunning Example {example_num}...\n")
            examples[example_num]()
        else:
            print(f"Invalid example number: {example_num}")

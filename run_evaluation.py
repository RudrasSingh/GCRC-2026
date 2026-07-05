"""
MASTER EVALUATION ORCHESTRATOR
Run complete cryptographic evaluation pipeline
"""

import os
import json
import argparse
from datetime import datetime

from evaluation_suite import CryptoEvaluator
from compare_ciphers import ComparativeBenchmark
from visualize_results import CryptoVisualizer


def main():
    parser = argparse.ArgumentParser(
        description='Complete Cryptographic Evaluation Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:

  # Full evaluation (slow, thorough)
  python run_evaluation.py --full

  # Quick evaluation (fewer samples/tests)
  python run_evaluation.py --quick

  # Performance benchmark only
  python run_evaluation.py --benchmark-only

  # Statistical evaluation only
  python run_evaluation.py --stats-only --samples 1000

  # Custom parameters
  python run_evaluation.py --samples 5000 --tests 2000 --output results/
        """
    )
    
    parser.add_argument('--full', action='store_true',
                       help='Full evaluation (10000 samples, 5000 tests)')
    parser.add_argument('--quick', action='store_true',
                       help='Quick evaluation (1000 samples, 500 tests)')
    parser.add_argument('--samples', type=int, default=1000,
                       help='Number of test samples (default: 1000)')
    parser.add_argument('--tests', type=int, default=500,
                       help='Number of statistical tests (default: 500)')
    parser.add_argument('--output', type=str, default='evaluation_results',
                       help='Output directory (default: evaluation_results)')
    parser.add_argument('--benchmark-only', action='store_true',
                       help='Only run performance benchmarks')
    parser.add_argument('--stats-only', action='store_true',
                       help='Only run statistical evaluation')
    parser.add_argument('--no-visualize', action='store_true',
                       help='Skip visualization generation')
    parser.add_argument('--no-save', action='store_true',
                       help='Do not save results')
    
    args = parser.parse_args()
    
    # Override sample/test counts based on presets
    if args.full:
        args.samples = 10000
        args.tests = 5000
        print("\n[*] Full evaluation mode: 10000 samples, 5000 tests")
    elif args.quick:
        args.samples = 1000
        args.tests = 500
        print("\n[*] Quick evaluation mode: 1000 samples, 500 tests")
    
    print(f"""
{'='*80}
CRYPTOGRAPHIC EVALUATION PIPELINE
DNA-GCRC Cipher vs AES-256, AES-128, 3DES
{'='*80}

Configuration:
  Samples:           {args.samples}
  Tests per cipher:  {args.tests}
  Output Directory:  {args.output}
  
  Benchmark Only:    {args.benchmark_only}
  Stats Only:        {args.stats_only}
  Visualizations:    {not args.no_visualize}
  Save Results:      {not args.no_save}
""")
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    
    # Initialize benchmark suite
    benchmark = ComparativeBenchmark(args.output)
    
    # ====================================================================
    # PERFORMANCE BENCHMARKING
    # ====================================================================
    
    if not args.stats_only:
        print(f"\n{'='*80}")
        print("PHASE 1: PERFORMANCE BENCHMARKING")
        print(f"{'='*80}\n")
        
        try:
            performance = benchmark.benchmark_performance(num_trials=1000)
            print("\n[+] Performance benchmarking completed")
        except Exception as e:
            print(f"\n[!] Performance benchmarking failed: {e}")
            performance = {}
    else:
        performance = {}
    
    if args.benchmark_only:
        print(f"\n[+] Benchmark-only mode. Skipping statistical evaluation.")
        if not args.no_save:
            benchmark.save_comparison_results()
        return
    
    # ====================================================================
    # STATISTICAL EVALUATION
    # ====================================================================
    
    if not args.benchmark_only:
        print(f"\n{'='*80}")
        print("PHASE 2: STATISTICAL EVALUATION")
        print(f"{'='*80}\n")
        
        print(f"Testing {args.samples} samples with {args.tests} trials per metric...\n")
        
        try:
            results = benchmark.statistical_comparison(
                num_samples=args.samples,
                num_tests=args.tests
            )
            print("\n[+] Statistical evaluation completed")
        except Exception as e:
            print(f"\n[!] Statistical evaluation failed: {e}")
            results = {}
    
    # ====================================================================
    # VISUALIZATION
    # ====================================================================
    
    if not args.no_visualize and not args.benchmark_only:
        print(f"\n{'='*80}")
        print("PHASE 3: GENERATING VISUALIZATIONS")
        print(f"{'='*80}\n")
        
        try:
            visualizer = CryptoVisualizer(args.output)
            visualizer.generate_all_plots(results, performance if not args.stats_only else {})
            print("\n[+] Visualization generation completed")
        except Exception as e:
            print(f"\n[!] Visualization generation failed: {e}")
    
    # ====================================================================
    # REPORTING
    # ====================================================================
    
    print(f"\n{'='*80}")
    print("PHASE 4: REPORT GENERATION")
    print(f"{'='*80}\n")
    
    if not args.no_save:
        try:
            benchmark.save_comparison_results()
            print("\n[+] Results and reports saved")
        except Exception as e:
            print(f"\n[!] Save failed: {e}")
    
    # ====================================================================
    # SUMMARY
    # ====================================================================
    
    print(f"\n{'='*80}")
    print("EVALUATION COMPLETE")
    print(f"{'='*80}\n")
    
    print(f"Output Directory: {os.path.abspath(args.output)}\n")
    
    print("Generated Files:")
    for filename in sorted(os.listdir(args.output)):
        if filename.startswith('.'):
            continue
        filepath = os.path.join(args.output, filename)
        size = os.path.getsize(filepath)
        size_str = f"{size/1024:.1f}KB" if size > 1024 else f"{size}B"
        print(f"  ✓ {filename:<40} ({size_str})")
    
    print(f"\n{'='*80}")
    print("NEXT STEPS:")
    print(f"{'='*80}")
    print("""
1. Review the comparison_*.txt report for detailed analysis
2. View PNG charts for visual presentation
3. Use comparison_*.json for data analysis or integration with other tools
4. Include PNG charts in academic papers
5. Reference metrics in cipher security claims

For academic papers, include:
  - Entropy histogram (entropy_comparison.png)
  - Avalanche effect chart (avalanche_comparison.png)
  - Performance benchmark (performance_comparison.png)
  - Metrics heatmap (metrics_heatmap.png)
  - Quality scorecards (quality_scorecards.png)
  
Use the text report to explain methodology and results.
""")


if __name__ == "__main__":
    main()

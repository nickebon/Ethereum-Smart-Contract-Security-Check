#!/usr/bin/env python3
"""
Batch pipeline runner for Smart Contract Security Analysis.
Executes run_pipeline.py for every contract in data/capstone_dataset/
and collects results into results/summary.csv.

Usage:
  python run_batch.py
"""

import sys
import subprocess
from pathlib import Path


def main():
    # Setup paths
    PROJECT_ROOT = Path(__file__).resolve().parent
    DATASET_DIR = PROJECT_ROOT / 'data' / 'capstone_dataset'
    
    # Find all .sol files recursively
    sol_files = sorted(DATASET_DIR.rglob('*.sol'))
    
    if not sol_files:
        print(f"❌ No .sol files found in {DATASET_DIR}")
        return
    
    print(f"\n📊 Batch Pipeline Runner")
    print(f"{'=' * 60}")
    print(f"Found {len(sol_files)} contract(s) to analyze")
    print(f"{'=' * 60}\n")
    
    # Track results
    success_count = 0
    failed_count = 0
    failed_contracts = []
    
    # Run pipeline for each contract
    for idx, contract_path in enumerate(sol_files, 1):
        # Determine category from parent folder
        category = contract_path.parent.name
        contract_name = contract_path.stem
        
        print(f"[{idx}/{len(sol_files)}] Running: {contract_name} ({category})")
        
        try:
            # Run run_pipeline.py as subprocess (stream output to terminal)
            result = subprocess.run(
                [sys.executable, 'run_pipeline.py', str(contract_path), category],
                cwd=PROJECT_ROOT,
                timeout=None  # No timeout, let run_pipeline handle its own
            )
            
            if result.returncode == 0:
                print(f"[{idx}/{len(sol_files)}] ✓ Done: {contract_name}\n")
                success_count += 1
            else:
                print(f"\n[ERROR] {contract_name} exited with code {result.returncode}, continuing...\n")
                failed_count += 1
                failed_contracts.append(contract_name)
        except subprocess.TimeoutExpired:
            print(f"\n[ERROR] {contract_name} timed out, continuing...\n")
            failed_count += 1
            failed_contracts.append(contract_name)
        except Exception as e:
            print(f"\n[ERROR] {contract_name} failed: {e}, continuing...\n")
            failed_count += 1
            failed_contracts.append(contract_name)
    
    # Print summary
    print("\n" + "=" * 60)
    print("Batch Complete")
    print("=" * 60)
    print(f"Total contracts: {len(sol_files)}")
    print(f"Successful: {success_count}")
    print(f"Failed: {failed_count}")
    if failed_contracts:
        print(f"Failed contracts: {', '.join(failed_contracts)}")
    print(f"\nResults saved to: results/summary.csv")
    print("=" * 60 + "\n")


if __name__ == '__main__':
    main()

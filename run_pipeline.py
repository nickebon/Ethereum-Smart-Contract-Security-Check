#!/usr/bin/env python3
"""
Single-contract pipeline runner.
Runs the full security analysis pipeline end-to-end for one Solidity contract.

Usage:
  python run_pipeline.py <path/to/contract.sol> <category>
  Example: python run_pipeline.py capstone_dataset/reentrancy/etherstore.sol reentrancy
"""

import sys
import os
import json
import csv
import shutil
import subprocess
import logging
import re
from pathlib import Path
from datetime import datetime
import time

# Import project modules
from parser import parse_slither, parse_mythril, combine_and_save
from llm_deduplicator import LLMDeduplicator


def setup_logging(log_path):
    """Configure logging with timestamp format [HH:MM:SS]."""
    class TimestampFormatter(logging.Formatter):
        def format(self, record):
            return f"[{datetime.now().strftime('%H:%M:%S')}] {record.getMessage()}"
    
    logger = logging.getLogger('pipeline')
    logger.setLevel(logging.DEBUG)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # File handler
    fh = logging.FileHandler(log_path)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(TimestampFormatter())
    logger.addHandler(fh)
    
    # Stream handler (stdout)
    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.DEBUG)
    sh.setFormatter(TimestampFormatter())
    logger.addHandler(sh)
    
    return logger


def main():
    # Parse arguments
    if len(sys.argv) < 3:
        print("Usage: python run_pipeline.py <path/to/contract.sol> <category>")
        sys.exit(1)
    
    contract_path_arg = sys.argv[1]
    category = sys.argv[2]
    
    # Setup paths
    PROJECT_ROOT = Path(__file__).resolve().parent
    contract_path = Path(contract_path_arg).resolve()
    contract_name = contract_path.stem
    
    # Create results directory
    results_dir = PROJECT_ROOT / 'results' / contract_name
    results_dir.mkdir(parents=True, exist_ok=True)
    
    # Setup logging
    log_path = results_dir / 'run.log'
    logger = setup_logging(log_path)
    
    start_time = time.time()
    logger.info(f"Pipeline started for contract: {contract_name}")
    logger.info(f"Category: {category}")
    logger.info(f"Contract path: {contract_path}")
    
    # State variables for final result
    raw_alert_count = 0
    unique_vuln_count = 0
    tokens_total = 0
    estimated_cost_usd = 0.0
    reduction_pct = 0.0
    deduplicated_findings = []
    
    try:
        # ========== Step 1: solc switching ==========
        logger.info("Step 1: Running auto_solc_use.sh...")
        try:
            solc_script = PROJECT_ROOT / 'tools' / 'auto_solc_use.sh'
            result = subprocess.run(
                [str(solc_script), str(contract_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.stdout:
                logger.info(f"solc output: {result.stdout}")
            if result.returncode != 0:
                logger.warning(f"solc switching exited with code {result.returncode}")
                if result.stderr:
                    logger.warning(f"solc stderr: {result.stderr}")
        except Exception as e:
            logger.warning(f"[ERROR] Step 1 failed: {e}")
        
        # ========== Step 2: Run Slither ==========
        logger.info("Step 2: Running Slither...")
        slither_json = None
        try:
            # Find slither binary
            slither_bin = None
            venv_slither = PROJECT_ROOT / '.venv' / 'bin' / 'slither'
            venv_slither_alt = PROJECT_ROOT / '.venv-slither' / 'bin' / 'slither'
            if venv_slither.exists():
                slither_bin = str(venv_slither)
            elif venv_slither_alt.exists():
                slither_bin = str(venv_slither_alt)
            else:
                slither_bin = shutil.which('slither')
            
            if not slither_bin:
                logger.error("[ERROR] slither not found")
            else:
                out_dir = PROJECT_ROOT / 'out'
                out_dir.mkdir(parents=True, exist_ok=True)
                
                slither_out = out_dir / f'{contract_name}.slither.json'
                
                if slither_out.exists():
                    slither_out.unlink()
                
                env = os.environ.copy()
                result = subprocess.run(
                    [slither_bin, str(contract_path), '--json', str(slither_out)],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    env=env
                )
                
                logger.info(f"Slither binary used: {slither_bin}")
                logger.info(f"Slither return code: {result.returncode}")
                logger.info(f"Slither output file path: {slither_out}")
                logger.info(f"Slither output file exists: {slither_out.exists()}")
                if slither_out.exists():
                    logger.info(f"Slither output file size: {slither_out.stat().st_size} bytes")
                logger.info(f"Slither stderr: {result.stderr if hasattr(result, 'stderr') else 'not captured'}")
                
                # Count detectors (treat any JSON as success)
                detector_count = 0
                if slither_out.exists() and slither_out.stat().st_size > 0:
                    try:
                        with open(slither_out) as f:
                            slither_data = json.load(f)
                            detector_count = len(slither_data.get('results', {}).get('detectors', []))
                        slither_json = slither_out
                        logger.info(f"Slither found {detector_count} issues")
                    except Exception as e:
                        logger.warning(f"Could not parse Slither output: {e}")
                        logger.info("Slither found 0 issues")
                else:
                    logger.info("Slither found 0 issues")
        except Exception as e:
            logger.error(f"[ERROR] Step 2 failed: {e}")
        
        # ========== Step 3: Run Mythril (Docker) ==========
        logger.info("Step 3: Running Mythril via Docker...")
        myth_json = None
        try:
            # Detect solc version from pragma
            solc_version = "0.4.25"  # default
            try:
                with open(contract_path) as f:
                    content = f.read()
                    pragma_match = re.search(r'pragma\s+solidity\s+[\^\~]?(\d+\.\d+)', content)
                    if pragma_match:
                        version_str = pragma_match.group(1)
                        major, minor = version_str.split('.')
                        if major == '0':
                            if minor == '4':
                                solc_version = "0.4.25"
                            elif minor == '5':
                                solc_version = "0.5.17"
                            elif minor == '6':
                                solc_version = "0.6.12"
                            elif minor == '7':
                                solc_version = "0.7.6"
                            elif minor == '8':
                                solc_version = "0.8.20"
            except Exception as e:
                logger.info(f"Could not detect solc version, using default {solc_version}: {e}")
            
            logger.info(f"Detected solc version: {solc_version}")
            
            # Get relative path to contract for container
            relative_contract_path = contract_path.relative_to(PROJECT_ROOT)
            container_contract_path = f"/sb/{relative_contract_path}"
            
            # Build Docker command
            solc_binary = f"/tmp/solc-linux-amd64-{solc_version}"
            docker_cmd = [
                "docker", "run", "--rm",
                "-v", f"{PROJECT_ROOT}:/sb",
                "-v", f"{solc_binary}:/usr/local/bin/solc",
                "smartbugs/mythril:0.24.8",
                "myth", "analyze", container_contract_path,
                "-o", "json",
                "--execution-timeout", "60",
                "--max-depth", "80"
            ]
            
            logger.info(f"Docker command: {' '.join(docker_cmd)}")
            
            out_dir = PROJECT_ROOT / 'out'
            out_dir.mkdir(parents=True, exist_ok=True)
            myth_out = out_dir / f'{contract_name}.myth.json'
            
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Write stdout to myth_out
            myth_out.write_text(result.stdout)
            
            # Count issues
            issue_count = 0
            if result.stdout.strip():
                try:
                    myth_data = json.loads(result.stdout)
                    issue_count = len(myth_data.get('issues', []))
                    myth_json = myth_out
                    logger.info(f"Mythril found {issue_count} issues")
                except Exception as e:
                    logger.warning(f"Could not parse Mythril output: {e}")
                    logger.info("Mythril found 0 issues")
            else:
                logger.info("Mythril found 0 issues")
        except Exception as e:
            logger.error(f"[ERROR] Step 3 failed: {e}")
        
        # ========== Step 4: Run Parser ==========
        logger.info("Step 4: Running parser...")
        try:
            slither_findings = []
            myth_findings = []
            
            if slither_json and Path(slither_json).exists():
                slither_findings = parse_slither(str(slither_json))
            
            if myth_json and Path(myth_json).exists():
                myth_findings = parse_mythril(str(myth_json))
            
            raw_alert_count = len(slither_findings) + len(myth_findings)
            logger.info(f"Parser: {len(slither_findings)} from Slither + {len(myth_findings)} from Mythril = {raw_alert_count} total")
            
            data_dir = PROJECT_ROOT / 'data' / 'combined'
            data_dir.mkdir(parents=True, exist_ok=True)
            combined_out = data_dir / f'{contract_name}_combined.json'
            
            combine_and_save(slither_findings, myth_findings, str(combined_out))
            logger.info(f"Combined findings saved to {combined_out}")
        except Exception as e:
            logger.error(f"[ERROR] Step 4 failed: {e}")
        
        # ========== Step 5: Run LLM Deduplication ==========
        logger.info("Step 5: Running LLM deduplication...")
        try:
            combined_out = PROJECT_ROOT / 'data' / 'combined' / f'{contract_name}_combined.json'
            
            if not combined_out.exists():
                logger.warning(f"Combined file not found: {combined_out}")
            else:
                with open(combined_out) as f:
                    combined_data = json.load(f)
                
                findings = combined_data.get('findings', [])
                
                if not findings:
                    logger.warning("No findings to deduplicate")
                    result = {
                        'unique_vulnerabilities': [],
                        'summary': {'total_input': 0, 'unique_count': 0, 'duplicates_removed': 0},
                        'tokens_total': 0,
                        'estimated_cost_usd': 0.0
                    }
                else:
                    deduplicator = LLMDeduplicator()
                    result = deduplicator.deduplicate(findings)
                
                # Extract metrics
                unique_vuln_count = len(result.get('unique_vulnerabilities', []))
                tokens_total = result.get('tokens_total', 0)
                estimated_cost_usd = result.get('estimated_cost_usd', 0.0)
                deduplicated_findings = result.get('unique_vulnerabilities', [])
                
                logger.info(f"LLM deduplication: {unique_vuln_count} unique vulnerabilities, {tokens_total} tokens, ${estimated_cost_usd:.5f}")
                
                # Save deduplicated output
                dedup_dir = PROJECT_ROOT / 'data' / 'deduplicated'
                dedup_dir.mkdir(parents=True, exist_ok=True)
                dedup_out = dedup_dir / f'{contract_name}_deduplicated.json'
                
                with open(dedup_out, 'w') as f:
                    json.dump(result, f, indent=2)
                logger.info(f"Deduplicated findings saved to {dedup_out}")
        except Exception as e:
            logger.error(f"[ERROR] Step 5 failed: {e}")
        
        # ========== Step 6: Write final result JSON ==========
        logger.info("Step 6: Writing final result JSON...")
        try:
            reduction_pct = 0.0
            if raw_alert_count > 0:
                reduction_pct = round(((raw_alert_count - unique_vuln_count) / raw_alert_count) * 100, 2)
            
            final_result = {
                'contract': contract_name,
                'category': category,
                'contract_path': str(contract_path),
                'raw_alert_count': raw_alert_count,
                'unique_vuln_count': unique_vuln_count,
                'reduction_pct': reduction_pct,
                'tokens_total': tokens_total,
                'estimated_cost_usd': estimated_cost_usd,
                'deduplicated_findings': deduplicated_findings
            }
            
            result_json = results_dir / 'result.json'
            with open(result_json, 'w') as f:
                json.dump(final_result, f, indent=2)
            logger.info(f"Final result saved to {result_json}")
        except Exception as e:
            logger.error(f"[ERROR] Step 6 failed: {e}")
        
        # ========== Step 7: Write/append to summary.csv ==========
        logger.info("Step 7: Updating summary.csv...")
        try:
            summary_csv = PROJECT_ROOT / 'results' / 'summary.csv'
            
            csv_row = {
                'contract': contract_name,
                'category': category,
                'raw_alerts': raw_alert_count,
                'unique_vulns': unique_vuln_count,
                'reduction_pct': reduction_pct,
                'tokens_total': tokens_total,
                'cost_usd': estimated_cost_usd
            }
            
            if not summary_csv.exists():
                # Write header
                with open(summary_csv, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=csv_row.keys())
                    writer.writeheader()
                    writer.writerow(csv_row)
                logger.info(f"Created summary.csv with first entry")
            else:
                # Append row
                with open(summary_csv, 'a', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=csv_row.keys())
                    writer.writerow(csv_row)
                logger.info(f"Appended entry to summary.csv")
        except Exception as e:
            logger.error(f"[ERROR] Step 7 failed: {e}")
        
    finally:
        # ========== Step 8: Final log ==========
        elapsed_time = time.time() - start_time
        logger.info(f"Pipeline complete ({elapsed_time:.1f}s)")


if __name__ == '__main__':
    main()
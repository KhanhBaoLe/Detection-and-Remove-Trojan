import os
from scanner.base_scanner import BaseScanner
from utils.file_hash import calculate_file_hash
from utils.pe_utils import analyze_pe_file, is_pe_file, is_trusted_signer
from config.settings import (
    SIGNATURE_HASH_ALGO,
    SCAN_SKIP_DIRS,
    TRUSTED_SIGNERS,
    PE_HEURISTIC_MIN_SCORE,
    PE_TRUSTED_SIGNER_MAX_SCORE,
)


class SignatureScanner(BaseScanner):
    def __init__(self, db_manager, use_virustotal=False, vt_api_key=None):
        """
        Args:
            db_manager: Database manager instance
            use_virustotal: Enable VirusTotal scanning
            vt_api_key: VirusTotal API key (required if use_virustotal=True)
        """
        super().__init__(db_manager)

        self.use_virustotal = use_virustotal
        self.vt_scanner = None
        self.threats_found = []

        # ✅ Skip unnecessary folders
        self.skip_dirs = set(SCAN_SKIP_DIRS)

        # ✅ Sync local signature repo into DB (hash,trojan_name,level)
        try:
            if self.db_manager and hasattr(self.db_manager, "sync_signature_dir"):
                self.db_manager.sync_signature_dir()
        except Exception as e:
            print(f"⚠️ Cannot sync signatures directory: {e}")

        if use_virustotal and vt_api_key:
            try:
                from scanner.virustotal_scanner import VirusTotalScanner
                self.vt_scanner = VirusTotalScanner(vt_api_key)

                print("=" * 70)
                print("✅ VirusTotal scanner initialized successfully!")
                print(f"🔑 API Key: {vt_api_key[:10]}...{vt_api_key[-10:]}")
                print("📊 Ready to check with 70+ antivirus engines")
                print("=" * 70)

            except Exception as e:
                print(f"⚠️ Cannot initialize VirusTotal: {e}")
                self.use_virustotal = False

    def scan(self, path, scan_id=None):
        """Scan files using signature-based detection"""
        self.threats_found = []
        files_scanned = 0

        # ---------------------------
        # Collect files to scan
        # ---------------------------
        if os.path.isfile(path):
            files_to_scan = [path]
        else:
            files_to_scan = []
            for root, dirs, files in os.walk(path):
                # Skip unwanted directories
                dirs[:] = [d for d in dirs if d not in self.skip_dirs]

                for file in files:
                    file_path = os.path.join(root, file)
                    if self.is_suspicious_extension(file_path):
                        files_to_scan.append(file_path)

        # ---------------------------
        # Header
        # ---------------------------
        print("\n" + "=" * 70)
        print(f"📂 Found {len(files_to_scan)} files to scan")
        if self.use_virustotal:
            print("🌐 VirusTotal mode: ENABLED")
            print("⏱️  Rate limit: 15 seconds between API calls")
        print("=" * 70)

        # ---------------------------
        # Scan each file
        # ---------------------------
        for file_path in files_to_scan:
            files_scanned += 1
            file_name = os.path.basename(file_path)

            print(f"\n[{files_scanned}/{len(files_to_scan)}] 📂 Scanning: {file_name}")

            try:
                detected = False
                is_pe = is_pe_file(file_path)
                pe_heuristics = None

                # 1️⃣ Check EICAR test file
                if self.scan_eicar(file_path):
                    print("    🔴 EICAR test file detected!")
                    self.record_detection(scan_id, {
                        'file_path': file_path,
                        'file_hash': 'EICAR_TEST',
                        'trojan_name': 'EICAR-Test-File',
                        'threat_level': 'high',
                        'detection_method': 'signature'
                    })
                    continue

                # 2️⃣ Calculate MD5 hash
                file_hash = calculate_file_hash(file_path, algorithm=SIGNATURE_HASH_ALGO)
                if not file_hash:
                    print("    ⚠️ Cannot calculate hash")
                    continue

                print(f"    🔐 {SIGNATURE_HASH_ALGO.upper()} Hash: {file_hash}")

                # 3️⃣ Check whitelist
                if self.db_manager.is_whitelisted(file_hash):
                    print("    ✅ File in whitelist, skipping...")
                    continue

                # 3b️⃣ Trusted signer whitelist (PE only)
                if is_pe:
                    pe_heuristics = analyze_pe_file(file_path)
                    trusted, matched_signer = is_trusted_signer(file_path, TRUSTED_SIGNERS)
                    pe_score = pe_heuristics.get("score", 0.0) if pe_heuristics else 0.0
                    if trusted and pe_score < PE_TRUSTED_SIGNER_MAX_SCORE:
                        print(
                            f"    ✅ Trusted signer '{matched_signer}' "
                            f"(heuristics score {pe_score:.1f}) - skipping..."
                        )
                        continue
                    elif trusted:
                        print(
                            f"    ⚠️ Trusted signer '{matched_signer}' but "
                            f"heuristics score {pe_score:.1f}, continuing scan"
                        )

                # 4️⃣ Check local signature database
                signature = self.db_manager.check_signature(file_hash)
                if signature:
                    print(f"    🔴 LOCAL DB: Threat detected - {signature.trojan_name}")
                    self.record_detection(scan_id, {
                        'file_path': file_path,
                        'file_hash': file_hash,
                        'trojan_name': signature.trojan_name,
                        'threat_level': signature.threat_level,
                        'detection_method': 'signature'
                    })
                    continue

                # 5️⃣ VirusTotal scan (optional)
                if self.use_virustotal and self.vt_scanner:
                    print("    🌐 Querying VirusTotal API...")

                    sha256_hash = calculate_file_hash(file_path, algorithm='sha256')
                    print(f"    🔐 SHA256: {sha256_hash}")

                    vt_result = self.vt_scanner.scan_file_by_hash(file_path)

                    if vt_result and vt_result.get('status') == 'completed':
                        print("    ✅ VirusTotal API Response: SUCCESS")
                        print(f"    📊 Detection Rate: {vt_result['detection_rate']}")
                        print(f"    🔢 Engines: {vt_result['total_engines']}")

                        if vt_result.get('is_malicious'):
                            print("    🔴 VIRUSTOTAL: MALICIOUS DETECTED!")
                            print(f"    🦠 Malware Name: {vt_result['trojan_name']}")
                            print(f"    ⚠️ Threat Level: {vt_result['threat_level'].upper()}")

                            self.record_detection(scan_id, {
                                'file_path': file_path,
                                'file_hash': vt_result['file_hash'],
                                'trojan_name': f"[VT] {vt_result['trojan_name']}",
                                'threat_level': vt_result['threat_level'],
                                'detection_method': 'virustotal',
                                'vt_detection': vt_result['detection_rate']
                            })
                            detected = True
                        else:
                            print("    ✅ VIRUSTOTAL: File is CLEAN")

                    elif vt_result and vt_result.get('status') == 'not_found':
                        print("    ⚠️ File not found in VirusTotal database")
                        print("    💡 This file hasn't been uploaded to VT before")
                    else:
                        print("    ❌ VirusTotal API request failed")

                else:
                    print("    ℹ️ VirusTotal disabled - local scan only")
                    print("    ✅ No threat detected in local database")

                if detected:
                    continue

                # 6️⃣ PE static heuristics (only if still not detected)
                if is_pe:
                    pe_heuristics = pe_heuristics or analyze_pe_file(file_path)
                    if pe_heuristics.get("analysis_error"):
                        print(f"    ⚠️ PE heuristic error: {pe_heuristics['analysis_error']}")
                    else:
                        score = pe_heuristics.get("score", 0.0)
                        reasons = pe_heuristics.get("reasons", [])
                        if score >= PE_HEURISTIC_MIN_SCORE:
                            threat_level = 'high'
                            if score >= 9.0:
                                threat_level = 'critical'
                            elif score < 7.5:
                                threat_level = 'medium'

                            trojan_name = "Suspicious.PE.Heuristic"
                            if reasons:
                                trojan_name += f" ({'; '.join(reasons[:2])})"

                            self.record_detection(scan_id, {
                                'file_path': file_path,
                                'file_hash': file_hash,
                                'trojan_name': trojan_name,
                                'threat_level': threat_level,
                                'detection_method': 'static_heuristic'
                            })
                            continue
                        else:
                            print(f"    ✅ PE heuristics clean (score {score:.1f})")

            except Exception as e:
                print(f"    ⚠️ Error: {str(e)}")

        # ---------------------------
        # Summary
        # ---------------------------
        print("\n" + "=" * 70)
        print("📊 SCAN SUMMARY")
        print("=" * 70)
        print(f"✅ Files Scanned: {files_scanned}")
        print(f"🔴 Threats Found: {len(self.threats_found)}")

        if self.use_virustotal:
            vt_threats = [
                t for t in self.threats_found
                if t['detection_method'] == 'virustotal'
            ]
            print(f"🌐 VirusTotal Detections: {len(vt_threats)}")

        print("=" * 70 + "\n")

        return files_scanned, len(self.threats_found)

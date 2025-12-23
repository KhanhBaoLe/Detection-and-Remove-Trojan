import os

from scanner.base_scanner import BaseScanner
from utils.file_hash import calculate_file_hash
from utils.pe_utils import (
    analyze_pe_file,
    is_pe_file,
    is_trusted_signer,
)
from config.settings import (
    SIGNATURE_HASH_ALGO,
    SCAN_SKIP_DIRS,
    TRUSTED_SIGNERS,
    PE_HEURISTIC_MIN_SCORE,
    PE_TRUSTED_SIGNER_MAX_SCORE,
)


class SignatureScanner(BaseScanner):
    """
    Signature + PE heuristic + signer trust scanner
    """

    def __init__(self, db_manager, use_virustotal=False, vt_api_key=None):
        super().__init__(db_manager)

        self.use_virustotal = use_virustotal
        self.vt_scanner = None
        self.threats_found = []

        # Skip unnecessary directories
        self.skip_dirs = set(SCAN_SKIP_DIRS)

        # Sync local signature repository into DB
        try:
            if self.db_manager and hasattr(self.db_manager, "sync_signature_dir"):
                self.db_manager.sync_signature_dir()
        except Exception as e:
            print(f"⚠️ Cannot sync signatures directory: {e}")

        # Init VirusTotal if enabled
        if use_virustotal and vt_api_key:
            try:
                from scanner.virustotal_scanner import VirusTotalScanner
                self.vt_scanner = VirusTotalScanner(vt_api_key)

                print("=" * 70)
                print("✅ VirusTotal scanner initialized")
                print(f"🔑 API Key: {vt_api_key[:10]}...{vt_api_key[-10:]}")
                print("=" * 70)

            except Exception as e:
                print(f"⚠️ Cannot initialize VirusTotal: {e}")
                self.use_virustotal = False

    # ------------------------------------------------------------------

    def scan(self, path, scan_id=None):
        self.threats_found = []
        files_scanned = 0

        # Collect files
        if os.path.isfile(path):
            files_to_scan = [path]
        else:
            files_to_scan = []
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in self.skip_dirs]
                for f in files:
                    full_path = os.path.join(root, f)
                    if self.is_suspicious_extension(full_path):
                        files_to_scan.append(full_path)

        print("\n" + "=" * 70)
        print(f"📂 Found {len(files_to_scan)} files to scan")
        print(f"🌐 VirusTotal: {'ENABLED' if self.use_virustotal else 'DISABLED'}")
        print("=" * 70)

        # ------------------------------------------------------------------
        # Scan each file
        # ------------------------------------------------------------------
        for file_path in files_to_scan:
            files_scanned += 1
            file_name = os.path.basename(file_path)

            print(f"\n[{files_scanned}/{len(files_to_scan)}] 📄 {file_name}")

            try:
                # 1️⃣ EICAR
                if self.scan_eicar(file_path):
                    self.record_detection(scan_id, {
                        "file_path": file_path,
                        "file_hash": "EICAR_TEST",
                        "trojan_name": "EICAR-Test-File",
                        "threat_level": "high",
                        "detection_method": "signature",
                    })
                    continue

                # 2️⃣ Hash
                file_hash = calculate_file_hash(
                    file_path, algorithm=SIGNATURE_HASH_ALGO
                )
                if not file_hash:
                    print("    ⚠️ Cannot calculate hash")
                    continue

                print(f"    🔐 {SIGNATURE_HASH_ALGO.upper()}: {file_hash}")

                # 3️⃣ Hash whitelist
                if self.db_manager.is_whitelisted(file_hash):
                    print("    ✅ Hash whitelisted")
                    continue

                # 4️⃣ PE signer trust gate
                pe_info = None
                is_pe = is_pe_file(file_path)

                if is_pe:
                    pe_info = analyze_pe_file(file_path)
                    pe_score = pe_info.get("score", 0.0)

                    trusted, signer = is_trusted_signer(
                        file_path, TRUSTED_SIGNERS
                    )

                    if trusted and pe_score < PE_TRUSTED_SIGNER_MAX_SCORE:
                        print(
                            f"    ✅ Trusted signer '{signer}' "
                            f"(heuristic score {pe_score:.1f}) → skip"
                        )
                        continue

                    if trusted:
                        print(
                            f"    ⚠️ Trusted signer '{signer}' "
                            f"but heuristic score {pe_score:.1f} → continue scan"
                        )

                # 5️⃣ Local signature DB
                signature = self.db_manager.check_signature(file_hash)
                if signature:
                    self.record_detection(scan_id, {
                        "file_path": file_path,
                        "file_hash": file_hash,
                        "trojan_name": signature.trojan_name,
                        "threat_level": signature.threat_level,
                        "detection_method": "signature",
                    })
                    continue

                # 6️⃣ VirusTotal (optional)
                if self.use_virustotal and self.vt_scanner:
                    print("    🌐 Querying VirusTotal…")
                    vt_result = self.vt_scanner.scan_file_by_hash(file_path)

                    if vt_result and vt_result.get("status") == "completed":
                        if vt_result.get("is_malicious"):
                            self.record_detection(scan_id, {
                                "file_path": file_path,
                                "file_hash": vt_result["file_hash"],
                                "trojan_name": f"[VT] {vt_result['trojan_name']}",
                                "threat_level": vt_result["threat_level"],
                                "detection_method": "virustotal",
                                "vt_detection": vt_result["detection_rate"],
                            })
                            continue
                        else:
                            print("    ✅ VirusTotal clean")

                # 7️⃣ PE heuristics (last line of defense)
                if is_pe and pe_info:
                    score = pe_info.get("score", 0.0)
                    reasons = pe_info.get("reasons", [])

                    if score >= PE_HEURISTIC_MIN_SCORE:
                        level = "medium"
                        if score >= 9.0:
                            level = "critical"
                        elif score >= 7.5:
                            level = "high"

                        name = "Suspicious.PE.Heuristic"
                        if reasons:
                            name += f" ({'; '.join(reasons[:2])})"

                        self.record_detection(scan_id, {
                            "file_path": file_path,
                            "file_hash": file_hash,
                            "trojan_name": name,
                            "threat_level": level,
                            "detection_method": "static_heuristic",
                        })
                    else:
                        print(f"    ✅ PE heuristics clean (score {score:.1f})")

            except Exception as e:
                print(f"    ⚠️ Error scanning file: {e}")

        # ------------------------------------------------------------------
        # Summary
        # ------------------------------------------------------------------
        print("\n" + "=" * 70)
        print("📊 SCAN SUMMARY")
        print(f"✅ Files scanned: {files_scanned}")
        print(f"🔴 Threats found: {len(self.threats_found)}")
        print("=" * 70 + "\n")

        return files_scanned, len(self.threats_found)

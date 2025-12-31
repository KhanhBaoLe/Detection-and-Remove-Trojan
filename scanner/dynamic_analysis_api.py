from scanner.dynamic_runner import DynamicRunner
from scanner.threat_scorer import ThreatScorer
from config.settings import (
    DYNAMIC_TIMEOUT_SECONDS,
    DYNAMIC_ENABLE_NETWORK,
    DYNAMIC_FIREWALL_GUARD_ENABLED,
)
import os
import traceback
import json

class DynamicAPI:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.timeout = DYNAMIC_TIMEOUT_SECONDS
        self.enable_network = DYNAMIC_ENABLE_NETWORK
        self.use_firewall_guard = DYNAMIC_FIREWALL_GUARD_ENABLED

    def analyze(self, sample_path, scan_id=None, timeout=None, capture_network=None):
        """
        Phân tích động một mẫu (ON-DEMAND)
        """
        timeout = timeout or self.timeout
        capture_network = (
            capture_network if capture_network is not None
            else self.enable_network
        )
        run_id = None
        try:
            # ===== 1. CREATE RUN RECORD =====
            run_id = self.db_manager.add_dynamic_run(
                scan_id=scan_id,
                sample_path=sample_path,
                timeout=timeout
            )
            # ===== 2. RUN SAMPLE =====
            runner = DynamicRunner(
                timeout_seconds=timeout,
                enable_network=capture_network,
                use_firewall_guard=self.use_firewall_guard,
            )
            result = runner.run_sample(sample_path)

            # ===== 3. PREPARE DATA & SCORING (UPDATED) =====
            summary = {}
            # SỬA 1: Đồng bộ Key mặc định cho khớp với ThreatScorer
            score_result = {
                "threat_score": 0, 
                "threat_level": "Unknown", 
                "reasons": []
            }
            
            if result:
                try:
                    summary = result.to_dict()
                    
                    def safe_get_first(data_dict, key):
                        val = data_dict.get(key)
                        if isinstance(val, list) and len(val) > 0:
                            return val[0] 
                        return {}

                    # Tách dữ liệu riêng lẻ
                    proc_data = safe_get_first(summary, "process_summary")
                    net_data = safe_get_first(summary, "network_summary")
                    fs_data = safe_get_first(summary, "fs_summary")
                    reg_data = safe_get_first(summary, "registry_summary")

                    # --- GỌI SCORER ---
                    # Hàm này trả về dict: {'threat_score': ..., 'threat_level': ...}
                    score_result = ThreatScorer.calculate_score(
                        proc_data, 
                        net_data, 
                        fs_data,
                        registry_data=reg_data  
                    )
                    
                    # Merge kết quả chấm điểm vào summary
                    summary["analysis_score"] = score_result
                except Exception as e:
                    print(f"Error processing summary/scoring: {e}")
                    traceback.print_exc()
                    summary = {"error": "Failed to parse result"}

            # ===== 4. SAVE BEHAVIOUR =====
            behavior_sample = self.db_manager.add_behavior_sample(
                run_id,
                result,
                score_data=score_result  
            )

            # ===== 5. UPDATE STATUS =====
            self.db_manager.update_dynamic_run(
                run_id,
                status='completed',
                exit_code=getattr(result, "exit_code", None),
                duration=getattr(result, "duration", 0)
            )

            # SỬA 2: Lấy đúng key "threat_score" thay vì "score"
            return {
                'success': True,
                'run_id': run_id,
                'sample_id': behavior_sample.id if behavior_sample else None,
                'exit_code': getattr(result, "exit_code", None),
                'duration': getattr(result, "duration", 0),
                
                # ---> ĐÂY LÀ CHỖ GÂY LỖI TRƯỚC ĐÓ <---
                'threat_score': score_result.get("threat_score", 0), 
                'threat_level': score_result.get("threat_level", "clean"),
                
                'summary': summary
            }

        except Exception as e:
            if run_id:
                self.db_manager.update_dynamic_run(
                    run_id,
                    status='failed'
                )

            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }
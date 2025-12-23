from scanner.dynamic_runner import DynamicRunner
from config.settings import DYNAMIC_TIMEOUT_SECONDS, DYNAMIC_ENABLE_NETWORK
import os
import traceback


class DynamicAPI:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.timeout = DYNAMIC_TIMEOUT_SECONDS
        self.enable_network = DYNAMIC_ENABLE_NETWORK

    def analyze(self, sample_path, scan_id=None, timeout=None, capture_network=None):
        """
        Phân tích động một mẫu (ON-DEMAND)

        ⚠️ Lưu ý:
        - Dynamic analysis có thể KHÔNG thu được process nào
        - API phải xử lý an toàn với dữ liệu rỗng
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
                enable_network=capture_network
            )

            result = runner.run_sample(sample_path)

            # ===== 3. SAFE SUMMARY =====
            summary = {}
            try:
                summary = result.to_dict() if result else {}
            except Exception:
                summary = {}

            # ===== 4. SAVE BEHAVIOUR =====
            behavior_sample = self.db_manager.add_behavior_sample(
                run_id,
                result
            )

            # ===== 5. UPDATE STATUS =====
            self.db_manager.update_dynamic_run(
                run_id,
                status='completed',
                exit_code=getattr(result, "exit_code", None),
                duration=getattr(result, "duration", 0)
            )

            return {
                'success': True,
                'run_id': run_id,
                'sample_id': behavior_sample.id if behavior_sample else None,
                'exit_code': getattr(result, "exit_code", None),
                'duration': getattr(result, "duration", 0),
                'threat_score': getattr(behavior_sample, "threat_score", 0),
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

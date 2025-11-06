#!/usr/bin/env bash
set -euo pipefail

# ---------------------------
# run_bench.sh
# Mục đích: tự động chạy các kịch bản benchmark trong package "benchmarks"
# - Tự load .env nếu có
# - Lưu log từng kịch bản vào thư mục bench_output/<timestamp>/
# - Chỉ chạy TOPK nặng nếu RUN_HEAVY=1 (bảo vệ OOM)
# ---------------------------

# Nếu có .env ở project root thì load các biến
if [ -f .env ]; then
  echo "[run_bench] Loading .env"
  set -o allexport
  source .env
  set +o allexport
fi

# Thông tin run
TS=$(date +%Y%m%d_%H%M%S)
OUT="bench_output/$TS"
mkdir -p "$OUT"

# Giá trị mặc định nếu chưa set
: "${REDIS_ADDR:=127.0.0.1:6379}"
: "${RUN_HEAVY:=0}"

echo "============================"
echo "Run ID: $TS"
echo "REDIS_ADDR: $REDIS_ADDR"
echo "RUN_HEAVY: $RUN_HEAVY"
echo "Output dir: $OUT"
echo "============================"

# Chạy từng kịch bản, ghi log bằng tee (vừa hiển thị vừa lưu file)
echo "[run_bench] 1) Warmup"
go test ./benchmarks -run Test_Run_Warmup -v 2>&1 | tee "$OUT/warmup.log"

echo "[run_bench] 2) Read-heavy (ZSCORE)"
go test ./benchmarks -run Test_Run_ReadHeavy -v 2>&1 | tee "$OUT/read.log"

echo "[run_bench] 3) Update 1 key (lặp)"
go test ./benchmarks -run Test_Update_1Key -v 2>&1 | tee "$OUT/update1.log"

echo "[run_bench] 4) Update 10k (compare pipeline)"
go test ./benchmarks -run Test_Run_WriteHeavy -v 2>&1 | tee "$OUT/update10k.log"

# TOPK lớn => chỉ chạy khi RUN_HEAVY=1
if [ "$RUN_HEAVY" = "1" ]; then
  echo "[run_bench] 5) TOPK (heavy)"
  go test ./benchmarks -run Test_Run_TopK -v 2>&1 | tee "$OUT/topk.log"
else
  echo "[run_bench] 5) TOPK skipped (set RUN_HEAVY=1 to run heavy test)"
fi

echo "[run_bench] 6) Mixed concurrent workload"
go test ./benchmarks -run Test_Run_Mixed_Concurrent -v 2>&1 | tee "$OUT/mixed.log"

# Copy results (CSV/JSON) and info snapshots
cp bench_results.csv bench_results.json "$OUT/" 2>/dev/null || true
cp info_*_"$TS".txt "$OUT/" 2>/dev/null || true

echo "[run_bench] Done. Results saved to $OUT"

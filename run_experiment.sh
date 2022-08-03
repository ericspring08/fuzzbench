PYTHONPATH=. python3 experiment/run_experiment.py \
--experiment-config config.yaml \
--benchmarks sqlite3_ossfuzz \
--experiment-name instrument \
--fuzzers aflplusplus

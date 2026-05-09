# dvara Benchmark Results

## Bloom lookup speed
- Claim: < 1ms (target 0.1ms)
- Result: avg=0.003ms  throughput=346,429 URLs/s

## False positive rate
- Claim: ≈ 0.1%
- Result: false positives=0/100,000  actual=0.0000%

## Memory / file size
- Claim: ~5MB filter
- Result: file=5.14MB  RAM_peak=10.53MB  count=268,970

## Throughput
- Claim: High-throughput in-memory URL checks
- Result: checked=726,649 URLs  throughput=145,330 URLs/s


| scenario | requests | clients | direct p50 ms | direct p99 ms | gateway p50 ms | gateway p99 ms | overhead p50 ms | overhead p99 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| buffered | 2000 | 4 | 0.129 | 0.556 | 1.829 | 4.336 | 1.700 | 3.780 |
| streaming (4-byte deltas) | 2000 | 4 | 9.451 | 15.339 | 15.773 | 43.156 | 6.321 | 27.816 |

Request body 1672 bytes, response text 2717 bytes; darwin/arm64, 8 CPUs, 1.27.1; upstream, gateway and load generator share one process on loopback.

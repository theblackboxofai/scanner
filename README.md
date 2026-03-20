# Blackbox Scanner

Blackbox Scanner is a Dockerized service that uses `masscan` to find Ollama servers on the CIDR ranges listed in `ranges.txt`, queries those servers for their models using the `Blackbox/1.0` user agent, and stores each successful scan result in Postgres.


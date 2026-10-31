package demo

// exception: owner=@dimss113 exp=2026-11-30 reason="demo: fixed test value, not a real credential"
// nosemgrep: generic.secrets.security.detected-generic-api-key.detected-generic-api-key
const apiKey = "d0b45fdd9d66dafe6b2a9ff7bba6c4cafd55e600"

func Key() string { return apiKey }

# SENTINEL-X Zeek configuration
# Enable JSON output and required log types for metadata extraction

# Load standard scripts
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/frameworks/notice
@load misc/capture-loss
@load misc/stats

# Load JA4 fingerprinting (installed via zkg at build time)
@load packages

# ── JSON output (required for normaliser parsing) ──
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_EPOCH;

# ── Log rotation: write to volume, rotate hourly ──
redef Log::default_rotation_interval = 1hr;
redef Log::default_logdir = "/var/log/zeek";

# ── Capture loss tracking (needed for Visibility Health) ──
redef CaptureLoss::too_much_loss = 0.10;  # Alert at 10% loss
redef CaptureLoss::watches += { [$prefix="", $loss_thresh=0.01] };

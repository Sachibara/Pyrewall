"""
Traffic parser for analytics.
"""

def summarize_packets(packets):
    summary = {
        "total": len(packets),
        "tcp": sum(1 for p in packets if p.is_tcp),
        "udp": sum(1 for p in packets if p.is_udp),
    }
    return summary

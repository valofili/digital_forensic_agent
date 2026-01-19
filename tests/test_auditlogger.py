def test_audit_logger_appends_entries(audit_logger):
    audit_logger.append("EVENT_A", {"x": 1})
    audit_logger.append("EVENT_B", {"y": 2})

    assert audit_logger.count_entries() == 2

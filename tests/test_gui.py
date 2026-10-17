"""Headless GUI smoke test (skipped when PyQt6 is unavailable)."""

import pytest

pytest.importorskip("PyQt6.QtWidgets")


def test_main_window_scan_flow(qtbot, sample_project):
    from gui.main_window import MainWindow

    window = MainWindow()
    qtbot.addWidget(window)
    window.path_input.setText(str(sample_project))
    window.online_check.setChecked(False)

    window._start_scan()
    qtbot.waitUntil(lambda: window.current_result is not None, timeout=30000)
    result = window.current_result

    # Regression: badges used to be garbage-collected, crashing here
    assert window.critical_badge.count_label.text() == str(result.get_critical_count())
    assert window.export_btn.isEnabled()
    assert window.scan_btn.text() == "Start Security Analysis"

    window.vuln_list.select_row(1)
    assert window.selected_vulnerability is not None

    window.vuln_list.search_input.setText("innerHTML")
    assert window.vuln_list.count_label.text().startswith("1 of")

    # Dashboard widgets are populated
    assert window.stack.currentIndex() == 1
    assert window.deps_table.rowCount() > 0
    assert window.secrets_table.rowCount() > 0
    assert window.owasp_chart.rows
    
    window._quick_fix_prompt()
    assert window._text_dialog.isVisible()
    window._text_dialog.close()


def test_domain_mode(qtbot, monkeypatch):
    import gui.main_window as mw
    from tests.test_domain_scanner import fake_dns, good_http
    
    class OfflineDomainScanner(mw.DomainScanner):
        def __init__(self, active=False):
            super().__init__(active=active, dns_query=fake_dns({('example.com', 'A'): ['1.2.3.4']}),
                             http_get=good_http, rdap_lookup=lambda d: None,
                             tls_probe=lambda h: {'reachable': True, 'verified': True, 'version': 'TLSv1.3',
                                                  'not_after': 'Jan  1 00:00:00 2099 GMT', 'legacy_protocols': []})
    
    monkeypatch.setattr(mw, "DomainScanner", OfflineDomainScanner)
    window = mw.MainWindow()
    qtbot.addWidget(window)
    window.domain_mode_btn.click()
    assert window.scan_btn.text() == "Scan Domain"
    assert not window.active_check.isEnabled()          # locked until authorization is confirmed
    window.authorized_check.setChecked(True)
    assert window.active_check.isEnabled()
    
    window.domain_input.setText("https://example.com/")
    window._start_scan()
    qtbot.waitUntil(lambda: window.current_result is not None, timeout=30000)
    
    assert window.current_result.metadata["scan_type"] == "domain"
    assert window.tabs.isTabVisible(window.tabs.indexOf(window.domain_tab))
    assert not window.tabs.isTabVisible(window.tabs.indexOf(window.deps_tab))
    assert window.stat_packages.title_label.text() == "DNSSEC"
    assert "No SPF Record" in [v.title for v in window.current_result.vulnerabilities]
    assert "example.com" in window.domain_view.toPlainText()

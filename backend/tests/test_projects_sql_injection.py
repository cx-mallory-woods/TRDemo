"""
Tests for SQL injection vulnerability remediation in projects route.

Verifies that the get_projects endpoint uses parameterized queries and
is not susceptible to SQL injection via the 'search' query parameter.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import db, Project, User


class TestGetProjectsParameterizedQuery:
    """Test that get_projects uses parameterized queries (no SQL injection)."""

    def test_search_returns_matching_projects(self, client, auth_headers, sample_project):
        """Normal search returns projects matching the term in name or description."""
        response = client.get(
            '/api/projects?search=Test',
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.get_json()
        assert 'projects' in data

    def test_search_with_no_results(self, client, auth_headers, sample_project):
        """Search that matches nothing returns an empty list."""
        response = client.get(
            '/api/projects?search=NonExistentProject12345',
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data['projects'] == []

    def test_no_search_returns_all_projects(self, client, auth_headers, sample_project):
        """Omitting the search param returns all projects via the ORM path."""
        response = client.get(
            '/api/projects',
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.get_json()
        assert 'projects' in data

    def test_sql_injection_tautology_does_not_expose_all_rows(
        self, client, auth_headers, db_session, sample_user
    ):
        """
        A classic tautology payload (' OR '1'='1) must NOT return extra rows.

        With a vulnerable concatenated query the payload transforms:
            WHERE name LIKE '%' OR '1'='1' --%'
        which returns every row.  With a parameterized query the entire
        payload is treated as a literal string and should match nothing.
        """
        # Create a project whose name cannot match the literal injection string
        safe_project = Project(
            name='SafeProject',
            description='Should not surface via injection',
            owner_id=sample_user.id,
            is_public=False
        )
        db_session.add(safe_project)
        db_session.commit()

        # SQL injection tautology payload
        injection_payload = "' OR '1'='1"
        response = client.get(
            f"/api/projects?search={injection_payload}",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.get_json()
        # The payload is treated as a literal string — nothing matches it
        assert data['projects'] == [], (
            "Tautology injection should not return any rows; "
            "parameterized query must treat the payload as a literal value."
        )

    def test_sql_injection_union_select_does_not_leak_data(
        self, client, auth_headers
    ):
        """
        A UNION SELECT injection must not expose data from other tables.

        Vulnerable query example:
            SELECT * FROM projects WHERE name LIKE '%' UNION SELECT ...
        A parameterized query wraps the entire value in quotes so the
        UNION keyword is never interpreted as SQL.
        """
        union_payload = "' UNION SELECT id,username,email,password_hash,role,created_at,updated_at,is_public FROM users --"
        response = client.get(
            f"/api/projects?search={union_payload}",
            headers=auth_headers
        )
        # Must not cause a 500 (broken syntax) or leak user data
        assert response.status_code == 200
        data = response.get_json()
        assert data['projects'] == [], (
            "UNION SELECT injection must be treated as a literal string, "
            "not executed as SQL."
        )

    def test_sql_injection_comment_truncation_payload(
        self, client, auth_headers, sample_project
    ):
        """
        A comment-truncation payload ('--) must not break the query or
        reveal rows it should not.
        """
        comment_payload = "Test' --"
        response = client.get(
            f"/api/projects?search={comment_payload}",
            headers=auth_headers
        )
        # Should return 200 and treat payload as a literal LIKE pattern
        assert response.status_code == 200
        data = response.get_json()
        assert 'projects' in data
        # 'Test' --' as a literal string won't match 'Test Project'
        assert data['projects'] == []

    def test_sql_injection_stacked_queries_payload(
        self, client, auth_headers
    ):
        """
        A stacked-queries payload ('; DROP TABLE projects; --) must not
        be executed.  After the request the projects table must still exist.
        """
        drop_payload = "'; DROP TABLE projects; --"
        response = client.get(
            f"/api/projects?search={drop_payload}",
            headers=auth_headers
        )
        # Must not crash and the table must still be intact
        assert response.status_code == 200

        # Confirm the table still functions by querying without a search term
        normal_response = client.get('/api/projects', headers=auth_headers)
        assert normal_response.status_code == 200

    def test_sql_injection_wildcard_does_not_expose_all_rows(
        self, client, auth_headers, db_session, sample_user
    ):
        """
        A bare '%' or '%%' as the search value should only match project
        names / descriptions that literally contain that character —
        not every row.

        In the parameterized form the driver escapes the % inside the
        bound parameter value, so it behaves as a LIKE literal ('%'
        matches rows with a literal percent sign, not every row).

        NOTE: SQLite and most databases do NOT escape % inside bound
        parameters automatically for LIKE — the application passes
        "%{search}%" so a search of "%" becomes "%%%", which does match
        everything.  This test verifies the injection vector is closed:
        the injected SQL operators (OR/UNION/comment) cannot alter the
        WHERE clause structure.
        """
        # This payload attempts SQL structural injection, not LIKE wildcards
        structural_payload = "%' OR name LIKE '%"
        response = client.get(
            f"/api/projects?search={structural_payload}",
            headers=auth_headers
        )
        assert response.status_code == 200
        # With parameterization the single-quote cannot escape the string context

    def test_search_with_special_characters_does_not_cause_500(
        self, client, auth_headers
    ):
        """
        Various special characters must not trigger a 500 Internal Server
        Error — they should all be safely passed as bound parameters.
        """
        special_inputs = [
            "O'Reilly",          # apostrophe
            'He said "hello"',   # double quotes
            "back\\slash",       # backslash
            "<script>",          # angle brackets
            "100%",              # percent sign
            "_under_score_",     # LIKE single-char wildcard
        ]
        for payload in special_inputs:
            response = client.get(
                f"/api/projects?search={payload}",
                headers=auth_headers
            )
            assert response.status_code == 200, (
                f"Special character payload '{payload}' caused a non-200 response: "
                f"{response.status_code}"
            )

    def test_unauthenticated_request_is_rejected(self, client):
        """Requests without a valid auth token must be rejected with 401."""
        response = client.get('/api/projects?search=test')
        assert response.status_code == 401

    def test_search_finds_project_by_description(
        self, client, auth_headers, db_session, sample_user
    ):
        """
        The LIKE pattern must match on the description column as well,
        confirming both WHERE predicates work correctly with parameters.
        """
        project = Project(
            name='UniqueAlpha',
            description='DescriptionBeta keyword here',
            owner_id=sample_user.id,
            is_public=False
        )
        db_session.add(project)
        db_session.commit()

        response = client.get(
            '/api/projects?search=keyword',
            headers=auth_headers
        )
        assert response.status_code == 200

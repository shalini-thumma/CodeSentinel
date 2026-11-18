import io
import unittest
import zipfile

from codesentinel.github_handler import RepositoryError, inspect_zip, parse_github_url


class GitHubUrlTests(unittest.TestCase):
    def test_accepts_repository_url_with_optional_git_suffix(self):
        self.assertEqual(parse_github_url("https://github.com/example/project.git"), ("example", "project"))

    def test_rejects_non_github_and_nested_urls(self):
        for value in (
            "http://github.com/example/project",
            "https://github.com.evil.test/example/project",
            "https://github.com/example/project/tree/main",
            "https://user@github.com/example/project",
            "https://github.com/example/project?download=true",
        ):
            with self.subTest(value=value), self.assertRaises(RepositoryError):
                parse_github_url(value)


class ArchiveInspectionTests(unittest.TestCase):
    @staticmethod
    def make_archive(entries):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for path, content in entries.items():
                archive.writestr(path, content)
        return buffer.getvalue()

    def test_counts_languages_and_ignores_generated_directories(self):
        archive = self.make_archive({
            "project-main/app.py": "print('ok')\n",
            "project-main/src/app.ts": "export const value = 1;\n",
            "project-main/node_modules/pkg/index.js": "dangerous but ignored\n",
            "project-main/__pycache__/app.py": "ignored\n",
            "project-main/README.md": "Project notes\n",
        })

        snapshot = inspect_zip(archive, "example", "project", "main", "https://github.com/example/project")

        self.assertEqual(snapshot.repository.languages, {"Python": 1, "TypeScript": 1})
        self.assertIn("README.md", snapshot.files)
        self.assertNotIn("node_modules/pkg/index.js", snapshot.files)
        self.assertNotIn("__pycache__/app.py", snapshot.files)

    def test_rejects_archives_without_supported_content(self):
        archive = self.make_archive({"project-main/image.png": "not source"})
        with self.assertRaises(RepositoryError):
            inspect_zip(archive, "example", "project", "main", "https://github.com/example/project")

    def test_caps_total_decompressed_relevant_content(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("project-main/app.py", "print('ok')\n")
            for index in range(26):
                archive.writestr(f"project-main/docs{index}/README.md", "x" * (1024 * 1024))

        snapshot = inspect_zip(buffer.getvalue(), "example", "project", "main", "https://github.com/example/project")

        self.assertIn("app.py", snapshot.files)
        self.assertGreater(snapshot.repository.skipped_files, 0)
        self.assertTrue(any("total analysis byte budget" in warning for warning in snapshot.warnings))


if __name__ == "__main__":
    unittest.main()
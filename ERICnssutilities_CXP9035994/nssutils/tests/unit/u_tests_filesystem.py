#!/usr/bin/python
import os
import pkgutil
import time
from StringIO import StringIO

import unittest2
from mock import patch

from nssutils.lib import filesystem, shell
from nssutils.tests import unit_test_utils


class FilesystemUnitTests(unittest2.TestCase):

    def setUp(self):
        unit_test_utils.setup()

    def tearDown(self):
        unit_test_utils.tear_down()

        if filesystem.is_dir("mock"):
            filesystem.remove_dir("mock")
        if filesystem.does_file_exist("/tmp/to_be_deleted.txt"):
            filesystem.delete_file("/tmp/to_be_deleted.txt")

    @patch("os.path.exists")
    def test_does_file_exist_returns_true_when_os_path_exists_returns_true(self, mock_os_path_exists):
        mock_os_path_exists.return_value = True
        self.assertTrue(filesystem.does_file_exist("mock/test/path/which/does/not/exist"))

    def test_does_file_exist_returns_false_os_path_realpath_returns_false(self):
        self.assertFalse(filesystem.does_file_exist("mock/test/path/which/does/exist"))

    @patch("os.path.exists")
    def test_assert_file_exists_does_not_raise_runtime_error_when_does_file_exist_returns_true(self, mock_os_path_exists):
        mock_os_path_exists.return_value = True
        try:
            filesystem.assert_file_exists("mock/test/path/which/does/exist")
        except:
            self.fail("File does not exist")

    def test_assert_file_exists_does_raises_runtime_error_when_does_file_exist_returns_false(self):
        self.assertRaises(RuntimeError, filesystem.assert_file_exists, "mock/test/path/which/does/not/exist")

    @patch("nssutils.lib.filesystem.does_file_exist")
    @patch("os.remove")
    def test_delete_file_does_not_raise_exception_if_file_deleted_successfully(self, mock_os_remove, mock_does_file_exist):
        mock_does_file_exist.return_value = False
        mock_os_remove.return_value = None

        # NOTE: There is no assertion here as delete_file() is void; if the test doesn't raise a runtime exception, it's a pass
        filesystem.delete_file("mock/test/path/which/does/exist")

    @patch("nssutils.lib.filesystem.does_file_exist")
    @patch("os.remove")
    def test_delete_file_raises_exception_if_file_exists_after_deletion_attempt(self, mock_os_remove, mock_does_file_exist):
        mock_does_file_exist.return_value = True
        mock_os_remove.return_value = None

        self.assertRaises(RuntimeError, filesystem.delete_file, "mock/test/path/which/does/exist")

    def test_delete_file_raises_exception_if_file_does_not_exist(self):
        self.assertRaises(OSError, filesystem.delete_file, "mock/test2/path/which/does/exist")

    @patch("os.path.isdir")
    def test_assert_dir_exist_does_not_raise_runtime_error_when_does_file_exist_returns_true(self, mock_os_path_isdir):
        mock_os_path_isdir.return_value = True
        try:
            filesystem.assert_dir_exists("mock/test/path/which/does/exist")
        except:
            self.fail("Directory does not exist")

    def test_assert_dir_exist_raises_runtime_error_when_does_file_exist_returns_false(self):
        self.assertRaises(RuntimeError, filesystem.assert_dir_exists, "mock/test/path/which/does/not/exist")

    @patch("os.path.isdir")
    def test_does_dir_exist_returns_true_when_os_path_isdir_returns_true(self, mock_os_path_isdir):
        mock_os_path_isdir.return_value = True
        self.assertTrue(filesystem.does_dir_exist("mock/test/dir/which/does/not/exist"))

    def test_does_dir_exist_returns_false_when_dir_does_not_exist(self):
        self.assertFalse(filesystem.does_dir_exist("mock/test/dir/which/does/exist"))

    def test_create_dir_makes_dir_if_dir_does_not_exist(self):
        filesystem.create_dir("mock/test/path/for/creation")
        self.assertTrue(filesystem.does_dir_exist("mock/test/path/for/creation"))
        filesystem.remove_dir("mock/test/path/for/creation")
        self.assertFalse(filesystem.does_dir_exist("mock/test/path/for/creation"))

    @patch("nssutils.lib.shell.run_remote_cmd")
    @patch("nssutils.lib.filesystem.does_remote_dir_exist")
    def test_create_remote_dir_makes_dir_when_password_is_none(self, mock_does_remote_dir_exist, mock_run_remote_cmd):
        mock_does_remote_dir_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(0, "blah", .123)

        # NOTE: There is no assertion here as create_remote_dir() is void; if the test doesn't raise a runtime exception, it's a pass
        filesystem.create_remote_dir("mock/test/dir", "test_host", "test_user")

    @patch("nssutils.lib.shell.run_remote_cmd")
    @patch("nssutils.lib.filesystem.does_remote_dir_exist")
    def test_create_remote_dir_makes_dir_when_password_is_not_none(self, mock_does_remote_dir_exist, mock_run_remote_cmd):
        mock_does_remote_dir_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(0, "blah", .123)

        # NOTE: There is no assertion here as create_remote_dir() is void; if the test doesn't raise a runtime exception, it's a pass
        filesystem.create_remote_dir("mock/test/dir", "test_host", "test_user", "secret")

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_create_remote_dir_raises_runtime_error_when_rc_is_not_0(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(2, "blah", .123)
        self.assertRaises(RuntimeError, filesystem.create_remote_dir, "mock/test/dir", "test_host", "test_user")

    @patch("nssutils.lib.shell.run_local_cmd")
    @patch("os.path.isdir")
    def test_remove_dir_executes_succefully_when_rc_is_0_and_file_no_longer_exists(self, mock_os_path_isdir, mock_run_local_cmd):
        mock_os_path_isdir.side_effect = [True, False]
        mock_run_local_cmd.return_value = shell.Response(0, "D", .12)

        try:
            filesystem.remove_dir("mock/test/path")
        except:
            self.fail("Directory could not be removed")

    @patch("nssutils.lib.shell.run_local_cmd")
    @patch("os.path.isdir")
    def test_remove_dir_raises_runtime_error_when_rc_is_not_0(self, mock_os_path_isdir, mock_run_local_cmd):
        mock_os_path_isdir.side_effect = [True, True]
        mock_run_local_cmd.return_value = shell.Response(1, "D", .12)

        self.assertRaises(RuntimeError, filesystem.remove_dir, "mock/test/path")

    @patch("nssutils.lib.shell.run_local_cmd")
    @patch("os.path.isdir")
    def test_remove_dir_raises_runtime_error_when_rc_is_0_but_dir_still_exists_after_deletion(self, mock_os_path_isdir, mock_run_local_cmd):
        mock_os_path_isdir.side_effect = [True, True]
        mock_run_local_cmd.return_value = shell.Response(0, "D", .12)

        self.assertRaises(RuntimeError, filesystem.remove_dir, "mock/test/path")

    @patch("nssutils.lib.shell.run_local_cmd")
    def test_copy_creates_dir_if_dir_does_not_exist_and_executes_copy_command_without_raising_runtime_exception_when_rc_is_0(self, mock_run_local_cmd):
        mock_run_local_cmd.return_value = shell.Response(0, "D", .12)
        filesystem.copy("mock/test/source/path", "mock/test/destination/path")
        self.assertTrue(filesystem.does_dir_exist("mock/test/destination"))
        os.rmdir("mock/test/destination")

    @patch("nssutils.lib.filesystem.create_dir")
    @patch("nssutils.lib.shell.run_local_cmd")
    def test_copy_does_not_create_dir_if_dir_already_exists_executes_copy_command_without_raising_runtime_exception_when_rc_is_0(self, mock_run_local_cmd, mock_create_dir):
        response = shell.Response(0, "D", .12)
        mock_run_local_cmd.return_value = response
        os.makedirs("mock/test/destination")
        filesystem.copy("mock/test/source/path", "mock/test/destination/path")
        self.assertFalse(mock_create_dir.called)
        os.rmdir("mock/test/destination")

    @patch("nssutils.lib.shell.run_local_cmd")
    def test_copy_raises_runtime_exception_when_rc_is_not_0(self, mock_run_local_cmd):
        mock_run_local_cmd.return_value = shell.Response(1, "D", .12)
        self.assertRaises(RuntimeError, filesystem.copy, "mock/test/source/path", "mock/test/destination/path")

    @patch("nssutils.lib.shell.run_local_cmd")
    def test_get_file_size_in_mb_returns_stdout_when_no_runtime_errors_are_raised(self, mock_run_local_cmd):
        mock_run_local_cmd.return_value = shell.Response(0, "100", .12)
        self.assertEquals(filesystem.get_file_size_in_mb("mock/test/path"), "100")

    @patch("nssutils.lib.shell.run_local_cmd")
    def test_get_file_size_in_mb_raises_runtime_error_when_rc_is_not_0(self, mock_run_local_cmd):
        mock_run_local_cmd.return_value = shell.Response(1, "D", .12)
        self.assertRaises(RuntimeError, filesystem.get_file_size_in_mb, "mock/test/path")

    @patch("nssutils.lib.shell.run_local_cmd")
    def test_get_file_size_in_mb_raises_runtime_error_when_stdout_is_an_empty_string(self, mock_run_local_cmd):
        mock_run_local_cmd.return_value = shell.Response(0, "", .12)
        self.assertRaises(RuntimeError, filesystem.get_file_size_in_mb, "mock/test/path")

    @patch("nssutils.lib.shell.run_local_cmd")
    def test_get_file_size_in_mb_raises_runtime_error_when_stdout_is_none(self, mock_run_local_cmd):
        mock_run_local_cmd.return_value = shell.Response(0, None, .12)
        self.assertRaises(RuntimeError, filesystem.get_file_size_in_mb, "mock/test/path")

    @patch("nssutils.lib.filesystem.does_file_exist")
    @patch("nssutils.lib.shell.run_local_cmd")
    def test_touch_file_executes_command_if_file_path_does_not_already_exist(self, mock_run_local_cmd, mock_does_file_exist):
        mock_does_file_exist.return_value = False
        mock_run_local_cmd.return_value = shell.Response(0, "D", .12)
        filesystem.touch_file("mock/test/path/which/does/not/exist")
        self.assertTrue(mock_run_local_cmd.called)

    @patch("os.path.exists")
    def test_touch_file_raises_runtime_error_if_path_already_exists(self, mock_os_path_exists):
        mock_os_path_exists.return_value = True
        self.assertRaises(RuntimeError, filesystem.touch_file, "mock/test/path/which/already/exists")

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_does_remote_file_exist_returns_true_when_rc_is_0_and_password_is_none(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(0, "blah", .123)
        self.assertTrue(filesystem.does_remote_file_exist("mock/test/file", "test_host", "test_user"))

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_does_remote_file_exist_returns_true_when_rc_is_0_and_password_is_not_none(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(0, "blah", .123)
        self.assertTrue(filesystem.does_remote_file_exist("mock/test/file", "test_host", "test_user", "secret"))

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_does_remote_file_exist_raises_runtime_error_when_rc_is_not_0(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(1, "blah", .123)
        self.assertFalse(filesystem.does_remote_file_exist("mock/test/file", "test_host", "test_user"))

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_does_remote_dir_exist_returns_true_when_rc_is_0_and_password_is_none(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(0, "blah", .123)
        self.assertTrue(filesystem.does_remote_dir_exist("mock/test/dir", "test_host", "test_user"))

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_does_remote_dir_exist_returns_true_when_rc_is_0_and_password_is_not_none(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(0, "blah", .123)
        self.assertTrue(filesystem.does_remote_dir_exist("mock/test/dir", "test_host", "test_user", "TestPassw0rd"))

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_does_remote_dir_exist_raises_runtime_error_when_rc_is_not_0(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(1, "blah", .123)
        self.assertFalse(filesystem.does_remote_dir_exist("mock/test/dir", "test_host", "test_user"))

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_remote_file_size_in_mb_raises_runtime_error_when_file_does_not_exist(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(1, "blah", .123)
        self.assertRaises(RuntimeError, filesystem.get_remote_file_size_in_mb, "mock/test/file/path/which/does/not/exit", "test_host", "test_user")

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_remote_file_size_in_mb_returns_stdout_when_password_is_none_and_and_rc_is_0(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(0, "100       mock/test/path", .123)
        self.assertEquals(filesystem.get_remote_file_size_in_mb("mock/test/path", "test_host", "test_user"), "100")

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_remote_file_size_in_mb_returns_stdout_when_password_is_not_none_and_and_rc_is_0(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(0, "200       mock/test/path", .123)
        self.assertEquals(filesystem.get_remote_file_size_in_mb("mock/test/path", "test_host", "test_user", "password"), "200")

    @patch("nssutils.lib.filesystem.does_remote_file_exist")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_remote_file_size_in_mb_raises_runtime_error_if_rc_is_not_0(self, mock_run_remote_cmd, mock_does_remote_file_exist):
        mock_does_remote_file_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(1, "200       mock/test/path", .123)
        self.assertRaises(RuntimeError, filesystem.get_remote_file_size_in_mb, "mock/test/file/path/which/does/not/exit", "test_host", "test_user")

    @patch("nssutils.lib.filesystem.does_remote_file_exist")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_remote_file_size_in_mb_raises_runtime_error_if_stdout_is_an_empty_string(self, mock_run_remote_cmd, _):
        mock_run_remote_cmd.return_value = shell.Response(1, "", .451)
        self.assertRaises(RuntimeError, filesystem.get_remote_file_size_in_mb, "mock/test/file/path/which/does/not/exit", "test_host", "test_user")

    @patch("nssutils.lib.filesystem.does_remote_file_exist")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_remote_file_size_in_mb_raises_runtime_error_if_stdout_is_none(self, mock_run_remote_cmd, mock_does_remote_file_exist):
        mock_does_remote_file_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(1, None, .451)
        self.assertRaises(RuntimeError, filesystem.get_remote_file_size_in_mb, "mock/test/file/path/which/does/not/exit", "test_host", "test_user")

    @patch("nssutils.lib.filesystem.does_remote_dir_exist")
    def test_get_files_in_remote_directory_raises_runtime_error_when_remote_dir_does_not_exist(self, mock_does_remote_dir_exist):
        mock_does_remote_dir_exist.return_value = False
        self.assertRaises(OSError, filesystem.get_files_in_remote_directory, "mock/test/dir/which/does/not/exist", "test_host", "test_user")

    @patch("nssutils.lib.filesystem.does_remote_dir_exist")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_files_in_remote_directory_raises_runtime_error_when_rc_is_not_0(self, mock_run_remote_cmd, mock_does_remote_dir_exist):
        mock_does_remote_dir_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(1, "Error", .001)
        self.assertRaises(RuntimeError, filesystem.get_files_in_remote_directory, "mock/test/dir/which/does/not/exist", "test_host", "test_user")

    @patch("nssutils.lib.filesystem.get_remote_hostname")
    @patch("nssutils.lib.filesystem.does_remote_dir_exist")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_files_in_remote_directory_raises_runtime_error_when_stdout_is_none(self, mock_run_remote_cmd, mock_does_remote_dir_exist, *_):
        mock_does_remote_dir_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(0, None, .001)
        self.assertRaises(RuntimeError, filesystem.get_files_in_remote_directory, "mock/test/dir/which/does/not/exist", "test_host", "test_user")

    @patch("nssutils.lib.filesystem.does_remote_dir_exist")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_files_in_remote_directory_returns_an_empty_list_when_stdout_is_an_empty_string(self, mock_run_remote_cmd, mock_does_remote_dir_exist):
        mock_does_remote_dir_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(0, "", .001)
        self.assertItemsEqual(list(filesystem.get_files_in_remote_directory("mock/test/dir/which/does/not/exist", "test_host", "test_user")), [])

    @patch("nssutils.lib.filesystem.does_remote_dir_exist")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_files_in_remote_directory_returns_the_appropriate_file_list_from_stdout_when_rc_is_0_and_password_is_none(self, mock_run_remote_cmd, mock_does_remote_dir_exist):
        mock_does_remote_dir_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(0, "one\ntwo\nthree\n", .211)
        self.assertItemsEqual(list(filesystem.get_files_in_remote_directory("/mock/test/file/", "test_host", "test_user", full_paths=True)),
                              ["/mock/test/file/one", "/mock/test/file/two", "/mock/test/file/three"])

    @patch("nssutils.lib.filesystem.does_remote_dir_exist")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_files_in_remote_directory_returns_the_appropriate_file_list_from_stdout_when_rc_is_0_and_password_is_not_none(self, mock_run_remote_cmd, mock_does_remote_dir_exist):
        mock_does_remote_dir_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(0, "one\ntwo\nthree\n", .211)
        self.assertItemsEqual(list(filesystem.get_files_in_remote_directory("/mock/test/file/", "test_host", "test_user", "password", full_paths=True)),
                              ["/mock/test/file/one", "/mock/test/file/two", "/mock/test/file/three"])

    @patch("nssutils.lib.filesystem.does_remote_dir_exist")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_files_in_remote_directory_with_pattern(self, mock_run_remote_cmd, mock_does_remote_dir_exist):
        mock_does_remote_dir_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(0, "one.abc\ntwo.abc\n", .211)
        self.assertItemsEqual(list(filesystem.get_files_in_remote_directory("/test/mock/dir/path/which/does/not/exist", "test_host", "test_user", "password", ends_with=".abc")),
                              ["one.abc", "two.abc"])

    @patch("nssutils.lib.filesystem.does_remote_dir_exist")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_files_in_remote_directory_recursive(self, mock_run_remote_cmd, mock_does_remote_dir_exist):
        mock_does_remote_dir_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(
            0, "/test/mock/dir/path/which/does/not/exist/one.abc\n/test/mock/dir/path/which/does/not/exist/two.abc\n", .211)
        files = filesystem.get_files_in_remote_directory_recursively("/test/mock/dir/path/which/does/not/exist", "test_host", "test_user", "password", ends_with=".abc")
        self.assertItemsEqual(files, ["one.abc", "two.abc"])

    def test_get_files_in_directory_raises_os_error_when_dir_does_not_exist(self):
        self.assertRaises(OSError, filesystem.get_files_in_directory, "test/mock/dir/path/which/does/not/exist")

    @patch("os.listdir")
    @patch("os.path.isdir")
    def test_get_files_in_directory_returns_file_list_if_dir_exists_and_os_list_dir_returns_a_list_of_files(self, mock_os_path_isdir, mock_os_listdir):
        mock_os_path_isdir.return_value = True
        mock_os_listdir.return_value = ["one.abc", "two.abc", "three.def"]
        self.assertItemsEqual(list(filesystem.get_files_in_directory("test/mock/dir/path/which/does/not/exist")), mock_os_listdir.return_value)

    @patch("os.listdir")
    @patch("os.path.isdir")
    def test_get_files_in_dir_with_pattern(self, mock_os_path_isdir, mock_os_listdir):
        mock_os_path_isdir.return_value = True
        mock_os_listdir.return_value = ["one.abc", "two.abc", "three.def"]
        file_in_directory = filesystem.get_files_in_directory("test/mock/dir/path/which/does/not/exist", ends_with=".abc")
        self.assertItemsEqual(mock_os_listdir.return_value[0:2], file_in_directory)

    def test_get_lines_from_file_raises_runtime_error_if_file_does_not_exist(self):
        self.assertRaises(RuntimeError, filesystem.get_lines_from_file, "mock/test/file/path/which/does/not/exit")

    @patch("__builtin__.open")
    @patch("os.path.exists")
    def test_get_lines_from_file_returns_file_lines_excluding_comments_and_empty_lines_when_file_exists(self, mock_os_path_exists, mock_open):
        correct_line_list = ['This is the first line', 'This is the second line', 'The previous line was a blank line']
        mock_os_path_exists.return_value = True
        mock_open.return_value = StringIO("#This is a comment    \n This is the first line \n This is the second line \n            \n The previous line was a blank line")
        self.assertEquals(filesystem.get_lines_from_file("/test/path/mock_file.txt"), correct_line_list)

    def test_get_local_file_checksum_raises_runtime_error_if_file_does_not_exist(self):
        self.assertRaises(RuntimeError, filesystem.get_local_file_checksum, "mock/test/file/path")

    @patch("nssutils.lib.shell.run_local_cmd")
    @patch("os.path.exists")
    def test_get_local_file_checksum_raises_runtime_error_when_rc_is_not_0(self, mock_os_path_exists, mock_run_local_cmd):
        mock_run_local_cmd.return_value = shell.Response(1, "D", .12)
        mock_os_path_exists.return_value = True
        self.assertRaises(RuntimeError, filesystem.get_local_file_checksum, "mock/test/path")

    @patch("nssutils.lib.shell.run_local_cmd")
    @patch("os.path.exists")
    def test_get_local_file_checksum_returns_stdout_when_file_exists_and_rc_is_0(self, mock_os_path_exists, mock_run_local_cmd):
        mock_run_local_cmd.return_value = shell.Response(0, "100", .12)
        mock_os_path_exists.return_value = True
        self.assertEquals(filesystem.get_local_file_checksum("mock/test/path"), "100")

    @patch("nssutils.lib.filesystem.does_remote_file_exist")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_remote_file_checksum_raises_runtime_error_if_file_does_not_exist(self, mock_run_remote_cmd, mock_does_remote_file_exist):
        mock_does_remote_file_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(1, "blah", .987)
        self.assertRaises(RuntimeError, filesystem.get_remote_file_checksum, "mock/test/file/path", "mock_host", "mock_user")

    @patch("nssutils.lib.filesystem.does_remote_file_exist")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_remote_file_checksum_raises_runtime_error_when_rc_is_not_0(self, mock_run_remote_cmd, mock_does_remote_file_exist):
        mock_does_remote_file_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(1, "100               mock/test/path", .282)
        self.assertRaises(RuntimeError, filesystem.get_remote_file_checksum, "mock/test/path", "mock_host", "mock_user")

    @patch("nssutils.lib.filesystem.get_remote_hostname")
    @patch("nssutils.lib.filesystem.does_remote_file_exist")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_remote_file_checksum_raises_runtime_error_when_stdout_is_None(self, mock_run_remote_cmd, mock_does_remote_file_exist, *_):
        mock_does_remote_file_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(0, None, .654)
        self.assertRaises(RuntimeError, filesystem.get_remote_file_checksum, "mock/test/path", "mock_host", "mock_user")

    @patch("nssutils.lib.filesystem.does_remote_file_exist")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_remote_file_checksum_raises_runtime_error_when_stdout_is_an_empty_string(self, mock_run_remote_cmd, mock_does_remote_file_exist):
        mock_does_remote_file_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(0, "", .654)
        self.assertRaises(RuntimeError, filesystem.get_remote_file_checksum, "mock/test/path", "mock_host", "mock_user")

    @patch("nssutils.lib.filesystem.does_remote_file_exist")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_get_remote_file_checksum_returns_checksum_from_stdout_when_rc_is_0_and_password_is_none(self, mock_run_remote_cmd, mock_does_remote_file_exist):
        mock_does_remote_file_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(0, "777               mock/test/path", .432)
        self.assertEquals(filesystem.get_remote_file_checksum("mock/test/file/path", "test_host", "test_user"), "777")

    @patch("nssutils.lib.filesystem.does_remote_file_exist")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_get_remote_file_checksum_returns_checksum_from_stdout_when_rc_is_0_and_password_is_not_none(self, mock_run_remote_cmd, mock_does_remote_file_exist):
        mock_does_remote_file_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(0, "888               mock/test/path", .432)
        self.assertEquals(filesystem.get_remote_file_checksum("mock/test/file/path", "test_host", "test_user", "test_password"), "888")

    @patch("nssutils.lib.filesystem.does_remote_file_exist")
    def test_get_lines_from_remote_file_raises_exception_when_does_remote_file_exist_returns_false(self, mock_does_remote_file_exist):
        mock_does_remote_file_exist.return_value = False
        self.assertEquals([], filesystem.get_lines_from_remote_file("mock/test/path", "mock_host", "mock_user"))

    @patch("nssutils.lib.filesystem.does_remote_file_exist")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_lines_from_remote_file_returns_an_empty_list_when_rc_is_not_0(self, mock_run_remote_cmd, mock_does_remote_file_exist):
        mock_does_remote_file_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(1, "blah", .654)
        self.assertEquals(filesystem.get_lines_from_remote_file("mock/file/path", "test_host", "test_user"), [])

    @patch("nssutils.lib.filesystem.does_remote_file_exist")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_lines_from_remote_file_returns_list_of_lines_from_stdout_when_rc_is_0_and_password_is_none(self, mock_run_remote_cmd, mock_does_remote_file_exist):
        mock_does_remote_file_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(0, "This is line 1\nThis is line 2\nThis is line 3", .654)
        self.assertEquals(filesystem.get_lines_from_remote_file("mock/file/path", "test_host", "test_user", "password"), ["This is line 1", "This is line 2", "This is line 3"])

    @patch("nssutils.lib.filesystem.does_remote_dir_exist")
    def test_verify_remote_directory_exists_is_true_no_password(self, mock_does_remote_dir_exist):
        mock_does_remote_dir_exist.return_value = True
        self.assertIsNone(filesystem.verify_remote_directory_exists("mock/file/path", "test_host", "test_user"))

    @patch("nssutils.lib.filesystem.does_remote_dir_exist")
    def test_verify_remote_directory_exists_is_false_password_is_none(self, mock_does_remote_dir_exist):
        mock_does_remote_dir_exist.return_value = False
        self.assertRaises(OSError, filesystem.verify_remote_directory_exists, "mock/file/path", "test_host", "test_user", password=None)

    @patch("nssutils.lib.filesystem.does_remote_dir_exist")
    def test_verify_remote_directory_exists_is_true(self, mock_does_remote_dir_exist):
        mock_does_remote_dir_exist.return_value = True
        self.assertIsNone(filesystem.verify_remote_directory_exists("mock/file/path", "test_host", "test_user"))

    @patch("nssutils.lib.filesystem.does_remote_dir_exist")
    def test_verify_remote_directory_exists_is_false(self, mock_does_remote_dir_exist):
        mock_does_remote_dir_exist.return_value = False
        self.assertRaises(OSError, filesystem.verify_remote_directory_exists, "mock/file/path", "test_host", "test_user", password="test_password")

    @patch("nssutils.lib.filesystem.does_remote_dir_exist")
    def test_verify_remote_directory_exists_no_username(self, mock_does_remote_dir_exist):
        mock_does_remote_dir_exist.return_value = True
        self.assertRaises(TypeError, filesystem.verify_remote_directory_exists, "mock/file/path", "test_host", password="test_password")

    @patch("nssutils.lib.filesystem.does_remote_dir_exist")
    def test_verify_remote_directory_exists_password_and_no_username(self, mock_does_remote_dir_exist):
        mock_does_remote_dir_exist.return_value = True
        self.assertRaises(TypeError, filesystem.verify_remote_directory_exists, "mock/file/path", password="test_password")

    @patch("nssutils.lib.filesystem.does_remote_dir_exist")
    def test_verify_remote_directory_exists_no_params(self, mock_does_remote_dir_exist):
        mock_does_remote_dir_exist.return_value = True
        self.assertRaises(TypeError, filesystem.verify_remote_directory_exists)

    def test_verify_remove_file_over_certain_age_success(self):
        directory = '/tmp'
        file_path = "/tmp/to_be_deleted.txt"
        filesystem.touch_file(file_path)

        time.sleep(1)
        filesystem.remove_local_files_over_certain_age(directory, r'to_be.*\.txt', 1)

        self.assertFalse(filesystem.does_file_exist(file_path))

    @patch("nssutils.lib.log.logger.debug")
    def test_verify_remove_file_over_certain_age_no_matches_found(self, mock_debug_log):
        directory = os.path.join(pkgutil.get_loader('nssutils').filename, "etc")

        time.sleep(1)
        filesystem.remove_local_files_over_certain_age(directory, r'^no_file.*\.txt', 1)
        self.assertFalse(mock_debug_log.called)

    def test_verify_remove_file_over_certain_age_and_case_insensitive_match_success(self):
        directory = '/tmp'
        file_path = "/tmp/to_be_CMEXPORT_deleted.txt"
        filesystem.touch_file(file_path)

        time.sleep(1)
        filesystem.remove_local_files_over_certain_age(directory, r'export.*\.txt', 1)

        self.assertFalse(filesystem.does_file_exist(file_path))

    @patch("nssutils.lib.shell.run_remote_cmd")
    @patch("nssutils.lib.filesystem.does_remote_file_exist")
    def test_get_files_with_pattern_in_remote_file(self, mock_does_remote_file_exist, mock_run_remote_cmd):
        expected_list = ["/test/mock/dir/path/directory_one/file_one.txt", "/test/mock/dir/path/directory_two/file_one.txt"]
        mock_does_remote_file_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(0, "/test/mock/dir/path/directory_one/file_one.txt\n/test/mock/dir/path/directory_two/file_one.txt\n", .211)
        self.assertEquals(filesystem.get_remote_files_with_pattern_in_content("/test/mock/dir/path/", "test_host", "test_user", "file_one.txt", "some_pattern", password=None), expected_list)

    @patch("nssutils.lib.shell.run_remote_cmd")
    @patch("nssutils.lib.filesystem.does_remote_file_exist")
    def test_get_files_with_pattern_in_remote_file_returns_zero_files(self, mock_does_remote_file_exist, mock_run_remote_cmd):
        mock_does_remote_file_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(0, "\n", .211)
        self.assertRaises(RuntimeError, filesystem.get_remote_files_with_pattern_in_content, "/test/mock/dir/path/", "test_host", "test_user", "file_one.txt", "some_pattern", password=None)

    @patch("nssutils.lib.shell.run_remote_cmd")
    @patch("nssutils.lib.filesystem.does_remote_file_exist")
    @patch("nssutils.lib.log.logger.debug")
    def test_get_files_with_pattern_in_remote_file_with_errors(self, mock_logger_debug, mock_does_remote_file_exist, mock_run_remote_cmd):
        expected_list = ["/test/mock/dir/path/directory_one/file_one.txt", "/test/mock/dir/path/directory_two/file_one.txt"]

        mock_does_remote_file_exist.return_value = True
        resp_text = "/test/mock/dir/path/directory_one/file_one.txt\negrep: can't open ath/directory_one/file_one.txt\nfind: stat() error /test/mock/dir/path/directory_three/file_one.txt: Permission denied\n/test/mock/dir/path/directory_two/file_one.txt\n"
        mock_run_remote_cmd.return_value = shell.Response(0, resp_text, .211)

        self.assertEquals(filesystem.get_remote_files_with_pattern_in_content("/test/mock/dir/path/", "test_host", "test_user", "file_one.txt", "some_pattern", password=None), expected_list)
        self.assertTrue(mock_logger_debug.called)

    @patch("nssutils.lib.filesystem.does_remote_dir_exist", return_value=True)
    @patch("nssutils.lib.shell.run_remote_cmd")
    @patch("nssutils.lib.filesystem.does_remote_file_exist")
    def test_get_files_with_pattern_in_remote_file_with_errors_and_invalid_return_code(self, mock_does_remote_file_exist, mock_run_remote_cmd, *_):
        expected_list = ["/test/mock/dir/path/directory_one/file_one.txt", "/test/mock/dir/path/directory_two/file_one.txt"]

        mock_does_remote_file_exist.return_value = True
        mock_run_remote_cmd.return_value = shell.Response(
            1, "/test/mock/dir/path/directory_one/file_one.txt\negrep: can't open ath/directory_one/file_one.txt\nfind: stat() error /test/mock/dir/path/directory_three/file_one.txt: Permission denied\n/test/mock/dir/path/directory_two/file_one.txt\n", .211)

        self.assertEquals(filesystem.get_remote_files_with_pattern_in_content("/test/mock/dir/path/", "test_host", "test_user", "file_one.txt", "some_pattern", password=None), expected_list)

    @patch("nssutils.lib.filesystem.does_remote_dir_exist", return_value=False)
    def test_get_files_with_pattern_in_remote_file_with_non_existing_parent_directory(self, *_):
        self.assertRaises(OSError, filesystem.get_remote_files_with_pattern_in_content, "/test/mock/dir/path/", "test_host", "test_user", "file_one.txt", "some_pattern", password=None)

    @patch("nssutils.lib.cache.get_vnf_laf")
    def test_add_sudo_if_cloud_returns_correct_values(self, mock_get_vnf_laf):
        mock_get_vnf_laf.return_value = "1.2.3.4"
        self.assertEqual("sudo ", filesystem.add_sudo_if_cloud('1.2.3.4'))

    def test_add_sudo_if_cloud_defaults_to_empty_string(self):
        self.assertNotEqual("sudo ", filesystem.add_sudo_if_cloud('1.2.3.4'))

    @patch("nssutils.lib.cache.get_vnf_laf")
    def test_add_sudo_if_cloud_defaults_to_empty_string_if_no_matching_hostname(self, mock_get_vnf_laf):
        mock_get_vnf_laf.return_value = "1.2.3.5"
        self.assertNotEqual("sudo ", filesystem.add_sudo_if_cloud(' 1.2.3.4'))

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_hostname(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(rc=0, stdout="1.2.3.4")
        self.assertEqual("1.2.3.4", filesystem.get_remote_hostname('localhost', 'user', 'password'))

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_hostname_from_solaris_system(self, mock_run_remote_cmd):
        mock_run_remote_cmd.side_effect = unit_test_utils.RemoteCommandResponder({
            "uname": shell.Response(rc=0, stdout="SunOS"),
            "ifconfig -a | awk 'BEGIN { count=0; } { if ( $1 ~ /inet/ ) { count++; if( count==2 ) { print $2; } } }'": shell.Response(rc=0, stdout="1.2.3.4"),
        })
        self.assertEqual("1.2.3.4", filesystem.get_remote_hostname('localhost', 'user', 'password'))

    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_hostname_returns_empty_hostname_on_failure(self, mock_run_remote_cmd):
        mock_run_remote_cmd.return_value = shell.Response(rc=5, stdout="1.2.3.4")
        self.assertEqual("", filesystem.get_remote_hostname('localhost', 'user', 'password'))


if __name__ == "__main__":
    unittest2.main(verbosity=2)

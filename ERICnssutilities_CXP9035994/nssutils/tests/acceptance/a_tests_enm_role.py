import unittest2

from nssutils.lib.enm_user_2 import CustomRole, EnmComRole, EnmRoleAlias, RoleCapability
from nssutils.tests import func_test_utils, test_fixture, test_utils
from nssutils.tests.func_test_utils import func_dec


class EnmRoleAcceptanceTests(unittest2.TestCase):

    NAME = "Acceptance_{0}".format(test_utils.get_random_string(4))
    DESCRIPTION = "Test Role"
    UPDATED_DESCRIPTION = "Test Role Updated"

    @classmethod
    def setUpClass(cls):
        cls.fixture = test_fixture.AcceptanceTestFixture(cls)
        cls.fixture.num_users = 1
        cls.fixture.user_roles = ["SECURITY_ADMIN"]

    @classmethod
    def tearDownClass(cls):
        func_test_utils.module_tear_down(cls)

    def setUp(self):
        func_test_utils.setup(self)
        self.enm_role = EnmComRole(self.NAME, description=self.DESCRIPTION, user=self.fixture.users[0])
        self.alias_role = EnmRoleAlias(self.NAME, {EnmComRole("SystemAdministrator")}, description=self.DESCRIPTION,
                                       user=self.fixture.users[0])
        self.custom_role = CustomRole(self.NAME, description=self.DESCRIPTION,
                                      roles={EnmComRole("SystemAdministrator")},
                                      capabilities=RoleCapability.get_role_capabilities_for_resource("cm_editor"),
                                      user=self.fixture.users[0])

    def tearDown(self):
        func_test_utils.tear_down(self)

    @func_dec("Enm_User_Role", "Create Role")
    def test_01_create_enm_role(self):
        self.enm_role.create()

    @func_dec("Enm_User_Role", "Update Role")
    def test_02_update_enm_role(self):
        self.enm_role.update()

    @func_dec("Enm_User_Role", "Delete Role")
    def test_03_delete_enm_role(self):
        self.enm_role.delete()

    @func_dec("Enm_User_Role", "Create custom Role")
    def test_04_create_custom_role(self):
        self.custom_role.create()

    @func_dec("Enm_User_Role", "Update custom Role")
    def test_05_update_custom_role(self):
        self.custom_role.status = True
        self.custom_role.roles = {EnmComRole("SystemAdministrator")}
        self.custom_role.capabilities = RoleCapability.get_role_capabilities_for_resource("nhm")
        self.custom_role.update()

    @func_dec("Enm_User_Role", "Delete custom Role")
    def test_06_delete_custom_role(self):
        self.custom_role.delete()

    @func_dec("Enm_User_Role", "Create alias Role")
    def test_07_create_alias_role(self):
        self.alias_role.create()

    @func_dec("Enm_User_Role", "Delete  alias Role")
    def test_08_delete_alias_role(self):
        self.alias_role.delete()


if __name__ == "__main__":
    unittest2.main(verbosity=2)

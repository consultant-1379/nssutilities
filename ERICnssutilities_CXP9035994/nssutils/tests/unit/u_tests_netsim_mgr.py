#!/usr/bin/env python

import unittest2
from mock import Mock, patch
from parameterizedtestcase import ParameterizedTestCase

from nssutils.lib import enm_node, netsim_mgr, persistence, shell
from nssutils.tests import unit_test_utils
from nssutils.tests.unit_test_utils import patch_netsim_executor


class NetsimMgrUnitTests(ParameterizedTestCase):

    def setUp(self):
        unit_test_utils.setup()
        unit_test_utils.mock_admin_session()

    def tearDown(self):
        unit_test_utils.tear_down()
        shell.connection_mgr = None

    def _setup_test_node_object(self):
        name = "netsimlin537_LTE07ERBS00123"
        node_ip = "10.241.112.201"
        mim_version = "4.1.189"
        netsim = "netsimlin537"
        simulation = "blade_runners"
        model_identity = "1094-174-285"
        node = enm_node.Node(
            name, node_ip, mim_version, model_identity, security_state='ON', normal_user='test',
            normal_password='test', secure_user='test', secure_password='test', subnetwork='subnetwork', netsim=netsim, simulation=simulation)
        persisted_node_objects = {}
        persisted_node_objects[node.node_id] = node
        persistence.set("workload_node_pool", persisted_node_objects, 5)
        return node

    def _valid_started_nodes_response(self):
        return "{0}\n{1}\n{2}\n{3}\n{4}\n{5}\n{6}\n{7}\n{8}\n{9}".format(
            ">> .open LTEE1200-V2x160-RV-FDD-LTE01", "OK",
            ">> .show started",
            "'server_00156_LTE_ERBS_E1200-V2@netsimlin704' for LTE ERBS E1200-V2",
            "=================================================================",
            "    NE                       Address          Simulation/Commands",
            "    LTE01ERBS00138           10.243.0.138     /netsim/netsimdir/LTEE1200-V2x160-RV-FDD-LTE01",
            "    LTE01ERBS00137           10.243.0.137     /netsim/netsimdir/LTEE1200-V2x160-RV-FDD-LTE01",
            "    LTE01ERBS00130           10.243.0.130     /netsim/netsimdir/LTEE1200-V2x160-RV-FDD-LTE01",
            "END")

    def _mock_run_cmd(self, mock_run_cmd, stdout):
        response = Mock()
        response.ok = True
        response.stdout = stdout
        mock_run_cmd.return_value = response

    @patch("nssutils.lib.network.is_host_pingable")
    @patch("nssutils.lib.cache.get")
    def test_validate_netsim_connectivity_with_unpingable_netsim_raises_runtime_error(self, mock_cache_get, mock_is_host_pingable):
        mock_cache_get.return_value = None
        mock_is_host_pingable.return_value = False
        self.assertRaises(
            RuntimeError, netsim_mgr.validate_netsim_connectivity, "invalid_netsim")

    @patch("nssutils.lib.shell.are_ssh_credentials_valid")
    @patch("nssutils.lib.network.is_host_pingable")
    @patch("nssutils.lib.cache.get")
    def test_validate_netsim_connectivity_with_wrong_credentials_netsim_raises_runtime_error(self, mock_cache_get, mock_is_host_pingable, mock_are_ssh_credentials_valid):
        mock_cache_get.return_value = None
        mock_is_host_pingable.return_value = True
        mock_are_ssh_credentials_valid.return_value = False
        self.assertRaises(
            RuntimeError, netsim_mgr.validate_netsim_connectivity, "invalid_netsim")

    @patch("nssutils.lib.shell.copy_ssh_key_to_server")
    @patch("nssutils.lib.shell.are_ssh_credentials_valid")
    @patch("nssutils.lib.network.is_host_pingable")
    def test_validate_netsim_connectivity_is_ok(self, mock_is_host_pingable, mock_are_ssh_credentials_valid, mock_copy_ssh_key_to_server):
        mock_is_host_pingable.return_value = True
        mock_are_ssh_credentials_valid.return_value = True
        netsim_mgr.validate_netsim_connectivity("netsimlin704")
        self.assertFalse(mock_copy_ssh_key_to_server.called)

    @patch("nssutils.lib.filesystem.does_remote_file_exist")
    @patch("nssutils.lib.config.get_prop")
    @patch("nssutils.lib.cache.get")
    def test_check_if_ref_file_exists_returns_true_if_ref_file_is_not_created(self, mock_cache_get, mock_config_get_prop, mock_does_remote_file_exist):
        node = self._setup_test_node_object()
        mock_cache_get.return_value = None
        mock_config_get_prop.side_effect = ["prop1", "prop2"]
        mock_does_remote_file_exist.return_value = True
        self.assertTrue(
            netsim_mgr.check_if_ref_file_exists(node.netsim, node.simulation))

    @patch("nssutils.lib.cache.get")
    def test_check_if_ref_file_exists_returns_true_if_ref_file_is_already_created(self, mock_cache_get):
        node = self._setup_test_node_object()
        mock_cache_get.return_value = True
        self.assertTrue(
            netsim_mgr.check_if_ref_file_exists(node.netsim, node.simulation))

    @patch("nssutils.lib.filesystem.does_remote_file_exist")
    @patch("nssutils.lib.config.get_prop")
    @patch("nssutils.lib.cache.get")
    def test_check_if_ref_file_exists_returns_false_if_ref_file_is_not_created(self, mock_cache_get, mock_config_get_prop, mock_does_remote_file_exist):
        node = self._setup_test_node_object()
        mock_cache_get.return_value = None
        mock_config_get_prop.side_effect = ["prop1", "prop2"]
        mock_does_remote_file_exist.return_value = False
        self.assertFalse(
            netsim_mgr.check_if_ref_file_exists(node.netsim, node.simulation))

    def test_check_node_status_for_nodes_list_returns_error_when_no_nodes_specified(self):
        nodes_list = None
        self.assertRaises(
            ValueError, netsim_mgr.check_node_status_for_nodes_list, nodes_list)

    @patch("nssutils.lib.netsim_mgr._get_started_nodes")
    def test_check_node_status_for_nodes_list_status_as_started_for_one_node_list(self, mock_get_started_nodes):
        nodes_list = []
        mock_node = Mock()
        mock_node.node_id = "LTE01ERBS00137"
        nodes_list.append(mock_node)
        mock_get_started_nodes.return_value = self._valid_started_nodes_response()

        updated_nodes_list = netsim_mgr.check_node_status_for_nodes_list(
            nodes_list)
        self.assertEqual(updated_nodes_list[0].node_started, True)

    @patch("nssutils.lib.netsim_executor.run_cmd")
    def test_get_started_nodes_calls_run_ne_cmd(self, mock_run_netsim_command):
        netsim_name = "netsimlin704"
        simulation_name = "LTEE1200-V2x160-RV-FDD-LTE01"
        show_started_cmd = ".show started"
        response = Mock()
        response.stdout = self._valid_started_nodes_response()
        mock_run_netsim_command.return_value = response

        netsim_mgr._get_started_nodes(netsim_name, simulation_name)
        mock_run_netsim_command.assert_called_with(
            show_started_cmd, netsim_name, sim=simulation_name)

    @patch("nssutils.lib.netsim_executor.run_cmd")
    @patch("nssutils.lib.log.green_text")
    def test_update_simulation_calls_log_function_with_all_message(self, mock_log, mock_run_netsim):
        mock_run_netsim.return_value = Mock()
        netsim_mgr.update_simulation(
            "LTE01", sim_host="netsimlin704", cmd='some_command', operation="start")
        mock_log.assert_called_with(
            "Attempting to start all nodes on simulation LTE01")
        mock_run_netsim.assert_called_with(
            'some_command', 'netsimlin704', sim='LTE01', node_names=None)

    @patch("nssutils.lib.netsim_executor.run_cmd")
    @patch("nssutils.lib.log.green_text")
    def test_update_simulation_calls_log_function_with_num_nodes_message(self, mock_log, mock_run_netsim):
        mock_run_netsim.return_value = Mock()
        netsim_mgr.update_simulation(
            "LTE01", sim_host="netsimlin704", cmd='some_command', nodes=['1', '1'], operation="start")
        mock_log.assert_called_with(
            "Attempting to start 2 nodes on simulation LTE01")
        mock_run_netsim.assert_called_with(
            'some_command', 'netsimlin704', node_names='1 1', sim='LTE01')

    @patch("nssutils.lib.netsim_mgr._print_simulations")
    def test_execute_calls_list_simulations_option(self, mock_print_simulations):
        netsim_mgr.execute("list_simulations", "netsim", ['sim1'])
        self.assertTrue(mock_print_simulations.called)

    @patch("nssutils.lib.netsim_mgr._print_nodes")
    @patch("nssutils.lib.thread_queue.ThreadQueue")
    def test_execute_calls_list_nodes_option(self, mock_constructor, mock_print_nodes):
        mock_thread_queue = Mock()
        mock_constructor.return_value = mock_thread_queue
        netsim_mgr.execute("list_nodes", 'netsim', ['LTE01'])
        self.assertTrue(mock_print_nodes.called)

    @patch("nssutils.lib.netsim_mgr._print_info")
    @patch("nssutils.lib.netsim_mgr._activity_info_added")
    @patch("nssutils.lib.netsim_mgr._subscription_info_added")
    @patch("nssutils.lib.netsim_mgr._core_info_added")
    def test_execute_calls_activities_option(self, mock_core_info, mock_subscription_info, mock_activity_info, mock_print_info):
        mock_core_info.return_value = True
        mock_subscription_info.return_value = True
        mock_activity_info.return_value = True
        mock_print_info.return_value = None
        netsim_mgr.execute("activities", 'netsim', ['LTE01'])
        self.assertTrue(mock_subscription_info.called)
        self.assertTrue(mock_activity_info.called)

    @patch("nssutils.lib.netsim_mgr._print_info")
    @patch("nssutils.lib.netsim_mgr._core_info_added")
    def test_execute_calls_info_option(self, mock_core_info, mock_print_info):
        mock_core_info.return_value = True
        mock_print_info.return_value = None
        netsim_mgr.execute("info", 'netsim', ['LTE01'])
        self.assertTrue(mock_core_info.called)

    @patch("nssutils.lib.netsim_mgr.update_simulation")
    def test_operation_args_calls_update_simulation(self, mock_update):
        netsim_mgr.execute('start', 'netsim', ['LTE01'], ['NODE1', 'NODE2'])
        self.assertTrue(mock_update.called)

    @patch("nssutils.lib.thread_queue.ThreadQueue")
    def test_operation_args_calls_thread_queues(self, mock_constructor):
        mock_thread_queue = Mock()
        mock_work_entry = Mock()
        mock_work_entry.result = "OK"
        mock_thread_queue.work_entries = [mock_work_entry]
        mock_constructor.return_value = mock_thread_queue
        self.assertTrue(netsim_mgr.execute('start', 'netsim', ['LTE01']))
        self.assertTrue(mock_thread_queue.execute.called)

    @patch("nssutils.lib.netsim_executor.run_cmd")
    def test_network_elements_produces_nodes_list(self, mock_run_netsim_cmd):
        response = Mock()
        response.stdout = "someoutput_before=['required','value'] sim_nes=['LTE01','LTE02']"
        mock_run_netsim_cmd.return_value = response
        nodes = netsim_mgr.get_network_elements("netsim", "simulation")
        self.assertEqual(nodes, ['LTE01', 'LTE02'])

    @patch("nssutils.lib.exception.process_exception")
    @patch("nssutils.lib.netsim_executor.run_cmd")
    def test_network_elements_produces_exception_netsim_output_bad(self, mock_run_netsim_cmd, mock_exception):
        mock_exception.side_effect = SystemExit("Exit Message")
        response = Mock()
        response.stdout = "someoutput_before=['required','value'] bad_output=['LTE01','LTE02']"
        mock_run_netsim_cmd.return_value = response

        with self.assertRaises(SystemExit):
            netsim_mgr.get_network_elements("netsim", "simulation")

        self.assertTrue(mock_exception.called)

    @patch("nssutils.lib.netsim_mgr._core_info_added")
    @patch("nssutils.lib.netsim_executor.run_cmd")
    def test_core_info_calls_build_core_info(self, mock_run_cmd, mock_core_info):
        response = Mock()
        response.ok = True
        response.stdout = "['command', 'output', 'LTE01', '10.45.200.5', '_server']"
        mock_run_cmd.return_value = response

        simulation_list = ['LTEE1200-V2x160-RV-FDD-LTE01']
        netsim_mgr._core_info_added("netsim", simulation_list)
        self.assertTrue(mock_core_info.called)

    @patch_netsim_executor()
    def test_core_info_added_merges_dict_as_expected(self, mock_connection_pool, *_):
        unit_test_utils.setup_mock_shell_remote_connection(self)
        show_all_sims_response = 'LTEG1124-limx160-5K-FDD-LTE03\n=====================\nNE              Address                     Server\nLTE03ERBS00001  192.168.101.68              server_00354_LTE_ERBS_G1124-lim@netsim\nLTE03ERBS00002  192.168.101.69              server_00354_LTE_ERBS_G1124-lim@netsim\nLTE03ERBS00003  192.168.101.70              server_00354_LTE_ERBS_G1124-lim@netsim\nLTE03ERBS00004  192.168.101.71              server_00354_LTE_ERBS_G1124-lim@netsim\nLTE03ERBS00005  192.168.101.72              server_00354_LTE_ERBS_G1124-lim@netsim'
        unit_test_utils.add_shell_connection_responses(self, stdout_response=show_all_sims_response)
        show_simne_response = '>> .show simne LTE03ERBS00001\naddress             :  "192.168.101.68"\ncreated_from        :  {{"LTE-TEMPLATE","ERBS","CPP-9-0",[]},\n                        {1,1305098395570410}}\ncs_use_attribute_cha:  [true]\ndbprops             :  [{type,ets}]\ninstpatha           :  []\ninstpathz           :  []\nne_name             :  [{"LTE03ERBS","00001"}]\nne_type             :  {"LTE","ERBS","G1124-lim",[]}\npm_scanner_state    :  disabled\nport                :  "IIOP_PROT"\nserver              :  "netsim"\nssliop_def          :  "SL2"\nssliop_state        :  pending_ssliop\nstatus              :  started\nsubaddr             :  "192.168.101.68"\ntmpfs               :  [{root,"/pms_tmpfs/LTE03/LTE03ERBS00001"}]\ntype                :  "receiver"\nunique_netype       :  {1,1448456346790887}\nusers               :  [[{username,"netsim"},{password,"netsim"}]]\n{cs_attrib_defaultva:  false\n{cs_attrib_defaultva:  false\n{cs_software_upgrade:  1364992\n{cs_software_upgrade:  true\n{cs_software_upgrade:  sftp\n{fs_resource,"fs"}  :  [{root,default}]\n\n'
        unit_test_utils.add_shell_connection_responses(self, stdout_response=show_simne_response)

        mock_pool = Mock()
        mock_pool.get_connection.return_value = self.mock_connection
        mock_connection_pool.return_value = mock_pool
        dict_to_update = {'LTE03ERBS00001': {}}
        netsim_mgr._core_info_added("netsim", dict_to_update)
        self.assertEqual({'LTE03ERBS00001': {'mim': 'unknown'}}, dict_to_update)

    @patch("nssutils.lib.netsim_executor.deploy_script")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_build_core_info_returns_stopped_status_for_com_ecim_node(self, mock_run_cmd, _):
        response = Mock()
        mock_run_cmd.return_value = response
        response.stdout = 'sample text \nne_type    : {"WPP","SGSN","15A-WPP-V5",[]}\n sample text'
        node_data_list = ">> .show allsimnes\n" \
                         "CORE-FT-SGSNMME-15A-V5x6\n" \
                         "===========\n" \
                         "NE Address Server\n" \
                         "SGSN-MME-15A01 10.243.5.228 161 public v1 .128.0.0.193.1.10.243.5.228 CORE-FT-SGSNMME-15A-V5x6_SGSN-MME-15A01 authpass privpass hmac_md5 cbc_des Not Started\n\n"
        simulation = 'CORE-FT-SGSNMME-15A-V5x6'
        netsim = 'netsimlin704'
        core_info = netsim_mgr._build_core_info(simulation, node_data_list, netsim)

        expected_core_info = {'SGSN-MME-15A01': {'ip': '10.243.5.228', 'status': 'stopped'}, 'mim': '{"WPP","SGSN","15A-WPP-V5",[]}'}

        self.assertEquals(core_info, expected_core_info)

    @patch("nssutils.lib.netsim_executor.deploy_script")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_build_core_info_returns_started_status_for_com_ecim_node(self, mock_run_cmd, _):
        response = Mock()
        mock_run_cmd.return_value = response
        response.stdout = 'sample text\n ne_type    : {"WPP","SGSN","15A-WPP-V5",[]}\n sample text'
        node_data_list = ">> .show allsimnes\n" \
                         "CORE-FT-SGSNMME-15A-V5x6\n" \
                         "===========\n" \
                         "NE Address Server\n" \
                         "SGSN-MME-15A01 10.243.5.228 161 public v1 .128.0.0.193.1.10.243.5.228 CORE-FT-SGSNMME-15A-V5x6_SGSN-MME-15A01 authpass privpass hmac_md5 cbc_des server_00333_LTE_ERBS_D1189-lim@netsimlin704\n\n"
        simulation = 'CORE-FT-SGSNMME-15A-V5x6'
        netsim = 'netsimlin704'
        core_info = netsim_mgr._build_core_info(simulation, node_data_list, netsim)
        expected_core_info = {'SGSN-MME-15A01': {'ip': '10.243.5.228', 'status': 'started'}, 'mim': '{"WPP","SGSN","15A-WPP-V5",[]}'}

        self.assertEquals(core_info, expected_core_info)

    @patch("nssutils.lib.netsim_executor.deploy_script")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_build_core_info_returns_started_status_for_node(self, mock_run_cmd, _):
        response = Mock()
        mock_run_cmd.return_value = response
        response.stdout = "sample text \nne_type    : LTE ERBS D1189\n sample text"
        node_data_list = ">> .show allsimnes\n" \
                         "LTED1189-limx160-FDD-LTE07\n" \
                         "===========\n" \
                         "NE Address Server\n" \
                         "LTE07ERBS00001 10.45.200.5 server_00333_LTE_ERBS_D1189-lim@netsimlin704\n\n"
        simulation = 'LTED1189-limx160-FDD-LTE07'
        netsim = 'netsimlin704'
        core_info = netsim_mgr._build_core_info(simulation, node_data_list, netsim)

        expected_core_info = {'LTE07ERBS00001': {'ip': '10.45.200.5', 'status': 'started'}, 'mim': 'D1189'}

        self.assertEquals(core_info, expected_core_info)

    @patch("nssutils.lib.netsim_executor.deploy_script")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_build_core_info_returns_stopped_status_for_node(self, mock_run_cmd, _):
        response = Mock()
        mock_run_cmd.return_value = response
        response.stdout = "sample text \nne_type    : LTE ERBS D1189\n sample text"
        node_data_list = ">> .show allsimnes\n" \
                         "LTED1189-limx160-FDD-LTE07\n" \
                         "===========\n" \
                         "NE Address Server\n" \
                         "LTE07ERBS00001 10.45.200.5 not started\n\n"
        simulation = 'LTED1189-limx160-FDD-LTE07'
        netsim = 'netsimlin704'
        core_info = netsim_mgr._build_core_info(simulation, node_data_list, netsim)

        expected_core_info = {'LTE07ERBS00001': {'ip': '10.45.200.5', 'status': 'stopped'}, 'mim': 'D1189'}

        self.assertEquals(core_info, expected_core_info)

    @patch("nssutils.lib.exception.process_exception")
    def test_build_core_info_calls_exception_when_simulation_does_not_exist(self, mock_exception):
        mock_exception.side_effect = SystemExit("Exit Message")
        node_data_list = ">> .show allsimnes\n LTED1189-limx160-FDD-LTE98\n ===========\n NE Address Server\n LTE07ERBS00001 10.45.200.5 not started\n\n"
        with self.assertRaises(SystemExit):
            netsim_mgr._build_core_info("LTED1189-limx160-FDD-LTE07", node_data_list, "netsimlin704")

        self.assertTrue(mock_exception.called)

    def test_is_node_list_entry_returns_true(self):
        node_list_entry = "LTE01:"
        nodes = ['LTE01']

        self.assertTrue(netsim_mgr._is_node(node_list_entry, nodes))

    def test_is_node_not_a_list_entry_returns_false(self):
        node_list_entry = "LTE01"
        nodes = ['LTE01']

        self.assertFalse(netsim_mgr._is_node(node_list_entry, nodes))

    @patch("nssutils.lib.netsim_mgr._build_simulation_dictionary")
    @patch("nssutils.lib.netsim_mgr._parse_activity_status")
    @patch("nssutils.lib.netsim_mgr._parse_nodes")
    @patch("nssutils.lib.netsim_executor.run_cmd")
    def test_get_activity_info_processes_component_data(self, mock_run_cmd, mock_parse_nodes, mock_parse_activity, mock_build_simulation_dictionary):
        response = Mock()
        response.ok = True
        response.stdout = "CC00010"
        mock_run_cmd.return_value = response

        # assert _parse_nodes called
        netsim_mgr._get_activity_info("sim", "netsim")
        self.assertTrue(mock_parse_nodes.called)
        self.assertTrue(mock_parse_activity.called)
        self.assertTrue(mock_build_simulation_dictionary.called)

    @patch("nssutils.lib.netsim_mgr._parse_nodes")
    @patch("nssutils.lib.netsim_executor.run_cmd")
    def test_get_activity_info_with_no_component_data(self, mock_run_cmd, mock_parse_nodes):

        # assert
        response = Mock()
        response.ok = True
        response.stdout = "There are no components"
        mock_run_cmd.return_value = response

        # MOCK. CALL COUNT = 0
        self.assertFalse(mock_parse_nodes.called)

    def test_parse_components_no_components_returns_empty_list(self):
        components_data = "There are no components"
        self.assertEquals(
            [], netsim_mgr._parse_components(components_data, "sim"))

    def test_parse_components_returns_component_list(self):
        components_data = "CC00010"
        self.assertEquals(
            ['CC00010'], netsim_mgr._parse_components(components_data, "sim"))

    def test_parse_nodes_returns_activities_nodes(self):

        component_data = ">>> show info\n activities : [\"+alarm_activity\"]\n  erlpids : []\n  force : off\n  laps : 1\n paired : \"avcburst\"\n program : {}\n sim_nes : [\"LTE01ERBS00001\",\"LTE01ERBS00002\",\"LTE01ERBS00003\",\n   \"LTE01ERBS00004\",\"LTE01ERBS00005\"]\n"
        activities_nodes = {
            '+alarm_activity': ['LTE01ERBS00001', 'LTE01ERBS00002', 'LTE01ERBS00003', 'LTE01ERBS00004', 'LTE01ERBS00005']}
        self.assertEquals(
            activities_nodes, netsim_mgr._parse_nodes(component_data, {}))

    def test_parse_activity_status_returns_started_activity(self):
        activity_data = ">> .show activities +alarm_activity started -alarm_activity"

        activity_status = {'+alarm_activity': 'started'}
        self.assertEquals(
            activity_status, netsim_mgr._parse_activity_status(activity_data, {}))

    def test_parse_activity_status_returns_stopped_activity(self):
        activity_data = ">> .show activities +alarm_activity -alarm_activity"

        activity_status = {'+alarm_activity': 'stopped'}
        self.assertEquals(
            activity_status, netsim_mgr._parse_activity_status(activity_data, {}))

    def test_build_simulation_dictionary_assembles_correct_dictionary(self):
        activity_nodes = {'+alarm_activity': ['LTE01ERBS00001', 'LTE01ERBS00002']}
        activity_status = {'+alarm_activity': 'started'}

        expected_simulation_dictionary = {'LTE01ERBS00001': {'activities': {'+alarm_activity': 'started'}}, 'LTE01ERBS00002': {'activities': {'+alarm_activity': 'started'}}}

        simulation_dictionary = netsim_mgr._build_simulation_dictionary(activity_nodes, activity_status)
        self.assertEquals(simulation_dictionary, expected_simulation_dictionary)

    @patch("nssutils.lib.netsim_executor.run_cmd")
    def test_get_subcription_info_returns_inactive_if_simulation_stopped(self, mock_run_cmd):
        response = Mock()
        response.ok = True
        sims_dict = {'CORE-ST-SGSN-WPP-14B-V10x5': {'mim': '{"WPP","SGSN","14B-WPP-V10",[]}', 'SGSN-14B-WPP-V1001': {'status': 'started', 'ip': '192.168.105.7'}}}
        response.stdout = ">> status; Not started!"
        mock_run_cmd.return_value = response
        expected = {'fm_sub': 'inactive', 'pm_sub': 'inactive', 'cm_sub': 'inactive'}
        actual = netsim_mgr._get_subscription_info("CORE-ST-SGSN-WPP-14B-V10x5", "netsim", "network", sims_dict)

        self.assertEqual(expected, actual['SGSN-14B-WPP-V1001'])

    @patch("nssutils.lib.netsim_executor.run_cmd")
    def test_get_subscription_info_assigns_inactive_to_pm_fm_cm_for_all_nodes_if_status_command_crashed(self, mock_run_cmd):
        response = Mock()
        response.ok = True
        sims_dict = {'CORE-ST-SGSN-WPP-14B-V10x5': {'mim': '{"WPP","SGSN","14B-WPP-V10",[]}', 'SGSN-14B-WPP-V1001': {'status': 'started', 'ip': '192.168.105.7'}}}
        response.stdout = ">> status; SGSN-14B-WPP-V1001: Streamsession crashed: {terminated {cmd_crashed"
        mock_run_cmd.return_value = response

        expected_simulation_dictionary = {'fm_sub': 'inactive', 'pm_sub': 'inactive', 'cm_sub': 'inactive'}

        simulation_dictionary = netsim_mgr._get_subscription_info("CORE-ST-SGSN-WPP-14B-V10x5", "netsim", "network", sims_dict)
        self.assertEquals(simulation_dictionary['SGSN-14B-WPP-V1001'], expected_simulation_dictionary)

    @patch("nssutils.lib.netsim_executor.run_cmd")
    def test_get_subscription_info_correctly_assigns_inactive_to_pm_fm_cm_for_all_nodes_if_no_subscriptions(self, mock_run_cmd):

        stdout = ">> status; LTE03ERBS00160: NE name Address Simulation LTE03ERBS00160 10.243.1.2 /netsim/netsimdir/LTEE1200-V2x160-RV-FDD-LTE03 MIB prefix: SubNetwork=ERBS-SUBNW-2,MeContext=netsimlin704_LTE03ERBS00160 Currently executing commands: gencmdshell status Corba security information: Corba security: off No security definition defined IPSec information: IP security: off Alarm Service information: No active alarm subscriptions There are no alarm/event generators active on this NE. Configuration Service information: No sessions No CS subscriptions Performance Management information: NOTE! PM data is DISABLED! No PM files will be generated. se 'pmdata:enable;' to enable file generation. performanceDataPath=/c/pm_data/ There are no scanners"

        self._mock_run_cmd(mock_run_cmd, stdout)
        sims_dict = {'LTED1189-limx160-FDD-LTE07': {'mim': '{"WPP","SGSN","14B-WPP-V10",[]}', 'LTE03ERBS00160': {'status': 'started', 'ip': '192.168.105.7'}}}
        expected_simulation_dictionary = {'LTE03ERBS00160': {'fm_sub': 'inactive', 'pm_sub': 'inactive', 'cm_sub': 'inactive'}}
        simulation_dictionary = netsim_mgr._get_subscription_info("LTED1189-limx160-FDD-LTE07", "netsim", "network", sims_dict)

        self.assertEquals(simulation_dictionary, expected_simulation_dictionary)

    @patch("nssutils.lib.netsim_executor.run_cmd")
    def test_get_subscription_info_correctly_assigns_active_if_subscriptions(self, mock_run_cmd):

        stdout = ">> status; LTE03ERBS00160: NE name Address Simulation LTE03ERBS00160 10.243.1.2 /netsim/netsimdir/LTEE1200-V2x160-RV-FDD-LTE03 MIB prefix: SubNetwork=ERBS-SUBNW-2,MeContext=netsimlin704_LTE03ERBS00160 Currently executing commands: gencmdshell status Corba security information: Corba security: off No security definition defined IPSec information: IP security: off Alarm Service information: Alarm subscriptions: ID: 19 Timeout = 15 There are no alarm/event generators active on this NE. Configuration Service information: No sessions Subscriptions: Internal id.........: 9  Performance Management information: NOTE! PM data is DISABLED! No PM files will be generated. Use 'pmdata:enable;' to enable file generation. performanceDataPath=/c/pm_data/ Scanners: Id Name Type State Reference fileset Error info ========= 11 USERDEF-Test2.Cont.Y.ST stats active"

        self._mock_run_cmd(mock_run_cmd, stdout)

        sims_dict = {'LTED1189-limx160-FDD-LTE07': {'mim': '{"WPP","SGSN","14B-WPP-V10",[]}', 'LTE03ERBS00160': {'status': 'started', 'ip': '192.168.105.7'}}}
        expected_simulation_dictionary = {'LTE03ERBS00160': {'fm_sub': 'active', 'pm_sub': 'active', 'cm_sub': 'active'}}
        simulation_dictionary = netsim_mgr._get_subscription_info("LTED1189-limx160-FDD-LTE07", "netsim", "network", sims_dict)

        self.assertEquals(simulation_dictionary, expected_simulation_dictionary)

    @patch("nssutils.lib.log.logger.warn")
    def test_print_simulations_calls_log_function_with_no_simulation_message(self, mock_log):
        netsim_mgr._print_simulations("netsimlin704", [])
        mock_log.assert_called_with("There are no simulations on netsimlin704")

    @patch("nssutils.lib.log.green_text")
    def test_print_simulations_calls_log_function_with_simulation_message(self, mock_log):
        netsim_mgr._print_simulations("netsimlin704", ["sim1"])
        self.assertTrue(mock_log.called)

    @patch("nssutils.lib.log.logger.info")
    def test_print_nodes_with_no_nodes_in_simulation(self, mock_log):
        mock_log.side_effect = None
        thread_queue_entry = Mock()
        thread_queue_entry.arg_list = ['simulation', 'LTE01']
        thread_queue_entry.result = []
        thread_queue_entries = [thread_queue_entry]
        netsim_mgr._print_nodes(thread_queue_entries)
        self.assertEquals(mock_log.call_count, 4)

    @patch("nssutils.lib.log.logger.info")
    def test_print_nodes_with_nodes_in_simulation(self, mock_log):
        mock_log.side_effect = None
        thread_queue_entry = Mock()
        thread_queue_entry.arg_list = ['simulation', 'LTE01']
        thread_queue_entry.result = ['LTE01']
        thread_queue_entries = [thread_queue_entry]
        netsim_mgr._print_nodes(thread_queue_entries)
        self.assertEquals(mock_log.call_count, 5)

    @patch('nssutils.lib.shell.run_remote_cmd')
    @patch("nssutils.lib.log.logger.info")
    def test_restart_netsim_returns_false_if_start_and_stop_commands_return_rc_1(self, mock_log, mock_run_remote_cmd):
        mock_log.side_effect = None
        response = Mock()
        response.rc = 1
        response.stdout = "ERROR"
        mock_run_remote_cmd.side_effect = [response, response]
        self.assertEquals(netsim_mgr.restart_netsim('netsim'), False)

    @patch('nssutils.lib.shell.run_remote_cmd')
    @patch("nssutils.lib.log.logger.info")
    def test_restart_netsim_returns_false_if_start_command_returns_rc_1(self, mock_log, mock_run_remote_cmd):
        mock_log.side_effect = None

        # Mock for netsim_stop
        response1 = Mock()
        response1.rc = 0
        response1.stdout = "PASS"

        # Mocks for netsim_start
        response2 = Mock()
        response2.rc = 1
        response2.stdout = "FAIL"
        response3 = Mock()
        response3.rc = 1
        response3.stdout = "FAIL"

        mock_run_remote_cmd.side_effect = [response1, response2, response3]
        self.assertEquals(netsim_mgr.restart_netsim('netsim'), False)

    @patch('nssutils.lib.shell.run_remote_cmd')
    @patch("nssutils.lib.log.logger.info")
    def test_restart_netsim_returns_false_if_stop_command_returns_rc_1(self, mock_log, mock_run_remote_cmd):
        mock_log.side_effect = None
        response = Mock()
        response.rc = 1
        response.stdout = "FAIL"
        mock_run_remote_cmd.return_value = response
        self.assertEquals(netsim_mgr.restart_netsim('netsim'), False)

    @patch('nssutils.lib.shell.run_remote_cmd')
    @patch("nssutils.lib.log.logger.info")
    def test_restart_netsim_returns_True_if_start_and_stop_commands_return_rc_0(self, mock_log, mock_run_remote_cmd):
        mock_log.side_effect = None
        response = Mock()
        response.rc = 0
        response.stdout = "PASS"
        mock_run_remote_cmd.side_effect = [response, response]
        self.assertEquals(netsim_mgr.restart_netsim('netsim'), True)

    @patch("nssutils.lib.netsim_mgr.execute")
    def test_switch_mim_raises_runtime_error_if_unable_to_start_nodes_on_simulation(self, mock_netsim_mgr_execute):
        mock_netsim_mgr_execute.return_value = False
        self.assertRaises(RuntimeError, netsim_mgr.switch_mim, "netsimlin704", "LTE_01", "LTER01ERBS0001", "E1239")

    @patch("nssutils.lib.netsim_executor.run_cmd")
    @patch("nssutils.lib.netsim_mgr._get_ne_type")
    @patch("nssutils.lib.netsim_mgr.execute")
    def test_switch_mim_returns_false_without_attempting_to_attemting_change_mim_version_ifcurrent_mim_version_is_same_as_paramater_mim(self, mock_netsim_mgr_execute, mock_get_ne_type, mock_run_cmd):
        mock_netsim_mgr_execute.return_value = True
        mock_get_ne_type.return_value = "LTE ERBS E1239"
        self.assertFalse(netsim_mgr.switch_mim("netsimlin704", "LTE_01", "LTER01ERBS0001", "E1239"))
        self.assertFalse(mock_run_cmd.called)

    @patch("nssutils.lib.netsim_executor.run_cmd")
    @patch("nssutils.lib.netsim_mgr.get_network_elements")
    @patch("nssutils.lib.netsim_mgr._get_ne_type")
    @patch("nssutils.lib.netsim_mgr.execute")
    def test_switch_mim_returns_false_if_num_nodes_updated_does_not_equal_the_num_nodes_on_the_simulation(self, mock_netsim_mgr_execute, mock_get_ne_type, mock_get_network_elements, mock_run_cmd):
        mock_netsim_mgr_execute.return_value = True
        # All we need is the length of the list so use range instead of Mock objects
        mock_get_network_elements.return_value = range(10)
        mock_get_ne_type.return_value = "LTE ERBS E1200"
        mock_response = Mock()
        mock_response_stdout = ""
        for _ in xrange(9):
            mock_response_stdout += "Mim change done \n"
        mock_response.stdout = mock_response_stdout
        mock_run_cmd.return_value = mock_response
        self.assertFalse(netsim_mgr.switch_mim("netsimlin704", "LTE_01", "LTER01ERBS0001", "E1239"))
        self.assertTrue(mock_run_cmd.called)

    @patch("nssutils.lib.netsim_executor.run_cmd")
    @patch("nssutils.lib.netsim_mgr.get_network_elements")
    @patch("nssutils.lib.netsim_mgr._get_ne_type")
    @patch("nssutils.lib.netsim_mgr.execute")
    def test_switch_mim_returns_True_if_num_nodes_updated_equals_the_num_nodes_on_the_simulation(self, mock_netsim_mgr_execute, mock_get_ne_type, mock_get_network_elements, mock_run_cmd):
        mock_netsim_mgr_execute.return_value = True
        # All we need is the length of the list so use range instead of Mock objects
        mock_get_network_elements.return_value = range(10)
        mock_get_ne_type.return_value = "LTE ERBS E1200"
        mock_response = Mock()
        mock_response_stdout = ""
        for _ in xrange(10):
            mock_response_stdout += "Mim change done for NE\n"
        mock_response.stdout = mock_response_stdout
        mock_run_cmd.return_value = mock_response
        self.assertTrue(netsim_mgr.switch_mim("netsimlin704", "LTE_01", "LTER01ERBS0001", "E1239"))
        self.assertTrue(mock_run_cmd.called)

    @patch("nssutils.lib.netsim_executor.run_cmd")
    def test_get_ne_type_returns_ne_information_for_node(self, mock_run_cmd):
        mock_response = Mock()
        mock_response.stdout = "oasfhuahfoaofb\n" \
            "sauoifgusgafosfhfs\n" \
            "ne_type        :LTE ERBS E1239\n" \
            "ljfuosdhfdsfohdf"
        mock_run_cmd.return_value = mock_response
        self.assertEquals(netsim_mgr._get_ne_type("LTE_01", "netsimlin704", "LTE01ERBS0001"), "LTE ERBS E1239")

    mixed_scanner_response = ">> showscanners2;\n" \
        "LTE04ERBS00152: id  measurement_name    status   info\n" \
        "======================================\n" \
        "123  PREDEF.STATS  ACTIVE\n\n" \
        "LTE04ERBS00126: id  measurement_name    status   info\n" \
        "======================================\n" \
        "111  PREDEF.STATS  ACTIVE\n" \
        "123  PREDEF.STATS  ACTIVE\n\n" \
        "LTE04ERBS00143: id  measurement_name    status   info\n" \
        "======================================\n" \
        "111  PREDEF.STATS  ACTIVE\n" \
        "123  PREDEF.STATS  ACTIVE\n\n" \
        "LTE04ERBS00120: There are no scanners\n"

    no_scanners_response = ">> showscanners2;\n" \
        "There are no scanners\n"

    all_scanners_response = ">> showscanners2;\n" \
        "id  measurement_name    status   info\n" \
        "======================================\n" \
        "111  PREDEF.STATS  ACTIVE\n" \
        "123  PREDEF.STATS  ACTIVE\n"

    @patch("nssutils.lib.netsim_executor.run_cmd")
    @ParameterizedTestCase.parameterize(
        ("response_stdout", "expected_result"),
        [
            (no_scanners_response, {"LTE04ERBS00152": False, "LTE04ERBS00126": False, "LTE04ERBS00143": False, "LTE04ERBS00120": False}),
            (all_scanners_response, {"LTE04ERBS00152": True, "LTE04ERBS00126": True, "LTE04ERBS00143": True, "LTE04ERBS00120": True}),
            (mixed_scanner_response, {"LTE04ERBS00152": False, "LTE04ERBS00126": True, "LTE04ERBS00143": True, "LTE04ERBS00120": False}),
        ]
    )
    def test_check_nodes_for_predefined_scanners_returns_correct(self, response_stdout, expected_result, mock_run_cmd):
        response = Mock()
        response.stdout = response_stdout
        mock_run_cmd.return_value = response
        self.assertEquals(expected_result, netsim_mgr.check_nodes_for_predefined_scanners("netsimlin704", "sim1", ["LTE04ERBS00120", "LTE04ERBS00126", "LTE04ERBS00143", "LTE04ERBS00152"], "111"))

    @patch("os.path.exists")
    @patch("nssutils.lib.thread_queue.ThreadQueue.__new__")
    def test_fetch_arne_xmls_returns_true_if_no_exceptions_were_raised_in_thread_queue(self, mock_thread_queue, mock_exists):
        mock_exists.return_value = True
        tq = Mock()
        tq.exceptions_raised = 0
        mock_thread_queue.return_value = tq
        self.assertTrue(
            netsim_mgr.fetch_arne_xmls_from_netsim("netsimlin704", ["sim1"], "/var/tmp"))
        self.assertTrue(tq.execute.called)

    @patch("nssutils.lib.thread_queue.ThreadQueue.__new__")
    def test_fetch_arne_xmls_returns_false_if_an_exceptions_was_raised_in_thread_queue(self, mock_thread_queue):
        entry_mock = Mock()
        entry_mock.exception_raised = False
        tq = Mock()
        tq.work_entries = [entry_mock]
        tq.exceptions_raised = 1
        mock_thread_queue.return_value = tq
        self.assertFalse(
            netsim_mgr.fetch_arne_xmls_from_netsim("netsimlin704", ["sim1"], "/var/tmp"))
        self.assertTrue(tq.execute.called)

    @patch("nssutils.lib.log.logger.debug")
    @patch("nssutils.lib.netsim_mgr.extract_error_summary_from_output_of_failed_create_arne_operation")
    @patch("nssutils.lib.shell.download_file")
    @patch("nssutils.lib.shell.Command")
    @patch("nssutils.lib.netsim_mgr.get_password_for_simulation")
    @patch("nssutils.lib.filesystem.delete_remote_file")
    @patch("nssutils.lib.filesystem.does_file_exist")
    @patch("nssutils.lib.filesystem.does_remote_file_exist")
    @patch("nssutils.lib.shell.run_local_cmd")
    @patch("nssutils.lib.shell.run_remote_cmd")
    def test_get_xml_file_from_netsim(self, mock_run_remote_cmd, mock_run_local_cmd,
                                      mock_does_remote_file_exist, mock_does_file_exist, mock_delete_remote_file,
                                      mock_password, *_):

        work_item = ["netsimlin704", "sim1"]
        xml_dir = "/var/tmp"
        mock_password.return_value = 'netsim'
        create_xml_cmd_response = Mock()
        mock_run_remote_cmd.return_value = create_xml_cmd_response
        create_xml_cmd_response.rc = 1
        self.assertRaises(RuntimeError, netsim_mgr.get_xml_file_from_netsim, work_item, xml_dir)

        create_xml_cmd_response.rc = 0
        mock_does_remote_file_exist.side_effect = [False, True, True, True, True, True, True, True]
        self.assertRaises(RuntimeError, netsim_mgr.get_xml_file_from_netsim, work_item, xml_dir)

        mock_does_file_exist.return_value = True
        add_netsim_and_simulation_to_arne_xml_cmd_reponse = Mock()
        mock_run_local_cmd.return_value = add_netsim_and_simulation_to_arne_xml_cmd_reponse
        add_netsim_and_simulation_to_arne_xml_cmd_reponse.rc = 1
        self.assertRaises(RuntimeError, netsim_mgr.get_xml_file_from_netsim, work_item, xml_dir)

        add_netsim_and_simulation_to_arne_xml_cmd_reponse.rc = 0
        self.assertIsNone(netsim_mgr.get_xml_file_from_netsim(work_item, xml_dir, delete_created_files=True))
        self.assertEquals(mock_delete_remote_file.call_count, 3)

    @patch("nssutils.lib.log.logger.debug")
    @patch("nssutils.lib.log.logger.info")
    def test_print_info_raises_exception_if_it_encounters_malformed_node_information_but_continues(self, mock_log_info, mock_log_debug):
        mal_formed_sim_info = {'CORE-ST-SGSN-WPP-15A-V5x5': {'mim': '{"WPP","SGSN","15A-WPP-V5",[]}', 'V503': {'pm_sub': 'inactive', 'fm_sub': 'inactive', 'cm_sub': 'inactive'}, 'SGSN-15A-WPP-V504': {'status': 'stopped', 'ip': '10.241.166.131'}}}
        netsim_mgr._print_info(mal_formed_sim_info, activities=True)
        self.assertTrue(mock_log_debug.called)  # Asserts that the debug in the caught exception is called
        self.assertTrue(mock_log_info.called)  # Assertes that the code continued and printed the other node information

    version_response = ">> .show installation\n" \
        "The following function blocks installed:\n" \
        "CXC134778_3PP release T1M directory 3pp_config Mon Aug 24 17:12:24 CEST 2015\n" \
        "CXC134 release T1H directory ACME Mon Aug 24 18:09:16 CEST 2015\n" \
        "CXC134_ASC release T1A directory ADC Wed Aug 26 16:35:54 CEST 2015\n" \
        "CXC134778_WPP release T1HZ directory wpp Tue Aug 25 17:26:42 CEST 2015\n" \
        "CXC134778_XML release T1H directory xmlvalidator Mon Aug 24 17:14:05 CEST 2015\n" \
        "CXC134XRPC release T1BE directory xrpc Tue Aug 25 17:14:49 CEST 2015\n" \
        "\n" \
        ">>>>>>>>>>>>>>>>>>  NETSim  installation report <<<<<<<<<<<<<<<<<<<<<\n" \
        "Made  Fri Oct 16 11:35:49 IST 2015 by netsim on netsim\n" \
        "Directory: /netsim/R28E\n" \
        "\n" \
        " * NETSim UMTS R28E  installed\n" \
        "\n" \
        "NETSim license number no_value, revision [50], expires 2016-02-28 and allows 6000 concurrently started NEs.\n" \
        "The license is valid for all hostids.\n" \
        "\n"

    version_no_response = ">> .show installation\n" \
        "NETSim seems to be started but cannot be connected ({badrpc,nodedown}).\n" \
        "[Re]start NETSim by doing:\n" \
        "> <installation-directory>/restart_netsim\n" \
        "\n"

    patches_response = "Installed patches:\n" \
        "P04246_UMTS_R28E NS-3156changeFrequency action not supported for MSRBS_V1(PICO) & MSRBS_V2 (LRAT)sims\n" \
        "P04378_UMTS_R28E NS-3648Nodes moving to Error state when batch of Gen2 nodes are started\n" \
        "P04652_UMTS_R28E NS:4402 DG2 query support\n" \
        "P04659_UMTS_R28E NETSim R28c snmp trap event time doesn't match real nodes behaviour (DUG2 and SGSN-MME)\n"

    license_response = ">> .show license\n" \
        "NETSim license number 415, revision 2, for generation 6.8, expires 2016-02-28.\n" \
        "It allows 6000 concurrently started NEs.\n" \
        "The license is valid for all hostids.\n" \
        "\n"

    license_no_response = ">> .show license\n" \
        "NETSim seems to be started but cannot be connected ({badrpc,nodedown}).\n" \
        "[Re]start NETSim by doing:\n" \
        "> <installation-directory>/restart_netsim\n" \
        "\n"

    @patch("nssutils.lib.netsim_executor.run_cmd")
    @ParameterizedTestCase.parameterize(
        ("response_stdout", "expected_result"),
        [
            (version_no_response, {}),
            (''.join([version_response, license_no_response]), {'version': 'R28E', 'patches': [], 'license': {}}),
            (''.join([version_response, patches_response, license_no_response]), {'version': 'R28E', 'patches': [
                "P04246_UMTS_R28E NS-3156changeFrequency action not supported for MSRBS_V1(PICO) & MSRBS_V2 (LRAT)sims",
                "P04378_UMTS_R28E NS-3648Nodes moving to Error state when batch of Gen2 nodes are started",
                "P04652_UMTS_R28E NS:4402 DG2 query support",
                "P04659_UMTS_R28E NETSim R28c snmp trap event time doesn't match real nodes behaviour (DUG2 and SGSN-MME)"
            ], 'license': {}}),
            (''.join([version_response, license_response]), {'version': 'R28E', 'patches': [], 'license': {
                'number': '415', 'revision': '2', 'generation': '6.8', 'expiration': '2016-02-28', 'nodes': '6000', 'hosts': 'The license is valid for all hostids.'}}),
            (''.join([version_response, patches_response, license_response]), {'version': 'R28E', 'patches': [
                "P04246_UMTS_R28E NS-3156changeFrequency action not supported for MSRBS_V1(PICO) & MSRBS_V2 (LRAT)sims",
                "P04378_UMTS_R28E NS-3648Nodes moving to Error state when batch of Gen2 nodes are started",
                "P04652_UMTS_R28E NS:4402 DG2 query support",
                "P04659_UMTS_R28E NETSim R28c snmp trap event time doesn't match real nodes behaviour (DUG2 and SGSN-MME)"
            ], 'license': {'number': '415', 'revision': '2', 'generation': '6.8', 'expiration': '2016-02-28', 'nodes': '6000', 'hosts': 'The license is valid for all hostids.'}})
        ]
    )
    def test_get_version_returns_correct_version_and_patch_list_and_license_info(self, response_stdout, expected_result, mock_run_cmd):
        response = Mock()
        response.stdout = response_stdout
        mock_run_cmd.return_value = response
        self.assertEquals(expected_result, netsim_mgr.get_version("netsimlin704"))

    @patch("nssutils.lib.netsim_executor.run_cmd")
    def test_get_password_for_simulation_returns_correct(self, mock_run_cmd):
        response = Mock()
        response.stdout = ("================================================================= NE  Address  "
                           "Simulation/Commands CORE78ML-TN02  192.168.102.111 161 private,public,trap v1+v2+v3 "
                           ".128.0.0.193.1.192.168.102.111 authPrivSHA1DES ericsson ericsson hmac_sha cbc_des "
                           "admin_user ericsson no_value hmac_md5 none authPrivMD5DES ericsson ericsson hmac_md5 "
                           "cbc_des oper_user ericsson ericsson hmac_md5 none view_user ericsson ericsson "
                           "hmac_md5 none control_user ericsson ericsson hmac_md5 none authNoPrivMD5None ericsson "
                           "no_value hmac_md5 none authNoPrivSHA1None ericsson ericsson hmac_sha none noAuthNoPriv "
                           "ericsson ericsson none none  /netsim/netsimdir/MLTN4.4FP7x2-CORE78 CORE78ML-TN01 "
                           "192.168.102.110 161 private,public,trap v1+v2+v3 .128.0.0.193.1.192.168.102.110 "
                           "authPrivSHA1DES ericsson ericsson hmac_sha cbc_des admin_user ericsson no_value hmac_md5 "
                           "none authPrivMD5DES ericsson ericsson hmac_md5 cbc_des oper_user ericsson ericsson hmac_md5"
                           " none view_user ericsson ericsson hmac_md5 none control_user ericsson ericsson hmac_md5"
                           " none authNoPrivMD5None ericsson no_value hmac_md5 none authNoPrivSHA1None ericsson "
                           "ericsson hmac_sha none noAuthNoPriv ericsson ericsson none none  "
                           "/netsim/netsimdir/MLTN4.4FP7x2-CORE78 "
                           "================================================================= ' "
                           "server_00095_GSM_LANSWITCH_BSC-NWI-E-450A@netsim' for GSM LANSWITCH BSC-NWI-E-450A")
        mock_run_cmd.return_value = response
        self.assertEqual(netsim_mgr.get_password_for_simulation('netsim', 'MLTN4.4FP7x2-CORE78'), 'ericsson')

    @patch("nssutils.lib.netsim_executor.run_cmd")
    def test_get_password_for_simulation_raises_exception(self, mock_run_cmd):
        mock_run_cmd.side_effect = Exception("Some exception")
        self.assertRaises(Exception, netsim_mgr.get_password_for_simulation, 'netsim', 'MLTN4.4FP7x2-CORE78')

    def test_fetch_arne_xmls_from_netsim_removes_default(self):
        target_simulations = ["default"]
        self.assertRaises(ValueError, netsim_mgr.fetch_arne_xmls_from_netsim, "netsim", target_simulations, "/tmp")

    @patch('nssutils.lib.netsim_mgr.thread_queue.ThreadQueue.__new__')
    def test_fetch_arne_xmls_from_netsim_returns_false_if_file_not_found(self, mock_thread_queue):
        entry_mock = Mock()
        entry_mock.exception_raised = False
        tq = Mock()
        tq.work_entries = [entry_mock]
        tq.exceptions_raised = 0
        mock_thread_queue.return_value = tq
        target_simulations = ["default", "sim1", "sim2"]
        self.assertFalse(netsim_mgr.fetch_arne_xmls_from_netsim("netsim", target_simulations, "/tmp", num_workers=1))

    @patch('nssutils.lib.log.logger.error')
    @patch('nssutils.lib.netsim_mgr.thread_queue.ThreadQueue.__new__')
    def test_fetch_arne_xmls_from_netsim_logs_exceptions(self, mock_thread_queue, mock_error):
        entry_mock = Mock()
        entry_mock.exception_raised = True
        entry_mock.arg_list = [[["Something"], ["Something", "Darkside"]]]
        entry_mock.exception = Exception("some exception")
        tq = Mock()
        tq.work_entries = [entry_mock]
        tq.exceptions_raised = 1
        mock_thread_queue.return_value = tq
        target_simulations = ["default", "sim1", "sim2"]
        netsim_mgr.fetch_arne_xmls_from_netsim("netsim", target_simulations, "/tmp", num_workers=1)
        self.assertTrue(mock_error.called)

    @patch('nssutils.lib.netsim_mgr.filesystem.delete_remote_file', return_value=True)
    @patch('nssutils.lib.netsim_mgr.get_password_for_simulation', return_value="netsim")
    @patch('nssutils.lib.netsim_mgr.shell.download_file', return_value="netsim")
    @patch('nssutils.lib.netsim_mgr.filesystem.does_remote_file_exist', return_value=True)
    @patch('nssutils.lib.netsim_mgr.shell.run_local_cmd')
    def test_get_xml_file_from_netsim_force_create(self, mock_run_local_cmd, *_):
        response = Mock()
        response.rc = 0
        mock_run_local_cmd.return_value = response
        netsim_mgr.get_xml_file_from_netsim(["host", "sim"], xml_dir="dir/", delete_created_files=False)

    @patch('nssutils.lib.netsim_mgr.filesystem.delete_remote_file', return_value=True)
    @patch('nssutils.lib.netsim_mgr.get_password_for_simulation', return_value="netsim")
    @patch('nssutils.lib.netsim_mgr.shell.download_file', return_value="netsim")
    @patch('nssutils.lib.netsim_mgr.filesystem.does_file_exist', return_value=True)
    @patch('nssutils.lib.netsim_mgr.filesystem.does_remote_file_exist', side_effect=[True, True, False, False])
    @patch('nssutils.lib.netsim_mgr.shell.run_local_cmd')
    def test_get_xml_file_from_netsim_force_create_verbose(self, mock_run_local_cmd, *_):
        response = Mock()
        response.rc = 0
        mock_run_local_cmd.return_value = response
        netsim_mgr.get_xml_file_from_netsim(["host", "sim"], verbose=False, xml_dir="dir/", delete_created_files=False)

    @patch('nssutils.lib.netsim_mgr.get_password_for_simulation', return_value="netsim")
    @patch('nssutils.lib.netsim_mgr.filesystem.does_remote_file_exist', side_effect=[True, False])
    @patch('nssutils.lib.netsim_mgr.extract_error_summary_from_output_of_failed_create_arne_operation')
    @patch('nssutils.lib.netsim_mgr.shell.run_remote_cmd')
    def test_get_xml_file_from_netsim_raises_runtime_error_prints_response(self, mock_run_remote_cmd, mock_summary, *_):
        response = Mock()
        response.rc = 1
        response.stdout = "Some error"
        mock_run_remote_cmd.return_value = response
        self.assertRaises(RuntimeError, netsim_mgr.get_xml_file_from_netsim, ["host", "sim"], xml_dir="dir/",
                          delete_created_files=False, force_create=True)
        self.assertTrue(mock_summary.called)

    @patch('nssutils.lib.netsim_mgr.get_password_for_simulation', return_value="netsim")
    @patch('nssutils.lib.netsim_mgr.filesystem.does_remote_file_exist', side_effect=[True, False])
    @patch('nssutils.lib.netsim_mgr.shell.run_remote_cmd')
    def test_get_xml_file_from_netsim_raises_runtime(self, mock_run_remote_cmd, *_):
        response = Mock()
        mock_run_remote_cmd.return_value = response
        self.assertRaises(RuntimeError, netsim_mgr.get_xml_file_from_netsim, ["host", "sim"], xml_dir="dir/",
                          delete_created_files=False)


if __name__ == "__main__":
    unittest2.main(verbosity=2)

##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

from logrotate_plugin.logrotate_plugin import LogrotatePlugin
from logrotate_plugin.logrotate_plugin import (
    _get_values, _ensure_unique_name, _query_existing, _get_all_nodes
)
from logrotate_extension.logrotate_extension import LogrotateExtension

from litp.core.plugin_context_api import PluginApiContext
from litp.extensions.core_extension import CoreExtension
from litp.core.model_manager import ModelManager, QueryItem
from litp.core.plugin_manager import PluginManager
from litp.core.model_item import ModelItem
from litp.core.task import ConfigTask
from litp.core.validators import ValidationError
from litp.core import constants

from litp.core.translator import Translator
t = Translator('ERIClitplogrotate_CXP9030583')
_ = t._

import unittest
from mock import Mock, PropertyMock


class TestLogrotatePlugin(unittest.TestCase):

    def setUp(self):
        self.model = ModelManager()
        self.plugin_manager = PluginManager(self.model)
        self.context = PluginApiContext(self.model)
        self.plugin_manager.add_property_types(
            CoreExtension().define_property_types())
        self.plugin_manager.add_item_types(
            CoreExtension().define_item_types())

        self.plugin_manager.add_default_model()

        self.plugin = LogrotatePlugin()
        self.plugin_manager.add_plugin('LogrotatePlugin', 'LogrotatePlugin',
                                       '1.0.0', self.plugin)

        self.plugin_manager.add_property_types(
            LogrotateExtension().define_property_types())

        self.plugin_manager.add_item_types(
            LogrotateExtension().define_item_types())

    def setup_model(self):
        # Use ModelManager.crete_item and ModelManager.create_link
        # to create and reference (i.e.. link) items in the model.
        # These correspond to CLI/REST verbs to create or link
        # items.
        self.node1 = self.model.create_item("node", "/node1",
                                            hostname="node1")
        self.node2 = self.model.create_item("node", "/node2",
                                            hostname="special")

    def query(self, item_type=None, **kwargs):
        # Use PluginApiContext.query to find items in the model
        # properties to match desired item are passed as kwargs.
        # The use of this method is not required, but helps
        # plugin developer mimic the run-time environment
        # where plugin sees QueryItem-s.
        return self.context.query(item_type, **kwargs)

    def test_validate_model(self):
        self.setup_model()
        # Invoke plugin's methods to run test cases
        # and assert expected output.
        errors = self.plugin.validate_model(self)
        self.assertEqual(0, len(errors))

    def test_create_configuration(self):
        self.setup_model()
        # Invoke plugin's methods to run test cases
        # and assert expected output.
        tasks = self.plugin.create_configuration(self)
        self.assertEqual(0, len(tasks))

    def _create_standard_items_ok(self):
        self.cluster_url = "/deployments/d1/clusters/c1"
        self.node1_url = "/deployments/d1/clusters/c1/nodes/node1"
        self.model.create_root_item("root", "/")
        self.model.create_item('deployment', '/deployments/d1')
        self.model.create_item('cluster', self.cluster_url)

        # Nodes
        self.model.create_item("node", self.node1_url,
                               hostname="node1")

        # new network model
        self.model.create_item(
            'network',
            '/infrastructure/networking/networks/mgmt_network',
            name='mgmt',
            subnet='10.0.1.0/24',
            litp_management='true'
        )
        self.model.create_item(
            'network',
            '/infrastructure/networking/networks/hrbt_ntwk',
            name='heartbleed',
            subnet='10.0.2.0/24'
        )

        # MS NIC
        self.model.create_item(
            'eth',
            '/ms/network_interfaces/if0',
            network_name="mgmt",
            device_name="eth0",
            ipaddress="10.0.1.10",
            macaddress='08:00:27:5B:C1:3F'
        )

        # Node 1 NICs
        self.model.create_item(
            'eth',
            self.node1_url + "/network_interfaces/if0",
            network_name="mgmt",
            device_name="eth0",
            ipaddress="10.0.1.0",
            macaddress='08:00:27:5B:C1:3F'
        )
        self.model.create_item(
            'eth',
            self.node1_url + "/network_interfaces/if1",
            network_name="heartbleed",
            device_name="eth1",
            ipaddress="10.0.2.0",
            macaddress='08:00:27:5B:C1:3F'
        )

    def test_log_task_added(self):
        self.model.create_item("logrotate-rule-config",
                               "/ms/configs/logrotate-app1")

        self.model.create_item(
            "logrotate-rule",
            "/ms/configs/logrotate-app1/rules/mylogrotaterule",
            path="/tmp",
            name="hourly_log_rotate")

        node1 = self.context.query_by_vpath("/ms")

        logrotate_rule = self.context.query_by_vpath(
            "/ms/configs/logrotate-app1/rules/mylogrotaterule")

        tasks = self.plugin.create_configuration(self.context)

        test_task = ConfigTask(node1, logrotate_rule,
                               'Create logrotate rule "hourly_log_rotate" on node "ms"',
                               "logrotate::rule",
                               call_id=logrotate_rule.name,
                               path=logrotate_rule.path
                               )

        self.assertEquals(test_task.model_item, tasks[0].model_item)
        self.assertEquals(test_task.item_vpath, tasks[0].item_vpath)
        # self.assertEquals(test_task.description, tasks[0].description)

    def test_update_task(self):
        self._create_standard_items_ok()
        i1 = self.model.create_item("logrotate-rule-config",
                               "/deployments/d1/clusters/c1/nodes/node1/configs/logrotate-app1")

        i2 = self.model.create_item(
            "logrotate-rule",
            "/deployments/d1/clusters/c1/nodes/node1/configs/logrotate-app1/rules/mylogrotaterule",
            path="/tmp",
            name="hourly_log_rotate")

        i1.set_applied()
        i2.set_applied()

        self.model.update_item("/deployments/d1/clusters/c1/nodes/node1/configs/logrotate-app1/rules/mylogrotaterule", compress='true')

        node1 = self.context.query_by_vpath("/deployments/d1/clusters/c1/nodes/node1")

        logrotate_rule = self.context.query_by_vpath(
            "/deployments/d1/clusters/c1/nodes/node1/configs/logrotate-app1/rules/mylogrotaterule")

        test_task = ConfigTask(node1, logrotate_rule,
                               'Update logrotate rule "hourly_log_rotate" on node "node1"',
                               "logrotate::rule",
                               call_id=logrotate_rule.name,
                               path=logrotate_rule.path
                               )
        tasks = self.plugin.create_configuration(self.context)

        self.assertEquals(test_task.description, tasks[0].description)
        self.assertEqual('true', tasks[0].kwargs['compress'])

    def test_validate_unique(self):
        '''Positive test to ensure the logrotate name is unique'''
        self._create_standard_items_ok()

        self.model.create_item("logrotate-rule-config",
                               "/ms/configs/logrotate-app1")

        self.model.create_item(
            "logrotate-rule",
            "/ms/configs/logrotate-app1/rules/mylogrotaterule",
            path="/tmp",
            name="hourly_log_rotate")

        errors = self.plugin.validate_model(self.context)

        self.assertEqual(0, len(errors))

    def test_remove_single_logrotate_config(self):
        self._create_standard_items_ok()
        self.model.create_item("logrotate-rule-config",
                               "/ms/configs/logrotate-app1")
        item = self.model.create_item(
            "logrotate-rule",
            "/ms/configs/logrotate-app1/rules/mylogrotaterule",
            path="/tmp",
            name="hourly_log_rotate")

        item.set_for_removal()

        tasks = self.plugin.create_configuration(self.context)
        self.assertEquals("absent", tasks[0].kwargs['ensure'])

    def test_remove_logrotate_config(self):
        '''Removing the logrotate-rule-config should remove\
        all of its children nodes as well.'''
        self._create_standard_items_ok()

        item = self.model.create_item("logrotate-rule-config",
                                      "/ms/configs/logrotate-app1")

        i1 = self.model.create_item(
            "logrotate-rule",
            "/ms/configs/logrotate-app1/rules/mylogrotaterule1",
            path="/tmp",
            name="hourly_log_rotate")

        i2 = self.model.create_item(
            "logrotate-rule",
            "/ms/configs/logrotate-app1/rules/mylogrotaterule2",
            path="/tmp",
            name="daily_log_rotate")

        i1.set_applied()
        i2.set_applied()

        self.model.remove_item("/ms/configs/logrotate-app1/")

        tasks = self.plugin.create_configuration(self.context)
        self.assertEquals(2, len(tasks))
        self.assertEquals("absent", tasks[0].kwargs['ensure'])
        self.assertEquals("absent", tasks[1].kwargs['ensure'])

    def test_validate_unique_should_have_error(self):
        '''Negative validation test, when creating two nodes with \
        same name an error is added'''
        self._create_standard_items_ok()

        rule1 = self.model.create_item("logrotate-rule-config",
                               "/ms/configs/logrotate-app1")

        rule2 = self.model.create_item(
            "logrotate-rule",
            "/ms/configs/logrotate-app1/rules/mylogrotaterule1",
            path="/var",
            name="hourly_log_rotate")

        rule3 = self.model.create_item(
            "logrotate-rule",
            "/ms/configs/logrotate-app1/rules/mylogrotaterule2",
            path="/tmp",
            name="hourly_log_rotate")

        rule4 = self.model.create_item(
            "logrotate-rule",
            "/ms/configs/logrotate-app1/rules/mylogrotaterule3",
            path="/tmp",
            name="hourly_log_rotate")

        rule5 = self.model.create_item(
            "logrotate-rule",
            "/ms/configs/logrotate-app1/rules/mylogrotaterule4",
            path="/tmp",
            name="weekly_log_rotate")

        errors = self.plugin.validate_model(self.context)
        ref_errors = [ValidationError(item_path = ("/ms/configs/logrotate-app1/"
                                                   "rules/mylogrotaterule1"
                                                   ),
                                      error_message = (_("FIELD_NOT_UNIQUE_ERR")% ( 'name', 'hourly_log_rotate')),
                                      error_type=constants.VALIDATION_ERROR),
                      ValidationError(item_path = ("/ms/configs/logrotate-app1/"
                                                   "rules/mylogrotaterule2"
                                                   ),
                                      error_message = (_("FIELD_NOT_UNIQUE_ERR")% ('name', 'hourly_log_rotate')),
                                      error_type=constants.VALIDATION_ERROR),
                      ValidationError(item_path = ("/ms/configs/logrotate-app1/"
                                                   "rules/mylogrotaterule3"
                                                   ),
                                      error_message = (_("FIELD_NOT_UNIQUE_ERR")% ('name', 'hourly_log_rotate')),
                                      error_type=constants.VALIDATION_ERROR),]
        self.assertEqual(len(errors), len(ref_errors))
        self.assertTrue(all(x in ref_errors for x in errors))

    def test_cannot_update_name(self):
        self._create_standard_items_ok()
        i1 = self.model.create_item("logrotate-rule-config",
                               "/ms/configs/logrotate-app1")

        i2 = self.model.create_item(
            "logrotate-rule",
            "/ms/configs/logrotate-app1/rules/mylogrotaterule",
            path="/tmp",
            name="hourly_log_rotate")

        self.assertEqual(0, len(self.model.update_item("/ms/configs/logrotate-app1/rules/mylogrotaterule", name='new_name')))
        i1.set_applied()
        i2.set_applied()
        update_test=self.model.update_item("/ms/configs/logrotate-app1/rules/mylogrotaterule", name='fail_name')
        ref_error = [ValidationError(item_path=("/ms/configs/logrotate-app1/rules/mylogrotaterule"
                                                   ),
                                      error_message=('Unable to modify readonly property: name'),
                                      error_type=constants.INVALID_REQUEST_ERROR, property_name='name')]
        self.assertEquals(update_test,ref_error)

    def test_validate_only_one_config_allowed_per_node(self):
        '''Negative validation test, when creating two nodes with \
        same name an error is added'''
        self._create_standard_items_ok()

        rule1 = self.model.create_item("logrotate-rule-config",
                               "/ms/configs/logrotate-app1")
        rule2 = self.model.create_item("logrotate-rule-config",
                               "/ms/configs/logrotate-app2")
        errors = self.plugin.validate_model(self.context)
        ref_errors = [ValidationError(item_path=("/ms/configs/logrotate-app2"
                                                   ),
                                      error_message=_("ONE_RULE_PER_NODE_ERR"),
                                      error_type=constants.VALIDATION_ERROR),
                      ValidationError(item_path=("/ms/configs/logrotate-app1"
                                                   ),
                                      error_message=_("ONE_RULE_PER_NODE_ERR"),
                                      error_type=constants.VALIDATION_ERROR)
                      ]
        self.assertTrue(all(x in ref_errors for x in errors))

    def test_validate_mailfirst_and_maillast_not_set_together(self):
        self._create_standard_items_ok()

        config = self.model.create_item("logrotate-rule-config",
                               "/ms/configs/logrotate-app1")

        rule = self.model.create_item(
            "logrotate-rule",
            "/ms/configs/logrotate-app1/rules/mylogrotaterule",
             path="/tmp",
             name="hourly_log_rotate",
             mailfirst="true", maillast="true")

        ref_errors = [ValidationError(item_path=(None),
                                      error_message=_("MAILFIRST_MAILLAST_ERR"),
                                      error_type=constants.VALIDATION_ERROR)]

        self.assertEqual(rule, ref_errors)

    def test_validate_create_group_requires_create_owner_etc(self):
        self._create_standard_items_ok()

        config = self.model.create_item("logrotate-rule-config",
                               "/ms/configs/logrotate-app1")

        rule = self.model.create_item(
            "logrotate-rule",
            "/ms/configs/logrotate-app1/rules/mylogrotaterule",
             path="/tmp",
             name="hourly_log_rotate",
             create_group="theGroup")

        errors = self.plugin.validate_model(self.context)
        ref_errors = [ValidationError(item_path = ("/ms/configs/logrotate-app1/"
                                                   "rules/mylogrotaterule"
                                                   ),
                                      error_message = _("CREATE_OWNER_REQ_CREATE_GROUP_ERR"),
                                      error_type=constants.VALIDATION_ERROR),
                      ValidationError(item_path = ("/ms/configs/logrotate-app1/"
                                                   "rules/mylogrotaterule"
                                                   ),
                                      error_message = _("CREATE_MODE_REQ_CREATE_OWNER_ERR"),
                                      error_type=constants.VALIDATION_ERROR),
                      ValidationError(item_path = ("/ms/configs/logrotate-app1/"
                                                   "rules/mylogrotaterule"
                                                   ),
                                      error_message = _("CREATE_MODE_REQ_CREATE_ERR"),
                                      error_type=constants.VALIDATION_ERROR)
                      ]

        self.assertEqual(errors, ref_errors)

    def test_validate_create_owner_requires_create_mode_etc(self):
        self._create_standard_items_ok()

        config = self.model.create_item("logrotate-rule-config",
                               "/ms/configs/logrotate-app1")

        rule = self.model.create_item(
            "logrotate-rule",
            "/ms/configs/logrotate-app1/rules/mylogrotaterule",
             path="/tmp",
             name="hourly_log_rotate",
             create_owner="theOwner",
             )

        errors = self.plugin.validate_model(self.context)
        ref_errors = [ValidationError(item_path = ("/ms/configs/logrotate-app1/"
                                                   "rules/mylogrotaterule"
                                                   ),
                                      error_message = _("CREATE_MODE_REQ_CREATE_OWNER_ERR"),
                                      error_type=constants.VALIDATION_ERROR),
                      ValidationError(item_path = ("/ms/configs/logrotate-app1/"
                                                   "rules/mylogrotaterule"
                                                   ),
                                      error_message = _("CREATE_MODE_REQ_CREATE_ERR"),
                                      error_type=constants.VALIDATION_ERROR)
                      ]

        self.assertEqual(errors, ref_errors)

    def test_validate_create_mode_requires_create(self):
        self._create_standard_items_ok()

        config = self.model.create_item("logrotate-rule-config",
                               "/ms/configs/logrotate-app1")

        rule = self.model.create_item(
            "logrotate-rule",
            "/ms/configs/logrotate-app1/rules/mylogrotaterule",
             path="/tmp",
             name="hourly_log_rotate",
             create_mode="777")

        errors = self.plugin.validate_model(self.context)
        ref_errors = [ValidationError(item_path = ("/ms/configs/logrotate-app1/"
                                                   "rules/mylogrotaterule"
                                                   ),
                                      error_message = _("CREATE_MODE_REQ_CREATE_ERR"),
                                      error_type=constants.VALIDATION_ERROR)]
        self.assertEqual(errors, ref_errors)

        def test_validate_create_is_false(self):
            self._create_standard_items_ok()

            config = self.model.create_item("logrotate-rule-config",
                                   "/ms/configs/logrotate-app1")

            rule = self.model.create_item(
                "logrotate-rule",
                "/ms/configs/logrotate-app1/rules/mylogrotaterule",
                 path="/tmp",
                 name="hourly_log_rotate",
                 create="false",
                 create_group="testgroup")

            errors = self.plugin.validate_model(self.context)
            ref_errors = []
            self.assertEqual(errors, ref_errors)

    def test_validate_create_mode_and_create_group(self):
        self._create_standard_items_ok()

        config = self.model.create_item("logrotate-rule-config",
                               "/ms/configs/logrotate-app1")

        rule = self.model.create_item(
            "logrotate-rule",
            "/ms/configs/logrotate-app1/rules/mylogrotaterule",
             path="/tmp",
             name="hourly_log_rotate",
             create_group="test_group",
             create_mode="555")

        errors = self.plugin.validate_model(self.context)
        ref_errors = [ValidationError(item_path = ("/ms/configs/logrotate-app1/"
                                                   "rules/mylogrotaterule"
                                                   ),
                                      error_message = _("CREATE_OWNER_REQ_CREATE_GROUP_ERR"),
                                      error_type=constants.VALIDATION_ERROR),

                      ValidationError(item_path = ("/ms/configs/logrotate-app1/"
                                                   "rules/mylogrotaterule"
                                                   ),
                                      error_message = _("CREATE_MODE_REQ_CREATE_ERR"),
                                      error_type=constants.VALIDATION_ERROR)
                      ]
        self.assertEqual(errors, ref_errors)

    def test_validate_with_no_errors(self):
        self._create_standard_items_ok()

        config = self.model.create_item("logrotate-rule-config",
                               "/ms/configs/logrotate-app1")

        rule = self.model.create_item(
            "logrotate-rule",
            "/ms/configs/logrotate-app1/rules/mylogrotaterule",
             path="/tmp",
             name="hourly_log_rotate",
             create_group="test_group",
             create_owner="test_owner",
             create_mode="555",
             create="true")

        errors = self.plugin.validate_model(self.context)
        ref_errors = []
        self.assertEqual(errors, ref_errors)


class QuickTestCase(unittest.TestCase):
    def test__ensure_unique_name(self):
        a = Mock(get_vpath=Mock(return_value='path_a'))
        pa = PropertyMock(return_value='a')
        type(a).name = pa
        b = Mock(get_vpath=Mock(return_value='path_b'))
        type(b).name = pa

        self.assertEqual(a.name, 'a')
        self.assertEqual(b.name, 'a')
        self.assertEqual(a.get_vpath(), 'path_a')
        self.assertEqual(b.get_vpath(), 'path_b')

        actual = set(_ensure_unique_name([a, b]))
        expected = set([
            ValidationError(item_path='path_b',
                            error_message=(_('FIELD_NOT_UNIQUE_ERR') %
                                           ('name', 'a'))),
            ValidationError(item_path='path_a',
                            error_message=(_('FIELD_NOT_UNIQUE_ERR') %
                                           ('name', 'a'))),
        ])
        self.assertEqual(expected, actual)

        pb = PropertyMock(return_value='b')
        type(b).name = pb
        self.assertEqual([], _ensure_unique_name([a, b]))

    def test_get_values(self):
        resource = Mock(properties={'path':'/tmp'})
        self.assertEqual({'path': '/tmp'}, _get_values(resource))

    def test__query_existing(self):
        def get_item(is_for_removal, is_removed, **kwargs):
            return Mock(is_for_removal=lambda: is_for_removal,
                        is_removed=lambda: is_removed,
                        **kwargs)
        removed = lambda: get_item(False, True)
        for_removal = lambda: get_item(True, False)
        existing = lambda mark: get_item(False, False, mark=mark)

        def query(item_type):
            if item_type == 'nonexisting':
                return []
            if item_type == 'removed_only':
                return [removed()]
            if item_type == 'for_removal_only':
                return [for_removal()]
            if item_type == 'all_nonexisting':
                return [removed(),
                        for_removal()]
            if item_type == 'existing_only':
                return [existing(1)]
            if item_type == 'mixed':
                return [existing(2),
                        removed(),
                        for_removal(),
                        existing(3)]

        context = Mock(query=query)
        self.assertEqual([], _query_existing(context, 'nonexisting'))
        self.assertEqual([], _query_existing(context, 'removed_only'))
        self.assertEqual([], _query_existing(context, 'for_removal_only'))
        self.assertEqual([], _query_existing(context, 'all_nonexisting'))

        result = _query_existing(context, 'existing_only')
        self.assertEqual(1, len(result))
        self.assertEqual(1, result[0].mark)

        result = _query_existing(context, 'mixed')
        self.assertEqual(2, len(result))
        self.assertEqual(set([2, 3]), set([r.mark for r in result]))

    def test__get_all_nodes(self):
        def get_item(is_for_removal, is_removed, **kwargs):
            return Mock(is_for_removal=lambda: is_for_removal,
                        is_removed=lambda: is_removed,
                        **kwargs)
        get_node = lambda a, b, **kw: get_item(a, b, item_type='node', **kw)
        get_ms = lambda a, b, **kw: get_item(a, b, item_type='ms', **kw)
        def query(item_type):
            if item_type == 'node':
                return [get_node(True, False), get_node(False, True),
                        get_node(False, False, mark=1),
                        get_node(False, False, mark=2)]
            if item_type == 'ms':
                return [get_ms(True, False), get_ms(False, True),
                        get_ms(False, False, mark=3),
                        get_ms(False, False, mark=4)]
        context = Mock(query=query)
        result = _get_all_nodes(context)
        self.assertEqual(4, len(result))
        expected = set([('node', 1),
                        ('node', 2),
                        ('ms', 3),
                        ('ms', 4)])
        actual = set([(x.item_type, x.mark) for x in result])
        self.assertEqual(expected, actual)

# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################
# pylint: disable=undefined-variable
from collections import namedtuple
from collections import defaultdict

from litp.core.plugin import Plugin
from litp.core.execution_manager import ConfigTask
from litp.core.validators import ValidationError
import litp.core.constants as constants

from litp.core.litp_logging import LitpLogger
log = LitpLogger()

from litp.core.translator import Translator
t = Translator('ERIClitplogrotate_CXP9030583')
_ = t._


class LogrotatePlugin(Plugin):
    """
    LITP Basic logrotate plugin for logrotate rule configuration.
    Update and remove reconfiguration actions are supported for \
    this plugin.
    """

    def validate_model(self, plugin_api_context):
        """
        The validation ensures that:
- The "name" property of a "logrotate-rule" is unique per node\
 in the deployment.
- "mailfirst" property and "maillast" property are mutually exclusive.
- "create_owner" property must be specified when "create_group" property is\
 defined.
- "create_mode" property must be specified when "create_owner" property is\
 defined.
- "create" property must be specified when "create_mode" property is defined.
- If there are duplicate paths in any of the files in the/etc/logrotate.d \
directory (including those files not managed by LITP), logrotate applies the \
rule that is found first (rule files are sorted alphabetically).
        """
        errors = []
        for node in _get_all_nodes(plugin_api_context):
            existing_configs = _query_existing(node, "logrotate-rule-config")
            if len(existing_configs) > 1:
                for config in existing_configs:
                    errors.append(ValidationError(
                        item_path=config.get_vpath(),
                        error_message=_('ONE_RULE_PER_NODE_ERR')
                    ))

            all_rules = node.query('logrotate-rule')
            errors.extend(_ensure_unique_name(all_rules))

            existing_rules = _query_existing(node, 'logrotate-rule')
            errors.extend(_validate_create_options(existing_rules))

        return errors

    def create_configuration(self, plugin_api_context):
        """
        *Example CLI for setting up a logrotate configuration file named \
        exampleservice that manages "exampleservice.log" stored \
        under "/var/log/exampleservice":*

        .. code-block:: bash

            litp create -t logrotate-rule-config -p /deployments/site1/\
clusters/cluster1/nodes/node1/configs/logrotate

            litp create -t logrotate-rule -p /deployments/site1/clusters/\
cluster1/nodes/node1/configs/logrotate/rules/exampleservice -o \
name="exampleservice" \
path="/var/log/exampleservice/exampleservice.log" missingok=true \
ifempty=true rotate=4 \
copytruncate=true

        *Example CLI for setting up a logrotate configuration file named \
        exampleservice_tasks that manages "*.log" \
        (all files ending with .log) \
        under "/var/log/exampleservice/tasks/":*

        .. code-block:: bash

            litp create -t logrotate-rule -p /deployments/site1/clusters/\
cluster1/nodes/node1/configs/logrotate/rules/exampleservice_tasks -o name=\
"exampleservice_tasks" path="/var/log/exampleservice/tasks/*.log" \
copytruncate=true \
rotate=0 missingok=true ifempty=true compress=false create=false mail=false

        *Example CLI for updating a logrotate rule:*

        .. code-block:: bash

            litp update -p /deployments/site1/clusters/cluster1/nodes/node1/\
configs/logrotate/rules/exampleservice -o missingok=false

        *Example CLI for removing a logrotate rule:*

        .. code-block:: bash

            litp remove -p /deployments/site1/clusters/cluster1/nodes/node1/\
configs/logrotate/rules/exampleservice
        For more information, see "Manage Log Rotation" \
from :ref:`LITP References <litp-references>`.

        """
        tasks = []
        for node in _get_all_nodes(plugin_api_context):
            for config in node.query("logrotate-rule-config"):
                for rule in config.rules:
                    if rule.is_applied():
                        continue
                    tasks.append(_create_task(rule, config, node))
        return tasks


def _get_all_nodes(plugin_api_context):
    results = []
    for item_type in ('node', 'ms'):
        results.extend(_query_existing(plugin_api_context, item_type))
    return results


def _query_existing(context, item_type):
    return [x for x in context.query(item_type)
            if not (x.is_for_removal() or x.is_removed())]


def _create_task(rule, config, node):
    call_id = "%s_%s_%s" % (node.item_id, config.item_id, rule.item_id)
    values = _get_values(rule)

    if rule.is_for_removal():
        desc = _('REMOVE_LOGROTATE_RULE') % (rule.name, node.hostname)
        values['ensure'] = 'absent'
    else:
        paths = values['path'].replace(",", " ")
        values['path'] = paths
        if rule.is_initial():
            desc = _('CREATE_LOGROTATE_RULE') % (rule.name, node.hostname)
        elif rule.is_updated():
            desc = _('UPDATE_LOGROTATE_RULE') % (rule.name, node.hostname)

    config_task = ConfigTask(
        node,
        rule,
        desc,
        "logrotate::rule",
        call_id,
        **values
    )
    config_task.model_items.add(config)

    return config_task


def _ensure_unique_name(item_types):
    errors = []
    namekeys = defaultdict(list)
    field = 'name'
    for f in item_types:
        name = getattr(f, field)
        namekeys[name].append(f.get_vpath())

    for name in namekeys:
        if len(namekeys[name]) > 1:
            for item_path in namekeys[name]:
                errors.append(ValidationError(
                    item_path=item_path,
                    error_message=(_('FIELD_NOT_UNIQUE_ERR')
                                   % (field, name))))
    return errors


PROPERTY_KEYS = frozenset(['name', 'path', 'compress',
                'compresscmd', 'compressext', 'compressoptions',
                'copy', 'copytruncate', 'create', 'create_mode',
                'create_owner', 'create_group', 'dateext',
                'dateformat', 'delaycompress', 'extension',
                'ifempty', 'mail', 'mailfirst', 'maillast', 'maxage',
                'minsize', 'missingok', 'olddir', 'postrotate',
                'prerotate', 'firstaction', 'lastaction', 'rotate',
                'rotate_every', 'size', 'sharedscripts', 'shred',
                'shredcycles', 'start', 'uncompresscmd'])


def _get_values(resource):
    # get values from properties to pass to puppet
    result = {}
    for key in PROPERTY_KEYS & set(resource.properties):
        result[key] = resource.properties[key]
    return result


def _validate_create_group_requires_create_owner(item, predicates):
    p = predicates
    if p.create_group and not p.create_owner:
        return [
            ValidationError(
                item_path=item.get_vpath(),
                error_type=constants.VALIDATION_ERROR,
                error_message=_('CREATE_OWNER_REQ_CREATE_GROUP_ERR'))
        ]


def _validate_create_owner_requires_create_mode(item, predicates):
    p = predicates
    if ((p.create_owner and not p.create_mode) or
        (p.create_group and not p.create_owner and not p.create_mode)):
        return [
            ValidationError(
                item_path=item.get_vpath(),
                error_type=constants.VALIDATION_ERROR,
                error_message=_('CREATE_MODE_REQ_CREATE_OWNER_ERR'))
        ]


def _validate_create_mode_requires_create(item, predicates):
    p = predicates
    if ((p.create_mode and not p.create) or
        (p.create_owner and not p.create_mode and not p.create) or
        (p.create_group and not p.create_owner and
         not p.create_mode and not p.create)):
        return [
            ValidationError(
                item_path=item.get_vpath(),
                error_type=constants.VALIDATION_ERROR,
                error_message=_('CREATE_MODE_REQ_CREATE_ERR'))
        ]


OPTIONS_ATTRIBUTES = ("create_owner", 'create_mode', "create_group", "create")
VALIDATORS = (_validate_create_group_requires_create_owner,
              _validate_create_owner_requires_create_mode,
              _validate_create_mode_requires_create)


def _validate_create_options(item_types):
    errors = []
    T = namedtuple('T', OPTIONS_ATTRIBUTES)
    for item in item_types:
        create_value = getattr(item, "create", None)
        if create_value != "false":
            predicates = T._make(getattr(item, attrname, None) is not None
                                 for attrname in OPTIONS_ATTRIBUTES)
            for f in VALIDATORS:
                errors.extend(f(item, predicates) or [])

    return errors

"""Journal non-registry system settings through constrained snapshot scripts."""
import base64
import json
from ..registry_txn import register_restorer


def capture(txn, ctx, resource):
    identity = 'system:' + resource
    snapshot = ctx.runner('status-system.ps1', {'Resource': resource})
    if snapshot.get('error') or 'value' not in snapshot:
        raise RuntimeError(snapshot.get('error') or f'Could not capture original {resource} settings.')
    txn.record('system', identity, {'resource': resource, 'value': snapshot['value']})


def restore(entry, context):
    payload = base64.b64encode(json.dumps(entry['value']).encode('utf-8')).decode('ascii')
    context['runner']('restore-system.ps1', {'Resource': entry['resource'], 'Data': payload})


register_restorer('system', restore)

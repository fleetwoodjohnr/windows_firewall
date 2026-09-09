"""Confirmation dialogs.

Callback-based rather than `exec()`-based, mirroring `Adw.AlertDialog.choose()`
in the Fedora app. `exec()` would spin a nested event loop inside whatever
handler called it, which is the Qt habit most likely to re-enter a signal
handler that is still part-way through updating a control -- exactly the class
of bug `service_row.py`'s `_syncing` guard exists to prevent. Staying
non-modal-with-a-callback keeps one event loop and one code path.
"""

import html

from PySide6.QtWidgets import QMessageBox


def escape_markup(text):
    """Qt rich text is HTML, so anything interpolated into it must be escaped.

    Level copy is authored in this repo, but service and firewall-rule-group
    names come from Windows, and a group name containing '&' would otherwise
    render as a broken entity.
    """
    return html.escape(str(text), quote=False)


def confirm(parent, heading, body, confirm_label, on_confirm, on_cancel=None, destructive=True):
    """Ask, then call back. Cancel is the default so that dismissing the dialog
    -- with Escape, or by clicking away -- never applies anything."""
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Warning if destructive else QMessageBox.Question)
    box.setWindowTitle(heading)
    box.setText(f"<b>{escape_markup(heading)}</b>")
    box.setInformativeText(_as_rich_text(body))
    box.setTextFormat(1)  # Qt.RichText

    accept = box.addButton(confirm_label, QMessageBox.AcceptRole)
    cancel = box.addButton("Cancel", QMessageBox.RejectRole)
    box.setDefaultButton(cancel)
    box.setEscapeButton(cancel)
    if destructive:
        accept.setProperty("destructive", True)

    def on_finished(_result):
        if box.clickedButton() is accept:
            on_confirm()
        elif on_cancel is not None:
            on_cancel()
        box.deleteLater()

    box.finished.connect(on_finished)
    box.setModal(True)
    box.open()
    return box


def _as_rich_text(body):
    """Preserve the paragraph breaks the level copy is written with."""
    paragraphs = [escape_markup(part).replace("\n", "<br>") for part in body.split("\n\n")]
    return "<p>" + "</p><p>".join(paragraphs) + "</p>"
